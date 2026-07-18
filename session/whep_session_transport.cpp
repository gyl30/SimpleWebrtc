#include "session/whep_session_transport.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include "dtls/dtls_packet.h"
#include "dtls/dtls_transport.h"
#include "ice/session_ice_udp_server.h"
#include "log/log.h"
#include "media/media_fanout_router.h"
#include "media/whep_rtp_rewriter.h"
#include "net/socket.h"
#include "session/session_stun_binding.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
whep_session_transport::whep_session_transport(boost::asio::io_context& io_context,
                                               std::string bind_host,
                                               std::shared_ptr<dtls_context> dtls_context,
                                               std::uint16_t dtls_ip_mtu,
                                               std::shared_ptr<media_fanout_router> media_fanout_router)
    : udp_server_(io_context, std::move(bind_host)),
      dtls_transport_(std::make_shared<dtls_transport>(std::move(dtls_context), dtls_ip_mtu)),
      srtp_transport_(std::make_shared<srtp_transport>(dtls_transport_)),
      media_fanout_router_(std::move(media_fanout_router))
{
}

whep_session_transport::~whep_session_transport()
{
    unsubscribe_media();
    udp_server_.stop();
}

whep_session_transport_result whep_session_transport::start(uint16_t local_port) { return udp_server_.start(local_port, *this); }

void whep_session_transport::set_peer_context(std::string local_ice_pwd,
                                              dtls_peer_identity identity,
                                              whep_rtp_rewriter_target target)
{
    unsubscribe_media();
    reset_selected_peer();

    local_ice_pwd_ = std::move(local_ice_pwd);
    dtls_identity_ = std::move(identity);

    {
        std::lock_guard lock(rtp_rewriter_mutex_);
        rtp_rewriter_target_ = std::move(target);
        publisher_source_.reset();
        publisher_source_generation_ = 0;
        pending_keyframe_request_ssrcs_.clear();
        requested_keyframe_ssrcs_.clear();
        rebuild_rtp_rewriter_locked();
    }

    subscribe_media();
}

void whep_session_transport::restart_peer_context(std::string local_ice_pwd,
                                                  dtls_peer_identity identity,
                                                  whep_rtp_rewriter_target target)
{
    reset_selected_peer();

    local_ice_pwd_ = std::move(local_ice_pwd);
    dtls_identity_ = std::move(identity);

    std::lock_guard lock(rtp_rewriter_mutex_);
    rtp_rewriter_target_ = std::move(target);
    pending_keyframe_request_ssrcs_.clear();
    requested_keyframe_ssrcs_.clear();
    rebuild_rtp_rewriter_locked();
}

void whep_session_transport::send_rtp(uint64_t source_generation, std::span<const uint8_t> plain_rtp)
{
    if (plain_rtp.empty() || !selected_remote_endpoint_.has_value())
    {
        return;
    }

    const std::string_view stream_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->stream_id) : std::string_view{};
    const std::string_view session_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->session_id) : std::string_view{};

    whep_rtp_rewrite_packet_result rewritten;

    {
        std::lock_guard lock(rtp_rewriter_mutex_);

        if (source_generation != publisher_source_generation_)
        {
            return;
        }

        rewritten = rtp_rewriter_.rewrite(plain_rtp);

        if (rewritten && rewritten->state == whep_rtp_rewrite_state::rewritten &&
            rewritten->kind == "video" && !rewritten->rtx)
        {
            if (rewritten->keyframe_request_needed)
            {
                requested_keyframe_ssrcs_.erase(rewritten->source_ssrc);
            }

            if (!requested_keyframe_ssrcs_.contains(rewritten->source_ssrc))
            {
                pending_keyframe_request_ssrcs_.insert(rewritten->source_ssrc);
            }
        }
    }

    if (!rewritten)
    {
        WEBRTC_LOG_WARN("WHEP RTP rewrite failed stream={} session={} error={}", stream_id, session_id, rewritten.error());
        return;
    }

    if (rewritten->state != whep_rtp_rewrite_state::rewritten || rewritten->packet.empty())
    {
        ++dropped_rtp_packet_count_;
        WEBRTC_LOG_DEBUG("WHEP RTP rewrite dropped stream={} session={} source_ssrc={} source_pt={} source_seq={} reason={} dropped={}",
                         stream_id,
                         session_id,
                         rewritten->source_ssrc,
                         rewritten->source_payload_type,
                         rewritten->source_sequence_number,
                         rewritten->reason,
                         dropped_rtp_packet_count_);
        return;
    }

    ++rewritten_rtp_packet_count_;

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);

    auto protected_packet =
        srtp_transport_->protect_outbound_packet(rewritten->packet, remote_address, srtp_packet_kind::rtp);

    if (!protected_packet)
    {
        WEBRTC_LOG_WARN(
            "WHEP RTP protect failed stream={} session={} remote={} error={}", stream_id, session_id, remote_address, protected_packet.error());
        return;
    }

    if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
    {
        WEBRTC_LOG_DEBUG("WHEP RTP protect ignored stream={} session={} remote={} state={} reason={}",
                         stream_id,
                         session_id,
                         remote_address,
                         srtp_packet_process_state_to_string(protected_packet->state),
                         protected_packet->reason);
        return;
    }

    WEBRTC_LOG_DEBUG(
        "WHEP RTP rewritten stream={} session={} kind={} rtx={} source_ssrc={} target_ssrc={} source_pt={} target_pt={} source_seq={} "
        "target_seq={} source_timestamp={} target_timestamp={} packets={}",
        stream_id,
        session_id,
        rewritten->kind,
        rewritten->rtx ? 1 : 0,
        rewritten->source_ssrc,
        rewritten->target_ssrc,
        rewritten->source_payload_type,
        rewritten->target_payload_type,
        rewritten->source_sequence_number,
        rewritten->target_sequence_number,
        rewritten->source_timestamp,
        rewritten->target_timestamp,
        rewritten_rtp_packet_count_);

    udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

    std::string publisher_session_id;
    bool request_keyframe = false;

    if (rewritten->kind == "video" && !rewritten->rtx)
    {
        std::lock_guard lock(rtp_rewriter_mutex_);

        if (source_generation == publisher_source_generation_ && publisher_source_ != nullptr &&
            pending_keyframe_request_ssrcs_.erase(rewritten->source_ssrc) != 0U)
        {
            requested_keyframe_ssrcs_.insert(rewritten->source_ssrc);
            publisher_session_id = publisher_source_->session_id;
            request_keyframe = true;
        }
    }

    if (!request_keyframe)
    {
        return;
    }

    const bool requested = media_fanout_router_->request_keyframe(
        stream_id, publisher_session_id, source_generation, rewritten->source_ssrc);

    if (requested)
    {
        WEBRTC_LOG_INFO("WHEP requested publisher keyframe stream={} session={} publisher_session={} generation={} media_ssrc={}",
                        stream_id,
                        session_id,
                        publisher_session_id,
                        source_generation,
                        rewritten->source_ssrc);
        return;
    }

    std::lock_guard lock(rtp_rewriter_mutex_);

    if (source_generation == publisher_source_generation_ && publisher_source_ != nullptr &&
        publisher_source_->session_id == publisher_session_id)
    {
        requested_keyframe_ssrcs_.erase(rewritten->source_ssrc);
        pending_keyframe_request_ssrcs_.insert(rewritten->source_ssrc);
    }
}

void whep_session_transport::subscribe_media()
{
    const std::weak_ptr<whep_session_transport> weak_transport = weak_from_this();

    media_fanout_router_->subscribe(
        dtls_identity_->stream_id,
        dtls_identity_->session_id,
        [weak_transport](uint64_t source_generation, std::span<const uint8_t> packet)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->send_rtp(source_generation, packet);
            }
        },
        [weak_transport](media_publisher_source_update update)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_publisher_source(std::move(update));
            }
        });
}

void whep_session_transport::unsubscribe_media()
{
    if (dtls_identity_.has_value())
    {
        media_fanout_router_->unsubscribe(dtls_identity_->session_id);
    }
}

void whep_session_transport::handle_publisher_source(media_publisher_source_update update)
{
    const std::string_view stream_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->stream_id) : std::string_view{};
    const std::string_view session_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->session_id) : std::string_view{};

    std::lock_guard lock(rtp_rewriter_mutex_);

    if (update.generation < publisher_source_generation_)
    {
        WEBRTC_LOG_DEBUG("WHEP ignored stale publisher source update stream={} session={} generation={} current_generation={}",
                         stream_id,
                         session_id,
                         update.generation,
                         publisher_source_generation_);
        return;
    }

    publisher_source_generation_ = update.generation;
    publisher_source_ = std::move(update.source);
    pending_keyframe_request_ssrcs_.clear();
    requested_keyframe_ssrcs_.clear();
    rebuild_rtp_rewriter_locked();
}

void whep_session_transport::rebuild_rtp_rewriter_locked()
{
    const std::string_view stream_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->stream_id) : std::string_view{};
    const std::string_view session_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->session_id) : std::string_view{};

    if (publisher_source_ == nullptr)
    {
        pending_keyframe_request_ssrcs_.clear();
        requested_keyframe_ssrcs_.clear();
        rtp_rewriter_.clear_source();
        WEBRTC_LOG_INFO("WHEP RTP publisher source unavailable stream={} session={} generation={}",
                        stream_id,
                        session_id,
                        publisher_source_generation_);
        return;
    }

    auto config = make_whep_rtp_rewriter_config(publisher_source_->session_id,
                                                 publisher_source_->offer,
                                                 rtp_rewriter_target_);

    if (!config)
    {
        pending_keyframe_request_ssrcs_.clear();
        requested_keyframe_ssrcs_.clear();
        rtp_rewriter_.clear_source();
        WEBRTC_LOG_WARN("WHEP RTP publisher source rejected stream={} session={} publisher_session={} generation={} error={}",
                        stream_id,
                        session_id,
                        publisher_source_->session_id,
                        publisher_source_generation_,
                        config.error());
        return;
    }

    rtp_rewriter_.set_config(std::move(*config));

    WEBRTC_LOG_INFO("WHEP RTP publisher source updated stream={} session={} publisher_session={} generation={}",
                    stream_id,
                    session_id,
                    publisher_source_->session_id,
                    publisher_source_generation_);
}

void whep_session_transport::reset_selected_peer()
{
    if (!selected_remote_endpoint_.has_value())
    {
        return;
    }

    const std::string remote_address = format_udp_endpoint(*selected_remote_endpoint_);
    srtp_transport_->forget_peer(remote_address);
    dtls_transport_->forget_peer(remote_address);
    selected_remote_endpoint_.reset();
}

session_udp_outbound_packet_list whep_session_transport::handle_udp_packet(const session_udp_packet& packet)
{
    ++received_packet_count_;

    const std::string_view stream_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->stream_id) : std::string_view{};
    const std::string_view session_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->session_id) : std::string_view{};

    session_stun_binding_context context;

    context.log_prefix = "WHEP";
    context.stream_id = stream_id;
    context.session_id = session_id;
    context.local_ice_ufrag = dtls_identity_.has_value() ? std::string_view(dtls_identity_->local_ice_ufrag) : std::string_view{};
    context.local_ice_pwd = local_ice_pwd_;
    context.remote_ice_ufrag = dtls_identity_.has_value() ? std::string_view(dtls_identity_->remote_ice_ufrag) : std::string_view{};

    auto stun_result = handle_session_stun_binding(packet.data, packet.remote_endpoint, context);

    if (stun_result.handled)
    {
        session_udp_outbound_packet_list result;

        if (stun_result.response.has_value())
        {
            selected_remote_endpoint_ = packet.remote_endpoint;
            result.push_back(std::move(*stun_result.response));
        }

        return result;
    }

    if (!selected_remote_endpoint_.has_value() || *selected_remote_endpoint_ != packet.remote_endpoint)
    {
        WEBRTC_LOG_DEBUG("WHEP session transport ignored packet from unselected endpoint stream={} session={} remote={} size={}",
                         stream_id,
                         session_id,
                         format_udp_endpoint(packet.remote_endpoint),
                         packet.data.size());

        return {};
    }

    if (is_dtls_packet(packet.data))
    {
        session_udp_outbound_packet_list result;

        if (!dtls_identity_.has_value())
        {
            WEBRTC_LOG_WARN("WHEP session transport dtls identity unavailable stream={} session={}", stream_id, session_id);

            return result;
        }

        const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
        const dtls_network_family network_family = packet.remote_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

        dtls_transport_->remember_peer(remote_address, *dtls_identity_);

        auto outbound_packets = dtls_transport_->handle_udp_packet(packet.data, remote_address, network_family);

        if (!outbound_packets)
        {
            WEBRTC_LOG_WARN("WHEP session transport dtls packet failed stream={} session={} remote={} error={}",
                            stream_id,
                            session_id,
                            remote_address,
                            outbound_packets.error());

            return result;
        }

        for (auto& outbound_packet : *outbound_packets)
        {
            result.push_back({std::move(outbound_packet), packet.remote_endpoint});
        }

        return result;
    }

    WEBRTC_LOG_DEBUG("WHEP session transport received udp packet remote={} size={} count={}",
                     packet.remote_endpoint.address().to_string(),
                     packet.data.size(),
                     received_packet_count_);

    return {};
}

}    // namespace webrtc
