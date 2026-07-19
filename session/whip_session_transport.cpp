#include "session/whip_session_transport.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
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
#include "net/socket.h"
#include "rtp/rtcp_compound_packet.h"
#include "rtp/rtcp_feedback.h"
#include "session/session_stun_binding.h"
#include "session/session_transport_peer_rebind.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
namespace
{
using namespace std::chrono_literals;
constexpr auto k_ice_restart_timeout = 30s;
constexpr auto k_media_log_interval = 5s;

uint32_t make_rtcp_sender_ssrc(std::string_view session_id)
{
    uint32_t hash = 2166136261U;

    for (const char value : session_id)
    {
        hash ^= static_cast<uint8_t>(value);
        hash *= 16777619U;
    }

    return hash == 0 ? 1U : hash;
}
}    // namespace

whip_session_transport::whip_session_transport(boost::asio::io_context& io_context,
                                               std::string bind_host,
                                               std::shared_ptr<dtls_context> dtls_context,
                                               std::uint16_t dtls_ip_mtu,
                                               std::shared_ptr<media_fanout_router> media_fanout_router)
    : udp_server_(io_context, std::move(bind_host)),
      ice_restart_timer_(io_context),
      dtls_transport_(std::make_shared<dtls_transport>(std::move(dtls_context), dtls_ip_mtu)),
      srtp_transport_(std::make_shared<srtp_transport>(dtls_transport_)),
      media_fanout_router_(std::move(media_fanout_router))
{
}

whip_session_transport::~whip_session_transport()
{
    clear_peer_state();
    udp_server_.stop();
}

whip_session_transport_result whip_session_transport::start(uint16_t local_port) { return udp_server_.start(local_port, *this); }

void whip_session_transport::record_media_log_event(media_log_event event, uint64_t value)
{
    media_log_stats_.counters.add(event, value);

    if (event != media_log_event::udp_received)
    {
        return;
    }

    int64_t interval_ms = 0;

    if (!media_log_stats_.summary_interval.try_begin(k_media_log_interval, interval_ms))
    {
        return;
    }

    const uint64_t udp_received = media_log_stats_.counters.take(media_log_event::udp_received);
    const uint64_t stun_received = media_log_stats_.counters.take(media_log_event::stun_received);
    const uint64_t dtls_received = media_log_stats_.counters.take(media_log_event::dtls_received);
    const uint64_t rtp_published = media_log_stats_.counters.take(media_log_event::rtp_published);
    const uint64_t rtp_bytes = media_log_stats_.counters.take(media_log_event::rtp_bytes);
    const uint64_t rtcp_received = media_log_stats_.counters.take(media_log_event::rtcp_received);
    const uint64_t rtcp_sender_report_received =
        media_log_stats_.counters.take(media_log_event::rtcp_sender_report_received);
    const uint64_t rtcp_receiver_report_received =
        media_log_stats_.counters.take(media_log_event::rtcp_receiver_report_received);
    const uint64_t rtcp_report_block_received =
        media_log_stats_.counters.take(media_log_event::rtcp_report_block_received);
    const uint64_t rtcp_sdes_received = media_log_stats_.counters.take(media_log_event::rtcp_sdes_received);
    const uint64_t rtcp_bye_received = media_log_stats_.counters.take(media_log_event::rtcp_bye_received);
    const uint64_t rtcp_pli_ignored = media_log_stats_.counters.take(media_log_event::rtcp_pli_ignored);
    const uint64_t rtcp_fir_ignored = media_log_stats_.counters.take(media_log_event::rtcp_fir_ignored);
    const uint64_t rtcp_generic_nack_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_generic_nack_ignored);
    const uint64_t rtcp_transport_cc_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_transport_cc_ignored);
    const uint64_t rtcp_remb_ignored = media_log_stats_.counters.take(media_log_event::rtcp_remb_ignored);
    const uint64_t rtcp_other_feedback_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_other_feedback_ignored);
    const uint64_t rtcp_unknown_block_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_unknown_block_ignored);
    const uint64_t rtcp_parse_failed = media_log_stats_.counters.take(media_log_event::rtcp_parse_failed);
    const uint64_t published_targets = media_log_stats_.counters.take(media_log_event::published_targets);
    const uint64_t dropped_unselected = media_log_stats_.counters.take(media_log_event::dropped_unselected);
    const uint64_t srtp_ignored = media_log_stats_.counters.take(media_log_event::srtp_ignored);
    const uint64_t srtp_unprotect_failed = media_log_stats_.counters.take(media_log_event::srtp_unprotect_failed);
    const uint64_t other_received = media_log_stats_.counters.take(media_log_event::other_received);

    WEBRTC_LOG_DEBUG(
        "WHIP media summary stream={} session={} interval_ms={} udp_received={} stun={} dtls={} rtp_published={} rtp_bytes={} "
        "rtcp_received={} rtcp_sr={} rtcp_rr={} rtcp_report_blocks={} rtcp_sdes={} rtcp_bye={} rtcp_pli_ignored={} "
        "rtcp_fir_ignored={} rtcp_generic_nack_ignored={} rtcp_transport_cc_ignored={} rtcp_remb_ignored={} "
        "rtcp_other_feedback_ignored={} rtcp_unknown_block_ignored={} rtcp_parse_failed={} published_targets={} "
        "dropped_unselected={} srtp_ignored={} srtp_unprotect_failed={} other_received={}",
        stream_id_,
        session_id_,
        interval_ms,
        udp_received,
        stun_received,
        dtls_received,
        rtp_published,
        rtp_bytes,
        rtcp_received,
        rtcp_sender_report_received,
        rtcp_receiver_report_received,
        rtcp_report_block_received,
        rtcp_sdes_received,
        rtcp_bye_received,
        rtcp_pli_ignored,
        rtcp_fir_ignored,
        rtcp_generic_nack_ignored,
        rtcp_transport_cc_ignored,
        rtcp_remb_ignored,
        rtcp_other_feedback_ignored,
        rtcp_unknown_block_ignored,
        rtcp_parse_failed,
        published_targets,
        dropped_unselected,
        srtp_ignored,
        srtp_unprotect_failed,
        other_received);
}

void whip_session_transport::handle_inbound_rtcp(std::span<const uint8_t> plain_rtcp)
{
    record_media_log_event(media_log_event::rtcp_received);

    auto compound = parse_rtcp_compound_packet(plain_rtcp);

    if (!compound)
    {
        record_media_log_event(media_log_event::rtcp_parse_failed);

        if (!media_log_stats_.rtcp_parse_failure_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_WARN("WHIP first inbound RTCP parse failure stream={} session={} error={}",
                            stream_id_,
                            session_id_,
                            compound.error());
        }

        WEBRTC_LOG_TRACE("WHIP inbound RTCP parse failed stream={} session={} error={}",
                         stream_id_,
                         session_id_,
                         compound.error());
        return;
    }

    record_media_log_event(media_log_event::rtcp_sender_report_received, compound->sender_report_count);
    record_media_log_event(media_log_event::rtcp_receiver_report_received, compound->receiver_report_count);
    record_media_log_event(media_log_event::rtcp_report_block_received, compound->report_block_count);
    record_media_log_event(media_log_event::rtcp_sdes_received, compound->sdes_packet_count);
    record_media_log_event(media_log_event::rtcp_bye_received, compound->bye_packets.size());
    record_media_log_event(media_log_event::rtcp_pli_ignored, compound->pli_count);
    record_media_log_event(media_log_event::rtcp_fir_ignored, compound->fir_block_count);
    record_media_log_event(media_log_event::rtcp_generic_nack_ignored, compound->generic_nack_block_count);
    record_media_log_event(media_log_event::rtcp_transport_cc_ignored, compound->transport_cc_block_count);
    record_media_log_event(media_log_event::rtcp_remb_ignored, compound->remb_block_count);
    record_media_log_event(media_log_event::rtcp_other_feedback_ignored, compound->other_feedback_block_count);
    record_media_log_event(media_log_event::rtcp_unknown_block_ignored, compound->unknown_block_count);

    for (const auto& block : compound->blocks)
    {
        if (block.feedback_name == "pli" &&
            !media_log_stats_.pli_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first inbound PLI ignored stream={} session={} sender_ssrc={} media_ssrc={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc);
        }

        if (block.feedback_name == "fir" &&
            !media_log_stats_.fir_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first inbound FIR ignored stream={} session={} sender_ssrc={} media_ssrc={} fir_entries={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc,
                block.fir_count);
        }

        if (block.has_generic_nack &&
            !media_log_stats_.generic_nack_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first Generic NACK ignored stream={} session={} sender_ssrc={} media_ssrc={} fci_entries={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc,
                block.nack_count);
        }

        if (block.has_transport_cc &&
            !media_log_stats_.transport_cc_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first transport-cc feedback ignored stream={} session={} sender_ssrc={} media_ssrc={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc);
        }

        if (block.has_remb &&
            !media_log_stats_.remb_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first REMB ignored stream={} session={} sender_ssrc={} media_ssrc={} bitrate_bps={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc,
                block.remb_bitrate_bps);
        }

        const bool other_feedback = block.is_feedback && block.feedback_name != "pli" &&
                                    block.feedback_name != "fir" && !block.has_generic_nack &&
                                    !block.has_transport_cc && !block.has_remb;

        if (other_feedback &&
            !media_log_stats_.other_feedback_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first other RTCP feedback ignored stream={} session={} type={} sender_ssrc={} media_ssrc={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_name,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc);
        }

        if (block.is_unknown &&
            !media_log_stats_.unknown_rtcp_block_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first unknown RTCP block ignored stream={} session={} packet_type={} packet_type_name={} count={} action=ignored",
                stream_id_,
                session_id_,
                block.packet_type,
                block.packet_type_name,
                block.count);
        }
    }

    WEBRTC_LOG_TRACE(
        "WHIP inbound RTCP stream={} session={} blocks={} sr={} rr={} report_blocks={} sdes={} bye={} pli_ignored={} fir_ignored={} "
        "generic_nack_ignored={} transport_cc_ignored={} remb_ignored={} other_feedback_ignored={} unknown_ignored={} summary={}",
        stream_id_,
        session_id_,
        compound->blocks.size(),
        compound->sender_report_count,
        compound->receiver_report_count,
        compound->report_block_count,
        compound->sdes_packet_count,
        compound->bye_packets.size(),
        compound->pli_count,
        compound->fir_block_count,
        compound->generic_nack_block_count,
        compound->transport_cc_block_count,
        compound->remb_block_count,
        compound->other_feedback_block_count,
        compound->unknown_block_count,
        rtcp_compound_feedback_summary_to_string(*compound));
}

void whip_session_transport::set_peer_context(std::string local_ice_pwd, dtls_peer_identity identity)
{
    clear_peer_state();

    std::lock_guard lock(peer_mutex_);
    stream_id_ = identity.stream_id;
    session_id_ = identity.session_id;
    local_ice_pwd_ = std::move(local_ice_pwd);
    rtcp_sender_ssrc_ = make_rtcp_sender_ssrc(identity.session_id);
    dtls_identity_ = std::move(identity);
    ++ice_generation_;
}

void whip_session_transport::restart_peer_context(std::string local_ice_pwd, dtls_peer_identity identity)
{
    uint64_t generation = 0;
    bool has_pending_association = false;

    {
        std::lock_guard lock(peer_mutex_);

        std::optional<boost::asio::ip::udp::endpoint> association_endpoint;
        std::optional<dtls_peer_identity> association_identity;

        if (pending_ice_restart_.has_value())
        {
            association_endpoint = pending_ice_restart_->association_endpoint;
            association_identity = pending_ice_restart_->association_identity;
        }
        else if (selected_remote_endpoint_.has_value() && dtls_identity_.has_value())
        {
            association_endpoint = selected_remote_endpoint_;
            association_identity = dtls_identity_;
        }

        selected_remote_endpoint_.reset();
        local_ice_pwd_ = std::move(local_ice_pwd);
        dtls_identity_ = std::move(identity);
        generation = ++ice_generation_;

        if (association_endpoint.has_value() && association_identity.has_value())
        {
            pending_ice_restart_ = pending_ice_restart{
                .generation = generation,
                .association_endpoint = *association_endpoint,
                .association_identity = std::move(*association_identity),
            };
            has_pending_association = true;
        }
        else
        {
            pending_ice_restart_.reset();
        }
    }

    ice_restart_timer_.cancel();

    if (has_pending_association)
    {
        schedule_ice_restart_timeout(generation);
    }
}

void whip_session_transport::send_keyframe_request(uint32_t media_ssrc)
{
    std::lock_guard lock(peer_mutex_);

    if (media_ssrc == 0 || rtcp_sender_ssrc_ == 0 || !selected_remote_endpoint_.has_value())
    {
        return;
    }

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);
    const auto plain_packet = make_rtcp_pli_packet(rtcp_sender_ssrc_, media_ssrc);

    auto protected_packet =
        srtp_transport_->protect_outbound_packet(plain_packet, remote_address, srtp_packet_kind::rtcp);

    if (!protected_packet)
    {
        WEBRTC_LOG_WARN("WHIP keyframe request protect failed remote={} media_ssrc={} error={}",
                        remote_address,
                        media_ssrc,
                        protected_packet.error());
        return;
    }

    if (protected_packet->state != srtp_packet_process_state::protected_packet ||
        protected_packet->protected_packet.empty())
    {
        WEBRTC_LOG_DEBUG("WHIP keyframe request ignored remote={} media_ssrc={} state={} reason={}",
                         remote_address,
                         media_ssrc,
                         srtp_packet_process_state_to_string(protected_packet->state),
                         protected_packet->reason);
        return;
    }

    udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

    WEBRTC_LOG_INFO("WHIP keyframe request sent remote={} media_ssrc={}", remote_address, media_ssrc);
}

void whip_session_transport::clear_peer_state()
{
    std::lock_guard lock(peer_mutex_);
    clear_peer_state_locked();
}

void whip_session_transport::clear_peer_state_locked()
{
    ice_restart_timer_.cancel();

    std::optional<boost::asio::ip::udp::endpoint> pending_endpoint;

    if (pending_ice_restart_.has_value())
    {
        pending_endpoint = pending_ice_restart_->association_endpoint;
    }

    if (selected_remote_endpoint_.has_value())
    {
        const std::string remote_address = format_udp_endpoint(*selected_remote_endpoint_);
        srtp_transport_->forget_peer(remote_address);
        dtls_transport_->forget_peer(remote_address);
    }

    if (pending_endpoint.has_value() &&
        (!selected_remote_endpoint_.has_value() || *pending_endpoint != *selected_remote_endpoint_))
    {
        const std::string remote_address = format_udp_endpoint(*pending_endpoint);
        srtp_transport_->forget_peer(remote_address);
        dtls_transport_->forget_peer(remote_address);
    }

    selected_remote_endpoint_.reset();
    pending_ice_restart_.reset();
}

void whip_session_transport::schedule_ice_restart_timeout(uint64_t generation)
{
    ice_restart_timer_.expires_after(k_ice_restart_timeout);
    const std::weak_ptr<whip_session_transport> weak_transport = weak_from_this();

    ice_restart_timer_.async_wait(
        [weak_transport, generation](const boost::system::error_code& error)
        {
            if (error == boost::asio::error::operation_aborted)
            {
                return;
            }

            if (const auto transport = weak_transport.lock())
            {
                transport->handle_ice_restart_timeout(generation);
            }
        });
}

void whip_session_transport::handle_ice_restart_timeout(uint64_t generation)
{
    std::lock_guard lock(peer_mutex_);

    if (!pending_ice_restart_.has_value() || pending_ice_restart_->generation != generation)
    {
        return;
    }

    const std::string remote_address = format_udp_endpoint(pending_ice_restart_->association_endpoint);
    srtp_transport_->forget_peer(remote_address);
    dtls_transport_->forget_peer(remote_address);
    pending_ice_restart_.reset();

    WEBRTC_LOG_WARN("WHIP ICE restart timed out stream={} session={} generation={} association_remote={}",
                    stream_id_,
                    session_id_,
                    generation,
                    remote_address);
}

whip_session_transport::peer_nomination_result whip_session_transport::nominate_remote_endpoint(
    const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    std::lock_guard lock(peer_mutex_);

    if (!dtls_identity_.has_value())
    {
        return std::unexpected(std::string("WHIP DTLS identity is unavailable"));
    }

    if (!pending_ice_restart_.has_value() && selected_remote_endpoint_.has_value() &&
        *selected_remote_endpoint_ == remote_endpoint)
    {
        return peer_nomination_state::unchanged;
    }

    std::optional<boost::asio::ip::udp::endpoint> association_endpoint;
    std::optional<dtls_peer_identity> association_identity;

    if (pending_ice_restart_.has_value())
    {
        association_endpoint = pending_ice_restart_->association_endpoint;
        association_identity = pending_ice_restart_->association_identity;
    }
    else if (selected_remote_endpoint_.has_value())
    {
        association_endpoint = selected_remote_endpoint_;
        association_identity = dtls_identity_;
    }

    peer_nomination_state state = peer_nomination_state::selected_fresh;

    if (association_endpoint.has_value() && association_identity.has_value())
    {
        auto rebound = rebind_session_transport_peer(dtls_transport_,
                                                     srtp_transport_,
                                                     *association_endpoint,
                                                     remote_endpoint,
                                                     *association_identity,
                                                     *dtls_identity_);

        if (!rebound)
        {
            return std::unexpected(rebound.error());
        }

        if (*rebound)
        {
            state = peer_nomination_state::association_rebound;
        }
    }

    selected_remote_endpoint_ = remote_endpoint;
    pending_ice_restart_.reset();
    ice_restart_timer_.cancel();

    WEBRTC_LOG_INFO("WHIP ICE endpoint nominated stream={} session={} generation={} remote={} association_reused={}",
                    stream_id_,
                    session_id_,
                    ice_generation_,
                    format_udp_endpoint(remote_endpoint),
                    state == peer_nomination_state::association_rebound ? 1 : 0);

    return state;
}

session_udp_outbound_packet_list whip_session_transport::handle_udp_packet(const session_udp_packet& packet)
{
    ++received_packet_count_;
    record_media_log_event(media_log_event::udp_received);

    std::string local_ice_ufrag;
    std::string local_ice_pwd;
    std::string remote_ice_ufrag;

    {
        std::lock_guard lock(peer_mutex_);

        if (dtls_identity_.has_value())
        {
            local_ice_ufrag = dtls_identity_->local_ice_ufrag;
            remote_ice_ufrag = dtls_identity_->remote_ice_ufrag;
        }

        local_ice_pwd = local_ice_pwd_;
    }

    session_stun_binding_context context;
    context.log_prefix = "WHIP";
    context.stream_id = stream_id_;
    context.session_id = session_id_;
    context.local_ice_ufrag = local_ice_ufrag;
    context.local_ice_pwd = local_ice_pwd;
    context.remote_ice_ufrag = remote_ice_ufrag;

    auto stun_result = handle_session_stun_binding(packet.data, packet.remote_endpoint, context);

    if (stun_result.handled)
    {
        record_media_log_event(media_log_event::stun_received);
        session_udp_outbound_packet_list result;

        if (stun_result.response.has_value())
        {
            if (stun_result.nominated)
            {
                auto nomination = nominate_remote_endpoint(packet.remote_endpoint);

                if (!nomination)
                {
                    WEBRTC_LOG_WARN("WHIP ICE endpoint nomination failed stream={} session={} remote={} error={}",
                                    stream_id_,
                                    session_id_,
                                    format_udp_endpoint(packet.remote_endpoint),
                                    nomination.error());
                }
            }

            result.push_back(std::move(*stun_result.response));
        }

        return result;
    }

    std::unique_lock peer_lock(peer_mutex_);

    if (!selected_remote_endpoint_.has_value() || *selected_remote_endpoint_ != packet.remote_endpoint)
    {
        record_media_log_event(media_log_event::dropped_unselected);
        WEBRTC_LOG_TRACE("WHIP session transport ignored packet from unselected endpoint stream={} session={} remote={} size={}",
                         stream_id_,
                         session_id_,
                         format_udp_endpoint(packet.remote_endpoint),
                         packet.data.size());
        return {};
    }

    if (is_dtls_packet(packet.data))
    {
        record_media_log_event(media_log_event::dtls_received);
        session_udp_outbound_packet_list result;

        if (!dtls_identity_.has_value())
        {
            WEBRTC_LOG_WARN("WHIP session transport dtls identity unavailable stream={} session={}", stream_id_, session_id_);
            return result;
        }

        const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
        const dtls_network_family network_family =
            packet.remote_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

        dtls_transport_->remember_peer(remote_address, *dtls_identity_);

        auto outbound_packets = dtls_transport_->handle_udp_packet(packet.data, remote_address, network_family);

        if (!outbound_packets)
        {
            WEBRTC_LOG_WARN("WHIP session transport dtls packet failed stream={} session={} remote={} error={}",
                            stream_id_,
                            session_id_,
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

    const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
    auto srtp_packet = srtp_transport_->handle_inbound_packet(packet.data, remote_address);
    peer_lock.unlock();

    if (!srtp_packet)
    {
        record_media_log_event(media_log_event::srtp_unprotect_failed);
        WEBRTC_LOG_WARN("WHIP session transport srtp unprotect failed stream={} session={} remote={} error={}",
                        stream_id_,
                        session_id_,
                        remote_address,
                        srtp_packet.error());
        return {};
    }

    if (srtp_packet->state == srtp_packet_process_state::unprotected && srtp_packet->kind == srtp_packet_kind::rtp)
    {
        const std::span<const uint8_t> plain_packet(srtp_packet->plain_packet.data(), srtp_packet->plain_packet.size());
        const std::size_t target_count = media_fanout_router_->publish_rtp(stream_id_, session_id_, plain_packet);
        record_media_log_event(media_log_event::rtp_published);
        record_media_log_event(media_log_event::rtp_bytes, srtp_packet->plain_packet.size());
        record_media_log_event(media_log_event::published_targets, target_count);

        if (mark_session_transport_value_once(media_log_stats_.logged_source_ssrcs, srtp_packet->ssrc))
        {
            WEBRTC_LOG_DEBUG("WHIP first RTP published stream={} session={} remote={} ssrc={} pt={} seq={} timestamp={} size={} targets={}",
                             stream_id_,
                             session_id_,
                             remote_address,
                             srtp_packet->ssrc,
                             srtp_packet->payload_type,
                             srtp_packet->sequence_number,
                             srtp_packet->timestamp,
                             srtp_packet->plain_packet.size(),
                             target_count);
        }

        WEBRTC_LOG_TRACE("WHIP RTP published stream={} session={} remote={} ssrc={} pt={} seq={} timestamp={} size={} targets={}",
                         stream_id_,
                         session_id_,
                         remote_address,
                         srtp_packet->ssrc,
                         srtp_packet->payload_type,
                         srtp_packet->sequence_number,
                         srtp_packet->timestamp,
                         srtp_packet->plain_packet.size(),
                         target_count);
        return {};
    }

    if (srtp_packet->state == srtp_packet_process_state::unprotected && srtp_packet->kind == srtp_packet_kind::rtcp)
    {
        handle_inbound_rtcp(srtp_packet->plain_packet);
        return {};
    }
    else if (srtp_packet->state == srtp_packet_process_state::ignored)
    {
        record_media_log_event(media_log_event::srtp_ignored);
    }
    else
    {
        record_media_log_event(media_log_event::other_received);
    }

    WEBRTC_LOG_TRACE("WHIP session transport received udp packet remote={} size={} count={}",
                     packet.remote_endpoint.address().to_string(),
                     packet.data.size(),
                     received_packet_count_);

    return {};
}
}    // namespace webrtc
