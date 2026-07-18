#include "session/whep_session_transport.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include <boost/asio.hpp>

#include "dtls/dtls_packet.h"
#include "dtls/dtls_transport.h"
#include "ice/ice_credentials.h"
#include "ice/session_ice_udp_server.h"
#include "log/log.h"
#include "media/media_fanout_router.h"
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

whep_session_transport::~whep_session_transport() { stop(); }

whep_session_transport_result whep_session_transport::start(uint16_t local_port) { return udp_server_.start(local_port, *this); }

void whep_session_transport::set_ice_context(std::string stream_id, std::string session_id, ice_credentials local_ice, std::string remote_ice_ufrag)
{
    unsubscribe_media();

    stream_id_ = std::move(stream_id);
    session_id_ = std::move(session_id);
    local_ice_ = std::move(local_ice);
    remote_ice_ufrag_ = std::move(remote_ice_ufrag);

    subscribe_media();
}

void whep_session_transport::set_dtls_peer_identity(dtls_peer_identity identity)
{
    dtls_identity_ = std::move(identity);
    dtls_identity_ready_ = true;
}

void whep_session_transport::send_rtp(std::span<const uint8_t> plain_rtp)
{
    if (plain_rtp.empty() || !selected_remote_endpoint_.has_value())
    {
        return;
    }

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);

    auto protected_packet = srtp_transport_->protect_outbound_packet(plain_rtp, remote_address, srtp_packet_kind::rtp);

    if (!protected_packet)
    {
        WEBRTC_LOG_WARN(
            "WHEP RTP protect failed stream={} session={} remote={} error={}", stream_id_, session_id_, remote_address, protected_packet.error());

        return;
    }

    if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
    {
        WEBRTC_LOG_DEBUG("WHEP RTP protect ignored stream={} session={} remote={} state={} reason={}",
                         stream_id_,
                         session_id_,
                         remote_address,
                         srtp_packet_process_state_to_string(protected_packet->state),
                         protected_packet->reason);

        return;
    }

    udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);
}

void whep_session_transport::stop()
{
    unsubscribe_media();

    udp_server_.stop();
}

void whep_session_transport::subscribe_media()
{
    if (media_subscribed_ || stream_id_.empty() || session_id_.empty())
    {
        return;
    }

    const std::weak_ptr<whep_session_transport> weak_transport = weak_from_this();

    if (weak_transport.expired())
    {
        WEBRTC_LOG_WARN("WHEP media subscribe skipped because transport is not shared stream={} session={}", stream_id_, session_id_);

        return;
    }

    media_fanout_router_->subscribe(
        stream_id_,
        session_id_,
        [weak_transport](std::span<const uint8_t> packet)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->send_rtp(packet);
            }
        });

    media_subscribed_ = true;
}

void whep_session_transport::unsubscribe_media()
{
    if (!media_subscribed_)
    {
        return;
    }

    if (!session_id_.empty())
    {
        media_fanout_router_->unsubscribe(session_id_);
    }

    media_subscribed_ = false;
}

session_udp_dispatch_result whep_session_transport::handle_udp_packet(const session_udp_packet& packet)
{
    ++received_packet_count_;

    session_stun_binding_context context;

    context.log_prefix = "WHEP";
    context.stream_id = stream_id_;
    context.session_id = session_id_;
    context.local_ice_ufrag = local_ice_.ufrag;
    context.local_ice_pwd = local_ice_.pwd;
    context.remote_ice_ufrag = remote_ice_ufrag_;

    auto stun_result = handle_session_stun_binding(packet.data, packet.remote_endpoint, context);

    if (stun_result.handled)
    {
        session_udp_dispatch_result result;

        if (stun_result.response.has_value())
        {
            selected_remote_endpoint_ = packet.remote_endpoint;
            result.outbound_packets.push_back(std::move(*stun_result.response));
        }

        return result;
    }

    if (!selected_remote_endpoint_.has_value() || *selected_remote_endpoint_ != packet.remote_endpoint)
    {
        WEBRTC_LOG_DEBUG("WHEP session transport ignored packet from unselected endpoint stream={} session={} remote={} size={}",
                         stream_id_,
                         session_id_,
                         format_udp_endpoint(packet.remote_endpoint),
                         packet.data.size());

        return {};
    }

    if (is_dtls_packet(packet.data))
    {
        session_udp_dispatch_result result;

        if (!dtls_identity_ready_)
        {
            WEBRTC_LOG_WARN("WHEP session transport dtls identity unavailable stream={} session={}", stream_id_, session_id_);

            return result;
        }

        const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
        const dtls_network_family network_family = packet.remote_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

        dtls_transport_->remember_peer(remote_address, dtls_identity_);

        auto outbound_packets = dtls_transport_->handle_udp_packet(packet.data, remote_address, network_family);

        if (!outbound_packets)
        {
            WEBRTC_LOG_WARN("WHEP session transport dtls packet failed stream={} session={} remote={} error={}",
                            stream_id_,
                            session_id_,
                            remote_address,
                            outbound_packets.error());

            return result;
        }

        for (auto& outbound_packet : *outbound_packets)
        {
            result.outbound_packets.push_back({std::move(outbound_packet), packet.remote_endpoint});
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
