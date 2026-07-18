#include "session/whip_session_transport.h"

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
#include "session/session_stun_binding.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
whip_session_transport::whip_session_transport(boost::asio::io_context& io_context,
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

whip_session_transport::~whip_session_transport() { udp_server_.stop(); }

whip_session_transport_result whip_session_transport::start(uint16_t local_port) { return udp_server_.start(local_port, *this); }

void whip_session_transport::set_peer_context(std::string local_ice_pwd, dtls_peer_identity identity)
{
    local_ice_pwd_ = std::move(local_ice_pwd);
    dtls_identity_ = std::move(identity);
}

session_udp_outbound_packet_list whip_session_transport::handle_udp_packet(const session_udp_packet& packet)
{
    ++received_packet_count_;

    const std::string_view stream_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->stream_id) : std::string_view{};
    const std::string_view session_id = dtls_identity_.has_value() ? std::string_view(dtls_identity_->session_id) : std::string_view{};

    session_stun_binding_context context;

    context.log_prefix = "WHIP";
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
        WEBRTC_LOG_DEBUG("WHIP session transport ignored packet from unselected endpoint stream={} session={} remote={} size={}",
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
            WEBRTC_LOG_WARN("WHIP session transport dtls identity unavailable stream={} session={}", stream_id, session_id);

            return result;
        }

        const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
        const dtls_network_family network_family = packet.remote_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

        dtls_transport_->remember_peer(remote_address, *dtls_identity_);

        auto outbound_packets = dtls_transport_->handle_udp_packet(packet.data, remote_address, network_family);

        if (!outbound_packets)
        {
            WEBRTC_LOG_WARN("WHIP session transport dtls packet failed stream={} session={} remote={} error={}",
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

    const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);

    auto srtp_packet = srtp_transport_->handle_inbound_packet(packet.data, remote_address);

    if (!srtp_packet)
    {
        WEBRTC_LOG_WARN("WHIP session transport srtp unprotect failed stream={} session={} remote={} error={}",
                        stream_id,
                        session_id,
                        remote_address,
                        srtp_packet.error());

        return {};
    }

    if (srtp_packet->state == srtp_packet_process_state::unprotected && srtp_packet->kind == srtp_packet_kind::rtp)
    {
        const std::span<const uint8_t> plain_packet(srtp_packet->plain_packet.data(), srtp_packet->plain_packet.size());

        const std::size_t target_count = media_fanout_router_->publish_rtp(stream_id, plain_packet);

        WEBRTC_LOG_DEBUG("WHIP RTP published stream={} session={} remote={} ssrc={} pt={} seq={} timestamp={} size={} targets={}",
                         stream_id,
                         session_id,
                         remote_address,
                         srtp_packet->ssrc,
                         srtp_packet->payload_type,
                         srtp_packet->sequence_number,
                         srtp_packet->timestamp,
                         srtp_packet->plain_packet.size(),
                         target_count);

        return {};
    }

    WEBRTC_LOG_DEBUG("WHIP session transport received udp packet remote={} size={} count={}",
                     packet.remote_endpoint.address().to_string(),
                     packet.data.size(),
                     received_packet_count_);

    return {};
}
}    // namespace webrtc
