#include "srtp/srtp_transport.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dtls/dtls_srtp_keying_material.h"
#include "log/log.h"
#include "srtp/srtp_session.h"

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

bool is_rtp_or_rtcp_packet(std::span<const uint8_t> data)
{
    if (data.empty())
    {
        return false;
    }

    return data[0] >= 128U && data[0] <= 191U;
}

bool is_rtcp_packet(std::span<const uint8_t> data)
{
    if (data.size() < 2)
    {
        return false;
    }

    return data[1] >= 192U && data[1] <= 223U;
}

srtp_packet_kind classify_packet(std::span<const uint8_t> data)
{
    if (!is_rtp_or_rtcp_packet(data))
    {
        return srtp_packet_kind::unknown;
    }

    if (is_rtcp_packet(data))
    {
        return srtp_packet_kind::rtcp;
    }

    return srtp_packet_kind::rtp;
}

srtp_packet_process_result make_ignored_result(srtp_packet_kind kind, std::size_t packet_size, std::string_view reason)
{
    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::ignored;
    result.kind = kind;
    result.packet_size = packet_size;
    result.unprotected_size = 0;
    result.reason = std::string(reason);
    return result;
}

srtp_packet_process_result make_unprotected_result(srtp_packet_kind kind,
                                                   std::size_t packet_size,
                                                   std::size_t unprotected_size,
                                                   std::span<const uint8_t> packet)
{
    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::unprotected;
    result.kind = kind;
    result.packet_size = packet_size;
    result.unprotected_size = unprotected_size;

    if (kind == srtp_packet_kind::rtp && packet.size() >= 12)
    {
        result.payload_type = static_cast<uint8_t>(packet[1] & 0x7FU);

        result.ssrc = read_u32(packet, 8);
    }
    else if (kind == srtp_packet_kind::rtcp && packet.size() >= 8)
    {
        result.payload_type = packet[1];
        result.ssrc = read_u32(packet, 4);
    }

    return result;
}
}    // namespace

struct srtp_transport::impl
{
    explicit impl(std::shared_ptr<dtls_transport> dtls_transport) : dtls_transport_(std::move(dtls_transport)) {}

    struct srtp_peer_context
    {
        bool sessions_ready = false;

        std::optional<srtp_session> inbound_session;
        std::optional<srtp_session> outbound_session;

        uint64_t inbound_packet_count = 0;
        uint64_t inbound_byte_count = 0;
        uint64_t inbound_rtp_count = 0;
        uint64_t inbound_rtcp_count = 0;
    };

    srtp_transport_result handle_inbound_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
    {
        const srtp_packet_kind kind = classify_packet(data);

        if (kind == srtp_packet_kind::unknown)
        {
            return make_ignored_result(kind, data.size(), "packet is not rtp or rtcp");
        }

        std::lock_guard lock(mutex_);

        auto& peer = peers_by_endpoint_[std::string(remote_endpoint)];

        auto ready_result = ensure_sessions_ready_locked(peer, remote_endpoint);

        if (!ready_result)
        {
            return std::unexpected(ready_result.error());
        }

        if (!*ready_result)
        {
            return make_ignored_result(kind, data.size(), "dtls handshake is not complete");
        }

        if (!peer.inbound_session.has_value())
        {
            return make_error("srtp inbound session is empty");
        }

        std::vector<uint8_t> packet(data.begin(), data.end());

        srtp_packet_result unprotect_result = kind == srtp_packet_kind::rtcp ? peer.inbound_session->unprotect_rtcp(packet, packet.size())
                                                                             : peer.inbound_session->unprotect_rtp(packet, packet.size());

        if (!unprotect_result)
        {
            std::string message = "srtp inbound unprotect failed remote=";

            message.append(std::string(remote_endpoint));
            message.append(" kind=");
            message.append(srtp_packet_kind_to_string(kind));
            message.append(" error=");
            message.append(unprotect_result.error());

            return std::unexpected(std::move(message));
        }

        const std::size_t unprotected_size = *unprotect_result;

        packet.resize(unprotected_size);

        peer.inbound_packet_count += 1;
        peer.inbound_byte_count += static_cast<uint64_t>(unprotected_size);

        if (kind == srtp_packet_kind::rtp)
        {
            peer.inbound_rtp_count += 1;
        }
        else
        {
            peer.inbound_rtcp_count += 1;
        }

        auto result = make_unprotected_result(kind, data.size(), unprotected_size, packet);

        WEBRTC_LOG_DEBUG("srtp inbound packet unprotected remote={} kind={} size={} plain_size={} ssrc={} payload_type={} packets={}",
                         remote_endpoint,
                         srtp_packet_kind_to_string(kind),
                         data.size(),
                         unprotected_size,
                         result.ssrc,
                         static_cast<unsigned int>(result.payload_type),
                         peer.inbound_packet_count);

        return result;
    }

    void forget_peer(std::string_view remote_endpoint)
    {
        if (remote_endpoint.empty())
        {
            return;
        }

        std::lock_guard lock(mutex_);

        peers_by_endpoint_.erase(std::string(remote_endpoint));
    }

    std::size_t peer_count() const
    {
        std::lock_guard lock(mutex_);

        return peers_by_endpoint_.size();
    }

    std::expected<bool, std::string> ensure_sessions_ready_locked(srtp_peer_context& peer, std::string_view remote_endpoint)
    {
        if (peer.sessions_ready)
        {
            return true;
        }

        if (dtls_transport_ == nullptr)
        {
            return make_error("dtls transport is null");
        }

        auto material = dtls_transport_->get_srtp_keying_material(remote_endpoint);

        if (!material.has_value())
        {
            if (!dtls_transport_->is_handshake_done(remote_endpoint))
            {
                return false;
            }

            return make_error("dtls handshake is complete but srtp keying material is empty");
        }

        auto inbound_config = make_inbound_srtp_session_config(*material);

        auto outbound_config = make_outbound_srtp_session_config(*material);

        auto inbound = make_srtp_session(inbound_config);

        if (!inbound)
        {
            return std::unexpected(inbound.error());
        }

        auto outbound = make_srtp_session(outbound_config);

        if (!outbound)
        {
            return std::unexpected(outbound.error());
        }

        peer.inbound_session.emplace(std::move(*inbound));
        peer.outbound_session.emplace(std::move(*outbound));
        peer.sessions_ready = true;

        WEBRTC_LOG_INFO("srtp sessions created remote={} profile={} inbound={} outbound={}",
                        remote_endpoint,
                        srtp_profile_id_to_string(material->profile),
                        srtp_direction_to_string(srtp_direction::inbound),
                        srtp_direction_to_string(srtp_direction::outbound));

        return true;
    }

    std::shared_ptr<dtls_transport> dtls_transport_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, srtp_peer_context> peers_by_endpoint_;
};

srtp_transport::srtp_transport(std::shared_ptr<dtls_transport> dtls_transport) : impl_(std::make_unique<impl>(std::move(dtls_transport))) {}

srtp_transport::~srtp_transport() = default;

srtp_transport_result srtp_transport::handle_inbound_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
{
    return impl_->handle_inbound_packet(data, remote_endpoint);
}

void srtp_transport::forget_peer(std::string_view remote_endpoint) { impl_->forget_peer(remote_endpoint); }

std::size_t srtp_transport::peer_count() const { return impl_->peer_count(); }

std::string srtp_packet_kind_to_string(srtp_packet_kind kind)
{
    switch (kind)
    {
        case srtp_packet_kind::rtp:
            return "rtp";

        case srtp_packet_kind::rtcp:
            return "rtcp";

        case srtp_packet_kind::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string srtp_packet_process_state_to_string(srtp_packet_process_state state)
{
    switch (state)
    {
        case srtp_packet_process_state::ignored:
            return "ignored";

        case srtp_packet_process_state::unprotected:
            return "unprotected";
    }

    return "unknown";
}
}    // namespace webrtc
