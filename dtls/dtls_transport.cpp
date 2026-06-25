#include "dtls/dtls_transport.h"

#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "dtls/dtls_packet.h"
#include "log/log.h"

namespace webrtc
{
void dtls_transport::remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    auto& context = peers_by_endpoint_[std::string(remote_endpoint)];

    context.identity = std::move(identity);

    WEBRTC_LOG_INFO("dtls remember peer remote={} role={} stream={} session={} local_ufrag={}",
                    remote_endpoint,
                    dtls_peer_role_to_string(context.identity.role),
                    context.identity.stream_id,
                    context.identity.session_id,
                    context.identity.local_ice_ufrag);
}

void dtls_transport::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    peers_by_endpoint_.erase(std::string(remote_endpoint));
}

void dtls_transport::handle_udp_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
{
    auto header = parse_dtls_record_header(data);

    if (!header)
    {
        WEBRTC_LOG_WARN("dtls packet parse failed remote={} error={}", remote_endpoint, header.error());

        return;
    }

    std::lock_guard lock(mutex_);

    auto* context = find_peer_locked(remote_endpoint);

    if (context == nullptr)
    {
        WEBRTC_LOG_WARN("dtls packet from unknown peer remote={} content_type={} version={} size={}",
                        remote_endpoint,
                        dtls_record_content_type_to_string(header->content_type),
                        dtls_version_to_string(header->version),
                        data.size());

        return;
    }

    context->packet_count += 1;
    context->byte_count += static_cast<uint64_t>(data.size());
    context->saw_dtls_packet = true;

    handle_known_peer_packet_locked(*context, data, remote_endpoint);
}

std::size_t dtls_transport::peer_count() const
{
    std::lock_guard lock(mutex_);

    return peers_by_endpoint_.size();
}

dtls_transport::dtls_peer_context* dtls_transport::find_peer_locked(std::string_view remote_endpoint)
{
    const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

    if (iterator == peers_by_endpoint_.end())
    {
        return nullptr;
    }

    return &iterator->second;
}

void dtls_transport::handle_known_peer_packet_locked(dtls_peer_context& context, std::span<const uint8_t> data, std::string_view remote_endpoint)
{
    auto header = parse_dtls_record_header(data);

    if (!header)
    {
        WEBRTC_LOG_WARN("dtls known peer parse failed remote={} session={} error={}", remote_endpoint, context.identity.session_id, header.error());

        return;
    }

    if (header->content_type == dtls_record_content_type::handshake)
    {
        const dtls_handshake_type handshake_type = get_dtls_handshake_type(data);

        if (handshake_type == dtls_handshake_type::client_hello)
        {
            context.saw_client_hello = true;

            WEBRTC_LOG_INFO("dtls client hello received remote={} role={} stream={} session={} version={} epoch={} record_size={} packet_count={}",
                            remote_endpoint,
                            dtls_peer_role_to_string(context.identity.role),
                            context.identity.stream_id,
                            context.identity.session_id,
                            dtls_version_to_string(header->version),
                            header->epoch,
                            header->record_size,
                            context.packet_count);

            return;
        }

        WEBRTC_LOG_INFO("dtls handshake packet received remote={} session={} type={} version={} epoch={} record_size={}",
                        remote_endpoint,
                        context.identity.session_id,
                        dtls_handshake_type_to_string(handshake_type),
                        dtls_version_to_string(header->version),
                        header->epoch,
                        header->record_size);

        return;
    }

    WEBRTC_LOG_DEBUG("dtls packet received remote={} session={} content_type={} version={} epoch={} record_size={} packet_count={} byte_count={}",
                     remote_endpoint,
                     context.identity.session_id,
                     dtls_record_content_type_to_string(header->content_type),
                     dtls_version_to_string(header->version),
                     header->epoch,
                     header->record_size,
                     context.packet_count,
                     context.byte_count);
}

std::string dtls_peer_role_to_string(dtls_peer_role role)
{
    switch (role)
    {
        case dtls_peer_role::publisher:
            return "publisher";

        case dtls_peer_role::subscriber:
            return "subscriber";

        case dtls_peer_role::unknown:
            return "unknown";
    }

    return "unknown";
}
}    // namespace webrtc
