#include "media/media_router.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "log/log.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
namespace
{
media_peer_info make_peer_info(media_peer_role role, std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id)
{
    media_peer_info peer;
    peer.role = role;
    peer.remote_endpoint = std::string(remote_endpoint);
    peer.stream_id = std::string(stream_id);
    peer.session_id = std::string(session_id);
    return peer;
}
}    // namespace

void media_router::remember_publisher(std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id)
{
    if (remote_endpoint.empty() || stream_id.empty() || session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    remember_peer_locked(make_peer_info(media_peer_role::publisher, remote_endpoint, stream_id, session_id));
}

void media_router::remember_subscriber(std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id)
{
    if (remote_endpoint.empty() || stream_id.empty() || session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    remember_peer_locked(make_peer_info(media_peer_role::subscriber, remote_endpoint, stream_id, session_id));
}

void media_router::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    forget_peer_locked(remote_endpoint);
}

media_route_result media_router::handle_inbound_packet(std::string_view remote_endpoint, const srtp_packet_process_result& packet)
{
    media_route_result result;
    result.packet_kind = packet.kind;
    result.ssrc = packet.ssrc;
    result.payload_type = packet.payload_type;

    if (remote_endpoint.empty())
    {
        return result;
    }

    if (packet.state != srtp_packet_process_state::unprotected)
    {
        return result;
    }

    std::lock_guard lock(mutex_);

    const auto peer_iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

    if (peer_iterator == peers_by_endpoint_.end())
    {
        WEBRTC_LOG_WARN(
            "media router peer not found remote={} kind={} ssrc={}", remote_endpoint, srtp_packet_kind_to_string(packet.kind), packet.ssrc);

        return result;
    }

    result.known_peer = true;
    result.source = peer_iterator->second;

    if (result.source.role == media_peer_role::publisher)
    {
        result.action = media_route_action::fanout_to_subscribers;
        result.target_endpoints = get_subscriber_endpoints_locked(result.source.stream_id, remote_endpoint);

        WEBRTC_LOG_DEBUG("media router publisher packet stream={} session={} remote={} kind={} ssrc={} payload_type={} targets={}",
                         result.source.stream_id,
                         result.source.session_id,
                         remote_endpoint,
                         srtp_packet_kind_to_string(packet.kind),
                         packet.ssrc,
                         static_cast<unsigned int>(packet.payload_type),
                         result.target_endpoints.size());

        return result;
    }

    if (result.source.role == media_peer_role::subscriber && packet.kind == srtp_packet_kind::rtcp)
    {
        result.action = media_route_action::route_to_publisher;
        result.target_endpoints = get_publisher_endpoint_locked(result.source.stream_id, remote_endpoint);

        WEBRTC_LOG_DEBUG("media router subscriber rtcp stream={} session={} remote={} ssrc={} packet_type={} targets={}",
                         result.source.stream_id,
                         result.source.session_id,
                         remote_endpoint,
                         packet.ssrc,
                         static_cast<unsigned int>(packet.payload_type),
                         result.target_endpoints.size());

        return result;
    }

    result.action = media_route_action::none;

    WEBRTC_LOG_DEBUG("media router packet ignored stream={} session={} remote={} role={} kind={}",
                     result.source.stream_id,
                     result.source.session_id,
                     remote_endpoint,
                     media_peer_role_to_string(result.source.role),
                     srtp_packet_kind_to_string(packet.kind));

    return result;
}

std::optional<media_peer_info> media_router::get_peer(std::string_view remote_endpoint) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

    if (iterator == peers_by_endpoint_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::size_t media_router::peer_count() const
{
    std::lock_guard lock(mutex_);

    return peers_by_endpoint_.size();
}

std::size_t media_router::subscriber_count(std::string_view stream_id) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = subscribers_by_stream_.find(std::string(stream_id));

    if (iterator == subscribers_by_stream_.end())
    {
        return 0;
    }

    return iterator->second.size();
}

void media_router::remember_peer_locked(media_peer_info peer)
{
    forget_peer_locked(peer.remote_endpoint);

    if (peer.role == media_peer_role::publisher)
    {
        publisher_by_stream_[peer.stream_id] = peer.remote_endpoint;
    }
    else if (peer.role == media_peer_role::subscriber)
    {
        subscribers_by_stream_[peer.stream_id].insert(peer.remote_endpoint);
    }

    WEBRTC_LOG_INFO("media router remember peer remote={} role={} stream={} session={}",
                    peer.remote_endpoint,
                    media_peer_role_to_string(peer.role),
                    peer.stream_id,
                    peer.session_id);

    peers_by_endpoint_[peer.remote_endpoint] = std::move(peer);
}

void media_router::forget_peer_locked(std::string_view remote_endpoint)
{
    const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

    if (iterator == peers_by_endpoint_.end())
    {
        return;
    }

    const media_peer_info peer = iterator->second;

    if (peer.role == media_peer_role::publisher)
    {
        const auto publisher_iterator = publisher_by_stream_.find(peer.stream_id);

        if (publisher_iterator != publisher_by_stream_.end() && publisher_iterator->second == peer.remote_endpoint)
        {
            publisher_by_stream_.erase(publisher_iterator);
        }
    }
    else if (peer.role == media_peer_role::subscriber)
    {
        const auto subscribers_iterator = subscribers_by_stream_.find(peer.stream_id);

        if (subscribers_iterator != subscribers_by_stream_.end())
        {
            subscribers_iterator->second.erase(peer.remote_endpoint);

            if (subscribers_iterator->second.empty())
            {
                subscribers_by_stream_.erase(subscribers_iterator);
            }
        }
    }

    WEBRTC_LOG_INFO("media router forget peer remote={} role={} stream={} session={}",
                    peer.remote_endpoint,
                    media_peer_role_to_string(peer.role),
                    peer.stream_id,
                    peer.session_id);

    peers_by_endpoint_.erase(iterator);
}

std::vector<std::string> media_router::get_subscriber_endpoints_locked(std::string_view stream_id, std::string_view excluded_endpoint) const
{
    std::vector<std::string> endpoints;

    const auto iterator = subscribers_by_stream_.find(std::string(stream_id));

    if (iterator == subscribers_by_stream_.end())
    {
        return endpoints;
    }

    endpoints.reserve(iterator->second.size());

    for (const auto& endpoint : iterator->second)
    {
        if (endpoint != excluded_endpoint)
        {
            endpoints.push_back(endpoint);
        }
    }

    return endpoints;
}

std::vector<std::string> media_router::get_publisher_endpoint_locked(std::string_view stream_id, std::string_view excluded_endpoint) const
{
    std::vector<std::string> endpoints;

    const auto iterator = publisher_by_stream_.find(std::string(stream_id));

    if (iterator == publisher_by_stream_.end())
    {
        return endpoints;
    }

    if (iterator->second != excluded_endpoint)
    {
        endpoints.push_back(iterator->second);
    }

    return endpoints;
}

std::string media_peer_role_to_string(media_peer_role role)
{
    switch (role)
    {
        case media_peer_role::publisher:
            return "publisher";

        case media_peer_role::subscriber:
            return "subscriber";

        case media_peer_role::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string media_route_action_to_string(media_route_action action)
{
    switch (action)
    {
        case media_route_action::fanout_to_subscribers:
            return "fanout_to_subscribers";

        case media_route_action::route_to_publisher:
            return "route_to_publisher";

        case media_route_action::none:
            return "none";
    }

    return "none";
}
}    // namespace webrtc
