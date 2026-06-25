#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_ROUTER_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_ROUTER_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "srtp/srtp_transport.h"

namespace webrtc
{
enum class media_peer_role
{
    unknown,
    publisher,
    subscriber,
};

enum class media_route_action
{
    none,
    fanout_to_subscribers,
    route_to_publisher,
};

struct media_peer_info
{
    media_peer_role role = media_peer_role::unknown;

    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;
};

struct media_route_result
{
    bool known_peer = false;

    media_route_action action = media_route_action::none;
    media_peer_info source;

    srtp_packet_kind packet_kind = srtp_packet_kind::unknown;
    uint32_t ssrc = 0;
    uint8_t payload_type = 0;

    std::vector<std::string> target_endpoints;
};

class media_router
{
   public:
    media_router() = default;
    ~media_router() = default;

    media_router(const media_router&) = delete;
    media_router& operator=(const media_router&) = delete;

    media_router(media_router&&) = delete;
    media_router& operator=(media_router&&) = delete;

   public:
    void remember_publisher(std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id);

    void remember_subscriber(std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id);

    void forget_peer(std::string_view remote_endpoint);

    [[nodiscard]] media_route_result handle_inbound_packet(std::string_view remote_endpoint, const srtp_packet_process_result& packet);

    [[nodiscard]] std::optional<media_peer_info> get_peer(std::string_view remote_endpoint) const;

    [[nodiscard]] std::size_t peer_count() const;

    [[nodiscard]] std::size_t subscriber_count(std::string_view stream_id) const;

   private:
    void remember_peer_locked(media_peer_info peer);

    void forget_peer_locked(std::string_view remote_endpoint);

    [[nodiscard]] std::vector<std::string> get_subscriber_endpoints_locked(std::string_view stream_id, std::string_view excluded_endpoint) const;

    [[nodiscard]] std::vector<std::string> get_publisher_endpoint_locked(std::string_view stream_id, std::string_view excluded_endpoint) const;

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, media_peer_info> peers_by_endpoint_;
    std::unordered_map<std::string, std::string> publisher_by_stream_;
    std::unordered_map<std::string, std::unordered_set<std::string>> subscribers_by_stream_;
};

[[nodiscard]] std::string media_peer_role_to_string(media_peer_role role);

[[nodiscard]] std::string media_route_action_to_string(media_route_action action);
}    // namespace webrtc

#endif
