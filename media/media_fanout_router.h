#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_FANOUT_ROUTER_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_FANOUT_ROUTER_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
using media_rtp_handler = std::function<void(std::span<const uint8_t> packet)>;

class media_fanout_router
{
   public:
    void subscribe(std::string stream_id, std::string subscriber_session_id, media_rtp_handler handler);

    void unsubscribe(std::string_view subscriber_session_id);

    [[nodiscard]]
    std::size_t publish_rtp(std::string_view stream_id, std::string_view publisher_session_id, std::span<const uint8_t> packet);

   private:
    struct subscription
    {
        std::string stream_id;
        media_rtp_handler handler;
    };

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, subscription> subscriptions_by_session_id_;
};
}    // namespace webrtc

#endif
