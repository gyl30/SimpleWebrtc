#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_FANOUT_ROUTER_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_FANOUT_ROUTER_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
using media_keyframe_request_handler = std::function<void(uint32_t media_ssrc)>;

struct media_publisher_source
{
    std::string stream_id;
    std::string session_id;
    uint64_t generation = 0;
    sdp::webrtc_offer_summary offer;
    media_keyframe_request_handler keyframe_request_handler;
};

using media_publisher_source_ptr = std::shared_ptr<const media_publisher_source>;

struct media_publisher_source_update
{
    uint64_t generation = 0;
    media_publisher_source_ptr source;
};

using media_rtp_handler = std::function<void(uint64_t source_generation, std::span<const uint8_t> packet)>;
using media_publisher_source_handler = std::function<void(media_publisher_source_update update)>;

class media_fanout_router
{
   public:
    void subscribe(std::string stream_id,
                   std::string subscriber_session_id,
                   media_rtp_handler rtp_handler,
                   media_publisher_source_handler source_handler);

    void unsubscribe(std::string_view subscriber_session_id);

    void set_publisher_source(std::string stream_id,
                              std::string publisher_session_id,
                              sdp::webrtc_offer_summary publisher_offer,
                              media_keyframe_request_handler keyframe_request_handler);

    void clear_publisher_source(std::string_view stream_id, std::string_view publisher_session_id);

    [[nodiscard]] bool request_keyframe(std::string_view stream_id,
                                        std::string_view publisher_session_id,
                                        uint64_t source_generation,
                                        uint32_t media_ssrc);

    [[nodiscard]]
    std::size_t publish_rtp(std::string_view stream_id,
                            std::string_view publisher_session_id,
                            std::span<const uint8_t> packet);

   private:
    struct subscription
    {
        std::string stream_id;
        media_rtp_handler rtp_handler;
        media_publisher_source_handler source_handler;
    };

    [[nodiscard]] uint64_t allocate_source_generation_locked();

   private:
    std::mutex mutex_;

    uint64_t next_source_generation_ = 1;

    std::unordered_map<std::string, subscription> subscriptions_by_session_id_;
    std::unordered_map<std::string, media_publisher_source_ptr> publisher_sources_by_stream_id_;
    std::unordered_map<std::string, uint64_t> publisher_source_generations_by_stream_id_;
};
}    // namespace webrtc

#endif
