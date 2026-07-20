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
#include <unordered_set>

#include <boost/asio.hpp>

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

struct media_publisher_source_bye
{
    std::string publisher_session_id;
    uint64_t source_generation = 0;
    uint32_t source_ssrc = 0;
    std::string reason;
};

struct media_publisher_sender_timing
{
    std::string publisher_session_id;
    uint64_t source_generation = 0;
    uint32_t source_ssrc = 0;
    uint64_t ntp_timestamp = 0;
    uint32_t source_rtp_timestamp = 0;
    uint32_t sender_packet_count = 0;
    uint32_t sender_octet_count = 0;
};

using media_rtp_handler = std::function<void(uint64_t source_generation, std::span<const uint8_t> packet)>;
using media_publisher_source_handler = std::function<void(media_publisher_source_update update)>;
using media_publisher_sender_timing_handler = std::function<void(media_publisher_sender_timing timing)>;
using media_publisher_source_bye_handler = std::function<void(media_publisher_source_bye bye)>;

class media_fanout_router : public std::enable_shared_from_this<media_fanout_router>
{
   public:
    explicit media_fanout_router(boost::asio::io_context& io_context);
    ~media_fanout_router();

    media_fanout_router(const media_fanout_router&) = delete;
    media_fanout_router& operator=(const media_fanout_router&) = delete;

    media_fanout_router(media_fanout_router&&) = delete;
    media_fanout_router& operator=(media_fanout_router&&) = delete;

   public:
    void subscribe(std::string stream_id,
                   std::string subscriber_session_id,
                   media_rtp_handler rtp_handler,
                   media_publisher_source_handler source_handler,
                   media_publisher_sender_timing_handler sender_timing_handler,
                   media_publisher_source_bye_handler source_bye_handler);

    void unsubscribe(std::string_view subscriber_session_id);

    [[nodiscard]] uint64_t set_publisher_source(std::string stream_id,
                                                std::string publisher_session_id,
                                                sdp::webrtc_offer_summary publisher_offer,
                                                media_keyframe_request_handler keyframe_request_handler);

    void clear_publisher_source(std::string_view stream_id, std::string_view publisher_session_id);

    [[nodiscard]] bool request_keyframe(std::string_view stream_id,
                                        std::string_view subscriber_session_id,
                                        std::string_view publisher_session_id,
                                        uint64_t source_generation,
                                        uint32_t media_ssrc);

    void complete_keyframe_request(std::string_view stream_id,
                                   std::string_view subscriber_session_id,
                                   std::string_view publisher_session_id,
                                   uint64_t source_generation,
                                   uint32_t media_ssrc);

    void cancel_keyframe_requests(std::string_view subscriber_session_id);

    [[nodiscard]]
    std::size_t publish_rtp(std::string_view stream_id, std::string_view publisher_session_id, std::span<const uint8_t> packet);

    [[nodiscard]] bool publish_source_bye(
        std::string_view stream_id, std::string_view publisher_session_id, uint64_t source_generation, uint32_t source_ssrc, std::string reason);

    [[nodiscard]] bool publish_sender_timing(std::string_view stream_id,
                                             std::string_view publisher_session_id,
                                             uint64_t source_generation,
                                             uint32_t source_ssrc,
                                             uint64_t ntp_timestamp,
                                             uint32_t source_rtp_timestamp,
                                             uint32_t sender_packet_count,
                                             uint32_t sender_octet_count);

   private:
    struct subscription
    {
        std::string stream_id;
        media_rtp_handler rtp_handler;
        media_publisher_source_handler source_handler;
        media_publisher_sender_timing_handler sender_timing_handler;
        media_publisher_source_bye_handler source_bye_handler;
    };

    struct keyframe_request_key
    {
        std::string stream_id;
        std::string publisher_session_id;
        uint64_t source_generation = 0;
        uint32_t media_ssrc = 0;

        bool operator==(const keyframe_request_key&) const = default;
    };

    struct keyframe_request_key_hash
    {
        [[nodiscard]] std::size_t operator()(const keyframe_request_key& key) const noexcept;
    };

    struct keyframe_request_state
    {
        std::unordered_set<std::string> waiting_subscriber_session_ids;
        std::shared_ptr<boost::asio::steady_timer> retry_timer;
        std::size_t next_retry_delay_index = 0;
        std::size_t sent_count = 0;
        uint64_t timer_token = 0;
        bool retry_active = false;
    };

    [[nodiscard]] uint64_t allocate_source_generation_locked();

    void schedule_keyframe_retry_locked(const keyframe_request_key& key, keyframe_request_state& state);
    void handle_keyframe_retry(keyframe_request_key key, uint64_t timer_token);
    void cancel_keyframe_requests_locked(std::string_view subscriber_session_id);
    void cancel_stream_keyframe_requests_locked(std::string_view stream_id);
    void cancel_keyframe_request_state_locked(keyframe_request_state& state);

   private:
    boost::asio::io_context& io_context_;
    std::mutex mutex_;

    uint64_t next_source_generation_ = 1;

    std::unordered_map<std::string, subscription> subscriptions_by_session_id_;
    std::unordered_map<std::string, media_publisher_source_ptr> publisher_sources_by_stream_id_;
    std::unordered_map<std::string, uint64_t> publisher_source_generations_by_stream_id_;
    std::unordered_map<std::string, std::unordered_map<uint32_t, media_publisher_sender_timing>> publisher_sender_timings_by_stream_id_;
    std::unordered_map<keyframe_request_key, keyframe_request_state, keyframe_request_key_hash> keyframe_requests_;
};
}    // namespace webrtc

#endif
