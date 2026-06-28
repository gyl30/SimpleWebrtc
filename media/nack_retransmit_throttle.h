#ifndef SIMPLE_WEBRTC_MEDIA_NACK_RETRANSMIT_THROTTLE_H
#define SIMPLE_WEBRTC_MEDIA_NACK_RETRANSMIT_THROTTLE_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
struct nack_retransmit_throttle_config
{
    uint64_t min_interval_milliseconds = 30;
    uint64_t max_age_milliseconds = 60000;
    std::size_t max_entries = 8192;
};

struct nack_retransmit_throttle_decision
{
    bool allowed = true;
    uint64_t elapsed_milliseconds = 0;
    uint64_t wait_milliseconds = 0;
    uint64_t last_sent_at_milliseconds = 0;
};

class nack_retransmit_throttle
{
   public:
    nack_retransmit_throttle();

    explicit nack_retransmit_throttle(nack_retransmit_throttle_config config);

    ~nack_retransmit_throttle() = default;

    nack_retransmit_throttle(const nack_retransmit_throttle&) = delete;
    nack_retransmit_throttle& operator=(const nack_retransmit_throttle&) = delete;

    nack_retransmit_throttle(nack_retransmit_throttle&&) = delete;
    nack_retransmit_throttle& operator=(nack_retransmit_throttle&&) = delete;

   public:
    [[nodiscard]]
    nack_retransmit_throttle_decision check(std::string_view stream_id,
                                            std::string_view subscriber_session_id,
                                            uint32_t feedback_media_ssrc,
                                            uint32_t cache_media_ssrc,
                                            uint16_t feedback_sequence_number,
                                            uint16_t cache_sequence_number,
                                            bool rtx_feedback,
                                            uint64_t now_milliseconds);

    void remember_sent(std::string_view stream_id,
                       std::string_view subscriber_session_id,
                       uint32_t feedback_media_ssrc,
                       uint32_t cache_media_ssrc,
                       uint16_t feedback_sequence_number,
                       uint16_t cache_sequence_number,
                       bool rtx_feedback,
                       uint64_t now_milliseconds);

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    void clear();

    [[nodiscard]]
    std::size_t size() const;

   private:
    struct nack_retransmit_throttle_state
    {
        std::string stream_id;
        std::string subscriber_session_id;

        uint32_t feedback_media_ssrc = 0;
        uint32_t cache_media_ssrc = 0;

        uint16_t feedback_sequence_number = 0;
        uint16_t cache_sequence_number = 0;

        bool rtx_feedback = false;

        uint64_t last_sent_at_milliseconds = 0;
        uint64_t sent_count = 0;
        uint64_t suppressed_count = 0;
    };

    [[nodiscard]]
    static std::string make_key(std::string_view stream_id,
                                std::string_view subscriber_session_id,
                                uint32_t feedback_media_ssrc,
                                uint32_t cache_media_ssrc,
                                uint16_t feedback_sequence_number,
                                uint16_t cache_sequence_number,
                                bool rtx_feedback);

    void expire_old_locked(uint64_t now_milliseconds);

    void enforce_capacity_locked();

    void filter_insertion_order_locked();

   private:
    nack_retransmit_throttle_config config_;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, nack_retransmit_throttle_state> states_by_key_;
    std::deque<std::string> insertion_order_;
};
}    // namespace webrtc

#endif
