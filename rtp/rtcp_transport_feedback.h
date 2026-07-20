#ifndef SIMPLE_WEBRTC_RTP_RTCP_TRANSPORT_FEEDBACK_H
#define SIMPLE_WEBRTC_RTP_RTCP_TRANSPORT_FEEDBACK_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace webrtc
{
inline constexpr std::chrono::milliseconds k_default_transport_feedback_history_age{2000};
inline constexpr std::size_t k_default_transport_feedback_history_packets = 32768;
inline constexpr std::size_t k_default_transport_feedback_packet_size = 1000;

struct rtcp_transport_feedback_status
{
    uint16_t sequence_number = 0;
    bool received = false;
    std::optional<int16_t> delta_ticks;
};

struct parsed_rtcp_transport_feedback
{
    uint32_t sender_ssrc = 0;
    uint32_t media_ssrc = 0;
    uint16_t base_sequence_number = 0;
    uint16_t packet_status_count = 0;
    uint32_t reference_time = 0;
    uint8_t feedback_packet_count = 0;
    std::vector<rtcp_transport_feedback_status> statuses;
};

using rtcp_transport_feedback_parse_result =
    std::expected<parsed_rtcp_transport_feedback, std::string>;

struct built_rtcp_transport_feedback
{
    std::vector<uint8_t> packet;
    uint16_t base_sequence_number = 0;
    uint16_t packet_status_count = 0;
    uint32_t media_ssrc = 0;
    uint8_t feedback_packet_count = 0;
    std::size_t received_packet_count = 0;
    std::size_t lost_packet_count = 0;
    int64_t begin_extended_sequence = 0;
    int64_t end_extended_sequence = 0;
};

struct transport_feedback_observe_result
{
    bool inserted = false;
    bool duplicate = false;
    bool sequence_discontinuity = false;
    int64_t extended_sequence_number = 0;
};

struct transport_feedback_generator_snapshot
{
    std::size_t history_packets = 0;
    std::size_t pending_packets = 0;
    uint64_t observed_packets = 0;
    uint64_t duplicate_packets = 0;
    uint64_t sequence_discontinuities = 0;
    uint64_t feedback_packets_built = 0;
    uint64_t packet_statuses_built = 0;
};

class transport_feedback_generator
{
   public:
    transport_feedback_generator(
        std::chrono::milliseconds maximum_history_age =
            k_default_transport_feedback_history_age,
        std::size_t maximum_history_packets =
            k_default_transport_feedback_history_packets);

    [[nodiscard]] transport_feedback_observe_result observe(
        uint16_t sequence_number,
        std::chrono::steady_clock::time_point arrival_time,
        uint32_t media_ssrc);

    [[nodiscard]] std::expected<std::optional<built_rtcp_transport_feedback>,
                                std::string>
    preview_feedback(uint32_t sender_ssrc,
                     std::size_t maximum_packet_size =
                         k_default_transport_feedback_packet_size) const;

    void commit_feedback(const built_rtcp_transport_feedback& feedback);
    void expire(std::chrono::steady_clock::time_point now);

    [[nodiscard]] bool has_pending_feedback() const;
    [[nodiscard]] transport_feedback_generator_snapshot snapshot() const;
    void reset();

   private:
    struct arrival_record
    {
        std::chrono::steady_clock::time_point arrival_time;
    };

    [[nodiscard]] int64_t unwrap_sequence(uint16_t sequence_number,
                                          bool& discontinuity);
    void evict_old(std::chrono::steady_clock::time_point now);
    [[nodiscard]] std::size_t pending_status_count() const;

    std::chrono::milliseconds maximum_history_age_;
    std::size_t maximum_history_packets_ = 0;
    std::optional<int64_t> newest_extended_sequence_;
    std::optional<int64_t> feedback_window_start_;
    std::map<int64_t, arrival_record> arrivals_;
    uint32_t media_ssrc_ = 0;
    uint8_t feedback_packet_count_ = 0;
    transport_feedback_generator_snapshot stats_;
};

[[nodiscard]] rtcp_transport_feedback_parse_result parse_rtcp_transport_feedback(
    std::span<const uint8_t> packet);
}    // namespace webrtc

#endif
