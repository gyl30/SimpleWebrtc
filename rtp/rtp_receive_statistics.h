#ifndef SIMPLE_WEBRTC_RTP_RTP_RECEIVE_STATISTICS_H
#define SIMPLE_WEBRTC_RTP_RTP_RECEIVE_STATISTICS_H

#include <chrono>
#include <cstdint>

namespace webrtc
{
struct rtp_receive_report_snapshot
{
    uint8_t fraction_lost = 0;
    int32_t cumulative_lost = 0;
    uint32_t extended_highest_sequence_number = 0;
    uint32_t jitter = 0;
    uint64_t expected_packet_count = 0;
    uint64_t received_packet_count = 0;
};

class rtp_receive_statistics
{
   public:
    void reset();

    [[nodiscard]] bool observe(uint16_t sequence_number,
                               uint32_t rtp_timestamp,
                               uint32_t clock_rate,
                               std::chrono::steady_clock::time_point arrival_time);

    [[nodiscard]] bool initialized() const;

    [[nodiscard]] rtp_receive_report_snapshot preview_report() const;

    void commit_report();

   private:
    void initialize_sequence(uint16_t sequence_number);
    [[nodiscard]] bool update_sequence(uint16_t sequence_number);
    void update_jitter(uint32_t rtp_timestamp,
                       uint32_t clock_rate,
                       std::chrono::steady_clock::time_point arrival_time);
    [[nodiscard]] uint64_t expected_packet_count() const;

   private:
    bool sequence_initialized_ = false;
    uint16_t base_sequence_number_ = 0;
    uint16_t maximum_sequence_number_ = 0;
    uint32_t bad_sequence_number_ = 0;
    uint32_t sequence_cycles_ = 0;
    uint64_t received_packet_count_ = 0;
    uint64_t expected_packet_count_prior_ = 0;
    uint64_t received_packet_count_prior_ = 0;

    uint32_t clock_rate_ = 0;
    bool jitter_initialized_ = false;
    std::chrono::steady_clock::time_point arrival_anchor_;
    uint32_t rtp_timestamp_anchor_ = 0;
    int32_t previous_transit_ = 0;
    double jitter_ = 0.0;
};
}    // namespace webrtc

#endif
