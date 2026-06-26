#ifndef SIMPLE_WEBRTC_RTP_RTCP_SESSION_STATS_H
#define SIMPLE_WEBRTC_RTP_RTCP_SESSION_STATS_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "rtp/rtcp_report.h"

namespace webrtc
{
struct rtcp_received_rtp_packet
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    uint32_t ssrc = 0;
    uint16_t sequence_number = 0;
    uint32_t rtp_timestamp = 0;
    uint32_t clock_rate = 0;

    std::size_t payload_size = 0;
    uint64_t arrival_time_milliseconds = 0;
};

struct rtcp_sent_rtp_packet
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    uint32_t ssrc = 0;
    uint32_t rtp_timestamp = 0;

    std::size_t payload_size = 0;
    uint64_t send_time_milliseconds = 0;
};

struct rtcp_received_sender_report
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    uint32_t ssrc = 0;
    uint32_t ntp_msw = 0;
    uint32_t ntp_lsw = 0;

    uint64_t arrival_time_milliseconds = 0;
};

struct rtcp_session_report_snapshot
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    uint32_t ssrc = 0;
    uint32_t clock_rate = 0;

    bool initialized = false;

    uint16_t base_sequence_number = 0;
    uint16_t max_sequence_number = 0;
    uint32_t sequence_cycles = 0;
    uint32_t extended_highest_sequence_number = 0;

    uint64_t received_packets = 0;
    uint64_t expected_packets = 0;

    int64_t cumulative_lost = 0;
    uint8_t fraction_lost = 0;
    uint32_t jitter = 0;

    bool has_sender_report = false;
    uint32_t last_sender_report = 0;
    uint32_t delay_since_last_sender_report = 0;

    uint64_t last_packet_time_milliseconds = 0;

    rtcp_report_block report_block;
};

struct rtcp_sender_stats_snapshot
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    uint32_t ssrc = 0;
    uint32_t last_rtp_timestamp = 0;

    uint64_t sender_packet_count = 0;
    uint64_t sender_octet_count = 0;
    uint64_t last_send_time_milliseconds = 0;

    rtcp_sender_info sender_info;
};

using rtcp_session_stats_result = std::expected<void, std::string>;

using rtcp_report_block_result = std::expected<rtcp_report_block, std::string>;

using rtcp_sender_info_result = std::expected<rtcp_sender_info, std::string>;

class rtcp_session_stats
{
   public:
    rtcp_session_stats() = default;
    ~rtcp_session_stats() = default;

    rtcp_session_stats(const rtcp_session_stats&) = delete;

    rtcp_session_stats& operator=(const rtcp_session_stats&) = delete;

    rtcp_session_stats(rtcp_session_stats&&) = delete;

    rtcp_session_stats& operator=(rtcp_session_stats&&) = delete;

   public:
    [[nodiscard]]
    rtcp_session_stats_result observe_received_rtp(const rtcp_received_rtp_packet& packet);

    [[nodiscard]]
    rtcp_session_stats_result observe_sent_rtp(const rtcp_sent_rtp_packet& packet);

    [[nodiscard]]
    rtcp_session_stats_result observe_sender_report(const rtcp_received_sender_report& report);

    [[nodiscard]]
    rtcp_report_block_result make_report_block(std::string_view session_id,
                                               std::string_view remote_endpoint,
                                               uint32_t ssrc,
                                               uint64_t now_milliseconds);

    [[nodiscard]]
    std::vector<rtcp_report_block> make_report_blocks(std::string_view session_id,
                                                      std::string_view remote_endpoint,
                                                      uint64_t now_milliseconds,
                                                      std::size_t max_report_blocks);

    [[nodiscard]]
    rtcp_sender_info_result make_sender_info(std::string_view session_id,
                                             std::string_view remote_endpoint,
                                             uint32_t ssrc,
                                             uint64_t now_milliseconds) const;

    [[nodiscard]]
    std::optional<rtcp_session_report_snapshot> find_report_snapshot(std::string_view session_id,
                                                                     std::string_view remote_endpoint,
                                                                     uint32_t ssrc,
                                                                     uint64_t now_milliseconds) const;

    [[nodiscard]]
    std::optional<rtcp_sender_stats_snapshot> find_sender_snapshot(std::string_view session_id,
                                                                   std::string_view remote_endpoint,
                                                                   uint32_t ssrc,
                                                                   uint64_t now_milliseconds) const;

    void forget_ssrc(std::string_view session_id, std::string_view remote_endpoint, uint32_t ssrc);

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    void forget_peer(std::string_view remote_endpoint);

    void clear();

    [[nodiscard]]
    std::size_t source_count() const;

   private:
    struct source_state
    {
        std::string stream_id;
        std::string session_id;
        std::string remote_endpoint;

        uint32_t ssrc = 0;
        uint32_t clock_rate = 0;

        bool sequence_initialized = false;
        uint16_t base_sequence_number = 0;
        uint16_t max_sequence_number = 0;
        uint16_t bad_sequence_number = 0;
        uint32_t sequence_cycles = 0;

        uint64_t received_packets = 0;
        uint64_t received_prior = 0;
        uint32_t expected_prior = 0;

        bool transit_initialized = false;
        int64_t previous_transit = 0;
        double jitter = 0.0;

        bool has_sender_report = false;
        uint32_t last_sender_report = 0;
        uint64_t last_sender_report_arrival_milliseconds = 0;

        uint64_t last_received_time_milliseconds = 0;

        uint64_t sender_packet_count = 0;
        uint64_t sender_octet_count = 0;
        uint32_t last_sent_rtp_timestamp = 0;
        uint64_t last_send_time_milliseconds = 0;
        bool has_sent_rtp = false;
    };

   private:
    [[nodiscard]]
    static std::string make_source_key(std::string_view session_id, std::string_view remote_endpoint, uint32_t ssrc);

    [[nodiscard]]
    static rtcp_session_stats_result validate_received_rtp(const rtcp_received_rtp_packet& packet);

    [[nodiscard]]
    static rtcp_session_stats_result validate_sent_rtp(const rtcp_sent_rtp_packet& packet);

    [[nodiscard]]
    static rtcp_session_stats_result validate_sender_report(const rtcp_received_sender_report& report);

    [[nodiscard]]
    static uint32_t make_extended_highest_sequence_number(const source_state& state);

    [[nodiscard]]
    static uint64_t make_expected_packet_count(const source_state& state);

    static void fill_report_block(rtcp_report_block& block,
                                  const source_state& state,
                                  uint64_t expected_packets,
                                  uint8_t fraction_lost,
                                  uint32_t jitter,
                                  uint64_t now_milliseconds);

    [[nodiscard]]
    static rtcp_session_report_snapshot make_snapshot_from_state(const source_state& state,
                                                                 uint64_t now_milliseconds,
                                                                 bool update_interval,
                                                                 source_state* mutable_state);

    [[nodiscard]]
    static rtcp_sender_stats_snapshot make_sender_snapshot_from_state(const source_state& state, uint64_t now_milliseconds);

    static void reset_sequence_state(source_state& state, uint16_t sequence_number);

    [[nodiscard]]
    static bool update_sequence_state(source_state& state, uint16_t sequence_number);

    static void update_jitter(source_state& state, uint32_t rtp_timestamp, uint64_t arrival_time_milliseconds);

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, source_state> sources_by_key_;
};

[[nodiscard]]
std::string rtcp_session_report_snapshot_to_string(const rtcp_session_report_snapshot& snapshot);

[[nodiscard]]
std::string rtcp_sender_stats_snapshot_to_string(const rtcp_sender_stats_snapshot& snapshot);
}    // namespace webrtc

#endif
