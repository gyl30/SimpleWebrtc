#ifndef SIMPLE_WEBRTC_MEDIA_RTCP_REPORT_SERVICE_H
#define SIMPLE_WEBRTC_MEDIA_RTCP_REPORT_SERVICE_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <span>
#include <string>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "rtp/rtcp_report_generator.h"
#include "rtp/rtcp_session_stats.h"

namespace webrtc
{
struct rtcp_report_service_config
{
    std::size_t max_report_blocks = 31;

    uint64_t report_interval_milliseconds = 5000;
    uint64_t report_jitter_milliseconds = 1000;

    std::size_t max_packets_per_generation = 32;

    uint64_t stale_source_timeout_milliseconds = 60000;
};
struct rtcp_report_service_runtime_snapshot
{
    std::size_t configured_sources = 0;
    std::size_t stats_sources = 0;

    std::size_t max_report_blocks = 0;
    uint64_t report_interval_milliseconds = 0;
    uint64_t report_jitter_milliseconds = 0;
    std::size_t max_packets_per_generation = 0;
    uint64_t stale_source_timeout_milliseconds = 0;

    uint64_t inbound_rtcp_observe_attempts = 0;
    uint64_t inbound_rtcp_observe_failed = 0;
    uint64_t inbound_sender_report_sources = 0;

    uint64_t remember_source_attempts = 0;
    uint64_t remember_source_success = 0;
    uint64_t remember_source_failed = 0;

    uint64_t send_attempts = 0;
    uint64_t send_success = 0;
    uint64_t endpoint_not_found = 0;
    uint64_t protect_failed = 0;
    uint64_t protect_ignored = 0;

    uint64_t forgot_sources = 0;
    uint64_t forgot_sessions = 0;
    uint64_t forgot_streams = 0;
    uint64_t forgot_peers = 0;
    uint64_t stale_sources_expired = 0;

    uint64_t last_cleanup_time_milliseconds = 0;
    std::size_t last_cleanup_expired_sources = 0;

    uint64_t generated_report_rounds = 0;
    uint64_t generated_packets = 0;
    uint64_t skipped_packets = 0;
    uint64_t failed_packets = 0;
    uint64_t throttled_sources = 0;

    uint64_t observed_sender_reports = 0;

    uint64_t last_generation_time_milliseconds = 0;
    std::size_t last_generation_packets = 0;
    std::size_t last_generation_skipped = 0;
    std::size_t last_generation_failed = 0;
    std::size_t last_generation_due_sources = 0;
    std::size_t last_generation_throttled_sources = 0;
};

struct rtcp_report_source_config
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    std::string mid;
    std::optional<std::string> rid;
    std::optional<std::string> repaired_rid;

    uint32_t local_ssrc = 0;
    std::string cname;

    bool sender_report_enabled = false;
    bool receiver_report_enabled = true;

    std::size_t max_report_blocks = 0;
};

struct rtcp_report_service_packet
{
    rtcp_report_source_config source;

    rtcp_report_generation_result report;
};

struct rtcp_report_service_generation
{
    std::vector<rtcp_report_service_packet> packets;

    std::vector<std::string> errors;

    std::size_t skipped = 0;
    std::size_t failed = 0;

    std::size_t due_sources = 0;
    std::size_t throttled_sources = 0;

    std::size_t stale_sources_expired = 0;
};

struct rtcp_report_service_rtcp_observation
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    std::vector<uint32_t> sender_report_ssrcs;
    std::vector<uint32_t> receiver_report_ssrcs;
    std::vector<uint32_t> remb_ssrcs;

    std::size_t sender_report_count = 0;
    std::size_t receiver_report_count = 0;
    std::size_t remb_count = 0;

    uint64_t max_remb_bitrate_bps = 0;
};

using rtcp_report_service_result = std::expected<void, std::string>;

using rtcp_report_service_packet_result = std::expected<rtcp_report_service_packet, std::string>;

using rtcp_report_service_rtcp_observation_result = std::expected<rtcp_report_service_rtcp_observation, std::string>;

class rtcp_report_service
{
   public:
    rtcp_report_service();

    explicit rtcp_report_service(rtcp_report_service_config config);

    ~rtcp_report_service() = default;

    rtcp_report_service(const rtcp_report_service&) = delete;

    rtcp_report_service& operator=(const rtcp_report_service&) = delete;

    rtcp_report_service(rtcp_report_service&&) = delete;

    rtcp_report_service& operator=(rtcp_report_service&&) = delete;

   public:
    [[nodiscard]]
    rtcp_report_service_result remember_source(const rtcp_report_source_config& source);

    [[nodiscard]]
    rtcp_report_service_result remember_source(const rtcp_report_source_config& source, uint64_t now_milliseconds);

    void forget_source(std::string_view session_id, std::string_view remote_endpoint, uint32_t local_ssrc);

    [[nodiscard]]
    rtcp_report_service_result observe_received_rtp(const rtcp_received_rtp_packet& packet);

    [[nodiscard]]
    rtcp_report_service_result observe_sent_rtp(const rtcp_sent_rtp_packet& packet);

    [[nodiscard]]
    rtcp_report_service_result observe_sender_report(const rtcp_received_sender_report& report);

    [[nodiscard]]
    rtcp_report_service_result observe_receiver_report(const rtcp_received_receiver_report& report);

    [[nodiscard]]
    rtcp_report_service_result observe_remb(const rtcp_received_remb& report);

    [[nodiscard]]
    rtcp_report_service_result observe_received_rtcp(std::string_view stream_id,
                                                     std::string_view session_id,
                                                     std::string_view remote_endpoint,
                                                     std::span<const uint8_t> plain_packet,
                                                     uint64_t arrival_time_milliseconds);

    [[nodiscard]]
    rtcp_report_service_rtcp_observation_result observe_received_rtcp_with_summary(std::string_view stream_id,
                                                                                   std::string_view session_id,
                                                                                   std::string_view remote_endpoint,
                                                                                   std::span<const uint8_t> plain_packet,
                                                                                   uint64_t arrival_time_milliseconds);

    [[nodiscard]]
    rtcp_report_service_generation generate_reports(uint64_t now_milliseconds);

    [[nodiscard]]
    rtcp_report_service_packet_result generate_report_for_source(const rtcp_report_source_config& source, uint64_t now_milliseconds);

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    void forget_peer(std::string_view remote_endpoint);

    void clear();

    [[nodiscard]]
    std::size_t source_count() const;

    [[nodiscard]]
    std::size_t stats_source_count() const;

    [[nodiscard]]
    rtcp_report_service_runtime_snapshot runtime_snapshot() const;

    [[nodiscard]]
    rtcp_session_stats& stats();

    [[nodiscard]]
    const rtcp_session_stats& stats() const;

   private:
    struct rtcp_report_source_record
    {
        rtcp_report_source_config source;

        uint64_t next_due_milliseconds = 0;
        uint64_t last_active_milliseconds = 0;
    };

   private:
    [[nodiscard]]
    static std::string make_source_key(std::string_view session_id, std::string_view remote_endpoint, uint32_t local_ssrc);

    [[nodiscard]]
    static rtcp_report_service_result validate_config(const rtcp_report_service_config& config);

    [[nodiscard]]
    static rtcp_report_service_result validate_source(const rtcp_report_source_config& source);

    [[nodiscard]]
    static rtcp_report_service_result validate_rtcp_observation(std::string_view session_id,
                                                                std::string_view remote_endpoint,
                                                                std::span<const uint8_t> plain_packet);

    [[nodiscard]]
    static uint64_t make_initial_delay_milliseconds(std::string_view key, const rtcp_report_service_config& config);

    [[nodiscard]]
    static uint64_t make_next_delay_milliseconds(std::string_view key, uint64_t generation_round, const rtcp_report_service_config& config);

    [[nodiscard]]
    static uint64_t add_milliseconds_saturated(uint64_t timestamp_milliseconds, uint64_t delay_milliseconds);
    [[nodiscard]]
    std::size_t expire_stale_sources_locked(uint64_t now_milliseconds);

    [[nodiscard]]
    rtcp_report_source_config normalize_source(const rtcp_report_source_config& source) const;

    [[nodiscard]]
    rtcp_report_generation_request make_generation_request(const rtcp_report_source_config& source, uint64_t now_milliseconds) const;

    [[nodiscard]]
    rtcp_report_generation_result_type generate_report_packet(const rtcp_report_source_config& source, uint64_t now_milliseconds);

    void reset_runtime_counters_locked();

   private:
    rtcp_report_service_config config_;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, rtcp_report_source_record> sources_by_key_;

    uint64_t generated_report_rounds_ = 0;
    uint64_t generated_packets_ = 0;
    uint64_t skipped_packets_ = 0;
    uint64_t failed_packets_ = 0;
    uint64_t throttled_sources_ = 0;

    uint64_t forgot_sources_ = 0;
    uint64_t forgot_sessions_ = 0;
    uint64_t forgot_streams_ = 0;
    uint64_t forgot_peers_ = 0;
    uint64_t stale_sources_expired_ = 0;

    uint64_t last_cleanup_time_milliseconds_ = 0;
    std::size_t last_cleanup_expired_sources_ = 0;

    uint64_t observed_sender_reports_ = 0;
    uint64_t last_generation_time_milliseconds_ = 0;
    std::size_t last_generation_packets_ = 0;
    std::size_t last_generation_skipped_ = 0;
    std::size_t last_generation_failed_ = 0;
    std::size_t last_generation_due_sources_ = 0;
    std::size_t last_generation_throttled_sources_ = 0;

    rtcp_session_stats stats_;
};

[[nodiscard]]
std::string rtcp_report_source_config_to_string(const rtcp_report_source_config& source);

[[nodiscard]]
std::string rtcp_report_service_generation_to_string(const rtcp_report_service_generation& generation);

[[nodiscard]]
std::string rtcp_report_service_runtime_snapshot_to_string(const rtcp_report_service_runtime_snapshot& snapshot);

[[nodiscard]]
std::string rtcp_report_service_runtime_snapshot_to_json(const rtcp_report_service_runtime_snapshot& snapshot);

[[nodiscard]]
std::string rtcp_report_service_runtime_snapshot_to_prometheus(const rtcp_report_service_runtime_snapshot& snapshot);
}    // namespace webrtc

#endif
