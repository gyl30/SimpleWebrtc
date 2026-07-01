#ifndef SIMPLE_WEBRTC_MEDIA_RTCP_TRANSPORT_CC_FEEDBACK_SERVICE_H
#define SIMPLE_WEBRTC_MEDIA_RTCP_TRANSPORT_CC_FEEDBACK_SERVICE_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace webrtc
{
struct rtcp_transport_cc_observed_packet
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    std::string mid;
    std::string kind;

    uint32_t sender_ssrc = 0;
    uint32_t media_ssrc = 0;

    uint16_t transport_sequence_number = 0;
    uint64_t arrival_time_milliseconds = 0;
};
struct rtcp_transport_cc_feedback_packet
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;
    std::string mid;
    std::string kind;

    uint32_t sender_ssrc = 0;
    uint32_t media_ssrc = 0;

    uint16_t base_sequence_number = 0;
    uint16_t packet_status_count = 0;
    uint8_t feedback_packet_count = 0;

    std::vector<uint8_t> packet;
};

struct rtcp_transport_cc_feedback_generation
{
    std::vector<rtcp_transport_cc_feedback_packet> packets;
    std::vector<std::string> errors;

    std::size_t source_count = 0;
    std::size_t pending_packet_count = 0;
    std::size_t stale_sources_expired = 0;
    std::size_t skipped_sources = 0;
};

struct rtcp_transport_cc_feedback_config
{
    uint64_t feedback_interval_milliseconds = 100;
    uint64_t stale_source_milliseconds = 30000;

    std::size_t max_observed_packets_per_source = 512;
    std::size_t max_sources = 4096;
    std::size_t max_pending_packets_total = 65536;

    uint16_t max_packets_per_feedback = 64;
};
using rtcp_transport_cc_feedback_result = std::expected<void, std::string>;

class rtcp_transport_cc_feedback_service
{
   public:
    rtcp_transport_cc_feedback_service();

    explicit rtcp_transport_cc_feedback_service(rtcp_transport_cc_feedback_config config);

    ~rtcp_transport_cc_feedback_service() = default;

    rtcp_transport_cc_feedback_service(const rtcp_transport_cc_feedback_service&) = delete;
    rtcp_transport_cc_feedback_service& operator=(const rtcp_transport_cc_feedback_service&) = delete;

    rtcp_transport_cc_feedback_service(rtcp_transport_cc_feedback_service&&) = delete;
    rtcp_transport_cc_feedback_service& operator=(rtcp_transport_cc_feedback_service&&) = delete;

   public:
    [[nodiscard]]
    rtcp_transport_cc_feedback_result observe_received_packet(const rtcp_transport_cc_observed_packet& packet);

    [[nodiscard]]
    rtcp_transport_cc_feedback_generation generate_due_feedback(uint64_t now_milliseconds);

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    void forget_peer(std::string_view remote_endpoint);

    void forget_source(std::string_view session_id, std::string_view remote_endpoint, uint32_t media_ssrc);
    void clear();

    [[nodiscard]]
    std::size_t source_count() const;

    [[nodiscard]]
    std::size_t pending_packet_count() const;

   public:
    struct observed_packet_state
    {
        uint16_t transport_sequence_number = 0;
        uint64_t arrival_time_milliseconds = 0;
    };

    struct source_state
    {
        std::string stream_id;
        std::string session_id;
        std::string remote_endpoint;

        std::string mid;
        std::string kind;

        uint32_t sender_ssrc = 0;
        uint32_t media_ssrc = 0;

        uint8_t feedback_packet_count = 0;
        uint64_t next_due_milliseconds = 0;
        uint64_t last_active_milliseconds = 0;

        std::vector<observed_packet_state> packets;
    };

   private:
    [[nodiscard]]
    static std::string make_source_key(std::string_view session_id, std::string_view remote_endpoint, uint32_t media_ssrc);

    [[nodiscard]]
    std::size_t pending_packet_count_locked() const;

    [[nodiscard]]
    static rtcp_transport_cc_feedback_result validate_observed_packet(const rtcp_transport_cc_observed_packet& packet);

    [[nodiscard]]
    std::expected<rtcp_transport_cc_feedback_packet, std::string> make_feedback_packet(source_state& source);

    void expire_stale_sources_locked(uint64_t now_milliseconds, rtcp_transport_cc_feedback_generation& generation);

   private:
    rtcp_transport_cc_feedback_config config_;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, source_state> sources_by_key_;
};
}    // namespace webrtc

#endif
