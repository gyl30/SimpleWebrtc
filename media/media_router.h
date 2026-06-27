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
#include "media/media_ssrc_mapper.h"
#include "media/media_track_resolver.h"

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
struct media_track_stats
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;
    std::string direction;

    std::string mid;
    std::string kind;

    std::string rid;
    std::string repaired_rid;

    bool has_transport_wide_sequence_number = false;
    uint32_t last_transport_wide_sequence_number = 0;

    bool has_audio_level = false;
    uint32_t last_audio_level = 0;

    bool has_voice_activity = false;
    bool last_voice_activity = false;

    uint32_t ssrc = 0;
    uint32_t payload_type = 0;

    uint64_t inbound_rtp_packets = 0;
    uint64_t inbound_rtp_bytes = 0;

    uint64_t outbound_rtp_packets = 0;
    uint64_t outbound_rtp_bytes = 0;

    uint32_t outbound_ssrc = 0;
    uint32_t outbound_payload_type = 0;

    uint32_t first_outbound_rtp_sequence_number = 0;
    uint32_t last_outbound_rtp_sequence_number = 0;
    uint32_t last_outbound_rtp_timestamp = 0;

    uint32_t first_rtp_sequence_number = 0;
    uint32_t last_rtp_sequence_number = 0;
    uint32_t last_rtp_timestamp = 0;
};

struct media_peer_stats
{
    media_peer_info peer;

    uint64_t inbound_rtp_packets = 0;
    uint64_t inbound_rtp_bytes = 0;
    uint64_t inbound_rtcp_packets = 0;
    uint64_t inbound_rtcp_bytes = 0;

    uint64_t routed_target_packets = 0;
    uint64_t routed_target_bytes = 0;

    uint64_t rtcp_feedback_packets = 0;
    uint64_t rtcp_generic_nack_packets = 0;
    uint64_t rtcp_keyframe_request_packets = 0;
    uint64_t rtcp_transport_cc_packets = 0;
    uint64_t rtcp_remb_packets = 0;

    uint64_t rtcp_nack_items = 0;
    uint64_t rtcp_fir_items = 0;

    uint64_t rtcp_report_packets = 0;
    uint64_t rtcp_report_blocks = 0;
    uint64_t rtcp_sender_report_packets = 0;
    uint64_t rtcp_receiver_report_packets = 0;

    uint8_t last_rtcp_fraction_lost = 0;
    int32_t last_rtcp_cumulative_lost = 0;
    uint32_t last_rtcp_jitter = 0;
    uint32_t last_rtcp_report_ssrc = 0;
    uint32_t last_rtcp_report_media_ssrc = 0;
    uint32_t last_rtcp_sr_packet_count = 0;
    uint32_t last_rtcp_sr_octet_count = 0;

    uint64_t rtcp_rtt_sample_count = 0;
    uint64_t rtcp_last_rtt_ms = 0;
    uint64_t rtcp_max_rtt_ms = 0;
    uint64_t rtcp_avg_rtt_ms = 0;
    uint64_t rtcp_rtt_sum_ms = 0;

    bool has_rtp_sequence = false;
    uint16_t expected_rtp_sequence_number = 0;

    uint64_t rtp_sequence_gap_events = 0;
    uint64_t rtp_sequence_lost_packets = 0;
    uint64_t rtp_out_of_order_packets = 0;
    uint64_t rtp_duplicate_packets = 0;
    uint64_t rtp_sequence_wraps = 0;

    uint32_t last_rtp_ssrc = 0;
    uint16_t last_rtp_sequence_number = 0;
    uint32_t last_rtp_timestamp = 0;
    uint8_t last_rtp_payload_type = 0;

    uint32_t last_rtcp_ssrc = 0;
    uint8_t last_rtcp_packet_type = 0;
    uint64_t last_remb_bitrate_bps = 0;
};

struct media_stream_stats
{
    std::string stream_id;

    std::size_t active_publishers = 0;
    std::size_t active_subscribers = 0;

    uint64_t inbound_rtp_packets = 0;
    uint64_t inbound_rtp_bytes = 0;
    uint64_t inbound_rtcp_packets = 0;
    uint64_t inbound_rtcp_bytes = 0;

    uint64_t publisher_rtp_packets = 0;
    uint64_t subscriber_rtcp_packets = 0;

    uint64_t fanout_target_packets = 0;
    uint64_t route_to_publisher_packets = 0;

    uint64_t rtcp_feedback_packets = 0;
    uint64_t rtcp_generic_nack_packets = 0;
    uint64_t rtcp_keyframe_request_packets = 0;
    uint64_t rtcp_transport_cc_packets = 0;
    uint64_t rtcp_remb_packets = 0;

    uint64_t rtcp_nack_items = 0;
    uint64_t rtcp_fir_items = 0;

    uint64_t rtcp_report_packets = 0;
    uint64_t rtcp_report_blocks = 0;
    uint64_t rtcp_sender_report_packets = 0;
    uint64_t rtcp_receiver_report_packets = 0;

    uint8_t last_rtcp_fraction_lost = 0;
    int32_t last_rtcp_cumulative_lost = 0;
    uint32_t last_rtcp_jitter = 0;
    uint32_t last_rtcp_report_ssrc = 0;
    uint32_t last_rtcp_report_media_ssrc = 0;
    uint32_t last_rtcp_sr_packet_count = 0;
    uint32_t last_rtcp_sr_octet_count = 0;

    uint64_t rtcp_rtt_sample_count = 0;
    uint64_t rtcp_last_rtt_ms = 0;
    uint64_t rtcp_max_rtt_ms = 0;
    uint64_t rtcp_avg_rtt_ms = 0;
    uint64_t rtcp_rtt_sum_ms = 0;

    uint64_t rtp_sequence_gap_events = 0;
    uint64_t rtp_sequence_lost_packets = 0;
    uint64_t rtp_out_of_order_packets = 0;
    uint64_t rtp_duplicate_packets = 0;
    uint64_t rtp_sequence_wraps = 0;

    uint32_t last_rtp_ssrc = 0;
    uint16_t last_rtp_sequence_number = 0;
    uint32_t last_rtp_timestamp = 0;

    uint32_t last_rtcp_ssrc = 0;
    uint64_t last_remb_bitrate_bps = 0;

    std::vector<media_track_stats> tracks;
};
struct media_router_stats_snapshot
{
    std::size_t peer_count = 0;
    std::size_t stream_count = 0;
    std::size_t active_publisher_count = 0;
    std::size_t active_subscriber_count = 0;

    uint64_t inbound_rtp_packets = 0;
    uint64_t inbound_rtp_bytes = 0;
    uint64_t inbound_rtcp_packets = 0;
    uint64_t inbound_rtcp_bytes = 0;

    uint64_t routed_target_packets = 0;
    uint64_t routed_target_bytes = 0;

    uint64_t rtcp_feedback_packets = 0;
    uint64_t rtcp_report_packets = 0;
    uint64_t rtcp_report_blocks = 0;
    uint64_t rtcp_nack_items = 0;
    uint64_t rtcp_fir_items = 0;
    uint64_t rtcp_keyframe_request_packets = 0;
    uint64_t rtcp_generic_nack_packets = 0;
    uint64_t rtcp_transport_cc_packets = 0;
    uint64_t rtcp_remb_packets = 0;

    uint64_t rtcp_rtt_sample_count = 0;
    uint64_t rtcp_last_rtt_ms = 0;
    uint64_t rtcp_max_rtt_ms = 0;
    uint64_t rtcp_avg_rtt_ms = 0;
    uint64_t rtcp_rtt_sum_ms = 0;

    uint64_t rtp_sequence_gap_events = 0;
    uint64_t rtp_sequence_lost_packets = 0;
    uint64_t rtp_out_of_order_packets = 0;
    uint64_t rtp_duplicate_packets = 0;
    uint64_t rtp_sequence_wraps = 0;

    std::vector<media_peer_stats> peers;
    std::vector<media_stream_stats> streams;
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

    void forget_stream(std::string_view stream_id);

    void clear();

    [[nodiscard]] media_route_result handle_inbound_packet(std::string_view remote_endpoint, const srtp_packet_process_result& packet);

    void observe_inbound_track(const media_peer_info& peer, const srtp_packet_process_result& packet, const media_track_resolution& track_resolution);

    void observe_outbound_track(const media_peer_info& peer, const media_ssrc_mapping& mapping, std::span<const uint8_t> outbound_plain_packet);

    [[nodiscard]] std::optional<media_peer_info> get_peer(std::string_view remote_endpoint) const;

    [[nodiscard]] std::optional<media_peer_stats> get_peer_stats(std::string_view remote_endpoint) const;

    [[nodiscard]] std::optional<media_stream_stats> get_stream_stats(std::string_view stream_id) const;

    [[nodiscard]] media_router_stats_snapshot get_stats_snapshot() const;

    [[nodiscard]] std::size_t peer_count() const;

    [[nodiscard]] std::size_t subscriber_count(std::string_view stream_id) const;

   private:
    void remember_peer_locked(media_peer_info peer);

    void forget_peer_locked(std::string_view remote_endpoint);

    void update_stream_member_counts_locked(std::string_view stream_id);

    void update_inbound_stats_locked(const media_peer_info& peer,
                                     const srtp_packet_process_result& packet,
                                     media_route_action action,
                                     std::size_t target_count);

    void update_rtp_quality_stats_locked(media_peer_stats& peer_stats, media_stream_stats& stream_stats, const srtp_packet_process_result& packet);

    [[nodiscard]]
    media_track_stats& get_or_create_track_stats_locked(media_stream_stats& stream_stats,
                                                        const media_peer_info& peer,
                                                        const media_track_resolution& track_resolution);

    void update_track_stats_locked(media_track_stats& track_stats,
                                   const srtp_packet_process_result& packet,
                                   const media_track_resolution& track_resolution);

    [[nodiscard]]
    media_track_stats& get_or_create_outbound_track_stats_locked(media_stream_stats& stream_stats,
                                                                 const media_peer_info& peer,
                                                                 const media_ssrc_mapping& mapping,
                                                                 uint32_t outbound_ssrc);

    void update_outbound_track_stats_locked(media_track_stats& track_stats, std::span<const uint8_t> outbound_plain_packet);

    void update_rtcp_stats_locked(media_peer_stats& peer_stats, media_stream_stats& stream_stats, const srtp_packet_process_result& packet);

    void update_rtcp_feedback_stats_locked(media_peer_stats& peer_stats, media_stream_stats& stream_stats, const srtp_packet_process_result& packet);

    void update_rtcp_report_stats_locked(media_peer_stats& peer_stats, media_stream_stats& stream_stats, const srtp_packet_process_result& packet);

    void update_rtcp_rtt_stats_locked(media_peer_stats& peer_stats, media_stream_stats& stream_stats, uint64_t rtt_ms);

    void log_peer_stats_locked(const media_peer_stats& peer_stats, const media_stream_stats& stream_stats) const;

    [[nodiscard]] std::vector<std::string> get_subscriber_endpoints_locked(std::string_view stream_id, std::string_view excluded_endpoint) const;

    [[nodiscard]] std::vector<std::string> get_publisher_endpoint_locked(std::string_view stream_id, std::string_view excluded_endpoint) const;

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, media_peer_info> peers_by_endpoint_;
    std::unordered_map<std::string, media_peer_stats> peer_stats_by_endpoint_;
    std::unordered_map<std::string, media_stream_stats> stream_stats_by_stream_;

    std::unordered_map<std::string, std::string> publisher_by_stream_;
    std::unordered_map<std::string, std::unordered_set<std::string>> subscribers_by_stream_;
};

[[nodiscard]] std::string media_peer_role_to_string(media_peer_role role);

[[nodiscard]] std::string media_route_action_to_string(media_route_action action);
}    // namespace webrtc

#endif
