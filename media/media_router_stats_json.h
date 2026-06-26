#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_ROUTER_STATS_JSON_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_ROUTER_STATS_JSON_H

#include <cstdint>
#include <string>
#include <vector>

#include "media/media_router.h"
#include "util/reflect.h"

namespace webrtc
{
struct media_peer_info_json
{
    std::string role;
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;
};

struct media_track_stats_json
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

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

    uint32_t first_rtp_sequence_number = 0;
    uint32_t last_rtp_sequence_number = 0;
    uint32_t last_rtp_timestamp = 0;
};
struct media_peer_stats_json
{
    media_peer_info_json peer;

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

    uint32_t last_rtcp_fraction_lost = 0;
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
    uint32_t expected_rtp_sequence_number = 0;

    uint64_t rtp_sequence_gap_events = 0;
    uint64_t rtp_sequence_lost_packets = 0;
    uint64_t rtp_out_of_order_packets = 0;
    uint64_t rtp_duplicate_packets = 0;
    uint64_t rtp_sequence_wraps = 0;

    uint32_t last_rtp_ssrc = 0;
    uint32_t last_rtp_sequence_number = 0;
    uint32_t last_rtp_timestamp = 0;
    uint32_t last_rtp_payload_type = 0;

    uint32_t last_rtcp_ssrc = 0;
    uint32_t last_rtcp_packet_type = 0;
    uint64_t last_remb_bitrate_bps = 0;
};

struct media_stream_stats_json
{
    std::string stream_id;

    uint64_t active_publishers = 0;
    uint64_t active_subscribers = 0;

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

    uint32_t last_rtcp_fraction_lost = 0;
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
    uint32_t last_rtp_sequence_number = 0;
    uint32_t last_rtp_timestamp = 0;

    uint32_t last_rtcp_ssrc = 0;
    uint64_t last_remb_bitrate_bps = 0;

    uint64_t track_count = 0;
    std::vector<media_track_stats_json> tracks;
};

struct media_router_stats_snapshot_json
{
    uint64_t peer_count = 0;
    uint64_t stream_count = 0;
    uint64_t active_publisher_count = 0;
    uint64_t active_subscriber_count = 0;

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

    uint64_t track_count = 0;

    std::vector<media_peer_stats_json> peers;
    std::vector<media_stream_stats_json> streams;
};

[[nodiscard]] std::string media_router_stats_snapshot_to_json(const media_router_stats_snapshot& snapshot);

[[nodiscard]] std::string media_peer_stats_to_json(const media_peer_stats& stats);

[[nodiscard]] std::string media_stream_stats_to_json(const media_stream_stats& stats);

REFLECT_STRUCT(webrtc::media_peer_info_json, (role)(stream_id)(session_id)(remote_endpoint));

REFLECT_STRUCT(webrtc::media_peer_stats_json,
               (
                   peer)(inbound_rtp_packets)(inbound_rtp_bytes)(inbound_rtcp_packets)(inbound_rtcp_bytes)(routed_target_packets)(routed_target_bytes)(rtcp_feedback_packets)(rtcp_generic_nack_packets)(rtcp_keyframe_request_packets)(rtcp_transport_cc_packets)(rtcp_remb_packets)(rtcp_nack_items)(rtcp_fir_items)(rtcp_report_packets)(rtcp_report_blocks)(rtcp_sender_report_packets)(rtcp_receiver_report_packets)(last_rtcp_fraction_lost)(last_rtcp_cumulative_lost)(last_rtcp_jitter)(last_rtcp_report_ssrc)(last_rtcp_report_media_ssrc)(last_rtcp_sr_packet_count)(last_rtcp_sr_octet_count)(rtcp_rtt_sample_count)(rtcp_last_rtt_ms)(rtcp_max_rtt_ms)(rtcp_avg_rtt_ms)(rtcp_rtt_sum_ms)(has_rtp_sequence)(expected_rtp_sequence_number)(rtp_sequence_gap_events)(rtp_sequence_lost_packets)(rtp_out_of_order_packets)(rtp_duplicate_packets)(rtp_sequence_wraps)(last_rtp_ssrc)(last_rtp_sequence_number)(last_rtp_timestamp)(last_rtp_payload_type)(last_rtcp_ssrc)(last_rtcp_packet_type)(last_remb_bitrate_bps));

REFLECT_STRUCT(webrtc::media_stream_stats_json,
               (
                   stream_id)(active_publishers)(active_subscribers)(inbound_rtp_packets)(inbound_rtp_bytes)(inbound_rtcp_packets)(inbound_rtcp_bytes)(publisher_rtp_packets)(subscriber_rtcp_packets)(fanout_target_packets)(route_to_publisher_packets)(rtcp_feedback_packets)(rtcp_generic_nack_packets)(rtcp_keyframe_request_packets)(rtcp_transport_cc_packets)(rtcp_remb_packets)(rtcp_nack_items)(rtcp_fir_items)(rtcp_report_packets)(rtcp_report_blocks)(rtcp_sender_report_packets)(rtcp_receiver_report_packets)(last_rtcp_fraction_lost)(last_rtcp_cumulative_lost)(last_rtcp_jitter)(last_rtcp_report_ssrc)(last_rtcp_report_media_ssrc)(last_rtcp_sr_packet_count)(last_rtcp_sr_octet_count)(rtcp_rtt_sample_count)(rtcp_last_rtt_ms)(rtcp_max_rtt_ms)(rtcp_avg_rtt_ms)(rtcp_rtt_sum_ms)(rtp_sequence_gap_events)(rtp_sequence_lost_packets)(rtp_out_of_order_packets)(rtp_duplicate_packets)(rtp_sequence_wraps)(last_rtp_ssrc)(last_rtp_sequence_number)(last_rtp_timestamp)(last_rtcp_ssrc)(last_remb_bitrate_bps)(track_count)(tracks));

REFLECT_STRUCT(webrtc::media_router_stats_snapshot_json,
               (
                   peer_count)(stream_count)(active_publisher_count)(active_subscriber_count)(inbound_rtp_packets)(inbound_rtp_bytes)(inbound_rtcp_packets)(inbound_rtcp_bytes)(routed_target_packets)(routed_target_bytes)(rtcp_feedback_packets)(rtcp_report_packets)(rtcp_report_blocks)(rtcp_nack_items)(rtcp_fir_items)(rtcp_keyframe_request_packets)(rtcp_generic_nack_packets)(rtcp_transport_cc_packets)(rtcp_remb_packets)(rtcp_rtt_sample_count)(rtcp_last_rtt_ms)(rtcp_max_rtt_ms)(rtcp_avg_rtt_ms)(rtcp_rtt_sum_ms)(rtp_sequence_gap_events)(rtp_sequence_lost_packets)(rtp_out_of_order_packets)(rtp_duplicate_packets)(rtp_sequence_wraps)(track_count)(peers)(streams));
REFLECT_STRUCT(
    webrtc::media_track_stats_json,
    (stream_id)(session_id)(remote_endpoint)(mid)(kind)(rid)(repaired_rid)(has_transport_wide_sequence_number)(last_transport_wide_sequence_number)(has_audio_level)(last_audio_level)(has_voice_activity)(last_voice_activity)(ssrc)(payload_type)(inbound_rtp_packets)(inbound_rtp_bytes)(first_rtp_sequence_number)(last_rtp_sequence_number)(last_rtp_timestamp));

}    // namespace webrtc
#endif
