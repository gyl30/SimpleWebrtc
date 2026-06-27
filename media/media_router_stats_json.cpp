#include "media/media_router_stats_json.h"

#include <cstdint>
#include <string>
#include <vector>

#include "media/media_router.h"
#include "util/reflect.h"

namespace webrtc
{
namespace
{
[[nodiscard]] uint64_t to_json_size(std::size_t value) { return static_cast<uint64_t>(value); }

[[nodiscard]] uint32_t to_json_uint32(uint8_t value) { return static_cast<uint32_t>(value); }

[[nodiscard]] uint32_t to_json_uint32(uint16_t value) { return static_cast<uint32_t>(value); }

[[nodiscard]] media_peer_info_json make_media_peer_info_json(const media_peer_info& peer)
{
    media_peer_info_json json;
    json.role = media_peer_role_to_string(peer.role);
    json.stream_id = peer.stream_id;
    json.session_id = peer.session_id;
    json.remote_endpoint = peer.remote_endpoint;
    return json;
}

[[nodiscard]] media_peer_stats_json make_media_peer_stats_json(const media_peer_stats& stats)
{
    media_peer_stats_json json;
    json.peer = make_media_peer_info_json(stats.peer);

    json.inbound_rtp_packets = stats.inbound_rtp_packets;
    json.inbound_rtp_bytes = stats.inbound_rtp_bytes;
    json.inbound_rtcp_packets = stats.inbound_rtcp_packets;
    json.inbound_rtcp_bytes = stats.inbound_rtcp_bytes;

    json.routed_target_packets = stats.routed_target_packets;
    json.routed_target_bytes = stats.routed_target_bytes;

    json.rtcp_feedback_packets = stats.rtcp_feedback_packets;
    json.rtcp_generic_nack_packets = stats.rtcp_generic_nack_packets;
    json.rtcp_keyframe_request_packets = stats.rtcp_keyframe_request_packets;
    json.rtcp_transport_cc_packets = stats.rtcp_transport_cc_packets;
    json.rtcp_remb_packets = stats.rtcp_remb_packets;

    json.rtcp_nack_items = stats.rtcp_nack_items;
    json.rtcp_fir_items = stats.rtcp_fir_items;

    json.rtcp_report_packets = stats.rtcp_report_packets;
    json.rtcp_report_blocks = stats.rtcp_report_blocks;
    json.rtcp_sender_report_packets = stats.rtcp_sender_report_packets;
    json.rtcp_receiver_report_packets = stats.rtcp_receiver_report_packets;

    json.last_rtcp_fraction_lost = to_json_uint32(stats.last_rtcp_fraction_lost);
    json.last_rtcp_cumulative_lost = stats.last_rtcp_cumulative_lost;
    json.last_rtcp_jitter = stats.last_rtcp_jitter;
    json.last_rtcp_report_ssrc = stats.last_rtcp_report_ssrc;
    json.last_rtcp_report_media_ssrc = stats.last_rtcp_report_media_ssrc;
    json.last_rtcp_sr_packet_count = stats.last_rtcp_sr_packet_count;
    json.last_rtcp_sr_octet_count = stats.last_rtcp_sr_octet_count;

    json.rtcp_rtt_sample_count = stats.rtcp_rtt_sample_count;
    json.rtcp_last_rtt_ms = stats.rtcp_last_rtt_ms;
    json.rtcp_max_rtt_ms = stats.rtcp_max_rtt_ms;
    json.rtcp_avg_rtt_ms = stats.rtcp_avg_rtt_ms;
    json.rtcp_rtt_sum_ms = stats.rtcp_rtt_sum_ms;

    json.has_rtp_sequence = stats.has_rtp_sequence;
    json.expected_rtp_sequence_number = to_json_uint32(stats.expected_rtp_sequence_number);

    json.rtp_sequence_gap_events = stats.rtp_sequence_gap_events;
    json.rtp_sequence_lost_packets = stats.rtp_sequence_lost_packets;
    json.rtp_out_of_order_packets = stats.rtp_out_of_order_packets;
    json.rtp_duplicate_packets = stats.rtp_duplicate_packets;
    json.rtp_sequence_wraps = stats.rtp_sequence_wraps;

    json.last_rtp_ssrc = stats.last_rtp_ssrc;
    json.last_rtp_sequence_number = to_json_uint32(stats.last_rtp_sequence_number);
    json.last_rtp_timestamp = stats.last_rtp_timestamp;
    json.last_rtp_payload_type = to_json_uint32(stats.last_rtp_payload_type);

    json.last_rtcp_ssrc = stats.last_rtcp_ssrc;
    json.last_rtcp_packet_type = to_json_uint32(stats.last_rtcp_packet_type);
    json.last_remb_bitrate_bps = stats.last_remb_bitrate_bps;

    return json;
}
[[nodiscard]] media_track_stats_json make_media_track_stats_json(const media_track_stats& stats)
{
    media_track_stats_json json;

    json.stream_id = stats.stream_id;
    json.session_id = stats.session_id;
    json.remote_endpoint = stats.remote_endpoint;
    json.direction = stats.direction;

    json.mid = stats.mid;
    json.kind = stats.kind;

    json.rid = stats.rid;
    json.repaired_rid = stats.repaired_rid;

    json.has_transport_wide_sequence_number = stats.has_transport_wide_sequence_number;
    json.last_transport_wide_sequence_number = stats.last_transport_wide_sequence_number;

    json.has_audio_level = stats.has_audio_level;
    json.last_audio_level = stats.last_audio_level;

    json.has_voice_activity = stats.has_voice_activity;
    json.last_voice_activity = stats.last_voice_activity;

    json.ssrc = stats.ssrc;
    json.payload_type = stats.payload_type;

    json.inbound_rtp_packets = stats.inbound_rtp_packets;
    json.inbound_rtp_bytes = stats.inbound_rtp_bytes;

    json.first_rtp_sequence_number = stats.first_rtp_sequence_number;
    json.last_rtp_sequence_number = stats.last_rtp_sequence_number;
    json.last_rtp_timestamp = stats.last_rtp_timestamp;

    json.outbound_rtp_packets = stats.outbound_rtp_packets;
    json.outbound_rtp_bytes = stats.outbound_rtp_bytes;

    json.outbound_ssrc = stats.outbound_ssrc;
    json.outbound_payload_type = stats.outbound_payload_type;

    json.first_outbound_rtp_sequence_number = stats.first_outbound_rtp_sequence_number;
    json.last_outbound_rtp_sequence_number = stats.last_outbound_rtp_sequence_number;
    json.last_outbound_rtp_timestamp = stats.last_outbound_rtp_timestamp;
    return json;
}

[[nodiscard]] media_stream_stats_json make_media_stream_stats_json(const media_stream_stats& stats)
{
    media_stream_stats_json json;
    json.stream_id = stats.stream_id;

    json.active_publishers = to_json_size(stats.active_publishers);
    json.active_subscribers = to_json_size(stats.active_subscribers);

    json.inbound_rtp_packets = stats.inbound_rtp_packets;
    json.inbound_rtp_bytes = stats.inbound_rtp_bytes;
    json.inbound_rtcp_packets = stats.inbound_rtcp_packets;
    json.inbound_rtcp_bytes = stats.inbound_rtcp_bytes;

    json.publisher_rtp_packets = stats.publisher_rtp_packets;
    json.subscriber_rtcp_packets = stats.subscriber_rtcp_packets;

    json.fanout_target_packets = stats.fanout_target_packets;
    json.route_to_publisher_packets = stats.route_to_publisher_packets;

    json.rtcp_feedback_packets = stats.rtcp_feedback_packets;
    json.rtcp_generic_nack_packets = stats.rtcp_generic_nack_packets;
    json.rtcp_keyframe_request_packets = stats.rtcp_keyframe_request_packets;
    json.rtcp_transport_cc_packets = stats.rtcp_transport_cc_packets;
    json.rtcp_remb_packets = stats.rtcp_remb_packets;

    json.rtcp_nack_items = stats.rtcp_nack_items;
    json.rtcp_fir_items = stats.rtcp_fir_items;

    json.rtcp_report_packets = stats.rtcp_report_packets;
    json.rtcp_report_blocks = stats.rtcp_report_blocks;
    json.rtcp_sender_report_packets = stats.rtcp_sender_report_packets;
    json.rtcp_receiver_report_packets = stats.rtcp_receiver_report_packets;

    json.last_rtcp_fraction_lost = to_json_uint32(stats.last_rtcp_fraction_lost);
    json.last_rtcp_cumulative_lost = stats.last_rtcp_cumulative_lost;
    json.last_rtcp_jitter = stats.last_rtcp_jitter;
    json.last_rtcp_report_ssrc = stats.last_rtcp_report_ssrc;
    json.last_rtcp_report_media_ssrc = stats.last_rtcp_report_media_ssrc;
    json.last_rtcp_sr_packet_count = stats.last_rtcp_sr_packet_count;
    json.last_rtcp_sr_octet_count = stats.last_rtcp_sr_octet_count;

    json.rtcp_rtt_sample_count = stats.rtcp_rtt_sample_count;
    json.rtcp_last_rtt_ms = stats.rtcp_last_rtt_ms;
    json.rtcp_max_rtt_ms = stats.rtcp_max_rtt_ms;
    json.rtcp_avg_rtt_ms = stats.rtcp_avg_rtt_ms;
    json.rtcp_rtt_sum_ms = stats.rtcp_rtt_sum_ms;

    json.rtp_sequence_gap_events = stats.rtp_sequence_gap_events;
    json.rtp_sequence_lost_packets = stats.rtp_sequence_lost_packets;
    json.rtp_out_of_order_packets = stats.rtp_out_of_order_packets;
    json.rtp_duplicate_packets = stats.rtp_duplicate_packets;
    json.rtp_sequence_wraps = stats.rtp_sequence_wraps;

    json.last_rtp_ssrc = stats.last_rtp_ssrc;
    json.last_rtp_sequence_number = to_json_uint32(stats.last_rtp_sequence_number);
    json.last_rtp_timestamp = stats.last_rtp_timestamp;

    json.last_rtcp_ssrc = stats.last_rtcp_ssrc;
    json.last_remb_bitrate_bps = stats.last_remb_bitrate_bps;

    json.track_count = to_json_size(stats.tracks.size());

    json.tracks.reserve(stats.tracks.size());

    for (const auto& track : stats.tracks)
    {
        json.tracks.push_back(make_media_track_stats_json(track));
    }

    return json;
}

[[nodiscard]] media_router_stats_snapshot_json make_media_router_stats_snapshot_json(const media_router_stats_snapshot& snapshot)
{
    media_router_stats_snapshot_json json;
    json.peer_count = to_json_size(snapshot.peer_count);
    json.stream_count = to_json_size(snapshot.stream_count);
    json.active_publisher_count = to_json_size(snapshot.active_publisher_count);
    json.active_subscriber_count = to_json_size(snapshot.active_subscriber_count);

    json.inbound_rtp_packets = snapshot.inbound_rtp_packets;
    json.inbound_rtp_bytes = snapshot.inbound_rtp_bytes;
    json.inbound_rtcp_packets = snapshot.inbound_rtcp_packets;
    json.inbound_rtcp_bytes = snapshot.inbound_rtcp_bytes;

    json.routed_target_packets = snapshot.routed_target_packets;
    json.routed_target_bytes = snapshot.routed_target_bytes;

    json.rtcp_feedback_packets = snapshot.rtcp_feedback_packets;
    json.rtcp_report_packets = snapshot.rtcp_report_packets;
    json.rtcp_report_blocks = snapshot.rtcp_report_blocks;
    json.rtcp_nack_items = snapshot.rtcp_nack_items;
    json.rtcp_fir_items = snapshot.rtcp_fir_items;
    json.rtcp_keyframe_request_packets = snapshot.rtcp_keyframe_request_packets;
    json.rtcp_generic_nack_packets = snapshot.rtcp_generic_nack_packets;
    json.rtcp_transport_cc_packets = snapshot.rtcp_transport_cc_packets;
    json.rtcp_remb_packets = snapshot.rtcp_remb_packets;

    json.rtcp_rtt_sample_count = snapshot.rtcp_rtt_sample_count;
    json.rtcp_last_rtt_ms = snapshot.rtcp_last_rtt_ms;
    json.rtcp_max_rtt_ms = snapshot.rtcp_max_rtt_ms;
    json.rtcp_avg_rtt_ms = snapshot.rtcp_avg_rtt_ms;
    json.rtcp_rtt_sum_ms = snapshot.rtcp_rtt_sum_ms;

    json.rtp_sequence_gap_events = snapshot.rtp_sequence_gap_events;
    json.rtp_sequence_lost_packets = snapshot.rtp_sequence_lost_packets;
    json.rtp_out_of_order_packets = snapshot.rtp_out_of_order_packets;
    json.rtp_duplicate_packets = snapshot.rtp_duplicate_packets;
    json.rtp_sequence_wraps = snapshot.rtp_sequence_wraps;
    for (const auto& stream : snapshot.streams)
    {
        json.track_count += to_json_size(stream.tracks.size());
    }

    json.peers.reserve(snapshot.peers.size());
    for (const auto& peer : snapshot.peers)
    {
        json.peers.push_back(make_media_peer_stats_json(peer));
    }

    json.streams.reserve(snapshot.streams.size());
    for (const auto& stream : snapshot.streams)
    {
        json.streams.push_back(make_media_stream_stats_json(stream));
    }

    return json;
}
}    // namespace

std::string media_router_stats_snapshot_to_json(const media_router_stats_snapshot& snapshot)
{
    media_router_stats_snapshot_json json = make_media_router_stats_snapshot_json(snapshot);

    return serialize_struct(json);
}

std::string media_peer_stats_to_json(const media_peer_stats& stats)
{
    media_peer_stats_json json = make_media_peer_stats_json(stats);

    return serialize_struct(json);
}

std::string media_stream_stats_to_json(const media_stream_stats& stats)
{
    media_stream_stats_json json = make_media_stream_stats_json(stats);

    return serialize_struct(json);
}
}    // namespace webrtc
