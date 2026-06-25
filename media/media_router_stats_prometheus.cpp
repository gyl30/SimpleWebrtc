#include "media/media_router_stats_prometheus.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "media/media_router.h"

namespace webrtc
{
namespace
{
using label_list = std::vector<std::pair<std::string_view, std::string>>;

void append_escaped_label_value(std::string& output, std::string_view value)
{
    for (const char ch : value)
    {
        if (ch == '\\')
        {
            output.append(R"(\\)");
        }
        else if (ch == '"')
        {
            output.append(R"(\")");
        }
        else if (ch == '\n')
        {
            output.append(R"(\n)");
        }
        else
        {
            output.push_back(ch);
        }
    }
}

void append_metric_header(std::string& output, std::string_view name, std::string_view help, std::string_view type)
{
    output.append("# HELP ");
    output.append(name);
    output.push_back(' ');
    output.append(help);
    output.push_back('\n');

    output.append("# TYPE ");
    output.append(name);
    output.push_back(' ');
    output.append(type);
    output.push_back('\n');
}

void append_metric_value(std::string& output, uint64_t value)
{
    output.append(std::to_string(value));
    output.push_back('\n');
}

void append_metric(std::string& output, std::string_view name, uint64_t value)
{
    output.append(name);
    output.push_back(' ');
    append_metric_value(output, value);
}

void append_labeled_metric(std::string& output, std::string_view name, const label_list& labels, uint64_t value)
{
    output.append(name);
    output.push_back('{');

    bool first = true;

    for (const auto& [key, label_value] : labels)
    {
        if (!first)
        {
            output.push_back(',');
        }

        first = false;

        output.append(key);
        output.append(R"(=")");
        append_escaped_label_value(output, label_value);
        output.push_back('"');
    }

    output.append("} ");
    append_metric_value(output, value);
}

label_list make_stream_labels(const media_stream_stats& stream)
{
    label_list labels;
    labels.emplace_back("stream_id", stream.stream_id);
    return labels;
}

label_list make_peer_labels(const media_peer_stats& peer)
{
    label_list labels;
    labels.emplace_back("role", media_peer_role_to_string(peer.peer.role));
    labels.emplace_back("stream_id", peer.peer.stream_id);
    labels.emplace_back("session_id", peer.peer.session_id);
    labels.emplace_back("remote_endpoint", peer.peer.remote_endpoint);
    return labels;
}

void append_snapshot_metrics(std::string& output, const media_router_stats_snapshot& snapshot)
{
    append_metric_header(output, "simplewebrtc_media_peers", "current media peer count", "gauge");
    append_metric(output, "simplewebrtc_media_peers", static_cast<uint64_t>(snapshot.peer_count));

    append_metric_header(output, "simplewebrtc_media_streams", "current media stream count", "gauge");
    append_metric(output, "simplewebrtc_media_streams", static_cast<uint64_t>(snapshot.stream_count));

    append_metric_header(output, "simplewebrtc_media_active_publishers", "current active publisher count", "gauge");
    append_metric(output, "simplewebrtc_media_active_publishers", static_cast<uint64_t>(snapshot.active_publisher_count));

    append_metric_header(output, "simplewebrtc_media_active_subscribers", "current active subscriber count", "gauge");
    append_metric(output, "simplewebrtc_media_active_subscribers", static_cast<uint64_t>(snapshot.active_subscriber_count));

    append_metric_header(output, "simplewebrtc_media_inbound_rtp_packets_total", "total inbound rtp packets", "counter");
    append_metric(output, "simplewebrtc_media_inbound_rtp_packets_total", snapshot.inbound_rtp_packets);

    append_metric_header(output, "simplewebrtc_media_inbound_rtp_bytes_total", "total inbound rtp bytes", "counter");
    append_metric(output, "simplewebrtc_media_inbound_rtp_bytes_total", snapshot.inbound_rtp_bytes);

    append_metric_header(output, "simplewebrtc_media_inbound_rtcp_packets_total", "total inbound rtcp packets", "counter");
    append_metric(output, "simplewebrtc_media_inbound_rtcp_packets_total", snapshot.inbound_rtcp_packets);

    append_metric_header(output, "simplewebrtc_media_inbound_rtcp_bytes_total", "total inbound rtcp bytes", "counter");
    append_metric(output, "simplewebrtc_media_inbound_rtcp_bytes_total", snapshot.inbound_rtcp_bytes);

    append_metric_header(output, "simplewebrtc_media_routed_target_packets_total", "total routed target packets", "counter");
    append_metric(output, "simplewebrtc_media_routed_target_packets_total", snapshot.routed_target_packets);

    append_metric_header(output, "simplewebrtc_media_routed_target_bytes_total", "total routed target bytes", "counter");
    append_metric(output, "simplewebrtc_media_routed_target_bytes_total", snapshot.routed_target_bytes);

    append_metric_header(output, "simplewebrtc_media_rtcp_feedback_packets_total", "total rtcp feedback packets", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_feedback_packets_total", snapshot.rtcp_feedback_packets);

    append_metric_header(output, "simplewebrtc_media_rtcp_report_packets_total", "total rtcp report packets", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_report_packets_total", snapshot.rtcp_report_packets);

    append_metric_header(output, "simplewebrtc_media_rtcp_report_blocks_total", "total rtcp report blocks", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_report_blocks_total", snapshot.rtcp_report_blocks);

    append_metric_header(output, "simplewebrtc_media_rtcp_nack_items_total", "total rtcp nack items", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_nack_items_total", snapshot.rtcp_nack_items);

    append_metric_header(output, "simplewebrtc_media_rtcp_fir_items_total", "total rtcp fir items", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_fir_items_total", snapshot.rtcp_fir_items);

    append_metric_header(output, "simplewebrtc_media_rtcp_keyframe_request_packets_total", "total rtcp keyframe request packets", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_keyframe_request_packets_total", snapshot.rtcp_keyframe_request_packets);

    append_metric_header(output, "simplewebrtc_media_rtcp_generic_nack_packets_total", "total rtcp generic nack packets", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_generic_nack_packets_total", snapshot.rtcp_generic_nack_packets);

    append_metric_header(output, "simplewebrtc_media_rtcp_transport_cc_packets_total", "total rtcp transport cc packets", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_transport_cc_packets_total", snapshot.rtcp_transport_cc_packets);

    append_metric_header(output, "simplewebrtc_media_rtcp_remb_packets_total", "total rtcp remb packets", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_remb_packets_total", snapshot.rtcp_remb_packets);

    append_metric_header(output, "simplewebrtc_media_rtcp_rtt_samples_total", "total rtcp rtt samples", "counter");
    append_metric(output, "simplewebrtc_media_rtcp_rtt_samples_total", snapshot.rtcp_rtt_sample_count);

    append_metric_header(output, "simplewebrtc_media_rtcp_last_rtt_ms", "last rtcp rtt in milliseconds", "gauge");
    append_metric(output, "simplewebrtc_media_rtcp_last_rtt_ms", snapshot.rtcp_last_rtt_ms);

    append_metric_header(output, "simplewebrtc_media_rtcp_avg_rtt_ms", "average rtcp rtt in milliseconds", "gauge");
    append_metric(output, "simplewebrtc_media_rtcp_avg_rtt_ms", snapshot.rtcp_avg_rtt_ms);

    append_metric_header(output, "simplewebrtc_media_rtcp_max_rtt_ms", "maximum rtcp rtt in milliseconds", "gauge");
    append_metric(output, "simplewebrtc_media_rtcp_max_rtt_ms", snapshot.rtcp_max_rtt_ms);

    append_metric_header(output, "simplewebrtc_media_rtp_sequence_gap_events_total", "total rtp sequence gap events", "counter");
    append_metric(output, "simplewebrtc_media_rtp_sequence_gap_events_total", snapshot.rtp_sequence_gap_events);

    append_metric_header(output, "simplewebrtc_media_rtp_sequence_lost_packets_total", "total inferred rtp lost packets", "counter");
    append_metric(output, "simplewebrtc_media_rtp_sequence_lost_packets_total", snapshot.rtp_sequence_lost_packets);

    append_metric_header(output, "simplewebrtc_media_rtp_out_of_order_packets_total", "total rtp out of order packets", "counter");
    append_metric(output, "simplewebrtc_media_rtp_out_of_order_packets_total", snapshot.rtp_out_of_order_packets);

    append_metric_header(output, "simplewebrtc_media_rtp_duplicate_packets_total", "total rtp duplicate packets", "counter");
    append_metric(output, "simplewebrtc_media_rtp_duplicate_packets_total", snapshot.rtp_duplicate_packets);

    append_metric_header(output, "simplewebrtc_media_rtp_sequence_wraps_total", "total rtp sequence wraps", "counter");
    append_metric(output, "simplewebrtc_media_rtp_sequence_wraps_total", snapshot.rtp_sequence_wraps);
}

void append_stream_metrics(std::string& output, const media_router_stats_snapshot& snapshot)
{
    append_metric_header(output, "simplewebrtc_media_stream_active_publishers", "active publishers per stream", "gauge");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(
            output, "simplewebrtc_media_stream_active_publishers", make_stream_labels(stream), static_cast<uint64_t>(stream.active_publishers));
    }

    append_metric_header(output, "simplewebrtc_media_stream_active_subscribers", "active subscribers per stream", "gauge");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(
            output, "simplewebrtc_media_stream_active_subscribers", make_stream_labels(stream), static_cast<uint64_t>(stream.active_subscribers));
    }

    append_metric_header(output, "simplewebrtc_media_stream_inbound_rtp_packets_total", "total inbound rtp packets per stream", "counter");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(output, "simplewebrtc_media_stream_inbound_rtp_packets_total", make_stream_labels(stream), stream.inbound_rtp_packets);
    }

    append_metric_header(output, "simplewebrtc_media_stream_inbound_rtcp_packets_total", "total inbound rtcp packets per stream", "counter");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(
            output, "simplewebrtc_media_stream_inbound_rtcp_packets_total", make_stream_labels(stream), stream.inbound_rtcp_packets);
    }

    append_metric_header(output, "simplewebrtc_media_stream_fanout_target_packets_total", "total fanout target packets per stream", "counter");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(
            output, "simplewebrtc_media_stream_fanout_target_packets_total", make_stream_labels(stream), stream.fanout_target_packets);
    }

    append_metric_header(
        output, "simplewebrtc_media_stream_route_to_publisher_packets_total", "total route to publisher packets per stream", "counter");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(
            output, "simplewebrtc_media_stream_route_to_publisher_packets_total", make_stream_labels(stream), stream.route_to_publisher_packets);
    }

    append_metric_header(output, "simplewebrtc_media_stream_rtcp_avg_rtt_ms", "average rtcp rtt per stream in milliseconds", "gauge");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(output, "simplewebrtc_media_stream_rtcp_avg_rtt_ms", make_stream_labels(stream), stream.rtcp_avg_rtt_ms);
    }

    append_metric_header(
        output, "simplewebrtc_media_stream_rtp_sequence_lost_packets_total", "total inferred rtp lost packets per stream", "counter");

    for (const auto& stream : snapshot.streams)
    {
        append_labeled_metric(
            output, "simplewebrtc_media_stream_rtp_sequence_lost_packets_total", make_stream_labels(stream), stream.rtp_sequence_lost_packets);
    }
}

void append_peer_metrics(std::string& output, const media_router_stats_snapshot& snapshot)
{
    append_metric_header(output, "simplewebrtc_media_peer_inbound_rtp_packets_total", "total inbound rtp packets per peer", "counter");

    for (const auto& peer : snapshot.peers)
    {
        append_labeled_metric(output, "simplewebrtc_media_peer_inbound_rtp_packets_total", make_peer_labels(peer), peer.inbound_rtp_packets);
    }

    append_metric_header(output, "simplewebrtc_media_peer_inbound_rtcp_packets_total", "total inbound rtcp packets per peer", "counter");

    for (const auto& peer : snapshot.peers)
    {
        append_labeled_metric(output, "simplewebrtc_media_peer_inbound_rtcp_packets_total", make_peer_labels(peer), peer.inbound_rtcp_packets);
    }

    append_metric_header(output, "simplewebrtc_media_peer_routed_target_packets_total", "total routed target packets per peer", "counter");

    for (const auto& peer : snapshot.peers)
    {
        append_labeled_metric(output, "simplewebrtc_media_peer_routed_target_packets_total", make_peer_labels(peer), peer.routed_target_packets);
    }

    append_metric_header(output, "simplewebrtc_media_peer_rtcp_feedback_packets_total", "total rtcp feedback packets per peer", "counter");

    for (const auto& peer : snapshot.peers)
    {
        append_labeled_metric(output, "simplewebrtc_media_peer_rtcp_feedback_packets_total", make_peer_labels(peer), peer.rtcp_feedback_packets);
    }

    append_metric_header(output, "simplewebrtc_media_peer_rtcp_avg_rtt_ms", "average rtcp rtt per peer in milliseconds", "gauge");

    for (const auto& peer : snapshot.peers)
    {
        append_labeled_metric(output, "simplewebrtc_media_peer_rtcp_avg_rtt_ms", make_peer_labels(peer), peer.rtcp_avg_rtt_ms);
    }

    append_metric_header(output, "simplewebrtc_media_peer_rtp_sequence_lost_packets_total", "total inferred rtp lost packets per peer", "counter");

    for (const auto& peer : snapshot.peers)
    {
        append_labeled_metric(
            output, "simplewebrtc_media_peer_rtp_sequence_lost_packets_total", make_peer_labels(peer), peer.rtp_sequence_lost_packets);
    }
}
}    // namespace

std::string media_router_stats_snapshot_to_prometheus(const media_router_stats_snapshot& snapshot)
{
    std::string output;
    output.reserve(16384);

    append_snapshot_metrics(output, snapshot);

    append_stream_metrics(output, snapshot);

    append_peer_metrics(output, snapshot);

    return output;
}
}    // namespace webrtc
