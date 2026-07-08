#include "server/router.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <boost/beast/http.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "log/log.h"
#include "net/http.h"
#include "util/reflect.h"
#include "media/media_router.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "media/rtcp_report_service.h"
#include "server/http_error_response.h"
#include "server/trickle_ice_metrics.h"
#include "media/media_router_stats_json.h"
#include "signaling/webrtc_answer_factory.h"
#include "media/media_router_stats_prometheus.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

constexpr std::string_view k_cors_allow_methods = "GET, POST, PATCH, DELETE, OPTIONS";

constexpr std::string_view k_cors_allow_headers =
    "Content-Type, Authorization, If-Match, If-None-Match, Cache-Control, X-Requested-With, WHEP-Reconnect-Session, WHIP-Replace-Session";

constexpr std::string_view k_cors_max_age_seconds = "600";

inline constexpr std::string_view k_application_sdp = "application/sdp";

inline constexpr std::size_t k_max_sdp_offer_body_bytes = 256UL * 1024UL;

inline constexpr std::string_view k_sdp_offer_empty_error = "sdp_offer_empty";

inline constexpr std::string_view k_sdp_offer_body_too_large_error = "sdp_offer_body_too_large";

inline constexpr std::string_view k_whip_prefix = "/whip/";

inline constexpr std::string_view k_whep_prefix = "/whep/";

inline constexpr std::string_view k_whip_session_prefix = "/whip/session/";

inline constexpr std::string_view k_whep_session_prefix = "/whep/session/";

inline constexpr std::string_view k_sessions_path = "/api/sessions";

inline constexpr std::string_view k_sessions_prefix = "/api/sessions/";

inline constexpr std::string_view k_streams_prefix = "/api/streams/";

inline constexpr std::string_view k_streams_path = "/api/streams";

inline constexpr std::string_view k_keyframe_action = "keyframe";

inline constexpr std::string_view k_api_prefix = "/api/";

inline constexpr std::string_view k_health_path = "/api/health";

inline constexpr std::string_view k_version_path = "/api/version";

inline constexpr std::string_view k_bearer_prefix = "Bearer ";

inline constexpr std::string_view k_media_stats_path = "/api/stats/media";

inline constexpr std::string_view k_debug_state_path = "/api/debug/state";

inline constexpr std::string_view k_simulcast_rid_target_path = "/api/simulcast/rid-target";

inline constexpr std::string_view k_prometheus_metrics_path = "/metrics";

void append_router_prometheus_metric_header(std::string& output, std::string_view name, std::string_view help, std::string_view type)
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

void append_router_prometheus_metric_value(std::string& output, std::string_view name, uint64_t value)
{
    output.append(name);
    output.push_back(' ');
    output.append(std::to_string(value));
    output.push_back('\n');
}

std::string escape_prometheus_label_value(std::string_view value)
{
    std::string result;

    result.reserve(value.size());

    for (char ch : value)
    {
        if (ch == '\\' || ch == '"')
        {
            result.push_back('\\');
            result.push_back(ch);

            continue;
        }

        if (ch == '\n')
        {
            result.append("\\n");

            continue;
        }

        result.push_back(ch);
    }

    return result;
}

void append_prometheus_label(std::string& labels, std::string_view name, std::string_view value)
{
    if (!labels.empty())
    {
        labels.push_back(',');
    }

    labels.append(name);
    labels.append("=\"");
    labels.append(escape_prometheus_label_value(value));
    labels.push_back('"');
}

void append_router_prometheus_labeled_metric_value(std::string& output, std::string_view name, std::string_view labels, uint64_t value)
{
    output.append(name);
    output.push_back('{');
    output.append(labels);
    output.append("} ");
    output.append(std::to_string(value));
    output.push_back('\n');
}

std::string make_transport_cc_feedback_window_labels(const lifecycle_debug_transport_cc_feedback_window_entry& window)
{
    std::string labels;

    append_prometheus_label(labels, "stream_id", window.stream_id);
    append_prometheus_label(labels, "subscriber_session_id", window.subscriber_session_id);

    return labels;
}

std::string make_subscriber_downlink_bandwidth_labels(const lifecycle_debug_subscriber_downlink_bandwidth_entry& state)
{
    std::string labels;

    append_prometheus_label(labels, "stream_id", state.stream_id);
    append_prometheus_label(labels, "subscriber_session_id", state.subscriber_session_id);
    append_prometheus_label(labels, "control_state", state.control_state);

    return labels;
}
std::string make_subscriber_recovery_runtime_labels(const lifecycle_debug_subscriber_recovery_runtime_entry& entry)
{
    std::string labels;

    append_prometheus_label(labels, "stream_id", entry.stream_id);
    append_prometheus_label(labels, "subscriber_session_id", entry.subscriber_session_id);

    if (!entry.publisher_session_id.empty())
    {
        append_prometheus_label(labels, "publisher_session_id", entry.publisher_session_id);
    }

    return labels;
}

std::string make_runtime_resource_limit_labels(const lifecycle_debug_resource_limit_entry& entry)
{
    std::string labels;

    append_prometheus_label(labels, "resource", entry.name);

    return labels;
}

std::string make_lifecycle_drop_reason_labels(const lifecycle_debug_drop_reason_entry& entry)
{
    std::string labels;

    append_prometheus_label(labels, "category", entry.category);
    append_prometheus_label(labels, "reason", entry.reason);

    return labels;
}

void append_lifecycle_acceptance_summary_prometheus_metrics(std::string& output, const lifecycle_debug_snapshot& snapshot)
{
    const lifecycle_debug_runtime_acceptance_summary& summary = snapshot.runtime_acceptance_summary;

    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_debug_schema_version", "debug state schema version exposed by lifecycle snapshot", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_debug_schema_version", summary.debug_schema_version);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_release_gate_pass", "whether final runtime release gate checks pass", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_release_gate_pass", summary.release_gate_pass ? 1U : 0U);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_full_idle_clean", "whether active and delayed runtime state are clean", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_full_idle_clean", summary.full_idle_clean ? 1U : 0U);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_resource_limit_over_count", "number of runtime resource limits currently exceeded", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_resource_limit_over_count", summary.runtime_resource_limit_over_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_inconsistency_count", "number of lifecycle runtime consistency errors", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_inconsistency_count", summary.inconsistency_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_active_residual_count", "number of active runtime residual entries", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_active_residual_count", summary.active_runtime_residual_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_delayed_residual_count", "number of delayed runtime residual entries", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_delayed_residual_count", summary.delayed_runtime_residual_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_registry_sessions_current", "current registry session count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_registry_sessions_current", summary.registry_session_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_registry_publishers_current", "current registry publisher session count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_registry_publishers_current", summary.registry_publisher_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_registry_subscribers_current", "current registry subscriber session count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_registry_subscribers_current", summary.registry_subscriber_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_registry_pending_sessions_current", "current pending session count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_registry_pending_sessions_current", summary.registry_pending_session_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_runtime_endpoints_current", "current ICE endpoint count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_endpoints_current", summary.endpoint_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_runtime_candidate_pairs_current", "current ICE candidate pair count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_candidate_pairs_current", summary.candidate_pair_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_runtime_dtls_peers_current", "current DTLS peer count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_dtls_peers_current", summary.dtls_peer_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_runtime_srtp_peers_current", "current SRTP peer count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_srtp_peers_current", summary.srtp_peer_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_media_router_peers_current", "current media router peer count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_media_router_peers_current", summary.media_router_peer_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_media_router_streams_current", "current media router stream count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_media_router_streams_current", summary.media_router_stream_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_media_router_active_publishers_current", "current active publisher count in media router", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_media_router_active_publishers_current", summary.media_router_active_publisher_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_media_router_active_subscribers_current", "current active subscriber count in media router", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_media_router_active_subscribers_current", summary.media_router_active_subscriber_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_rtp_rtcp_drop_total", "total RTP/RTCP drops tracked by lifecycle debug state", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_rtp_rtcp_drop_total", summary.rtp_rtcp_drop_total);

    append_router_prometheus_metric_header(output, "simplewebrtc_rtp_rtcp_drop_reason_count", "number of RTP/RTCP drop reason buckets", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_rtp_rtcp_drop_reason_count", summary.rtp_rtcp_drop_reason_count);

    append_router_prometheus_metric_header(output, "simplewebrtc_rtp_cache_packets_current", "current RTP cache packet count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_rtp_cache_packets_current", summary.rtp_cache_packet_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_outbound_transport_cc_packets_current", "current outbound transport-cc packet identity count", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_outbound_transport_cc_packets_current", summary.outbound_transport_cc_packet_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_bandwidth_states_current", "current subscriber downlink bandwidth state count", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_subscriber_downlink_bandwidth_states_current", summary.subscriber_downlink_bandwidth_state_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_states_current", "current subscriber downlink pacing state count", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_subscriber_downlink_pacing_states_current", summary.subscriber_downlink_pacing_state_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_packets_current", "current subscriber downlink pacing queued packet count", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_packets_current", summary.subscriber_downlink_pacing_queue_packet_count);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_bytes_current", "current subscriber downlink pacing queued byte count", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_bytes_current", summary.subscriber_downlink_pacing_queue_byte_count);
}

void append_lifecycle_resource_limit_prometheus_metrics(std::string& output, const lifecycle_debug_snapshot& snapshot)
{
    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_resource_limit_current", "current runtime resource usage by resource name", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_resource_limit", "configured runtime resource limit by resource name", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_runtime_resource_limit_over", "whether runtime resource usage exceeds configured limit", "gauge");

    for (const auto& entry : snapshot.runtime_resource_limits)
    {
        const std::string labels = make_runtime_resource_limit_labels(entry);

        append_router_prometheus_labeled_metric_value(output, "simplewebrtc_runtime_resource_limit_current", labels, entry.current);
        append_router_prometheus_labeled_metric_value(output, "simplewebrtc_runtime_resource_limit", labels, entry.limit);
        append_router_prometheus_labeled_metric_value(output, "simplewebrtc_runtime_resource_limit_over", labels, entry.over_limit ? 1U : 0U);
    }
}

void append_lifecycle_drop_reason_prometheus_metrics(std::string& output, const lifecycle_debug_snapshot& snapshot)
{
    append_router_prometheus_metric_header(
        output, "simplewebrtc_rtp_rtcp_drop_reason_total", "RTP/RTCP drops grouped by lifecycle debug drop category and reason", "gauge");

    for (const auto& entry : snapshot.rtp_rtcp_drop_reasons)
    {
        const std::string labels = make_lifecycle_drop_reason_labels(entry);

        append_router_prometheus_labeled_metric_value(output, "simplewebrtc_rtp_rtcp_drop_reason_total", labels, entry.count);
    }
}

void append_lifecycle_recovery_prometheus_metrics(std::string& output, const lifecycle_debug_snapshot& snapshot)
{
    if (!output.empty() && output.back() != '\n')
    {
        output.push_back('\n');
    }

    append_lifecycle_acceptance_summary_prometheus_metrics(output, snapshot);
    append_lifecycle_resource_limit_prometheus_metrics(output, snapshot);
    append_lifecycle_drop_reason_prometheus_metrics(output, snapshot);

    append_router_prometheus_metric_header(output, "simplewebrtc_runtime_active_clean", "whether active runtime state is clean", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_active_clean", snapshot.active_runtime_clean ? 1U : 0U);
    append_router_prometheus_metric_header(output, "simplewebrtc_runtime_delayed_clean", "whether delayed runtime state is clean", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_delayed_clean", snapshot.delayed_runtime_clean ? 1U : 0U);

    append_router_prometheus_metric_header(output, "simplewebrtc_runtime_consistent", "whether runtime consistency checks pass", "gauge");
    append_router_prometheus_metric_value(output, "simplewebrtc_runtime_consistent", snapshot.consistent ? 1U : 0U);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_transport_cc_feedback_total", "total subscriber transport cc feedback packets received", "counter");
    append_router_prometheus_metric_value(output, "simplewebrtc_transport_cc_feedback_total", snapshot.transport_cc_feedback_total);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_transport_cc_feedback_packet_status_total", "total subscriber transport cc packet status entries received", "counter");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_transport_cc_feedback_packet_status_total", snapshot.transport_cc_feedback_packet_status_total);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_transport_cc_feedback_lookup_hit_total", "total transport cc feedback lookup hits", "counter");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_transport_cc_feedback_lookup_hit_total", snapshot.transport_cc_feedback_lookup_hit_total);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_transport_cc_feedback_lookup_miss_total", "total transport cc feedback lookup misses", "counter");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_transport_cc_feedback_lookup_miss_total", snapshot.transport_cc_feedback_lookup_miss_total);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_transport_cc_feedback_received_packet_total", "total received packet statuses in transport cc feedback", "counter");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_transport_cc_feedback_received_packet_total", snapshot.transport_cc_feedback_received_packet_total);

    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_transport_cc_feedback_not_received_packet_total",
                                           "total not received packet statuses in transport cc feedback",
                                           "counter");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_transport_cc_feedback_not_received_packet_total", snapshot.transport_cc_feedback_not_received_packet_total);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_transport_cc_feedback_small_delta_total", "total small deltas in transport cc feedback", "counter");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_transport_cc_feedback_small_delta_total", snapshot.transport_cc_feedback_small_delta_total);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_transport_cc_feedback_large_delta_total", "total large or negative deltas in transport cc feedback", "counter");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_transport_cc_feedback_large_delta_total", snapshot.transport_cc_feedback_large_delta_total);

    append_router_prometheus_metric_header(
        output, "simplewebrtc_outbound_transport_cc_sequences_current", "current outbound transport cc sequence states", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_outbound_transport_cc_sequences_current", static_cast<uint64_t>(snapshot.outbound_transport_cc_sequence_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_outbound_transport_cc_packets_current", "current outbound transport cc packet identity entries", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_outbound_transport_cc_packets_current", static_cast<uint64_t>(snapshot.outbound_transport_cc_packet_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_outbound_transport_cc_feedback_windows_current", "current outbound transport cc feedback windows", "gauge");
    append_router_prometheus_metric_value(output,
                                          "simplewebrtc_outbound_transport_cc_feedback_windows_current",
                                          static_cast<uint64_t>(snapshot.outbound_transport_cc_feedback_window_count));

    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_observations_current",
                                           "current outbound transport cc feedback window observations",
                                           "gauge");
    append_router_prometheus_metric_value(output,
                                          "simplewebrtc_outbound_transport_cc_feedback_window_observations_current",
                                          static_cast<uint64_t>(snapshot.outbound_transport_cc_feedback_window_observation_count));

    append_router_prometheus_metric_header(output, "simplewebrtc_rtx_sequence_allocators_current", "current rtx sequence allocators", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_rtx_sequence_allocators_current", static_cast<uint64_t>(snapshot.rtx_sequence_allocator_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_rtx_retransmission_index_entries_current", "current rtx retransmission index entries", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_rtx_retransmission_index_entries_current", static_cast<uint64_t>(snapshot.rtx_retransmission_index_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_nack_retransmit_throttle_entries_current", "current nack retransmit throttle entries", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_nack_retransmit_throttle_entries_current", static_cast<uint64_t>(snapshot.nack_retransmit_throttle_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_bandwidth_states_current", "current subscriber downlink bandwidth states", "gauge");
    append_router_prometheus_metric_value(output,
                                          "simplewebrtc_subscriber_downlink_bandwidth_states_current",
                                          static_cast<uint64_t>(snapshot.subscriber_downlink_bandwidth_state_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_states_current", "current subscriber downlink pacing states", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_subscriber_downlink_pacing_states_current", static_cast<uint64_t>(snapshot.subscriber_downlink_pacing_state_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_packets_current", "current subscriber downlink pacing queued packets", "gauge");
    append_router_prometheus_metric_value(output,
                                          "simplewebrtc_subscriber_downlink_pacing_queue_packets_current",
                                          static_cast<uint64_t>(snapshot.subscriber_downlink_pacing_queue_packet_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_bytes_current", "current subscriber downlink pacing queued bytes", "gauge");
    append_router_prometheus_metric_value(output,
                                          "simplewebrtc_subscriber_downlink_pacing_queue_bytes_current",
                                          static_cast<uint64_t>(snapshot.subscriber_downlink_pacing_queue_byte_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_runtimes_current", "current subscriber recovery runtime entries", "gauge");
    append_router_prometheus_metric_value(
        output, "simplewebrtc_subscriber_recovery_runtimes_current", static_cast<uint64_t>(snapshot.subscriber_recovery_runtime_count));

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_target_bitrate_bps", "observe-only subscriber downlink target bitrate in bps", "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_subscriber_downlink_lookup_hit_rate_ppm",
                                           "subscriber downlink transport cc lookup hit rate in parts per million",
                                           "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_loss_rate_ppm", "subscriber downlink loss rate in parts per million", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_window_observations", "subscriber downlink transport cc window observation count", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_transition_count", "subscriber downlink control state transition count", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_bitrate_gate_budget_bytes", "subscriber downlink bitrate gate current budget in bytes", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_bitrate_gate_allowed_packets", "subscriber downlink bitrate gate allowed packets", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_bitrate_gate_dropped_packets", "subscriber downlink bitrate gate dropped packets", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_bitrate_gate_allowed_bytes", "subscriber downlink bitrate gate allowed bytes", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_bitrate_gate_dropped_bytes", "subscriber downlink bitrate gate dropped bytes", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_packets", "subscriber downlink pacing queued packets", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_queue_bytes", "subscriber downlink pacing queued bytes", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_budget_bytes", "subscriber downlink pacing current budget bytes", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_enqueued_packets", "subscriber downlink pacing enqueued packets", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_sent_packets", "subscriber downlink pacing sent packets", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_dropped_packets", "subscriber downlink pacing dropped packets", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_enqueued_bytes", "subscriber downlink pacing enqueued bytes", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_sent_bytes", "subscriber downlink pacing sent bytes", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_downlink_pacing_dropped_bytes", "subscriber downlink pacing dropped bytes", "gauge");

    for (const auto& downlink_state : snapshot.subscriber_downlink_bandwidth_states)
    {
        const std::string labels = make_subscriber_downlink_bandwidth_labels(downlink_state);

        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_target_bitrate_bps", labels, downlink_state.target_bitrate_bps);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_lookup_hit_rate_ppm", labels, downlink_state.lookup_hit_rate_ppm);
        append_router_prometheus_labeled_metric_value(output, "simplewebrtc_subscriber_downlink_loss_rate_ppm", labels, downlink_state.loss_rate_ppm);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_window_observations", labels, downlink_state.window_observation_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_transition_count", labels, downlink_state.transition_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_bitrate_gate_budget_bytes", labels, downlink_state.bitrate_gate_budget_bytes);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_bitrate_gate_allowed_packets", labels, downlink_state.bitrate_gate_allowed_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_bitrate_gate_dropped_packets", labels, downlink_state.bitrate_gate_dropped_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_bitrate_gate_allowed_bytes", labels, downlink_state.bitrate_gate_allowed_byte_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_bitrate_gate_dropped_bytes", labels, downlink_state.bitrate_gate_dropped_byte_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_queue_packets", labels, downlink_state.pacing_queue_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_queue_bytes", labels, downlink_state.pacing_queue_byte_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_budget_bytes", labels, downlink_state.pacing_budget_bytes);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_enqueued_packets", labels, downlink_state.pacing_enqueued_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_sent_packets", labels, downlink_state.pacing_sent_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_dropped_packets", labels, downlink_state.pacing_dropped_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_enqueued_bytes", labels, downlink_state.pacing_enqueued_byte_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_sent_bytes", labels, downlink_state.pacing_sent_byte_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_downlink_pacing_dropped_bytes", labels, downlink_state.pacing_dropped_byte_count);
    }

    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_forward_bindings", "subscriber recovery forward binding count", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_rtx_forward_bindings", "subscriber recovery rtx forward binding count", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_transport_cc_windows", "subscriber recovery transport cc feedback window count", "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_subscriber_recovery_transport_cc_lookup_hit_rate_ppm",
                                           "subscriber recovery transport cc lookup hit rate in parts per million",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_subscriber_recovery_transport_cc_loss_rate_ppm",
                                           "subscriber recovery transport cc loss rate in parts per million",
                                           "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_downlink_target_bitrate_bps", "subscriber recovery downlink target bitrate bps", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_pacing_queue_packets", "subscriber recovery pacing queued packet count", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_pacing_sent_packets", "subscriber recovery pacing sent packet count", "gauge");
    append_router_prometheus_metric_header(
        output, "simplewebrtc_subscriber_recovery_bitrate_gate_dropped_packets", "subscriber recovery bitrate gate dropped packet count", "gauge");

    for (const auto& recovery_runtime : snapshot.subscriber_recovery_runtimes)
    {
        const std::string labels = make_subscriber_recovery_runtime_labels(recovery_runtime);

        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_forward_bindings", labels, recovery_runtime.forward_binding_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_rtx_forward_bindings", labels, recovery_runtime.rtx_forward_binding_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_transport_cc_windows", labels, recovery_runtime.transport_cc_feedback_window_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_transport_cc_lookup_hit_rate_ppm", labels, recovery_runtime.transport_cc_lookup_hit_rate_ppm);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_transport_cc_loss_rate_ppm", labels, recovery_runtime.transport_cc_loss_rate_ppm);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_downlink_target_bitrate_bps", labels, recovery_runtime.downlink_target_bitrate_bps);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_pacing_queue_packets", labels, recovery_runtime.pacing_queue_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_pacing_sent_packets", labels, recovery_runtime.pacing_sent_packet_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_subscriber_recovery_bitrate_gate_dropped_packets", labels, recovery_runtime.bitrate_gate_dropped_packet_count);
    }

    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_feedback_count",
                                           "transport cc feedback packets tracked by current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_packet_status_count",
                                           "transport cc packet statuses tracked by current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_lookup_hit_count",
                                           "transport cc lookup hits tracked by current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_lookup_miss_count",
                                           "transport cc lookup misses tracked by current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_lookup_hit_rate_ppm",
                                           "transport cc lookup hit rate in parts per million for current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_received_count",
                                           "received packet statuses tracked by current transport cc feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_lost_count",
                                           "lost packet statuses tracked by current transport cc feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_loss_rate_ppm",
                                           "transport cc loss rate in parts per million for current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_small_delta_count",
                                           "small deltas tracked by current transport cc feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_large_delta_count",
                                           "large or negative deltas tracked by current transport cc feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_avg_delta_microseconds",
                                           "average transport cc delta in microseconds for current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_min_delta_microseconds",
                                           "minimum transport cc delta in microseconds for current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_max_delta_microseconds",
                                           "maximum transport cc delta in microseconds for current feedback window",
                                           "gauge");
    append_router_prometheus_metric_header(output,
                                           "simplewebrtc_outbound_transport_cc_feedback_window_observations",
                                           "observations tracked by current transport cc feedback window",
                                           "gauge");

    for (const auto& window : snapshot.outbound_transport_cc_feedback_windows)
    {
        const std::string labels = make_transport_cc_feedback_window_labels(window);

        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_feedback_count", labels, window.feedback_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_packet_status_count", labels, window.feedback_packet_status_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_lookup_hit_count", labels, window.lookup_hit_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_lookup_miss_count", labels, window.lookup_miss_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_lookup_hit_rate_ppm", labels, window.lookup_hit_rate_ppm);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_received_count", labels, window.received_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_lost_count", labels, window.lost_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_loss_rate_ppm", labels, window.loss_rate_ppm);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_small_delta_count", labels, window.small_delta_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_large_delta_count", labels, window.large_delta_count);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_avg_delta_microseconds", labels, window.avg_delta_microseconds);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_min_delta_microseconds", labels, window.min_delta_microseconds);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_max_delta_microseconds", labels, window.max_delta_microseconds);
        append_router_prometheus_labeled_metric_value(
            output, "simplewebrtc_outbound_transport_cc_feedback_window_observations", labels, window.observation_count);
    }
}

std::string_view remove_query(std::string_view target)
{
    const std::size_t query_position = target.find('?');

    if (query_position == std::string_view::npos)
    {
        return target;
    }

    return target.substr(0, query_position);
}

std::string_view query_part(std::string_view target)
{
    const std::size_t query_position = target.find('?');

    if (query_position == std::string_view::npos)
    {
        return {};
    }

    return target.substr(query_position + 1);
}

std::optional<std::string> query_parameter_value(std::string_view target, std::string_view name)
{
    std::string_view query = query_part(target);

    while (!query.empty())
    {
        const std::size_t separator_position = query.find('&');

        const std::string_view item = separator_position == std::string_view::npos ? query : query.substr(0, separator_position);

        const std::size_t equal_position = item.find('=');

        const std::string_view key = equal_position == std::string_view::npos ? item : item.substr(0, equal_position);

        const std::string_view value = equal_position == std::string_view::npos ? std::string_view{} : item.substr(equal_position + 1);

        if (key == name)
        {
            return std::string(value);
        }

        if (separator_position == std::string_view::npos)
        {
            break;
        }

        query = query.substr(separator_position + 1);
    }

    return std::nullopt;
}

struct debug_state_filter_options
{
    std::string section;
    std::string stream_id;
    std::string session_id;
};

debug_state_filter_options make_debug_state_filter_options(std::string_view target)
{
    debug_state_filter_options options;

    if (const auto value = query_parameter_value(target, "section"); value.has_value())
    {
        options.section = *value;
    }

    if (const auto value = query_parameter_value(target, "stream_id"); value.has_value())
    {
        options.stream_id = *value;
    }

    if (const auto value = query_parameter_value(target, "session_id"); value.has_value())
    {
        options.session_id = *value;
    }

    return options;
}

bool debug_filter_stream_matches(std::string_view value, const debug_state_filter_options& options)
{
    return options.stream_id.empty() || value == options.stream_id;
}

bool debug_filter_session_matches(std::string_view value, const debug_state_filter_options& options)
{
    return options.session_id.empty() || value == options.session_id;
}

bool debug_filter_any_session_matches(std::initializer_list<std::string_view> values, const debug_state_filter_options& options)
{
    if (options.session_id.empty())
    {
        return true;
    }

    for (std::string_view value : values)
    {
        if (value == options.session_id)
        {
            return true;
        }
    }

    return false;
}

bool debug_filter_stream_and_session_matches(std::string_view stream_id,
                                             std::initializer_list<std::string_view> session_ids,
                                             const debug_state_filter_options& options)
{
    return debug_filter_stream_matches(stream_id, options) && debug_filter_any_session_matches(session_ids, options);
}
void filter_lifecycle_debug_snapshot_by_stream_session(lifecycle_debug_snapshot& snapshot, const debug_state_filter_options& options)
{
    if (options.stream_id.empty() && options.session_id.empty())
    {
        return;
    }

    std::erase_if(snapshot.sessions,
                  [&options](const lifecycle_debug_session_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.removed_session_tombstones,
                  [&options](const lifecycle_debug_removed_session_tombstone_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.endpoints,
                  [&options](const lifecycle_debug_endpoint_entry& entry)
                  { return !options.stream_id.empty() || !debug_filter_session_matches(entry.session_id, options); });

    std::erase_if(snapshot.candidate_pairs,
                  [&options](const lifecycle_debug_candidate_pair_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.track_bindings,
                  [&options](const lifecycle_debug_track_binding_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.identity_track_bindings,
                  [&options](const lifecycle_debug_identity_track_binding_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.identity_rid_layers,
                  [&options](const lifecycle_debug_identity_rid_layer_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(
        snapshot.identity_forward_bindings,
        [&options](const lifecycle_debug_identity_forward_binding_entry& entry)
        { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.publisher_session_id, entry.subscriber_session_id}, options); });

    std::erase_if(snapshot.subscriber_forward_groups,
                  [&options](const lifecycle_debug_subscriber_forward_group_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.subscriber_session_id}, options); });

    std::erase_if(
        snapshot.selected_rid_layers,
        [&options](const lifecycle_debug_selected_rid_layer_entry& entry)
        { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.publisher_session_id, entry.subscriber_session_id}, options); });

    std::erase_if(snapshot.rtcp_report_sources,
                  [&options](const lifecycle_debug_rtcp_report_source_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.twcc_feedback_sources,
                  [&options](const lifecycle_debug_twcc_feedback_source_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.subscriber_rtcp_groups,
                  [&options](const lifecycle_debug_subscriber_rtcp_group_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.subscriber_session_id}, options); });

    std::erase_if(snapshot.subscriber_runtime_residuals,
                  [&options](const lifecycle_debug_subscriber_runtime_residual_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.subscriber_session_id}, options); });

    std::erase_if(snapshot.retired_ice_credentials,
                  [&options](const lifecycle_debug_retired_ice_credential_entry& entry)
                  { return !debug_filter_stream_and_session_matches(entry.stream_id, {entry.session_id}, options); });

    std::erase_if(snapshot.retired_endpoints,
                  [&options](const lifecycle_debug_retired_endpoint_entry& entry)
                  { return !options.stream_id.empty() || !debug_filter_session_matches(entry.session_id, options); });
}
bool debug_state_section_is_supported(std::string_view section) { return section.empty() || section == "all" || section == "simulcast"; }

void filter_lifecycle_debug_snapshot_by_section(lifecycle_debug_snapshot& snapshot, std::string_view section)
{
    if (section.empty() || section == "all")
    {
        return;
    }

    if (section != "simulcast")
    {
        return;
    }

    snapshot.sessions.clear();
    snapshot.removed_session_tombstones.clear();
    snapshot.endpoints.clear();
    snapshot.candidate_pairs.clear();
    snapshot.track_bindings.clear();
    snapshot.identity_track_bindings.clear();
    snapshot.identity_rid_layers.clear();
    snapshot.identity_forward_bindings.clear();
    snapshot.subscriber_forward_groups.clear();
    snapshot.rtcp_report_sources.clear();
    snapshot.twcc_feedback_sources.clear();
    snapshot.rtp_cache_streams.clear();
    snapshot.subscriber_rtcp_groups.clear();
    snapshot.subscriber_runtime_residuals.clear();
    snapshot.retired_endpoints.clear();
    snapshot.retired_ice_credentials.clear();
}
bool match_single_value_path(std::string_view path, std::string_view prefix, std::string_view& value)
{
    if (!boost::algorithm::starts_with(path, prefix))
    {
        return false;
    }

    value = path.substr(prefix.size());

    if (value.empty())
    {
        return false;
    }

    return value.find('/') == std::string_view::npos;
}

std::string json_error_body(std::string_view message)
{
    std::string body;

    body.reserve(message.size() + 16);

    body.append(R"({"error":")");
    body.append(message);
    body.append(R"("})");

    return body;
}

http_response_ptr validate_sdp_offer_body(http_request_t& request, std::string_view protocol_name, std::string_view stream_id)
{
    const std::string& body = request.req.body();

    if (body.empty())
    {
        WEBRTC_LOG_WARN("{} SDP offer body empty stream={}", protocol_name, stream_id);

        return make_json_http_error_response(request, 400, k_sdp_offer_empty_error, "sdp offer body is empty");
    }

    if (body.size() > k_max_sdp_offer_body_bytes)
    {
        WEBRTC_LOG_WARN(
            "{} SDP offer body too large stream={} body_size={} limit={}", protocol_name, stream_id, body.size(), k_max_sdp_offer_body_bytes);

        return make_json_http_error_response(request, 413, k_sdp_offer_body_too_large_error, "sdp offer body is too large");
    }

    return nullptr;
}
struct simulcast_rid_target_response_body
{
    bool ok = true;

    std::string stream_id;
    std::string publisher_session_id;
    std::string subscriber_session_id;
    std::string mid;
    std::string kind;
    std::string target_rid;
    std::string policy;
    std::string reason;

    bool changed = false;
    bool cleared = false;
    bool selected_state_found = false;

    uint64_t updated_at_milliseconds = 0;
    uint64_t applied_count = 0;
};

REFLECT_STRUCT(
    simulcast_rid_target_response_body,
    (ok)(stream_id)(publisher_session_id)(subscriber_session_id)(mid)(kind)(target_rid)(policy)(reason)(changed)(cleared)(selected_state_found)(updated_at_milliseconds)(applied_count));

std::string make_simulcast_rid_target_response_body(const simulcast_rid_target_result& result)
{
    simulcast_rid_target_response_body body;

    body.stream_id = result.stream_id;
    body.publisher_session_id = result.publisher_session_id;
    body.subscriber_session_id = result.subscriber_session_id;
    body.mid = result.mid;
    body.kind = result.kind;
    body.target_rid = result.target_rid;
    body.policy = result.policy;
    body.reason = result.reason;
    body.changed = result.changed;
    body.cleared = result.cleared;
    body.selected_state_found = result.selected_state_found;
    body.updated_at_milliseconds = result.updated_at_milliseconds;
    body.applied_count = result.applied_count;

    return serialize_struct(body);
}

std::string_view beast_string_view_to_std_string_view(boost::beast::string_view value) { return {value.data(), value.size()}; }

std::optional<simulcast_rid_target_request> make_simulcast_rid_target_request_from_query(http_request_t& request, bool clear)
{
    const std::string_view target = beast_string_view_to_std_string_view(request.req.target());

    const auto stream_id = query_parameter_value(target, "stream_id");
    const auto publisher_session_id = query_parameter_value(target, "publisher_session_id");
    const auto subscriber_session_id = query_parameter_value(target, "subscriber_session_id");
    const auto mid = query_parameter_value(target, "mid");
    const auto kind = query_parameter_value(target, "kind");

    if (!stream_id.has_value() || !publisher_session_id.has_value() || !subscriber_session_id.has_value() || !mid.has_value() || !kind.has_value())
    {
        return std::nullopt;
    }

    simulcast_rid_target_request target_request;

    target_request.stream_id = *stream_id;
    target_request.publisher_session_id = *publisher_session_id;
    target_request.subscriber_session_id = *subscriber_session_id;
    target_request.mid = *mid;
    target_request.kind = *kind;
    target_request.clear = clear;

    if (const auto rid = query_parameter_value(target, "rid"); rid.has_value())
    {
        target_request.target_rid = *rid;
    }

    if (const auto reason = query_parameter_value(target, "reason"); reason.has_value())
    {
        target_request.reason = *reason;
    }

    return target_request;
}
bool constant_time_equals(std::string_view left, std::string_view right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    unsigned char difference = 0;

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        difference = static_cast<unsigned char>(
            difference | static_cast<unsigned char>(static_cast<unsigned char>(left[index]) ^ static_cast<unsigned char>(right[index])));
    }

    return difference == 0;
}

std::optional<std::string_view> bearer_token_from_authorization(std::string_view authorization)
{
    if (authorization.size() <= k_bearer_prefix.size())
    {
        return std::nullopt;
    }

    if (!authorization.starts_with(k_bearer_prefix))
    {
        return std::nullopt;
    }

    std::string_view token = authorization.substr(k_bearer_prefix.size());

    if (token.empty())
    {
        return std::nullopt;
    }

    return token;
}

bool stream_has_publisher_snapshot(std::string_view stream_id, const std::vector<stream_session_lifecycle_snapshot>& snapshots)
{
    return std::ranges::any_of(snapshots,
                               [stream_id](const stream_session_lifecycle_snapshot& snapshot)
                               { return snapshot.kind == stream_session_kind::publisher && std::string_view(snapshot.stream_id) == stream_id; });
}

std::optional<stream_session_lifecycle_snapshot> find_session_snapshot(std::string_view session_id,
                                                                       const std::vector<stream_session_lifecycle_snapshot>& snapshots)
{
    if (session_id.empty())
    {
        return std::nullopt;
    }

    for (const auto& snapshot : snapshots)
    {
        if (std::string_view(snapshot.session_id) == session_id)
        {
            return snapshot;
        }
    }

    return std::nullopt;
}

std::string beast_string_view_to_string(boost::beast::string_view value) { return std::string(value.data(), value.size()); }

void trim_trailing_space(std::string& value)
{
    while (!value.empty())
    {
        const auto current = static_cast<unsigned char>(value.back());

        if (std::isspace(current) == 0)
        {
            return;
        }

        value.pop_back();
    }
}

bool rtcp_report_runtime_snapshot_has_data(const rtcp_report_service_runtime_snapshot& snapshot)
{
    return snapshot.configured_sources != 0 || snapshot.stats_sources != 0 || snapshot.inbound_rtcp_observe_attempts != 0 ||
           snapshot.inbound_rtcp_observe_failed != 0 || snapshot.inbound_sender_report_sources != 0 || snapshot.remember_source_attempts != 0 ||
           snapshot.remember_source_success != 0 || snapshot.remember_source_failed != 0 || snapshot.send_attempts != 0 ||
           snapshot.send_success != 0 || snapshot.endpoint_not_found != 0 || snapshot.protect_failed != 0 || snapshot.protect_ignored != 0 ||
           snapshot.forgot_sources != 0 || snapshot.forgot_sessions != 0 || snapshot.forgot_streams != 0 || snapshot.forgot_peers != 0 ||
           snapshot.stale_sources_expired != 0 || snapshot.last_cleanup_time_milliseconds != 0 || snapshot.last_cleanup_expired_sources != 0 ||
           snapshot.generated_report_rounds != 0 || snapshot.generated_packets != 0 || snapshot.skipped_packets != 0 ||
           snapshot.failed_packets != 0 || snapshot.throttled_sources != 0 || snapshot.observed_sender_reports != 0 ||
           snapshot.last_generation_time_milliseconds != 0 || snapshot.last_generation_packets != 0 || snapshot.last_generation_skipped != 0 ||
           snapshot.last_generation_failed != 0 || snapshot.last_generation_due_sources != 0 || snapshot.last_generation_throttled_sources != 0;
}
std::string append_rtcp_report_service_json(std::string media_json, const rtcp_report_service_runtime_snapshot& rtcp_snapshot)
{
    trim_trailing_space(media_json);

    if (media_json.empty())
    {
        media_json = "{}";
    }

    if (media_json.back() != '}')
    {
        return media_json;
    }

    media_json.pop_back();

    if (media_json.size() > 1)
    {
        media_json.push_back(',');
    }

    media_json.append(R"("rtcp_report_service":)");

    media_json.append(rtcp_report_service_runtime_snapshot_to_json(rtcp_snapshot));

    media_json.push_back('}');

    return media_json;
}

void append_rtcp_report_service_prometheus(std::string& output, const rtcp_report_service_runtime_snapshot& rtcp_snapshot)
{
    if (!output.empty() && output.back() != '\n')
    {
        output.push_back('\n');
    }

    output.append(rtcp_report_service_runtime_snapshot_to_prometheus(rtcp_snapshot));
}
std::string append_trickle_ice_metrics_json(std::string media_json, const trickle_ice_metrics_snapshot& trickle_snapshot)
{
    trim_trailing_space(media_json);

    if (media_json.empty())
    {
        media_json = "{}";
    }

    if (media_json.back() != '}')
    {
        return media_json;
    }

    media_json.pop_back();

    if (media_json.size() > 1)
    {
        media_json.push_back(',');
    }

    media_json.append(R"("trickle_ice":)");

    media_json.append(trickle_ice_metrics_snapshot_to_json(trickle_snapshot));

    media_json.push_back('}');

    return media_json;
}

void append_trickle_ice_metrics_prometheus(std::string& output, const trickle_ice_metrics_snapshot& trickle_snapshot)
{
    if (!output.empty() && output.back() != '\n')
    {
        output.push_back('\n');
    }

    output.append(trickle_ice_metrics_snapshot_to_prometheus(trickle_snapshot));
}
bool match_single_value_action_path(std::string_view path, std::string_view prefix, std::string_view action, std::string_view& value)
{
    if (!boost::algorithm::starts_with(path, prefix))
    {
        return false;
    }

    const std::string_view rest = path.substr(prefix.size());

    const std::size_t separator = rest.find('/');

    if (separator == std::string_view::npos)
    {
        return false;
    }

    value = rest.substr(0, separator);

    if (value.empty())
    {
        return false;
    }

    const std::string_view current_action = rest.substr(separator + 1);

    return current_action == action;
}
}    // namespace

router::router(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory)
    : router(std::move(registry), std::move(answer_factory), nullptr)
{
}

router::router(std::shared_ptr<stream_registry> registry,
               std::shared_ptr<webrtc_answer_factory> answer_factory,
               std::shared_ptr<media_router> media_router)
    : registry_(std::move(registry)),
      answer_factory_(std::move(answer_factory)),
      media_router_(std::move(media_router)),
      whip_(registry_, answer_factory_),
      whep_(registry_, answer_factory_)
{
}

http_response_ptr router::handle(http_request_t& request)
{
    const auto method = request.req.method();

    const std::string_view path = request_path(request);

    WEBRTC_LOG_DEBUG("http route method={} path={}", beast_string_view_to_string(request.req.method_string()), path);

    if (method == http::verb::options)
    {
        return handle_options(request);
    }

    if (admin_auth_required(path) && !is_admin_authorized(request))
    {
        return admin_unauthorized(request);
    }

    if (method == http::verb::get && path == k_health_path)
    {
        return handle_health(request);
    }

    if (method == http::verb::get && path == k_version_path)
    {
        return handle_version(request);
    }
    if (path == k_sessions_path)
    {
        return handle_sessions(request);
    }

    std::string_view api_session_id;

    if (match_single_value_path(path, k_sessions_prefix, api_session_id))
    {
        return handle_session(request, api_session_id);
    }

    if (path == k_streams_path)
    {
        return handle_streams(request);
    }
    std::string_view api_keyframe_stream_id;

    if (match_single_value_action_path(path, k_streams_prefix, k_keyframe_action, api_keyframe_stream_id))
    {
        return handle_stream_keyframe(request, api_keyframe_stream_id);
    }

    std::string_view api_stream_id;

    if (match_single_value_path(path, k_streams_prefix, api_stream_id))
    {
        return handle_stream(request, api_stream_id);
    }

    if (path == k_media_stats_path)
    {
        return handle_media_stats(request);
    }

    if (path == k_debug_state_path)
    {
        return handle_debug_state(request);
    }
    if (path == k_simulcast_rid_target_path)
    {
        return handle_simulcast_rid_target(request);
    }
    if (path == k_prometheus_metrics_path)
    {
        return handle_prometheus_metrics(request);
    }

    std::string_view session_id;

    if (match_single_value_path(path, k_whip_session_prefix, session_id))
    {
        return handle_whip_session(request, session_id);
    }

    if (match_single_value_path(path, k_whep_session_prefix, session_id))
    {
        return handle_whep_session(request, session_id);
    }

    std::string_view stream_id;

    if (match_single_value_path(path, k_whip_prefix, stream_id))
    {
        return handle_whip_create(request, stream_id);
    }

    if (match_single_value_path(path, k_whep_prefix, stream_id))
    {
        return handle_whep_create(request, stream_id);
    }

    return not_found(request);
}

void router::set_media_router(std::shared_ptr<media_router> media_router) { media_router_ = std::move(media_router); }

void router::set_keyframe_request_handler(keyframe_request_handler handler) { keyframe_request_handler_ = std::move(handler); }
void router::set_simulcast_rid_target_handler(simulcast_rid_target_handler handler) { simulcast_rid_target_handler_ = std::move(handler); }

void router::set_rtcp_report_runtime_snapshot_provider(rtcp_report_runtime_snapshot_provider provider)
{
    rtcp_report_runtime_snapshot_provider_ = std::move(provider);

    WEBRTC_LOG_INFO("rtcp report runtime snapshot provider {}", rtcp_report_runtime_snapshot_provider_ ? "mounted" : "cleared");
}
void router::set_lifecycle_debug_snapshot_provider(lifecycle_debug_snapshot_provider provider)
{
    lifecycle_debug_snapshot_provider_ = std::move(provider);
}

void router::set_admin_token(std::string token) { admin_token_ = std::move(token); }

bool router::admin_auth_required(std::string_view path) const
{
    if (admin_token_.empty())
    {
        return false;
    }

    if (!path.starts_with(k_api_prefix))
    {
        return false;
    }

    if (path == k_health_path)
    {
        return false;
    }

    if (path == k_version_path)
    {
        return false;
    }

    return true;
}

bool router::is_admin_authorized(const http_request_t& request) const
{
    if (admin_token_.empty())
    {
        return true;
    }

    const auto authorization_value = request.req[http::field::authorization];

    const std::string_view authorization(authorization_value.data(), authorization_value.size());

    const std::optional<std::string_view> token = bearer_token_from_authorization(authorization);

    if (!token.has_value())
    {
        return false;
    }

    return constant_time_equals(*token, admin_token_);
}

http_response_ptr router::admin_unauthorized(http_request_t& request)
{
    auto response = json_response(request, 401, json_error_body("unauthorized"));

    response->set(http::field::www_authenticate, "Bearer realm=\"simplewebrtc\"");

    return response;
}

http_response_ptr router::handle_options(http_request_t& request)
{
    auto response = text_response(request, 204, "");

    response->set(http::field::access_control_allow_methods, std::string(k_cors_allow_methods));

    response->set(http::field::access_control_allow_headers, std::string(k_cors_allow_headers));

    response->set(http::field::access_control_expose_headers, std::string(k_trickle_ice_expose_headers_value));

    response->set(http::field::access_control_max_age, std::string(k_cors_max_age_seconds));

    response->set(std::string(k_http_cors_private_network_header), "true");

    set_trickle_ice_patch_headers(response);

    return response;
}

http_response_ptr router::handle_health(http_request_t& request) { return json_response(request, 200, R"({"status":"ok"})"); }

http_response_ptr router::handle_version(http_request_t& request)
{
    return json_response(request, 200, R"({"name":"SimpleWebrtc","version":"0.1"})");
}

http_response_ptr router::handle_sessions(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    const std::string body = make_session_lifecycle_response_body(snapshots);

    return json_response(request, 200, body);
}
http_response_ptr router::handle_session(http_request_t& request, std::string_view session_id)
{
    if (!is_valid_resource_id(session_id))
    {
        return bad_request(request, "invalid session id");
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const auto method = request.req.method();

    if (method != http::verb::get && method != http::verb::delete_)
    {
        return method_not_allowed(request);
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    const std::optional<stream_session_lifecycle_snapshot> snapshot = find_session_snapshot(session_id, snapshots);

    if (!snapshot.has_value())
    {
        return json_response(request, 404, json_error_body("session not found"));
    }

    if (method == http::verb::get)
    {
        return json_response(request, 200, make_session_lifecycle_entry_response_body(*snapshot));
    }

    if (snapshot->kind == stream_session_kind::publisher)
    {
        auto result = registry_->remove_publisher_session(snapshot->session_id);

        if (!result)
        {
            if (result.error() == stream_registry_error::publisher_session_not_found)
            {
                return json_response(request, 404, json_error_body("session not found"));
            }

            return json_response(request, 500, json_error_body("delete publisher session failed"));
        }

        return text_response(request, 204, "");
    }

    if (snapshot->kind == stream_session_kind::subscriber)
    {
        auto result = registry_->remove_subscriber_session(snapshot->session_id);

        if (!result)
        {
            if (result.error() == stream_registry_error::subscriber_session_not_found)
            {
                return json_response(request, 404, json_error_body("session not found"));
            }

            return json_response(request, 500, json_error_body("delete subscriber session failed"));
        }

        return text_response(request, 204, "");
    }

    return json_response(request, 500, json_error_body("unsupported session kind"));
}

http_response_ptr router::handle_streams(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    const std::string body = make_stream_list_response_body(snapshots);

    return json_response(request, 200, body);
}

http_response_ptr router::handle_stream(http_request_t& request, std::string_view stream_id)
{
    if (!is_valid_resource_id(stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const auto method = request.req.method();

    if (method == http::verb::get)
    {
        const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

        if (!stream_has_publisher_snapshot(stream_id, snapshots))
        {
            return json_response(request, 404, json_error_body("stream publisher not found"));
        }

        const std::string body = make_stream_detail_response_body(stream_id, snapshots);

        return json_response(request, 200, body);
    }

    if (method == http::verb::delete_)
    {
        auto publisher = registry_->find_publisher_by_stream_id(stream_id);

        if (publisher == nullptr)
        {
            return json_response(request, 404, json_error_body("stream publisher not found"));
        }

        const std::string publisher_session_id = publisher->session_id();

        auto result = registry_->remove_publisher_session(publisher_session_id);

        if (!result)
        {
            if (result.error() == stream_registry_error::publisher_session_not_found)
            {
                return json_response(request, 404, json_error_body("stream publisher not found"));
            }

            return json_response(request, 500, json_error_body("delete stream failed"));
        }

        return text_response(request, 204, "");
    }

    return method_not_allowed(request);
}

http_response_ptr router::handle_stream_keyframe(http_request_t& request, std::string_view stream_id)
{
    if (request.req.method() != http::verb::post)
    {
        return method_not_allowed(request);
    }

    if (!is_valid_resource_id(stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (!keyframe_request_handler_)
    {
        return json_response(request, 503, json_error_body("keyframe request handler unavailable"));
    }

    keyframe_request_expected result = keyframe_request_handler_(stream_id);

    if (!result)
    {
        const std::string& error = result.error();

        if (error == "stream publisher not found")
        {
            return json_response(request, 404, json_error_body(error));
        }

        if (error == "publisher endpoint not found" || error == "publisher media ssrc not found")
        {
            return json_response(request, 409, json_error_body(error));
        }

        if (error == "session registry unavailable" || error == "srtp transport unavailable")
        {
            return json_response(request, 503, json_error_body(error));
        }

        return json_response(request, 500, json_error_body(error));
    }

    return json_response(request, 200, make_keyframe_request_response_body(*result));
}
http_response_ptr router::handle_simulcast_rid_target(http_request_t& request)
{
    const auto method = request.req.method();

    if (method != http::verb::post && method != http::verb::delete_)
    {
        return method_not_allowed(request);
    }

    if (!simulcast_rid_target_handler_)
    {
        return json_response(request, 503, json_error_body("simulcast rid target handler unavailable"));
    }

    const bool clear = method == http::verb::delete_;

    const std::optional<simulcast_rid_target_request> target_request = make_simulcast_rid_target_request_from_query(request, clear);

    if (!target_request.has_value())
    {
        return bad_request(request, "missing simulcast rid target query parameters");
    }

    if (!is_valid_resource_id(target_request->stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (!is_valid_resource_id(target_request->publisher_session_id))
    {
        return bad_request(request, "invalid publisher session id");
    }

    if (!is_valid_resource_id(target_request->subscriber_session_id))
    {
        return bad_request(request, "invalid subscriber session id");
    }

    if (!clear && !is_valid_resource_id(target_request->target_rid))
    {
        return bad_request(request, "invalid rid");
    }

    simulcast_rid_target_expected result = simulcast_rid_target_handler_(*target_request);

    if (!result)
    {
        const std::string& error = result.error();

        if (error.find("empty") != std::string::npos || error.find("unsupported") != std::string::npos)
        {
            return json_response(request, 400, json_error_body(error));
        }

        return json_response(request, 500, json_error_body(error));
    }

    return json_response(request, 200, make_simulcast_rid_target_response_body(*result));
}

http_response_ptr router::handle_debug_state(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (!lifecycle_debug_snapshot_provider_)
    {
        return json_response(request, 503, json_error_body("debug state provider unavailable"));
    }

    const std::string_view target = beast_string_view_to_std_string_view(request.req.target());

    const debug_state_filter_options filter_options = make_debug_state_filter_options(target);

    if (!debug_state_section_is_supported(filter_options.section))
    {
        return json_response(request, 400, json_error_body("unsupported debug state section"));
    }

    lifecycle_debug_snapshot snapshot = lifecycle_debug_snapshot_provider_();

    filter_lifecycle_debug_snapshot_by_stream_session(snapshot, filter_options);

    filter_lifecycle_debug_snapshot_by_section(snapshot, filter_options.section);

    return json_response(request, 200, lifecycle_debug_snapshot_to_json(snapshot));
}

http_response_ptr router::handle_media_stats(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (media_router_ == nullptr)
    {
        return json_response(request, 503, json_error_body("media router unavailable"));
    }

    const media_router_stats_snapshot snapshot = media_router_->get_stats_snapshot();

    std::string body = media_router_stats_snapshot_to_json(snapshot);

    if (rtcp_report_runtime_snapshot_provider_)
    {
        const rtcp_report_service_runtime_snapshot rtcp_snapshot = rtcp_report_runtime_snapshot_provider_();

        WEBRTC_LOG_DEBUG("http media stats rtcp report provider mounted=1 has_data={} snapshot={}",
                         rtcp_report_runtime_snapshot_has_data(rtcp_snapshot) ? 1 : 0,
                         rtcp_report_service_runtime_snapshot_to_string(rtcp_snapshot));

        body = append_rtcp_report_service_json(std::move(body), rtcp_snapshot);
    }
    else
    {
        WEBRTC_LOG_DEBUG("http media stats rtcp report provider mounted=0 has_data=0");
    }
    body = append_trickle_ice_metrics_json(std::move(body), global_trickle_ice_metrics().snapshot());
    return json_response(request, 200, body);
}

http_response_ptr router::handle_prometheus_metrics(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (media_router_ == nullptr)
    {
        return text_response(request, 503, "media router unavailable");
    }

    const media_router_stats_snapshot snapshot = media_router_->get_stats_snapshot();

    std::string body = media_router_stats_snapshot_to_prometheus(snapshot);

    if (rtcp_report_runtime_snapshot_provider_)
    {
        const rtcp_report_service_runtime_snapshot rtcp_snapshot = rtcp_report_runtime_snapshot_provider_();

        WEBRTC_LOG_INFO("http prometheus metrics rtcp report provider mounted=1 has_data={} snapshot={}",
                        rtcp_report_runtime_snapshot_has_data(rtcp_snapshot) ? 1 : 0,
                        rtcp_report_service_runtime_snapshot_to_string(rtcp_snapshot));

        append_rtcp_report_service_prometheus(body, rtcp_snapshot);
    }
    else
    {
        WEBRTC_LOG_INFO("http prometheus metrics rtcp report provider mounted=0 has_data=0");
    }

    if (lifecycle_debug_snapshot_provider_)
    {
        const lifecycle_debug_snapshot lifecycle_snapshot = lifecycle_debug_snapshot_provider_();

        WEBRTC_LOG_DEBUG(
            "http prometheus metrics lifecycle provider mounted=1 transport_cc_feedback_total={} lookup_hit={} lookup_miss={} "
            "outbound_twcc_windows={} active_clean={} delayed_clean={} consistent={}",
            lifecycle_snapshot.transport_cc_feedback_total,
            lifecycle_snapshot.transport_cc_feedback_lookup_hit_total,
            lifecycle_snapshot.transport_cc_feedback_lookup_miss_total,
            lifecycle_snapshot.outbound_transport_cc_feedback_window_count,
            lifecycle_snapshot.active_runtime_clean ? 1 : 0,
            lifecycle_snapshot.delayed_runtime_clean ? 1 : 0,
            lifecycle_snapshot.consistent ? 1 : 0);

        append_lifecycle_recovery_prometheus_metrics(body, lifecycle_snapshot);
    }
    else
    {
        WEBRTC_LOG_DEBUG("http prometheus metrics lifecycle provider mounted=0");
    }

    append_trickle_ice_metrics_prometheus(body, global_trickle_ice_metrics().snapshot());

    return prometheus_response(request, 200, body);
}

http_response_ptr router::handle_whip_create(http_request_t& request, std::string_view stream_id)
{
    if (request.req.method() != http::verb::post)
    {
        return method_not_allowed(request);
    }

    if (!is_valid_resource_id(stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (!is_application_sdp(request))
    {
        return unsupported_media_type(request);
    }

    auto body_validation_error = validate_sdp_offer_body(request, "WHIP", stream_id);

    if (body_validation_error != nullptr)
    {
        return body_validation_error;
    }

    return whip_.create_publisher(request, stream_id);
}

http_response_ptr router::handle_whip_session(http_request_t& request, std::string_view session_id)
{
    if (!is_valid_resource_id(session_id))
    {
        return bad_request(request, "invalid session id");
    }

    const auto method = request.req.method();

    if (method == http::verb::patch)
    {
        return whip_.patch_session(request, session_id);
    }

    if (method == http::verb::delete_)
    {
        return whip_.delete_session(request, session_id);
    }

    return method_not_allowed(request);
}

http_response_ptr router::handle_whep_create(http_request_t& request, std::string_view stream_id)
{
    if (request.req.method() != http::verb::post)
    {
        return method_not_allowed(request);
    }

    if (!is_valid_resource_id(stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (!is_application_sdp(request))
    {
        return unsupported_media_type(request);
    }

    auto body_validation_error = validate_sdp_offer_body(request, "WHEP", stream_id);

    if (body_validation_error != nullptr)
    {
        return body_validation_error;
    }

    return whep_.create_subscriber(request, stream_id);
}

http_response_ptr router::handle_whep_session(http_request_t& request, std::string_view session_id)
{
    if (!is_valid_resource_id(session_id))
    {
        return bad_request(request, "invalid session id");
    }

    const auto method = request.req.method();

    if (method == http::verb::patch)
    {
        return whep_.patch_session(request, session_id);
    }

    if (method == http::verb::delete_)
    {
        return whep_.delete_session(request, session_id);
    }

    return method_not_allowed(request);
}

http_response_ptr router::not_found(http_request_t& request) { return make_json_http_error_response(request, 404, "not_found", "not found"); }

http_response_ptr router::method_not_allowed(http_request_t& request)
{
    auto response = make_json_http_error_response(request, 405, "method_not_allowed", "method not allowed");

    response->set(http::field::allow, "GET, POST, PATCH, DELETE, OPTIONS");

    return response;
}

http_response_ptr router::bad_request(http_request_t& request, std::string_view message)
{
    return make_json_http_error_response(request, 400, "bad_request", message);
}

http_response_ptr router::unsupported_media_type(http_request_t& request)
{
    return make_json_http_error_response(request, 415, "unsupported_media_type", "unsupported media type, expected application/sdp");
}

http_response_ptr router::not_implemented(http_request_t& request, std::string_view message)
{
    return make_json_http_error_response(request, 501, "not_implemented", message);
}

http_response_ptr router::json_response(http_request_t& request, int code, std::string_view body)
{
    return make_json_http_response(request, code, body);
}

http_response_ptr router::text_response(http_request_t& request, int code, std::string_view body)
{
    return make_text_http_response(request, code, body);
}

http_response_ptr router::prometheus_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    if (!content.empty() && content.back() != '\n')
    {
        content.push_back('\n');
    }

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "text/plain; version=0.0.4; charset=utf-8");

    add_common_headers(response);

    return response;
}

void router::add_common_headers(const http_response_ptr& response) { add_http_common_headers(response); }

std::string_view router::request_path(http_request_t& request)
{
    const std::string_view target = beast_string_view_to_std_string_view(request.req.target());

    const std::string_view path = remove_query(target);

    if (path.empty())
    {
        return "/";
    }

    return path;
}

bool router::is_application_sdp(http_request_t& request)
{
    const auto content_type_field = request.req[http::field::content_type];

    const std::string_view content_type = beast_string_view_to_std_string_view(content_type_field);

    if (content_type.empty())
    {
        return false;
    }

    if (boost::algorithm::iequals(content_type, k_application_sdp))
    {
        return true;
    }

    if (!boost::algorithm::istarts_with(content_type, k_application_sdp))
    {
        return false;
    }

    if (content_type.size() <= k_application_sdp.size())
    {
        return false;
    }

    return content_type[k_application_sdp.size()] == ';';
}

bool router::is_valid_resource_id(std::string_view value)
{
    if (value.empty() || value.size() > 128)
    {
        return false;
    }

    return std::ranges::all_of(value,
                               [](char c)
                               {
                                   const auto ch = static_cast<unsigned char>(c);

                                   return std::isalnum(ch) != 0 || c == '-' || c == '_' || c == '.';
                               });
}
}    // namespace webrtc
