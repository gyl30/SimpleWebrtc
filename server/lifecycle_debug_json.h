#ifndef SIMPLE_WEBRTC_SERVER_LIFECYCLE_DEBUG_JSON_H
#define SIMPLE_WEBRTC_SERVER_LIFECYCLE_DEBUG_JSON_H

#include <cstdint>
#include <string>
#include <vector>

#include "util/reflect.h"

namespace webrtc
{
struct lifecycle_debug_session_entry
{
    std::string kind;
    std::string stream_id;
    std::string session_id;
    std::string state;

    std::string endpoint;
    bool has_endpoint = false;

    bool has_selected_candidate_pair = false;
    bool selected_candidate_pair_nominated = false;
    bool selected_candidate_pair_consent_in_flight = false;
    bool selected_candidate_pair_consent_stale = false;

    uint64_t selected_candidate_pair_last_binding_at_milliseconds = 0;
    uint64_t selected_candidate_pair_last_consent_response_at_milliseconds = 0;
    uint64_t selected_candidate_pair_consent_age_milliseconds = 0;
    uint64_t selected_candidate_pair_consent_failures = 0;

    bool transport_ready = false;
    uint64_t transport_blocker_count = 0;
    std::vector<std::string> transport_blockers;

    uint64_t created_at_milliseconds = 0;
    uint64_t updated_at_milliseconds = 0;
};
struct lifecycle_debug_removed_session_tombstone_entry
{
    std::string kind;
    std::string stream_id;
    std::string session_id;

    uint64_t removed_at_milliseconds = 0;
};
struct lifecycle_debug_endpoint_entry
{
    std::string endpoint;
    std::string session_id;

    bool has_endpoint = false;
    bool has_forward_session_index = false;
    bool has_reverse_endpoint_index = false;
    bool has_last_seen = false;

    uint64_t last_seen_milliseconds = 0;
};

struct lifecycle_debug_candidate_pair_entry
{
    std::string session_id;
    std::string stream_id;
    std::string remote_address;

    bool selected = false;
    bool nominated = false;
    bool consent_request_in_flight = false;

    uint64_t last_binding_at_milliseconds = 0;
    uint64_t last_consent_request_at_milliseconds = 0;
    uint64_t last_consent_response_at_milliseconds = 0;
    uint64_t consent_request_failures = 0;
};

struct lifecycle_debug_track_binding_entry
{
    std::string remote_endpoint;
    std::string stream_id;
    std::string session_id;

    std::string mid;
    std::string kind;
    std::string rid;
    std::string repaired_rid;

    std::string initial_resolution_state;
    bool fallback_resolution = false;

    bool has_audio_level = false;
    uint64_t audio_level = 0;

    bool has_voice_activity = false;
    bool voice_activity = false;

    uint32_t ssrc = 0;
    uint64_t payload_type = 0;

    bool rtx = false;
    uint32_t rtx_primary_ssrc = 0;
    uint32_t rtx_repair_ssrc = 0;

    uint64_t packet_count = 0;
};
struct lifecycle_debug_transport_cc_feedback_window_entry
{
    std::string stream_id;
    std::string subscriber_session_id;

    uint64_t first_feedback_at_milliseconds = 0;
    uint64_t last_feedback_at_milliseconds = 0;

    uint64_t feedback_count = 0;
    uint64_t feedback_packet_status_count = 0;

    uint64_t lookup_hit_count = 0;
    uint64_t lookup_miss_count = 0;
    uint64_t lookup_hit_rate_ppm = 0;

    uint64_t received_count = 0;
    uint64_t lost_count = 0;
    uint64_t loss_rate_ppm = 0;

    uint64_t small_delta_count = 0;
    uint64_t large_delta_count = 0;

    int64_t avg_delta_microseconds = 0;
    int64_t min_delta_microseconds = 0;
    int64_t max_delta_microseconds = 0;

    uint64_t observation_count = 0;
};

struct lifecycle_debug_subscriber_downlink_bandwidth_entry
{
    std::string stream_id;
    std::string subscriber_session_id;
    std::string control_state;

    uint64_t created_at_milliseconds = 0;
    uint64_t updated_at_milliseconds = 0;
    uint64_t last_feedback_at_milliseconds = 0;
    uint64_t last_transition_at_milliseconds = 0;

    uint64_t transition_count = 0;

    std::string last_transition_reason;

    uint64_t target_bitrate_bps = 0;
    uint64_t min_bitrate_bps = 0;
    uint64_t max_bitrate_bps = 0;

    uint64_t feedback_count = 0;
    uint64_t window_observation_count = 0;
    uint64_t window_packet_status_count = 0;

    uint64_t lookup_hit_rate_ppm = 0;
    uint64_t loss_rate_ppm = 0;

    uint64_t received_count = 0;
    uint64_t lost_count = 0;

    int64_t avg_delta_microseconds = 0;
    int64_t min_delta_microseconds = 0;
    int64_t max_delta_microseconds = 0;

    uint64_t bitrate_gate_last_update_milliseconds = 0;
    uint64_t bitrate_gate_budget_bytes = 0;
    uint64_t bitrate_gate_allowed_packet_count = 0;
    uint64_t bitrate_gate_dropped_packet_count = 0;
    uint64_t bitrate_gate_allowed_byte_count = 0;
    uint64_t bitrate_gate_dropped_byte_count = 0;
};

struct lifecycle_debug_identity_track_binding_entry
{
    std::string remote_endpoint;
    std::string stream_id;
    std::string session_id;

    std::string track_key;

    std::string mid;
    std::string kind;
    std::string rid;
    std::string repaired_rid;

    uint32_t ssrc = 0;
    uint64_t payload_type = 0;

    bool rtx = false;

    uint64_t packet_count = 0;
};

struct lifecycle_debug_identity_rid_layer_entry
{
    std::string remote_endpoint;
    std::string stream_id;
    std::string session_id;

    std::string mid;
    std::string kind;
    std::string rid;

    uint32_t primary_ssrc = 0;
    uint32_t repair_ssrc = 0;

    uint64_t primary_payload_type = 0;
    uint64_t repair_payload_type = 0;

    uint64_t packet_count = 0;
};

struct lifecycle_debug_identity_forward_binding_entry
{
    std::string stream_id;

    std::string publisher_session_id;
    std::string subscriber_session_id;

    std::string publisher_track_key;
    std::string subscriber_track_key;

    std::string publisher_mid;
    std::string subscriber_mid;
    std::string kind;

    uint64_t publisher_media_ordinal = 0;
    uint64_t subscriber_media_ordinal = 0;
    bool audio_ordinal_mismatch = false;

    uint32_t publisher_ssrc = 0;
    uint32_t subscriber_ssrc = 0;

    uint64_t publisher_payload_type = 0;
    uint64_t subscriber_payload_type = 0;

    bool rtx = false;
    uint64_t publisher_apt_payload_type = 0;
    uint64_t subscriber_apt_payload_type = 0;

    uint32_t publisher_rtx_primary_ssrc = 0;
    uint32_t publisher_rtx_repair_ssrc = 0;

    bool payload_type_rewrite_required = false;
    bool mid_rewrite_required = false;
    bool ssrc_rewrite_required = false;

    uint64_t packet_count = 0;
};

struct lifecycle_debug_subscriber_forward_group_entry
{
    std::string stream_id;
    std::string publisher_session_id;
    std::string subscriber_session_id;

    uint64_t forward_binding_count = 0;
    uint64_t audio_forward_binding_count = 0;
    uint64_t video_forward_binding_count = 0;
    uint64_t audio_ordinal_mismatch_count = 0;
    uint64_t primary_forward_binding_count = 0;
    uint64_t rtx_forward_binding_count = 0;
    uint64_t payload_type_rewrite_required_count = 0;
    uint64_t mid_rewrite_required_count = 0;
    uint64_t ssrc_rewrite_required_count = 0;
    uint64_t packet_count = 0;
};

struct lifecycle_debug_rtcp_report_source_entry
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    std::string mid;
    std::string kind;
    std::string rid;
    std::string repaired_rid;

    uint64_t local_ssrc = 0;

    bool sender_report_enabled = false;
    bool receiver_report_enabled = false;

    uint64_t max_report_blocks = 0;

    uint64_t next_due_milliseconds = 0;
    uint64_t last_active_milliseconds = 0;
};
struct lifecycle_debug_twcc_feedback_source_entry
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;
    std::string mid;
    std::string kind;

    uint64_t sender_ssrc = 0;
    uint64_t media_ssrc = 0;

    uint64_t feedback_packet_count = 0;
    uint64_t total_feedback_packet_count = 0;
    uint64_t pending_packet_count = 0;

    uint64_t feedback_interval_milliseconds = 0;
    uint64_t stale_source_milliseconds = 0;

    uint64_t next_due_milliseconds = 0;
    uint64_t last_active_milliseconds = 0;
    uint64_t last_feedback_milliseconds = 0;

    uint64_t oldest_pending_packet_milliseconds = 0;
    uint64_t newest_pending_packet_milliseconds = 0;
};
struct lifecycle_debug_rtp_cache_stream_entry
{
    std::string stream_id;

    uint64_t packet_count = 0;
    uint64_t byte_count = 0;

    uint64_t min_ssrc = 0;
    uint64_t max_ssrc = 0;
};
struct lifecycle_debug_subscriber_rtcp_group_entry
{
    std::string stream_id;
    std::string subscriber_session_id;

    uint64_t rtcp_report_source_count = 0;
    uint64_t twcc_feedback_source_count = 0;

    uint64_t audio_rtcp_report_source_count = 0;
    uint64_t video_rtcp_report_source_count = 0;

    uint64_t audio_twcc_feedback_source_count = 0;
    uint64_t video_twcc_feedback_source_count = 0;

    uint64_t sender_report_enabled_count = 0;
    uint64_t receiver_report_enabled_count = 0;

    uint64_t twcc_pending_packet_count = 0;
};
struct lifecycle_debug_subscriber_runtime_residual_entry
{
    std::string stream_id;
    std::string subscriber_session_id;

    uint64_t media_router_peer_count = 0;
    uint64_t track_binding_count = 0;
    uint64_t ssrc_mapping_count = 0;
    uint64_t identity_track_binding_count = 0;
    uint64_t identity_rid_layer_binding_count = 0;
    uint64_t identity_forward_binding_count = 0;
    uint64_t rtcp_report_source_count = 0;
    uint64_t twcc_feedback_source_count = 0;
    uint64_t rtx_retransmission_index_count = 0;
    uint64_t nack_retransmit_throttle_count = 0;

    uint64_t residual_count = 0;
};

struct lifecycle_debug_selected_rid_layer_entry
{
    std::string stream_id;

    std::string publisher_session_id;
    std::string subscriber_session_id;

    std::string mid;
    std::string kind;

    std::string selected_rid;
    std::string previous_rid;

    std::string target_rid;
    std::string target_policy;

    std::string effective_target_rid;
    std::string effective_target_policy;

    bool manual_target_active = false;

    std::string adaptive_suggested_rid;
    std::string adaptive_suggested_policy;
    std::string adaptive_suggested_reason;
    uint64_t adaptive_suggested_at_milliseconds = 0;

    uint64_t switch_count = 0;
    uint64_t last_switch_milliseconds = 0;
    std::string last_switch_reason;

    bool adaptive_enabled = false;
    std::string last_adaptive_decision;
    std::string last_adaptive_decision_reason;
    uint64_t last_adaptive_decision_milliseconds = 0;
    uint64_t switch_cooldown_remaining_milliseconds = 0;

    std::string selection_policy;
    std::vector<std::string> rid_preference;

    uint64_t primary_ssrc = 0;
    uint64_t repair_ssrc = 0;

    bool pending_keyframe_request = false;
    uint64_t pending_keyframe_request_since_milliseconds = 0;
    uint64_t pending_keyframe_request_expires_at_milliseconds = 0;
    uint64_t pending_keyframe_request_remaining_ttl_milliseconds = 0;

    uint64_t packet_count = 0;
    uint64_t byte_count = 0;

    uint64_t primary_packet_count = 0;
    uint64_t primary_byte_count = 0;

    uint64_t repair_packet_count = 0;
    uint64_t repair_byte_count = 0;

    uint64_t last_packet_milliseconds = 0;
    uint64_t bitrate_bps = 0;

    uint64_t nack_feedback_count = 0;
    uint64_t nack_sequence_count = 0;
    uint64_t last_nack_milliseconds = 0;

    uint64_t keyframe_request_attempt_count = 0;
    uint64_t keyframe_request_success_count = 0;
    uint64_t keyframe_request_restore_count = 0;
    uint64_t last_keyframe_request_milliseconds = 0;

    std::string last_keyframe_request_result;
    std::string last_keyframe_request_reason;
};
struct lifecycle_debug_drop_reason_entry
{
    std::string category;
    std::string reason;

    uint64_t count = 0;
};
struct lifecycle_debug_retired_endpoint_entry
{
    std::string remote_address;
    std::string session_id;
    std::string reason;

    uint64_t expires_at_milliseconds = 0;
    uint64_t remaining_ttl_milliseconds = 0;
    uint64_t suppressed_packets = 0;
};

struct lifecycle_debug_retired_ice_credential_entry
{
    std::string stream_id;
    std::string session_id;

    std::string local_ice_ufrag;
    std::string remote_ice_ufrag;

    std::string reason;

    uint64_t expires_at_milliseconds = 0;
    uint64_t remaining_ttl_milliseconds = 0;
    uint64_t suppressed_stun_packets = 0;
};

struct lifecycle_debug_snapshot
{
    uint64_t registry_stream_count = 0;
    uint64_t registry_publisher_count = 0;
    uint64_t registry_subscriber_count = 0;
    uint64_t registry_session_count = 0;
    uint64_t registry_pending_session_count = 0;

    uint64_t registry_removed_session_tombstone_count = 0;
    uint64_t registry_removed_publisher_tombstone_count = 0;
    uint64_t registry_removed_subscriber_tombstone_count = 0;

    uint64_t endpoint_count = 0;
    uint64_t endpoint_session_index_count = 0;
    uint64_t endpoint_reverse_index_count = 0;
    uint64_t endpoint_last_seen_count = 0;

    uint64_t retired_endpoint_count = 0;
    uint64_t retired_endpoint_suppressed_packet_count = 0;
    uint64_t retired_ice_credential_count = 0;
    uint64_t retired_ice_credential_suppressed_stun_packet_count = 0;

    uint64_t candidate_pair_count = 0;
    uint64_t selected_candidate_pair_count = 0;
    uint64_t candidate_pair_consent_in_flight_count = 0;
    uint64_t candidate_pair_consent_failure_count = 0;
    uint64_t candidate_pair_consent_stale_count = 0;

    uint64_t payload_type_mapping_count = 0;
    uint64_t keyframe_request_state_count = 0;

    uint64_t fir_sequence_number_state_count = 0;
    uint64_t publisher_video_ssrc_state_count = 0;

    uint64_t pending_republish_keyframe_request_count = 0;
    uint64_t selected_rid_layer_state_count = 0;
    uint64_t pending_selected_rid_keyframe_request_count = 0;
    uint64_t selected_rid_keyframe_pending_metadata_count = 0;
    std::string simulcast_rid_preference_policy;
    uint64_t extmap_rewrite_state_count = 0;
    uint64_t outbound_transport_cc_sequence_count = 0;
    uint64_t outbound_transport_cc_packet_count = 0;
    uint64_t outbound_transport_cc_feedback_window_count = 0;
    uint64_t outbound_transport_cc_feedback_window_observation_count = 0;

    uint64_t subscriber_downlink_bandwidth_state_count = 0;

    uint64_t dtls_peer_count = 0;
    uint64_t srtp_peer_count = 0;

    uint64_t media_router_peer_count = 0;
    uint64_t media_router_stream_count = 0;
    uint64_t media_router_active_publisher_count = 0;
    uint64_t media_router_active_subscriber_count = 0;

    uint64_t track_binding_count = 0;
    uint64_t ssrc_mapping_count = 0;

    uint64_t identity_authority_track_binding_count = 0;
    uint64_t identity_authority_rid_layer_binding_count = 0;
    uint64_t identity_authority_forward_binding_count = 0;

    uint64_t subscriber_forward_group_count = 0;

    uint64_t rtcp_report_source_count = 0;
    uint64_t twcc_feedback_source_count = 0;

    uint64_t transport_cc_feedback_total = 0;
    uint64_t transport_cc_feedback_packet_status_total = 0;
    uint64_t transport_cc_feedback_lookup_hit_total = 0;
    uint64_t transport_cc_feedback_lookup_miss_total = 0;
    uint64_t transport_cc_feedback_received_packet_total = 0;
    uint64_t transport_cc_feedback_not_received_packet_total = 0;
    uint64_t transport_cc_feedback_small_delta_total = 0;
    uint64_t transport_cc_feedback_large_delta_total = 0;

    uint64_t subscriber_rtcp_group_count = 0;

    uint64_t subscriber_runtime_residual_count = 0;

    uint64_t rtcp_report_stats_source_count = 0;

    uint64_t rtcp_transport_cc_source_count = 0;
    uint64_t rtcp_transport_cc_pending_packet_count = 0;

    uint64_t rtp_cache_packet_count = 0;
    uint64_t rtx_sequence_allocator_count = 0;
    uint64_t rtx_retransmission_index_count = 0;
    uint64_t nack_retransmit_throttle_count = 0;

    uint64_t rtp_rtcp_drop_total = 0;
    uint64_t rtp_rtcp_drop_reason_count = 0;

    std::vector<lifecycle_debug_drop_reason_entry> rtp_rtcp_drop_reasons;

    bool active_runtime_clean = false;
    bool delayed_runtime_clean = false;
    bool full_idle_clean = false;

    bool idle_clean = false;
    bool consistent = true;

    uint64_t inconsistency_count = 0;
    uint64_t delayed_residual_count = 0;

    std::vector<std::string> inconsistencies;
    std::vector<lifecycle_debug_session_entry> sessions;
    std::vector<lifecycle_debug_removed_session_tombstone_entry> removed_session_tombstones;
    std::vector<lifecycle_debug_endpoint_entry> endpoints;

    std::vector<lifecycle_debug_candidate_pair_entry> candidate_pairs;
    std::vector<lifecycle_debug_track_binding_entry> track_bindings;
    std::vector<lifecycle_debug_identity_track_binding_entry> identity_track_bindings;
    std::vector<lifecycle_debug_identity_rid_layer_entry> identity_rid_layers;
    std::vector<lifecycle_debug_identity_forward_binding_entry> identity_forward_bindings;
    std::vector<lifecycle_debug_subscriber_forward_group_entry> subscriber_forward_groups;

    std::vector<lifecycle_debug_selected_rid_layer_entry> selected_rid_layers;

    std::vector<lifecycle_debug_rtcp_report_source_entry> rtcp_report_sources;
    std::vector<lifecycle_debug_twcc_feedback_source_entry> twcc_feedback_sources;
    std::vector<lifecycle_debug_transport_cc_feedback_window_entry> outbound_transport_cc_feedback_windows;
    std::vector<lifecycle_debug_subscriber_downlink_bandwidth_entry> subscriber_downlink_bandwidth_states;
    std::vector<lifecycle_debug_rtp_cache_stream_entry> rtp_cache_streams;
    std::vector<lifecycle_debug_subscriber_rtcp_group_entry> subscriber_rtcp_groups;
    std::vector<lifecycle_debug_subscriber_runtime_residual_entry> subscriber_runtime_residuals;

    std::vector<lifecycle_debug_retired_endpoint_entry> retired_endpoints;

    std::vector<lifecycle_debug_retired_ice_credential_entry> retired_ice_credentials;
    std::vector<std::string> residuals;
    std::vector<std::string> delayed_residuals;
};

REFLECT_STRUCT(webrtc::lifecycle_debug_removed_session_tombstone_entry, (kind)(stream_id)(session_id)(removed_at_milliseconds));
REFLECT_STRUCT(webrtc::lifecycle_debug_session_entry,
               (kind)(stream_id)(session_id)(state)(endpoint)(has_endpoint)(has_selected_candidate_pair)(selected_candidate_pair_nominated)(selected_candidate_pair_consent_in_flight)(selected_candidate_pair_consent_stale)(selected_candidate_pair_last_binding_at_milliseconds)(selected_candidate_pair_last_consent_response_at_milliseconds)(selected_candidate_pair_consent_age_milliseconds)(selected_candidate_pair_consent_failures)(transport_ready)(transport_blocker_count)(transport_blockers)(created_at_milliseconds)(updated_at_milliseconds));
REFLECT_STRUCT(webrtc::lifecycle_debug_endpoint_entry,
               (endpoint)(session_id)(has_endpoint)(has_forward_session_index)(has_reverse_endpoint_index)(has_last_seen)(last_seen_milliseconds));

REFLECT_STRUCT(webrtc::lifecycle_debug_drop_reason_entry, (category)(reason)(count));
REFLECT_STRUCT(
    webrtc::lifecycle_debug_candidate_pair_entry,
    (session_id)(stream_id)(remote_address)(selected)(nominated)(consent_request_in_flight)(last_binding_at_milliseconds)(last_consent_request_at_milliseconds)(last_consent_response_at_milliseconds)(consent_request_failures));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_track_binding_entry,
    (remote_endpoint)(stream_id)(session_id)(mid)(kind)(rid)(repaired_rid)(initial_resolution_state)(fallback_resolution)(has_audio_level)(audio_level)(has_voice_activity)(voice_activity)(ssrc)(payload_type)(rtx)(rtx_primary_ssrc)(rtx_repair_ssrc)(packet_count));

REFLECT_STRUCT(webrtc::lifecycle_debug_identity_track_binding_entry,
               (remote_endpoint)(stream_id)(session_id)(track_key)(mid)(kind)(rid)(repaired_rid)(ssrc)(payload_type)(rtx)(packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_identity_rid_layer_entry,
    (remote_endpoint)(stream_id)(session_id)(mid)(kind)(rid)(primary_ssrc)(repair_ssrc)(primary_payload_type)(repair_payload_type)(packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_identity_forward_binding_entry, (stream_id)(publisher_session_id)(subscriber_session_id)(publisher_track_key)(subscriber_track_key)(publisher_mid)(subscriber_mid)(kind)(publisher_media_ordinal)(subscriber_media_ordinal)(audio_ordinal_mismatch)(publisher_ssrc)(subscriber_ssrc)(publisher_payload_type)(subscriber_payload_type)(rtx)(publisher_apt_payload_type)(subscriber_apt_payload_type)(publisher_rtx_primary_ssrc)(publisher_rtx_repair_ssrc)(payload_type_rewrite_required)(mid_rewrite_required)(ssrc_rewrite_required)(packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_subscriber_forward_group_entry,
    (stream_id)(publisher_session_id)(subscriber_session_id)(forward_binding_count)(audio_forward_binding_count)(video_forward_binding_count)(audio_ordinal_mismatch_count)(primary_forward_binding_count)(rtx_forward_binding_count)(payload_type_rewrite_required_count)(mid_rewrite_required_count)(ssrc_rewrite_required_count)(packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_rtcp_report_source_entry,
    (stream_id)(session_id)(remote_endpoint)(mid)(kind)(rid)(repaired_rid)(local_ssrc)(sender_report_enabled)(receiver_report_enabled)(max_report_blocks)(next_due_milliseconds)(last_active_milliseconds));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_twcc_feedback_source_entry,
    (stream_id)(session_id)(remote_endpoint)(mid)(kind)(sender_ssrc)(media_ssrc)(feedback_packet_count)(total_feedback_packet_count)(pending_packet_count)(feedback_interval_milliseconds)(stale_source_milliseconds)(next_due_milliseconds)(last_active_milliseconds)(last_feedback_milliseconds)(oldest_pending_packet_milliseconds)(newest_pending_packet_milliseconds));

REFLECT_STRUCT(webrtc::lifecycle_debug_rtp_cache_stream_entry, (stream_id)(packet_count)(byte_count)(min_ssrc)(max_ssrc));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_subscriber_rtcp_group_entry,
    (stream_id)(subscriber_session_id)(rtcp_report_source_count)(twcc_feedback_source_count)(audio_rtcp_report_source_count)(video_rtcp_report_source_count)(audio_twcc_feedback_source_count)(video_twcc_feedback_source_count)(sender_report_enabled_count)(receiver_report_enabled_count)(twcc_pending_packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_subscriber_runtime_residual_entry,
    (stream_id)(subscriber_session_id)(media_router_peer_count)(track_binding_count)(ssrc_mapping_count)(identity_track_binding_count)(identity_rid_layer_binding_count)(identity_forward_binding_count)(rtcp_report_source_count)(twcc_feedback_source_count)(rtx_retransmission_index_count)(nack_retransmit_throttle_count)(residual_count));

REFLECT_STRUCT(webrtc::lifecycle_debug_selected_rid_layer_entry,
               (
                   stream_id)(publisher_session_id)(subscriber_session_id)(mid)(kind)(selected_rid)(previous_rid)(target_rid)(target_policy)(effective_target_rid)(effective_target_policy)(manual_target_active)(adaptive_suggested_rid)(adaptive_suggested_policy)(adaptive_suggested_reason)(adaptive_suggested_at_milliseconds)(switch_count)(last_switch_milliseconds)(last_switch_reason)(adaptive_enabled)(last_adaptive_decision)(last_adaptive_decision_reason)(last_adaptive_decision_milliseconds)(switch_cooldown_remaining_milliseconds)(selection_policy)(rid_preference)(primary_ssrc)(repair_ssrc)(pending_keyframe_request)(pending_keyframe_request_since_milliseconds)(pending_keyframe_request_expires_at_milliseconds)(pending_keyframe_request_remaining_ttl_milliseconds)(packet_count)(byte_count)(primary_packet_count)(primary_byte_count)(repair_packet_count)(repair_byte_count)(last_packet_milliseconds)(bitrate_bps)(nack_feedback_count)(nack_sequence_count)(last_nack_milliseconds)(keyframe_request_attempt_count)(keyframe_request_success_count)(keyframe_request_restore_count)(last_keyframe_request_milliseconds)(last_keyframe_request_result)(last_keyframe_request_reason));

REFLECT_STRUCT(webrtc::lifecycle_debug_transport_cc_feedback_window_entry,
               (stream_id)(subscriber_session_id)(first_feedback_at_milliseconds)(last_feedback_at_milliseconds)(feedback_count)(feedback_packet_status_count)(lookup_hit_count)(lookup_miss_count)(lookup_hit_rate_ppm)(received_count)(lost_count)(loss_rate_ppm)(small_delta_count)(large_delta_count)(avg_delta_microseconds)(min_delta_microseconds)(max_delta_microseconds)(observation_count));

REFLECT_STRUCT(webrtc::lifecycle_debug_subscriber_downlink_bandwidth_entry,
               (
                   stream_id)(subscriber_session_id)(control_state)(created_at_milliseconds)(updated_at_milliseconds)(last_feedback_at_milliseconds)(last_transition_at_milliseconds)(transition_count)(last_transition_reason)(target_bitrate_bps)(min_bitrate_bps)(max_bitrate_bps)(feedback_count)(window_observation_count)(window_packet_status_count)(lookup_hit_rate_ppm)(loss_rate_ppm)(received_count)(lost_count)(avg_delta_microseconds)(min_delta_microseconds)(max_delta_microseconds)(bitrate_gate_last_update_milliseconds)(bitrate_gate_budget_bytes)(bitrate_gate_allowed_packet_count)(bitrate_gate_dropped_packet_count)(bitrate_gate_allowed_byte_count)(bitrate_gate_dropped_byte_count));

REFLECT_STRUCT(webrtc::lifecycle_debug_retired_endpoint_entry,
               (remote_address)(session_id)(reason)(expires_at_milliseconds)(remaining_ttl_milliseconds)(suppressed_packets));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_retired_ice_credential_entry,
    (stream_id)(session_id)(local_ice_ufrag)(remote_ice_ufrag)(reason)(expires_at_milliseconds)(remaining_ttl_milliseconds)(suppressed_stun_packets));

REFLECT_STRUCT(webrtc::lifecycle_debug_snapshot, (registry_stream_count)(registry_publisher_count)(registry_subscriber_count)(registry_session_count)(registry_pending_session_count)(registry_removed_session_tombstone_count)(registry_removed_publisher_tombstone_count)(registry_removed_subscriber_tombstone_count)(endpoint_count)(endpoint_session_index_count)(endpoint_reverse_index_count)(endpoint_last_seen_count)(retired_endpoint_count)(retired_endpoint_suppressed_packet_count)(retired_ice_credential_count)(retired_ice_credential_suppressed_stun_packet_count)(candidate_pair_count)(selected_candidate_pair_count)(candidate_pair_consent_in_flight_count)(candidate_pair_consent_failure_count)(candidate_pair_consent_stale_count)(payload_type_mapping_count)(keyframe_request_state_count)(fir_sequence_number_state_count)(publisher_video_ssrc_state_count)(pending_republish_keyframe_request_count)(selected_rid_layer_state_count)(pending_selected_rid_keyframe_request_count)(selected_rid_keyframe_pending_metadata_count)(simulcast_rid_preference_policy)(extmap_rewrite_state_count)(outbound_transport_cc_sequence_count)(outbound_transport_cc_packet_count)(outbound_transport_cc_feedback_window_count)(outbound_transport_cc_feedback_window_observation_count)(subscriber_downlink_bandwidth_state_count)(dtls_peer_count)(srtp_peer_count)(media_router_peer_count)(media_router_stream_count)(media_router_active_publisher_count)(media_router_active_subscriber_count)(track_binding_count)(ssrc_mapping_count)(identity_authority_track_binding_count)(identity_authority_rid_layer_binding_count)(identity_authority_forward_binding_count)(subscriber_forward_group_count)(rtcp_report_source_count)(twcc_feedback_source_count)(transport_cc_feedback_total)(transport_cc_feedback_packet_status_total)(transport_cc_feedback_lookup_hit_total)(transport_cc_feedback_lookup_miss_total)(transport_cc_feedback_received_packet_total)(transport_cc_feedback_not_received_packet_total)(transport_cc_feedback_small_delta_total)(transport_cc_feedback_large_delta_total)(subscriber_rtcp_group_count)(subscriber_runtime_residual_count)(rtcp_report_stats_source_count)(rtcp_transport_cc_source_count)(rtcp_transport_cc_pending_packet_count)(rtp_cache_packet_count)(rtx_sequence_allocator_count)(rtx_retransmission_index_count)(nack_retransmit_throttle_count)(rtp_rtcp_drop_total)(rtp_rtcp_drop_reason_count)(rtp_rtcp_drop_reasons)(active_runtime_clean)(delayed_runtime_clean)(full_idle_clean)(idle_clean)(consistent)(inconsistency_count)(delayed_residual_count)(inconsistencies)(sessions)(removed_session_tombstones)(endpoints)(candidate_pairs)(track_bindings)(identity_track_bindings)(identity_rid_layers)(identity_forward_bindings)(subscriber_forward_groups)(selected_rid_layers)(rtcp_report_sources)(twcc_feedback_sources)(outbound_transport_cc_feedback_windows)(subscriber_downlink_bandwidth_states)(rtp_cache_streams)(subscriber_rtcp_groups)(subscriber_runtime_residuals)(retired_endpoints)(retired_ice_credentials)(residuals)(delayed_residuals));

inline std::string lifecycle_debug_snapshot_to_json(const lifecycle_debug_snapshot& snapshot) { return serialize_struct(snapshot); }
}    // namespace webrtc

#endif
