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

    uint32_t ssrc = 0;
    uint64_t payload_type = 0;

    bool rtx = false;
    uint32_t rtx_primary_ssrc = 0;
    uint32_t rtx_repair_ssrc = 0;

    uint64_t packet_count = 0;
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
    uint64_t pending_packet_count = 0;

    uint64_t next_due_milliseconds = 0;
    uint64_t last_active_milliseconds = 0;
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
    uint64_t extmap_rewrite_state_count = 0;

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
    uint64_t subscriber_rtcp_group_count = 0;

    uint64_t subscriber_runtime_residual_count = 0;

    uint64_t rtcp_report_stats_source_count = 0;

    uint64_t rtcp_transport_cc_source_count = 0;
    uint64_t rtcp_transport_cc_pending_packet_count = 0;

    uint64_t rtp_cache_packet_count = 0;
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

    std::vector<lifecycle_debug_rtcp_report_source_entry> rtcp_report_sources;
    std::vector<lifecycle_debug_twcc_feedback_source_entry> twcc_feedback_sources;
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
    (remote_endpoint)(stream_id)(session_id)(mid)(kind)(rid)(repaired_rid)(initial_resolution_state)(fallback_resolution)(ssrc)(payload_type)(rtx)(rtx_primary_ssrc)(rtx_repair_ssrc)(packet_count));

REFLECT_STRUCT(webrtc::lifecycle_debug_identity_track_binding_entry,
               (remote_endpoint)(stream_id)(session_id)(track_key)(mid)(kind)(rid)(repaired_rid)(ssrc)(payload_type)(rtx)(packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_identity_rid_layer_entry,
    (remote_endpoint)(stream_id)(session_id)(mid)(kind)(rid)(primary_ssrc)(repair_ssrc)(primary_payload_type)(repair_payload_type)(packet_count));

REFLECT_STRUCT(webrtc::lifecycle_debug_identity_forward_binding_entry,
               (
                   stream_id)(publisher_session_id)(subscriber_session_id)(publisher_track_key)(subscriber_track_key)(publisher_mid)(subscriber_mid)(kind)(publisher_ssrc)(subscriber_ssrc)(publisher_payload_type)(subscriber_payload_type)(rtx)(publisher_apt_payload_type)(subscriber_apt_payload_type)(publisher_rtx_primary_ssrc)(publisher_rtx_repair_ssrc)(payload_type_rewrite_required)(mid_rewrite_required)(ssrc_rewrite_required)(packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_subscriber_forward_group_entry,
    (stream_id)(publisher_session_id)(subscriber_session_id)(forward_binding_count)(audio_forward_binding_count)(video_forward_binding_count)(primary_forward_binding_count)(rtx_forward_binding_count)(payload_type_rewrite_required_count)(mid_rewrite_required_count)(ssrc_rewrite_required_count)(packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_rtcp_report_source_entry,
    (stream_id)(session_id)(remote_endpoint)(mid)(kind)(rid)(repaired_rid)(local_ssrc)(sender_report_enabled)(receiver_report_enabled)(max_report_blocks)(next_due_milliseconds)(last_active_milliseconds));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_twcc_feedback_source_entry,
    (stream_id)(session_id)(remote_endpoint)(mid)(kind)(sender_ssrc)(media_ssrc)(feedback_packet_count)(pending_packet_count)(next_due_milliseconds)(last_active_milliseconds));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_subscriber_rtcp_group_entry,
    (stream_id)(subscriber_session_id)(rtcp_report_source_count)(twcc_feedback_source_count)(audio_rtcp_report_source_count)(video_rtcp_report_source_count)(audio_twcc_feedback_source_count)(video_twcc_feedback_source_count)(sender_report_enabled_count)(receiver_report_enabled_count)(twcc_pending_packet_count));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_subscriber_runtime_residual_entry,
    (stream_id)(subscriber_session_id)(media_router_peer_count)(track_binding_count)(ssrc_mapping_count)(identity_track_binding_count)(identity_rid_layer_binding_count)(identity_forward_binding_count)(rtcp_report_source_count)(twcc_feedback_source_count)(rtx_retransmission_index_count)(nack_retransmit_throttle_count)(residual_count));

REFLECT_STRUCT(webrtc::lifecycle_debug_retired_endpoint_entry,
               (remote_address)(session_id)(reason)(expires_at_milliseconds)(remaining_ttl_milliseconds)(suppressed_packets));

REFLECT_STRUCT(
    webrtc::lifecycle_debug_retired_ice_credential_entry,
    (stream_id)(session_id)(local_ice_ufrag)(remote_ice_ufrag)(reason)(expires_at_milliseconds)(remaining_ttl_milliseconds)(suppressed_stun_packets));

REFLECT_STRUCT(webrtc::lifecycle_debug_snapshot,
               (
                   registry_stream_count)(registry_publisher_count)(registry_subscriber_count)(registry_session_count)(registry_pending_session_count)(registry_removed_session_tombstone_count)(registry_removed_publisher_tombstone_count)(registry_removed_subscriber_tombstone_count)(endpoint_count)(endpoint_session_index_count)(endpoint_reverse_index_count)(endpoint_last_seen_count)(retired_endpoint_count)(retired_endpoint_suppressed_packet_count)(retired_ice_credential_count)(retired_ice_credential_suppressed_stun_packet_count)(candidate_pair_count)(selected_candidate_pair_count)(candidate_pair_consent_in_flight_count)(candidate_pair_consent_failure_count)(candidate_pair_consent_stale_count)(payload_type_mapping_count)(keyframe_request_state_count)(fir_sequence_number_state_count)(publisher_video_ssrc_state_count)(pending_republish_keyframe_request_count)(selected_rid_layer_state_count)(pending_selected_rid_keyframe_request_count)(extmap_rewrite_state_count)(dtls_peer_count)(srtp_peer_count)(media_router_peer_count)(media_router_stream_count)(media_router_active_publisher_count)(media_router_active_subscriber_count)(track_binding_count)(ssrc_mapping_count)(identity_authority_track_binding_count)(identity_authority_rid_layer_binding_count)(identity_authority_forward_binding_count)(subscriber_forward_group_count)(rtcp_report_source_count)(twcc_feedback_source_count)(subscriber_rtcp_group_count)(subscriber_runtime_residual_count)(rtcp_report_source_count)(rtcp_report_stats_source_count)(rtcp_transport_cc_source_count)(rtcp_transport_cc_pending_packet_count)(rtp_cache_packet_count)(rtx_retransmission_index_count)(nack_retransmit_throttle_count)(rtp_rtcp_drop_total)(rtp_rtcp_drop_reason_count)(rtp_rtcp_drop_reasons)(active_runtime_clean)(delayed_runtime_clean)(full_idle_clean)(idle_clean)(consistent)(inconsistency_count)(delayed_residual_count)(inconsistencies)(sessions)(removed_session_tombstones)(endpoints)(candidate_pairs)(track_bindings)(identity_track_bindings)(identity_rid_layers)(identity_forward_bindings)(subscriber_forward_groups)(rtcp_report_sources)(twcc_feedback_sources)(subscriber_rtcp_groups)(subscriber_runtime_residuals)(retired_endpoints)(retired_ice_credentials)(residuals)(delayed_residuals));

inline std::string lifecycle_debug_snapshot_to_json(const lifecycle_debug_snapshot& snapshot) { return serialize_struct(snapshot); }
}    // namespace webrtc

#endif
