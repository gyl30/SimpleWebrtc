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

    uint64_t created_at_milliseconds = 0;
    uint64_t updated_at_milliseconds = 0;
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
struct lifecycle_debug_snapshot
{
    uint64_t registry_stream_count = 0;
    uint64_t registry_publisher_count = 0;
    uint64_t registry_subscriber_count = 0;
    uint64_t registry_session_count = 0;
    uint64_t registry_pending_session_count = 0;

    uint64_t endpoint_count = 0;
    uint64_t endpoint_session_index_count = 0;
    uint64_t endpoint_reverse_index_count = 0;
    uint64_t endpoint_last_seen_count = 0;

    uint64_t candidate_pair_count = 0;
    uint64_t selected_candidate_pair_count = 0;
    uint64_t payload_type_mapping_count = 0;
    uint64_t keyframe_request_state_count = 0;

    uint64_t dtls_peer_count = 0;
    uint64_t srtp_peer_count = 0;

    uint64_t media_router_peer_count = 0;
    uint64_t media_router_stream_count = 0;
    uint64_t media_router_active_publisher_count = 0;
    uint64_t media_router_active_subscriber_count = 0;

    uint64_t track_binding_count = 0;
    uint64_t ssrc_mapping_count = 0;

    uint64_t identity_authority_track_binding_count = 0;
    uint64_t identity_authority_forward_binding_count = 0;

    uint64_t rtcp_report_source_count = 0;
    uint64_t rtcp_report_stats_source_count = 0;

    uint64_t rtcp_transport_cc_source_count = 0;
    uint64_t rtcp_transport_cc_pending_packet_count = 0;

    uint64_t rtp_cache_packet_count = 0;
    uint64_t rtx_retransmission_index_count = 0;
    uint64_t nack_retransmit_throttle_count = 0;

    bool idle_clean = false;
    bool consistent = true;

    uint64_t inconsistency_count = 0;
    std::vector<std::string> inconsistencies;
    std::vector<lifecycle_debug_session_entry> sessions;
    std::vector<lifecycle_debug_endpoint_entry> endpoints;
    std::vector<std::string> residuals;
};

REFLECT_STRUCT(webrtc::lifecycle_debug_session_entry,
               (kind)(stream_id)(session_id)(state)(endpoint)(has_endpoint)(created_at_milliseconds)(updated_at_milliseconds));

REFLECT_STRUCT(webrtc::lifecycle_debug_endpoint_entry,
               (endpoint)(session_id)(has_endpoint)(has_forward_session_index)(has_reverse_endpoint_index)(has_last_seen)(last_seen_milliseconds));

REFLECT_STRUCT(webrtc::lifecycle_debug_snapshot, (registry_stream_count)(registry_publisher_count)(registry_subscriber_count)(registry_session_count)(registry_pending_session_count)(endpoint_count)(endpoint_session_index_count)(endpoint_reverse_index_count)(endpoint_last_seen_count)(candidate_pair_count)(selected_candidate_pair_count)(payload_type_mapping_count)(keyframe_request_state_count)(dtls_peer_count)(srtp_peer_count)(media_router_peer_count)(media_router_stream_count)(media_router_active_publisher_count)(media_router_active_subscriber_count)(track_binding_count)(ssrc_mapping_count)(identity_authority_track_binding_count)(identity_authority_forward_binding_count)(rtcp_report_source_count)(rtcp_report_stats_source_count)(rtcp_transport_cc_source_count)(rtcp_transport_cc_pending_packet_count)(rtp_cache_packet_count)(rtx_retransmission_index_count)(nack_retransmit_throttle_count)(idle_clean)(consistent)(inconsistency_count)(inconsistencies)(sessions)(endpoints)(residuals));

inline std::string lifecycle_debug_snapshot_to_json(const lifecycle_debug_snapshot& snapshot) { return serialize_struct(snapshot); }
}    // namespace webrtc

#endif
