#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_ANSWER_BUILDER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_ANSWER_BUILDER_H

#include <cstdint>
#include <expected>
#include <string>

#include "signaling/sdp/sdp_summary.h"
#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
struct sdp_answer_options
{
    std::string origin_username = "-";
    uint64_t session_id = 1;
    uint64_t session_version = 1;

    std::string network_type = "IN";
    std::string address_type = "IP4";
    std::string unicast_address = "0.0.0.0";
    std::string media_address = "0.0.0.0";

    std::string local_ice_ufrag;
    std::string local_ice_pwd;

    fingerprint_info local_fingerprint;

    dtls_connection_role local_setup = dtls_connection_role::passive;

    bool ice_lite = false;
    bool enable_trickle = true;

    bool include_host_candidate = false;
    std::string local_candidate_foundation = "1";
    uint32_t local_candidate_component = 1;
    std::string local_candidate_transport = "udp";
    uint32_t local_candidate_priority = 2130706431;
    std::string local_candidate_address;
    uint16_t local_candidate_port = 0;
    std::string local_candidate_type = "host";
    bool end_of_candidates = true;

    std::string local_stream_id = "-";
};

using sdp_answer_result = std::expected<session_description, std::string>;

using sdp_answer_text_result = std::expected<std::string, std::string>;

[[nodiscard]] sdp_answer_result build_whip_answer(const webrtc_offer_summary& offer, const sdp_answer_options& options);

[[nodiscard]] sdp_answer_result build_whep_answer(const webrtc_offer_summary& offer, const sdp_answer_options& options);

[[nodiscard]] sdp_answer_text_result build_whip_answer_sdp(const webrtc_offer_summary& offer, const sdp_answer_options& options);

[[nodiscard]] sdp_answer_text_result build_whep_answer_sdp(const webrtc_offer_summary& offer, const sdp_answer_options& options);
}    // namespace webrtc::sdp

#endif
