#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_ANSWER_BUILDER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_ANSWER_BUILDER_H

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "signaling/sdp/sdp_summary.h"
#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
struct sdp_ice_candidate_options
{
    std::string foundation = "1";
    uint32_t component = 1;
    std::string transport = "udp";
    uint32_t priority = 2130706431;
    std::string address;
    uint16_t port = 0;
    std::string type = "host";
};

struct sdp_answer_media_source
{
    std::string mid;
    std::string kind;

    uint32_t ssrc = 0;

    uint32_t rtx_repair_ssrc = 0;

    std::string cname;
    std::string stream_id;
    std::string track_id;
};

struct sdp_answer_options
{
    uint64_t session_id = 1;
    uint64_t session_version = 1;

    std::string media_address = "0.0.0.0";

    std::string local_ice_ufrag;
    std::string local_ice_pwd;

    fingerprint_info local_fingerprint;

    std::vector<sdp_ice_candidate_options> local_candidates;

    std::string local_stream_id = "-";
    std::vector<sdp_answer_media_source> media_sources;
};

using sdp_answer_text_result = std::expected<std::string, std::string>;

[[nodiscard]] sdp_answer_text_result build_whip_answer_sdp(const webrtc_offer_summary& offer, const sdp_answer_options& options);

[[nodiscard]]
sdp_answer_text_result build_whep_answer_sdp(const webrtc_offer_summary& subscriber_offer,
                                             const webrtc_offer_summary& publisher_offer,
                                             const sdp_answer_options& options);
}    // namespace webrtc::sdp

#endif
