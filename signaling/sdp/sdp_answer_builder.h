#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_ANSWER_BUILDER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_ANSWER_BUILDER_H

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

#include "signaling/sdp/sdp_summary.h"
#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
struct sdp_answer_media_source
{
    std::string mid;
    std::string kind;

    uint32_t ssrc = 0;

    uint32_t rtx_repair_ssrc = 0;

    std::string cname;
};

struct sdp_answer_options
{
    uint64_t session_id = 1;
    uint64_t session_version = 1;

    std::string local_ice_ufrag;
    std::string local_ice_pwd;

    fingerprint_info local_fingerprint;

    std::span<const std::string> local_candidate_addresses;
    uint16_t local_candidate_port = 0;

    std::string local_stream_id = "-";
    std::vector<sdp_answer_media_source> media_sources;
};

struct generated_sdp_answer_text
{
    std::string sdp;
    std::vector<std::string> accepted_mids;
    std::vector<int> accepted_mline_indexes;
};

using sdp_answer_text_result = std::expected<generated_sdp_answer_text, std::string>;

[[nodiscard]] sdp_answer_text_result build_whip_answer_sdp(const webrtc_offer_summary& offer, const sdp_answer_options& options);

[[nodiscard]]
sdp_answer_text_result build_whep_answer_sdp(const webrtc_offer_summary& subscriber_offer,
                                             const webrtc_offer_summary& publisher_offer,
                                             const sdp_answer_options& options);
}    // namespace webrtc::sdp

#endif
