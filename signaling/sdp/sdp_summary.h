#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_SUMMARY_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_SUMMARY_H

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
struct fingerprint_info
{
    std::string algorithm;
    std::string value;
};

struct codec_info
{
    uint16_t payload_type = 0;
    std::string name;
    uint32_t clock_rate = 0;
    std::string encoding_parameters;
    std::string fmtp;
    std::vector<std::string> rtcp_feedback;
};
struct ssrc_group_summary
{
    std::string semantics;
    std::vector<uint32_t> ssrcs;
};
struct media_summary
{
    std::string kind;
    std::string mid;
    media_direction direction = media_direction::unknown;
    bool rtcp_mux = false;

    std::vector<uint16_t> payload_types;
    std::vector<codec_info> codecs;
    std::vector<rtp_header_extension> header_extensions;
    std::vector<ssrc_group_summary> ssrc_groups;
};

struct webrtc_offer_summary
{
    std::string ice_ufrag;
    std::string ice_pwd;
    fingerprint_info fingerprint;
    dtls_connection_role setup = dtls_connection_role::unknown;
    std::vector<std::string> bundle_mids;
    std::vector<media_summary> media;
};

using webrtc_offer_summary_result = std::expected<webrtc_offer_summary, std::string>;

[[nodiscard]]
std::optional<uint32_t> find_rtx_primary_ssrc(const media_summary& media, uint32_t repair_ssrc);

[[nodiscard]]
std::optional<uint32_t> find_rtx_repair_ssrc(const media_summary& media, uint32_t primary_ssrc);

[[nodiscard]]
bool media_ssrc_is_rtx_repair(const media_summary& media, uint32_t ssrc);

[[nodiscard]] webrtc_offer_summary_result extract_webrtc_offer_summary(const session_description& description);
}    // namespace webrtc::sdp

#endif
