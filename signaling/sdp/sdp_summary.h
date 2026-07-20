#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_SUMMARY_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_SUMMARY_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <optional>
#include <span>
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
struct rid_summary
{
    std::string id;
    std::string direction;
};

struct simulcast_summary
{
    std::vector<std::string> send_rids;
    std::vector<std::string> recv_rids;
};

struct msid_summary
{
    std::string stream_id;
    std::string track_id;
};
struct media_summary
{
    std::string kind;
    std::string mid;
    media_direction direction = media_direction::unknown;
    bool rtcp_mux = false;
    bool rtcp_rsize = false;
    bool extmap_allow_mixed = false;

    std::optional<uint32_t> ptime;
    std::optional<uint32_t> maxptime;

    std::vector<uint16_t> payload_types;
    std::vector<codec_info> codecs;
    std::vector<rtp_header_extension> header_extensions;
    std::vector<ssrc_group_summary> ssrc_groups;

    std::vector<rid_summary> rids;
    std::optional<simulcast_summary> simulcast;
    std::vector<msid_summary> msids;
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
std::expected<webrtc_offer_summary, std::string> make_offer_summary(const webrtc_offer_summary& original_offer,
                                                                    std::span<const int> accepted_mline_indexes);

[[nodiscard]]
bool media_has_rtx_codec(const media_summary& media);

[[nodiscard]] webrtc_offer_summary_result extract_webrtc_offer_summary(const session_description& description);
}    // namespace webrtc::sdp

#endif
