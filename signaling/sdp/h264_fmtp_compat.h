#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_H264_FMTP_COMPAT_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_H264_FMTP_COMPAT_H

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace webrtc::sdp
{
enum class h264_profile_kind
{
    unknown,
    constrained_baseline,
    baseline,
    main,
    constrained_high,
    high
};

struct h264_profile_level_id
{
    uint8_t profile_idc = 0;
    uint8_t profile_iop = 0;
    uint8_t level_idc = 0;

    h264_profile_kind profile = h264_profile_kind::unknown;

    std::string normalized_value;
};

struct h264_fmtp_parameters
{
    bool has_packetization_mode = false;
    uint8_t packetization_mode = 0;

    bool has_level_asymmetry_allowed = false;
    bool level_asymmetry_allowed = false;

    std::optional<h264_profile_level_id> profile_level_id;
};

struct h264_fmtp_answer_negotiation
{
    h264_fmtp_parameters offer_parameters;
    h264_fmtp_parameters local_parameters;

    h264_profile_level_id selected_profile_level_id;

    uint8_t selected_packetization_mode = 1;
    bool selected_level_asymmetry_allowed = false;

    std::string answer_fmtp;
};

struct h264_fmtp_relay_compatibility
{
    h264_fmtp_parameters publisher_parameters;
    h264_fmtp_parameters subscriber_parameters;

    bool compatible = false;
    std::string reason;
};

[[nodiscard]]
std::expected<h264_fmtp_parameters, std::string> parse_h264_fmtp(std::string_view fmtp);

[[nodiscard]]
std::expected<h264_fmtp_answer_negotiation, std::string> negotiate_h264_fmtp_for_answer(std::string_view offer_fmtp, std::string_view local_fmtp);

[[nodiscard]]
std::expected<h264_fmtp_relay_compatibility, std::string> check_h264_fmtp_relay_compatibility(std::string_view publisher_fmtp,
                                                                                              std::string_view subscriber_fmtp);

}    // namespace webrtc::sdp

#endif
