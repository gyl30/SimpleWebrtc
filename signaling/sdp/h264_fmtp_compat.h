#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_H264_FMTP_COMPAT_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_H264_FMTP_COMPAT_H

#include <expected>
#include <string>
#include <string_view>

namespace webrtc::sdp
{
[[nodiscard]]
std::expected<std::string, std::string> negotiate_h264_fmtp_for_answer(std::string_view offer_fmtp, std::string_view local_fmtp);

[[nodiscard]]
std::expected<bool, std::string> check_h264_fmtp_relay_compatibility(std::string_view publisher_fmtp, std::string_view subscriber_fmtp);

}    // namespace webrtc::sdp

#endif
