#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_PARSER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_PARSER_H

#include <expected>
#include <string>
#include <string_view>

#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
using session_description_result = std::expected<session_description, std::string>;

[[nodiscard]] session_description_result parse_session_description(std::string_view text);
}    // namespace webrtc::sdp

#endif
