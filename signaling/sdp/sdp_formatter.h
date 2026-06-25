#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_FORMATTER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_FORMATTER_H

#include <expected>
#include <string>

#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
using sdp_format_result = std::expected<std::string, std::string>;

[[nodiscard]] sdp_format_result format_session_description(const session_description& description);
}    // namespace webrtc::sdp

#endif
