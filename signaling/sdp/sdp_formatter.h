#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_FORMATTER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_FORMATTER_H

#include <string>

#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
[[nodiscard]] std::string format_session_description(const session_description& description);
}    // namespace webrtc::sdp

#endif
