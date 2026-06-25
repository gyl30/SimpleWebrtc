#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_PARSER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_PARSER_H

#include <string>
#include <string_view>

#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
struct sdp_parse_result
{
    bool success = false;
    std::string error;
    session_description description;
};

sdp_parse_result parse_session_description(std::string_view text);
}    // namespace webrtc::sdp

#endif
