#ifndef SIMPLE_WEBRTC_SESSION_SESSION_STATE_H
#define SIMPLE_WEBRTC_SESSION_SESSION_STATE_H

#include <string_view>

namespace webrtc
{
enum class session_state
{
    sdp_received,
    sdp_answered,
};

inline std::string_view session_state_to_string(session_state state)
{
    switch (state)
    {
        case session_state::sdp_received:
            return "sdp_received";
        case session_state::sdp_answered:
            return "sdp_answered";
    }

    return "unknown";
}
}    // namespace webrtc

#endif
