#ifndef SIMPLE_WEBRTC_SESSION_SESSION_STATE_H
#define SIMPLE_WEBRTC_SESSION_SESSION_STATE_H

#include <string_view>

namespace webrtc
{
enum class session_state
{
    created,
    sdp_received,
    sdp_answered,
    ice_connected,
    dtls_connected,
    closed,
};

inline std::string_view session_state_to_string(session_state state)
{
    switch (state)
    {
        case session_state::created:
            return "created";
        case session_state::sdp_received:
            return "sdp_received";
        case session_state::sdp_answered:
            return "sdp_answered";
        case session_state::ice_connected:
            return "ice_connected";
        case session_state::dtls_connected:
            return "dtls_connected";
        case session_state::closed:
            return "closed";
    }

    return "unknown";
}
}    // namespace webrtc

#endif
