#ifndef SIMPLE_WEBRTC_SERVER_SIGNALING_JSON_H
#define SIMPLE_WEBRTC_SERVER_SIGNALING_JSON_H

#include <string>
#include <string_view>

#include "util/reflect.h"

namespace webrtc
{
struct error_response
{
    std::string error;
};

struct session_created_response
{
    std::string type;
    std::string stream_id;
    std::string session_id;
    std::string state;
    std::string message;
};

REFLECT_STRUCT(webrtc::error_response, (error));                                                    // NOLINT
REFLECT_STRUCT(webrtc::session_created_response, (type)(stream_id)(session_id)(state)(message));    // NOLINT

inline std::string make_error_response_body(std::string_view message)
{
    error_response response;
    response.error = std::string(message);
    return serialize_struct(response);
}

inline std::string make_session_created_response_body(
    std::string_view type, std::string_view stream_id, std::string_view session_id, std::string_view state, std::string_view message)
{
    session_created_response response;
    response.type = std::string(type);
    response.stream_id = std::string(stream_id);
    response.session_id = std::string(session_id);
    response.state = std::string(state);
    response.message = std::string(message);
    return serialize_struct(response);
}
}    // namespace webrtc

#endif
