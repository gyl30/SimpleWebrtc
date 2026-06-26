#ifndef SIMPLE_WEBRTC_SERVER_SIGNALING_JSON_H
#define SIMPLE_WEBRTC_SERVER_SIGNALING_JSON_H

#include <string>
#include <string_view>

#include "util/reflect.h"
#include "session/stream_registry.h"

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
struct session_lifecycle_entry_response
{
    std::string type;
    std::string stream_id;
    std::string session_id;
    std::string state;
    uint64_t created_at_milliseconds = 0;
    uint64_t updated_at_milliseconds = 0;
};

struct session_lifecycle_response
{
    uint64_t publisher_count = 0;
    uint64_t subscriber_count = 0;
    uint64_t session_count = 0;
    std::vector<session_lifecycle_entry_response> sessions;
};

struct stream_detail_response
{
    std::string stream_id;
    uint64_t publisher_count = 0;
    uint64_t subscriber_count = 0;
    uint64_t session_count = 0;
    std::vector<session_lifecycle_entry_response> sessions;
};

REFLECT_STRUCT(webrtc::error_response, (error));                                                    // NOLINT
REFLECT_STRUCT(webrtc::session_created_response, (type)(stream_id)(session_id)(state)(message));    // NOLINT
REFLECT_STRUCT(webrtc::session_lifecycle_entry_response,
               (type)(stream_id)(session_id)(state)(created_at_milliseconds)(updated_at_milliseconds));                     // NOLINT
REFLECT_STRUCT(webrtc::session_lifecycle_response, (publisher_count)(subscriber_count)(session_count)(sessions));           // NOLINT
REFLECT_STRUCT(webrtc::stream_detail_response, (stream_id)(publisher_count)(subscriber_count)(session_count)(sessions));    // NOLINT

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
inline uint64_t to_json_count(std::size_t value) { return static_cast<uint64_t>(value); }

inline session_lifecycle_entry_response make_session_lifecycle_entry_response(const stream_session_lifecycle_snapshot& snapshot)
{
    session_lifecycle_entry_response response;

    response.type = std::string(stream_session_kind_to_string(snapshot.kind));
    response.stream_id = snapshot.stream_id;
    response.session_id = snapshot.session_id;
    response.state = std::string(session_state_to_string(snapshot.state));
    response.created_at_milliseconds = snapshot.created_at_milliseconds;
    response.updated_at_milliseconds = snapshot.updated_at_milliseconds;

    return response;
}
inline std::string make_session_lifecycle_entry_response_body(const stream_session_lifecycle_snapshot& snapshot)
{
    auto response = make_session_lifecycle_entry_response(snapshot);
    return webrtc::serialize_struct(response);
}

inline std::string make_session_lifecycle_response_body(const std::vector<stream_session_lifecycle_snapshot>& snapshots)
{
    session_lifecycle_response response;

    response.sessions.reserve(snapshots.size());

    for (const auto& snapshot : snapshots)
    {
        if (snapshot.kind == stream_session_kind::publisher)
        {
            response.publisher_count += 1;
        }
        else if (snapshot.kind == stream_session_kind::subscriber)
        {
            response.subscriber_count += 1;
        }

        response.sessions.push_back(make_session_lifecycle_entry_response(snapshot));
    }

    response.session_count = to_json_count(response.sessions.size());

    return serialize_struct(response);
}
inline std::string make_stream_detail_response_body(std::string_view stream_id, const std::vector<stream_session_lifecycle_snapshot>& snapshots)
{
    stream_detail_response response;

    response.stream_id = std::string(stream_id);

    response.sessions.reserve(snapshots.size());

    for (const auto& snapshot : snapshots)
    {
        if (std::string_view(snapshot.stream_id) != stream_id)
        {
            continue;
        }

        if (snapshot.kind == stream_session_kind::publisher)
        {
            response.publisher_count += 1;
        }
        else if (snapshot.kind == stream_session_kind::subscriber)
        {
            response.subscriber_count += 1;
        }

        response.sessions.push_back(make_session_lifecycle_entry_response(snapshot));
    }

    response.session_count = to_json_count(response.sessions.size());

    return serialize_struct(response);
}
}    // namespace webrtc

#endif
