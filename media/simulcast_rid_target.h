#ifndef SIMPLE_WEBRTC_MEDIA_SIMULCAST_RID_TARGET_H
#define SIMPLE_WEBRTC_MEDIA_SIMULCAST_RID_TARGET_H

#include <cstdint>
#include <expected>
#include <functional>
#include <string>

namespace webrtc
{
struct simulcast_rid_target_request
{
    std::string stream_id;
    std::string publisher_session_id;
    std::string subscriber_session_id;
    std::string mid;
    std::string kind;
    std::string target_rid;
    std::string reason;

    bool clear = false;
};

struct simulcast_rid_target_result
{
    std::string stream_id;
    std::string publisher_session_id;
    std::string subscriber_session_id;
    std::string mid;
    std::string kind;
    std::string target_rid;
    std::string policy;
    std::string reason;

    bool changed = false;
    bool cleared = false;
    bool selected_state_found = false;

    uint64_t updated_at_milliseconds = 0;
    uint64_t applied_count = 0;
};

using simulcast_rid_target_expected = std::expected<simulcast_rid_target_result, std::string>;

using simulcast_rid_target_handler = std::function<simulcast_rid_target_expected(const simulcast_rid_target_request&)>;
}    // namespace webrtc

#endif
