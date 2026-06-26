#ifndef SIMPLE_WEBRTC_MEDIA_KEYFRAME_REQUEST_H
#define SIMPLE_WEBRTC_MEDIA_KEYFRAME_REQUEST_H

#include <cstdint>
#include <expected>
#include <string>

namespace webrtc
{
struct keyframe_request_result
{
    std::string stream_id;
    std::string publisher_session_id;
    std::string publisher_remote_address;

    uint64_t media_ssrc_count = 0;
    uint64_t sent_count = 0;
    uint64_t failed_count = 0;
};

using keyframe_request_expected = std::expected<keyframe_request_result, std::string>;
}    // namespace webrtc

#endif
