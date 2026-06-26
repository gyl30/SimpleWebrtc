#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_JSON_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_JSON_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include "ice/ice_candidate.h"
#include "util/reflect.h"

namespace webrtc
{
struct trickle_ice_candidate_request
{
    std::string candidate;
    std::string sdpMid;
    int sdpMLineIndex = -1;
};

REFLECT_STRUCT(webrtc::trickle_ice_candidate_request,
               (candidate)(sdpMid)(sdpMLineIndex));    // NOLINT

inline std::expected<trickle_ice_candidate_request, std::string> parse_trickle_ice_candidate_request(std::string_view body)
{
    if (body.empty())
    {
        return std::unexpected(std::string("empty trickle ice request"));
    }

    trickle_ice_candidate_request request;

    if (!deserialize_struct(request, body.data(), body.size()))
    {
        return std::unexpected(std::string("invalid trickle ice json"));
    }

    return request;
}

inline remote_ice_candidate_result make_remote_ice_candidate_from_trickle_request(const trickle_ice_candidate_request& request,
                                                                                  uint64_t received_at_milliseconds)
{
    return make_remote_ice_candidate(request.candidate, request.sdpMid, request.sdpMLineIndex, received_at_milliseconds);
}
}    // namespace webrtc

#endif
