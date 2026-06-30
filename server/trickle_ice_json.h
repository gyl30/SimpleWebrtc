#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_JSON_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_JSON_H

#include <cstdint>
#include <expected>
#include <string>
#include <vector>
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

REFLECT_STRUCT(webrtc::trickle_ice_candidate_request, (candidate)(sdpMid)(sdpMLineIndex));    // NOLINT

struct trickle_ice_candidate_batch_request
{
    std::vector<trickle_ice_candidate_request> candidates;
};

REFLECT_STRUCT(webrtc::trickle_ice_candidate_batch_request, (candidates));    // NOLINT

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
inline std::expected<std::vector<trickle_ice_candidate_request>, std::string> parse_trickle_ice_candidate_requests(std::string_view body)
{
    if (body.empty())
    {
        return std::unexpected(std::string("empty trickle ice request"));
    }

    trickle_ice_candidate_batch_request batch_request;

    if (deserialize_struct(batch_request, body.data(), body.size()))
    {
        return std::move(batch_request.candidates);
    }

    auto single_request = parse_trickle_ice_candidate_request(body);

    if (!single_request)
    {
        return std::unexpected(single_request.error());
    }

    std::vector<trickle_ice_candidate_request> requests;

    requests.push_back(std::move(*single_request));

    return requests;
}

inline remote_ice_candidate_result make_remote_ice_candidate_from_trickle_request(const trickle_ice_candidate_request& request,
                                                                                  uint64_t received_at_milliseconds)
{
    return make_remote_ice_candidate(request.candidate, request.sdpMid, request.sdpMLineIndex, received_at_milliseconds);
}
inline std::expected<std::vector<remote_ice_candidate>, std::string> make_remote_ice_candidates_from_trickle_requests(
    const std::vector<trickle_ice_candidate_request>& requests, uint64_t received_at_milliseconds)
{
    std::vector<remote_ice_candidate> candidates;

    candidates.reserve(requests.size());

    for (std::size_t index = 0; index < requests.size(); ++index)
    {
        auto candidate = make_remote_ice_candidate_from_trickle_request(requests[index], received_at_milliseconds);

        if (!candidate)
        {
            std::string message = "trickle ice json candidate ";

            message.append(std::to_string(index));

            message.append(" is invalid: ");

            message.append(candidate.error());

            return std::unexpected(std::move(message));
        }

        candidates.push_back(std::move(*candidate));
    }

    return candidates;
}
}    // namespace webrtc

#endif
