#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_JSON_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_JSON_H

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

inline std::expected<std::vector<remote_ice_candidate>, std::string> parse_trickle_ice_candidates(std::string_view body)
{
    if (body.empty())
    {
        return std::unexpected(std::string("empty trickle ice request"));
    }

    std::vector<trickle_ice_candidate_request> requests;
    trickle_ice_candidate_batch_request batch_request;

    if (deserialize_struct(batch_request, body.data(), body.size()))
    {
        requests = std::move(batch_request.candidates);
    }
    else
    {
        trickle_ice_candidate_request request;

        if (!deserialize_struct(request, body.data(), body.size()))
        {
            return std::unexpected(std::string("invalid trickle ice json"));
        }

        requests.push_back(std::move(request));
    }

    std::vector<remote_ice_candidate> candidates;

    candidates.reserve(requests.size());

    for (std::size_t index = 0; index < requests.size(); ++index)
    {
        const auto& request = requests[index];

        auto candidate = make_remote_ice_candidate(request.candidate, request.sdpMid, request.sdpMLineIndex);

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
