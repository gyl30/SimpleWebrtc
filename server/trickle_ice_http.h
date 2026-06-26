#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H

#include <cstddef>
#include <string>
#include <string_view>

#include "net/http.h"

namespace webrtc
{
inline constexpr std::string_view k_trickle_ice_patch_accept_patch_value = "application/trickle-ice-sdpfrag, application/json";

inline constexpr std::string_view k_trickle_ice_expose_headers_value = "Location, ETag, Accept-Patch";

inline constexpr std::size_t k_trickle_ice_max_patch_body_bytes = 64 * 1024;

inline constexpr std::size_t k_trickle_ice_max_candidates_per_patch = 32;

inline void set_trickle_ice_patch_headers(const http_response_ptr& response)
{
    if (response == nullptr)
    {
        return;
    }

    response->set("Accept-Patch", std::string(k_trickle_ice_patch_accept_patch_value));
}

inline bool trickle_ice_patch_body_too_large(std::size_t body_size) { return body_size > k_trickle_ice_max_patch_body_bytes; }

inline bool trickle_ice_candidate_batch_too_large(std::size_t candidate_count) { return candidate_count > k_trickle_ice_max_candidates_per_patch; }
}    // namespace webrtc

#endif
