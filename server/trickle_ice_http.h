#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H

#include <string>
#include <string_view>

#include "net/http.h"

namespace webrtc
{
inline constexpr std::string_view k_trickle_ice_patch_accept_patch_value = "application/trickle-ice-sdpfrag, application/json";

inline constexpr std::string_view k_trickle_ice_expose_headers_value = "Location, ETag, Accept-Patch";

inline void set_trickle_ice_patch_headers(const http_response_ptr& response)
{
    if (response == nullptr)
    {
        return;
    }

    response->set("Accept-Patch", std::string(k_trickle_ice_patch_accept_patch_value));
}
}    // namespace webrtc

#endif
