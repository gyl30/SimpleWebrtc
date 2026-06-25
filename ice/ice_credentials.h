#ifndef SIMPLE_WEBRTC_ICE_ICE_CREDENTIALS_H
#define SIMPLE_WEBRTC_ICE_ICE_CREDENTIALS_H

#include <expected>
#include <string>

namespace webrtc
{
struct ice_credentials
{
    std::string ufrag;
    std::string pwd;
};

using ice_credentials_result = std::expected<ice_credentials, std::string>;

[[nodiscard]] ice_credentials_result generate_ice_credentials();
}    // namespace webrtc

#endif
