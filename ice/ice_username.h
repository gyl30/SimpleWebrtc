#ifndef SIMPLE_WEBRTC_ICE_ICE_USERNAME_H
#define SIMPLE_WEBRTC_ICE_ICE_USERNAME_H

#include <expected>
#include <string>
#include <string_view>

#include "ice/stun_message.h"

namespace webrtc
{
struct ice_username_parts
{
    std::string_view recipient_ufrag;
    std::string_view sender_ufrag;
};

std::expected<ice_username_parts, std::string> parse_ice_username(std::string_view username);

std::expected<void, std::string> validate_ice_connectivity_check(const stun_message& message);
}    // namespace webrtc

#endif
