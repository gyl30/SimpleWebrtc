#include "ice/ice_username.h"

#include <cctype>
#include <cstddef>
#include <string>
#include <utility>

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_ice_username_fragment_size = 256;
constexpr std::size_t k_max_ice_username_size = (k_max_ice_username_fragment_size * 2) + 1;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_field_error(std::string_view field, std::string_view message)
{
    std::string error;

    error.reserve(field.size() + message.size() + 2);

    error.append(field);
    error.push_back(' ');
    error.append(message);

    return std::unexpected(std::move(error));
}

bool is_valid_ice_username_character(char value)
{
    const auto byte = static_cast<unsigned char>(value);

    return std::isalnum(byte) != 0 || value == '+' || value == '/';
}

std::expected<void, std::string> validate_ice_username_fragment(std::string_view fragment, std::string_view field_name)
{
    if (fragment.empty())
    {
        return make_field_error(field_name, "is empty");
    }

    if (fragment.size() > k_max_ice_username_fragment_size)
    {
        return make_field_error(field_name, "is too large");
    }

    for (const char value : fragment)
    {
        if (!is_valid_ice_username_character(value))
        {
            return make_field_error(field_name, "contains invalid characters");
        }
    }

    return {};
}
}    // namespace

std::expected<ice_username_parts, std::string> parse_ice_username(std::string_view username)
{
    if (username.empty())
    {
        return make_error("ice username is empty");
    }

    if (username.size() > k_max_ice_username_size)
    {
        return make_error("ice username is too large");
    }

    const std::size_t separator = username.find(':');

    if (separator == std::string_view::npos)
    {
        return make_error("ice username separator is missing");
    }

    if (username.find(':', separator + 1) != std::string_view::npos)
    {
        return make_error("ice username contains multiple separators");
    }

    ice_username_parts parts;

    parts.recipient_ufrag = username.substr(0, separator);

    parts.sender_ufrag = username.substr(separator + 1);

    auto recipient_result = validate_ice_username_fragment(parts.recipient_ufrag, "ice username recipient ufrag");

    if (!recipient_result)
    {
        return std::unexpected(recipient_result.error());
    }

    auto sender_result = validate_ice_username_fragment(parts.sender_ufrag, "ice username sender ufrag");

    if (!sender_result)
    {
        return std::unexpected(sender_result.error());
    }

    return parts;
}

std::expected<void, std::string> validate_ice_connectivity_check(const stun_message& message)
{
    if (!message.priority.has_value())
    {
        return make_error("ice connectivity check missing priority");
    }

    if (*message.priority == 0)
    {
        return make_error("ice connectivity check priority is zero");
    }

    if (!message.ice_controlling.has_value())
    {
        return make_error("ice-lite connectivity check missing ice-controlling");
    }

    if (message.ice_controlled.has_value())
    {
        return make_error("ice-lite connectivity check contains ice-controlled");
    }

    return {};
}
}    // namespace webrtc
