#include <charconv>
#include <string>
#include <utility>
#include "signaling/sdp/sdp_types.h"

namespace webrtc::sdp
{
namespace
{
std::string_view trim_left(std::string_view value)
{
    const auto position = value.find_first_not_of(" \t");
    if (position == std::string_view::npos)
    {
        return {};
    }

    return value.substr(position);
}

std::string_view trim_right(std::string_view value)
{
    const auto position = value.find_last_not_of(" \t");
    if (position == std::string_view::npos)
    {
        return {};
    }

    return value.substr(0, position + 1);
}

std::string_view trim(std::string_view value) { return trim_right(trim_left(value)); }
}    // namespace

sdp_attribute make_property_attribute(std::string key)
{
    return sdp_attribute{
        .key = std::move(key),
        .value = "",
    };
}

sdp_attribute make_attribute(std::string key, std::string value)
{
    return sdp_attribute{
        .key = std::move(key),
        .value = std::move(value),
    };
}

std::optional<std::string> media_description::find_attribute_value(std::string_view key) const
{
    for (const auto& attribute : attributes)
    {
        if (attribute.key == key)
        {
            return attribute.value;
        }
    }

    return std::nullopt;
}

std::vector<const sdp_attribute*> media_description::find_attributes(std::string_view key) const
{
    std::vector<const sdp_attribute*> result;

    for (const auto& attribute : attributes)
    {
        if (attribute.key == key)
        {
            result.push_back(&attribute);
        }
    }

    return result;
}

std::string_view to_string(media_direction direction)
{
    switch (direction)
    {
        case media_direction::send_recv:
            return "sendrecv";
        case media_direction::send_only:
            return "sendonly";
        case media_direction::recv_only:
            return "recvonly";
        case media_direction::inactive:
            return "inactive";
        case media_direction::unknown:
            return "";
    }

    return "";
}

namespace
{
std::optional<media_direction> parse_media_direction(std::string_view value)
{
    if (value == "sendrecv")
    {
        return media_direction::send_recv;
    }

    if (value == "sendonly")
    {
        return media_direction::send_only;
    }

    if (value == "recvonly")
    {
        return media_direction::recv_only;
    }

    if (value == "inactive")
    {
        return media_direction::inactive;
    }

    return std::nullopt;
}
}    // namespace

std::string_view to_string(dtls_connection_role role)
{
    switch (role)
    {
        case dtls_connection_role::active:
            return "active";
        case dtls_connection_role::passive:
            return "passive";
        case dtls_connection_role::actpass:
            return "actpass";
        case dtls_connection_role::holdconn:
            return "holdconn";
        case dtls_connection_role::unknown:
            return "";
    }

    return "";
}

std::optional<dtls_connection_role> parse_dtls_connection_role(std::string_view value)
{
    if (value == "active")
    {
        return dtls_connection_role::active;
    }

    if (value == "passive")
    {
        return dtls_connection_role::passive;
    }

    if (value == "actpass")
    {
        return dtls_connection_role::actpass;
    }

    if (value == "holdconn")
    {
        return dtls_connection_role::holdconn;
    }

    return std::nullopt;
}

bool rtp_header_extension::parse_attribute_value(std::string_view value)
{
    value = trim(value);
    if (value.empty())
    {
        return false;
    }

    const auto first_space = value.find_first_of(" \t");
    if (first_space == std::string_view::npos)
    {
        return false;
    }

    const auto id_and_direction = value.substr(0, first_space);
    auto rest = trim(value.substr(first_space + 1));

    if (rest.empty())
    {
        return false;
    }

    const auto slash_position = id_and_direction.find('/');
    const auto id_text = slash_position == std::string_view::npos ? id_and_direction : id_and_direction.substr(0, slash_position);

    int parsed_id = 0;
    const auto parse_result = std::from_chars(id_text.data(), id_text.data() + id_text.size(), parsed_id);
    if (parse_result.ec != std::errc() || parsed_id < 1 || parsed_id > 246)
    {
        return false;
    }

    id = parsed_id;

    if (slash_position != std::string_view::npos)
    {
        const auto direction_text = id_and_direction.substr(slash_position + 1);
        auto parsed_direction = parse_media_direction(direction_text);
        if (!parsed_direction.has_value())
        {
            return false;
        }

        direction = parsed_direction.value();
    }
    else
    {
        direction = media_direction::unknown;
    }

    const auto second_space = rest.find_first_of(" \t");
    if (second_space == std::string_view::npos)
    {
        uri = std::string(rest);
        extension_attributes.reset();
        return !uri.empty();
    }

    uri = std::string(rest.substr(0, second_space));

    auto attributes_text = trim(rest.substr(second_space + 1));
    if (!attributes_text.empty())
    {
        extension_attributes = std::string(attributes_text);
    }
    else
    {
        extension_attributes.reset();
    }

    return !uri.empty();
}

std::optional<std::string> session_description::find_attribute_value(std::string_view key) const
{
    for (const auto& attribute : attributes)
    {
        if (attribute.key == key)
        {
            return attribute.value;
        }
    }

    return std::nullopt;
}

std::vector<const sdp_attribute*> session_description::find_attributes(std::string_view key) const
{
    std::vector<const sdp_attribute*> result;

    for (const auto& attribute : attributes)
    {
        if (attribute.key == key)
        {
            result.push_back(&attribute);
        }
    }

    return result;
}
}    // namespace webrtc::sdp
