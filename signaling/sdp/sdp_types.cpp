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

std::string sdp_address::to_string() const
{
    std::string result = address;

    if (ttl.has_value())
    {
        result += "/";
        result += std::to_string(ttl.value());
    }

    if (range.has_value())
    {
        result += "/";
        result += std::to_string(range.value());
    }

    return result;
}

std::string connection_information::to_string() const
{
    std::string result = network_type;
    result += " ";
    result += address_type;

    if (address.has_value())
    {
        result += " ";
        result += address->to_string();
    }

    return result;
}

std::string bandwidth_line::to_string() const
{
    std::string result;

    if (experimental)
    {
        result += "X-";
    }

    result += type;
    result += ":";
    result += std::to_string(value);

    return result;
}

bool sdp_attribute::is_property() const { return value.empty(); }

bool sdp_attribute::is_ice_candidate() const { return key == k_attribute_candidate; }

std::string sdp_attribute::to_string() const
{
    if (value.empty())
    {
        return key;
    }

    return key + ":" + value;
}

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

std::string sdp_version::to_string() const { return std::to_string(value); }

std::string origin_line::to_string() const
{
    std::string result;
    result.reserve(username.size() + network_type.size() + address_type.size() + unicast_address.size() + 64);

    result += username;
    result += " ";
    result += std::to_string(session_id);
    result += " ";
    result += std::to_string(session_version);
    result += " ";
    result += network_type;
    result += " ";
    result += address_type;
    result += " ";
    result += unicast_address;

    return result;
}

std::string ranged_port::to_string() const
{
    std::string result = std::to_string(value);

    if (range.has_value())
    {
        result += "/";
        result += std::to_string(range.value());
    }

    return result;
}

std::string media_name_line::to_string() const
{
    std::string result;

    result += media;
    result += " ";
    result += port.to_string();
    result += " ";

    for (std::size_t i = 0; i < protocols.size(); ++i)
    {
        if (i > 0)
        {
            result += "/";
        }

        result += protocols[i];
    }

    result += " ";

    for (std::size_t i = 0; i < formats.size(); ++i)
    {
        if (i > 0)
        {
            result += " ";
        }

        result += formats[i];
    }

    return result;
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

std::string timing_line::to_string() const { return std::to_string(start_time) + " " + std::to_string(stop_time); }

std::string repeat_time::to_string() const
{
    std::string result;

    result += std::to_string(interval);
    result += " ";
    result += std::to_string(duration);

    for (const auto offset : offsets)
    {
        result += " ";
        result += std::to_string(offset);
    }

    return result;
}

std::string time_zone::to_string() const { return std::to_string(adjustment_time) + " " + std::to_string(offset); }

std::string codec_description::to_string() const
{
    std::string result;

    result += std::to_string(payload_type);

    if (!name.empty())
    {
        result += " ";
        result += name;

        if (clock_rate != 0)
        {
            result += "/";
            result += std::to_string(clock_rate);
        }

        if (!encoding_parameters.empty())
        {
            result += "/";
            result += encoding_parameters;
        }
    }

    if (!fmtp.empty())
    {
        result += " fmtp=[";
        result += fmtp;
        result += "]";
    }

    if (!rtcp_feedback.empty())
    {
        result += " rtcp_feedback=[";

        for (std::size_t i = 0; i < rtcp_feedback.size(); ++i)
        {
            if (i > 0)
            {
                result += ", ";
            }

            result += rtcp_feedback[i];
        }

        result += "]";
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

std::string rtp_header_extension::to_attribute_value() const
{
    std::string result = std::to_string(id);

    const auto direction_text = to_string(direction);
    if (!direction_text.empty())
    {
        result += "/";
        result += direction_text;
    }

    if (!uri.empty())
    {
        result += " ";
        result += uri;
    }

    if (extension_attributes.has_value() && !extension_attributes->empty())
    {
        result += " ";
        result += extension_attributes.value();
    }

    return result;
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
