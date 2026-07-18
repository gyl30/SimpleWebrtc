#include "signaling/sdp/sdp_parser.h"

#include <charconv>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "signaling/sdp/sdp_lexer.h"

namespace webrtc::sdp
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

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

std::vector<std::string_view> split_whitespace(std::string_view value)
{
    std::vector<std::string_view> result;

    std::size_t position = 0;
    while (position < value.size())
    {
        while (position < value.size() && is_whitespace(value[position]))
        {
            ++position;
        }

        if (position >= value.size())
        {
            break;
        }

        const std::size_t start = position;

        while (position < value.size() && !is_whitespace(value[position]))
        {
            ++position;
        }

        result.push_back(value.substr(start, position - start));
    }

    return result;
}

std::vector<std::string_view> split_by_char(std::string_view value, char separator)
{
    std::vector<std::string_view> result;

    std::size_t start = 0;
    while (start <= value.size())
    {
        const std::size_t position = value.find(separator, start);
        if (position == std::string_view::npos)
        {
            result.push_back(value.substr(start));
            break;
        }

        result.push_back(value.substr(start, position - start));
        start = position + 1;
    }

    return result;
}

std::expected<uint64_t, std::string> parse_uint64_text(std::string_view value, std::string_view field_name)
{
    value = trim(value);
    if (value.empty())
    {
        std::string error(field_name);
        error += " is empty";
        return make_error(error);
    }

    uint64_t number = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), number);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size())
    {
        std::string error(field_name);
        error += " is invalid";
        return make_error(error);
    }

    return number;
}

std::expected<int32_t, std::string> parse_int32_text(std::string_view value, std::string_view field_name)
{
    value = trim(value);
    if (value.empty())
    {
        std::string error(field_name);
        error += " is empty";
        return make_error(error);
    }

    int32_t number = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), number);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size())
    {
        std::string error(field_name);
        error += " is invalid";
        return make_error(error);
    }

    return number;
}

std::expected<sdp_attribute, std::string> parse_attribute_line(std::string_view value)
{
    value = trim(value);
    if (value.empty())
    {
        return make_error("empty attribute");
    }

    const auto colon_position = value.find(':');
    if (colon_position == std::string_view::npos || colon_position == 0)
    {
        return make_property_attribute(std::string(value));
    }

    return make_attribute(std::string(value.substr(0, colon_position)), std::string(value.substr(colon_position + 1)));
}

std::expected<connection_information, std::string> parse_connection_information_line(std::string_view value)
{
    const auto fields = split_whitespace(value);

    if (fields.size() < 2)
    {
        return make_error("invalid connection information");
    }

    connection_information connection;
    connection.network_type = std::string(fields[0]);
    connection.address_type = std::string(fields[1]);

    if (!is_any_of(connection.network_type, {"IN"}))
    {
        return make_error("invalid connection network type");
    }

    if (!is_any_of(connection.address_type, {"IP4", "IP6"}))
    {
        return make_error("invalid connection address type");
    }

    if (fields.size() >= 3)
    {
        sdp_address address;
        address.address = std::string(fields[2]);
        connection.address = address;
    }

    return connection;
}

std::expected<void, std::string> validate_bandwidth_line(std::string_view value)
{
    value = trim(value);

    const auto colon_position = value.find(':');
    if (colon_position == std::string_view::npos || colon_position == 0 || colon_position + 1 >= value.size())
    {
        return make_error("invalid bandwidth line");
    }

    auto type = value.substr(0, colon_position);
    const auto bandwidth_value = value.substr(colon_position + 1);

    if (type.starts_with("X-"))
    {
        type = type.substr(2);
    }
    else if (!is_any_of(type, {"CT", "AS", "TIAS", "RS", "RR"}))
    {
        return make_error("invalid bandwidth type");
    }

    auto parsed_value = parse_uint64_text(bandwidth_value, "bandwidth value");
    if (!parsed_value)
    {
        return make_error(parsed_value.error());
    }

    return {};
}

std::expected<void, std::string> validate_timing_line(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.size() != 2)
    {
        return make_error("invalid timing line");
    }

    auto start_time = parse_uint64_text(fields[0], "timing start time");
    if (!start_time)
    {
        return make_error(start_time.error());
    }

    auto stop_time = parse_uint64_text(fields[1], "timing stop time");
    if (!stop_time)
    {
        return make_error(stop_time.error());
    }

    return {};
}

std::expected<void, std::string> validate_repeat_time_line(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.size() < 2)
    {
        return make_error("invalid repeat time line");
    }

    auto interval = parse_time_units(fields[0]);
    if (!interval)
    {
        return make_error(interval.error());
    }

    auto duration = parse_time_units(fields[1]);
    if (!duration)
    {
        return make_error(duration.error());
    }

    for (std::size_t i = 2; i < fields.size(); ++i)
    {
        auto offset = parse_time_units(fields[i]);
        if (!offset)
        {
            return make_error(offset.error());
        }
    }

    return {};
}

std::expected<void, std::string> validate_time_zone_line(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.empty() || fields.size() % 2 != 0)
    {
        return make_error("invalid time zone line");
    }

    for (std::size_t i = 0; i < fields.size(); i += 2)
    {
        auto adjustment_time = parse_uint64_text(fields[i], "time zone adjustment time");
        if (!adjustment_time)
        {
            return make_error(adjustment_time.error());
        }

        auto offset = parse_time_units(fields[i + 1]);
        if (!offset)
        {
            return make_error(offset.error());
        }
    }

    return {};
}

std::expected<ranged_port, std::string> parse_ranged_port(std::string_view value)
{
    ranged_port port;

    const auto slash_position = value.find('/');
    const auto port_text = slash_position == std::string_view::npos ? value : value.substr(0, slash_position);

    auto parsed_port = parse_port(port_text);
    if (!parsed_port)
    {
        return make_error("invalid media port");
    }

    port.value = *parsed_port;

    if (slash_position != std::string_view::npos)
    {
        const auto range_text = value.substr(slash_position + 1);
        auto range = parse_int32_text(range_text, "media port range");
        if (!range)
        {
            return make_error(range.error());
        }

        if (*range <= 0)
        {
            return make_error("invalid media port range");
        }
    }

    return port;
}

std::expected<media_name_line, std::string> parse_media_name_line(std::string_view value)
{
    const auto fields = split_whitespace(value);

    if (fields.size() < 4)
    {
        return make_error("invalid media line");
    }

    if (!is_any_of(fields[0], {"audio", "video", "text", "application", "message"}))
    {
        return make_error("invalid media type");
    }

    auto port = parse_ranged_port(fields[1]);
    if (!port)
    {
        return make_error(port.error());
    }

    media_name_line media_name;
    media_name.media = std::string(fields[0]);
    media_name.port = *port;

    const auto protocols = split_by_char(fields[2], '/');
    if (protocols.empty())
    {
        return make_error("empty media protocol");
    }

    for (const auto protocol : protocols)
    {
        if (protocol.empty())
        {
            return make_error("invalid media protocol");
        }

        if (!is_any_of(protocol,
                       {"UDP", "RTP", "AVP", "SAVP", "SAVPF", "TLS", "DTLS", "SCTP", "AVPF", "TCP", "MSRP", "BFCP", "UDT", "IX", "MRCPv2", "FEC"}))
        {
            return make_error("unsupported media protocol");
        }

        media_name.protocols.push_back(std::string(protocol));
    }

    for (std::size_t i = 3; i < fields.size(); ++i)
    {
        media_name.formats.push_back(std::string(fields[i]));
    }

    return media_name;
}

std::expected<origin_line, std::string> parse_origin_line(std::string_view value)
{
    const auto fields = split_whitespace(value);

    if (fields.size() != 6)
    {
        return make_error("invalid origin line");
    }

    auto session_id = parse_uint64_text(fields[1], "origin session id");
    if (!session_id)
    {
        return make_error(session_id.error());
    }

    auto session_version = parse_uint64_text(fields[2], "origin session version");
    if (!session_version)
    {
        return make_error(session_version.error());
    }

    origin_line origin;
    origin.username = std::string(fields[0]);
    origin.session_id = *session_id;
    origin.session_version = *session_version;
    origin.network_type = std::string(fields[3]);
    origin.address_type = std::string(fields[4]);
    origin.unicast_address = std::string(fields[5]);

    if (!is_any_of(origin.network_type, {"IN"}))
    {
        return make_error("invalid origin network type");
    }

    if (!is_any_of(origin.address_type, {"IP4", "IP6"}))
    {
        return make_error("invalid origin address type");
    }

    return origin;
}

std::expected<void, std::string> parse_session_level_line(session_description& description,
                                                          bool& has_version,
                                                          bool& has_origin,
                                                          bool& has_session_name,
                                                          bool& has_timing,
                                                          char type,
                                                          std::string_view value)
{
    switch (type)
    {
        case 'v':
        {
            auto version = parse_uint64_text(value, "sdp version");
            if (!version)
            {
                return make_error(version.error());
            }

            if (*version != 0)
            {
                return make_error("unsupported sdp version");
            }

            description.version.value = 0;
            has_version = true;
            return {};
        }

        case 'o':
        {
            auto origin = parse_origin_line(value);
            if (!origin)
            {
                return make_error(origin.error());
            }

            description.origin = *origin;
            has_origin = true;
            return {};
        }

        case 's':
            description.session_name = std::string(value);
            has_session_name = true;
            return {};

        case 'i':
            return {};

        case 'u':
            if (trim(value).empty())
            {
                return make_error("empty uri line");
            }

            return {};

        case 'e':
        case 'p':
            return {};

        case 'c':
        {
            auto connection = parse_connection_information_line(value);
            if (!connection)
            {
                return make_error(connection.error());
            }

            description.connection = *connection;
            return {};
        }

        case 'b':
        {
            auto validation = validate_bandwidth_line(value);
            if (!validation)
            {
                return make_error(validation.error());
            }

            return {};
        }

        case 't':
        {
            auto validation = validate_timing_line(value);
            if (!validation)
            {
                return make_error(validation.error());
            }

            has_timing = true;
            return {};
        }

        case 'r':
        {
            if (!has_timing)
            {
                return make_error("repeat time appears before timing");
            }

            auto validation = validate_repeat_time_line(value);
            if (!validation)
            {
                return make_error(validation.error());
            }

            return {};
        }

        case 'z':
        {
            auto validation = validate_time_zone_line(value);
            if (!validation)
            {
                return make_error(validation.error());
            }

            return {};
        }

        case 'k':
            return {};

        case 'a':
        {
            auto attribute = parse_attribute_line(value);
            if (!attribute)
            {
                return make_error(attribute.error());
            }

            description.attributes.push_back(*attribute);
            return {};
        }

        default:
            return make_error("unsupported session-level sdp line");
    }
}

std::expected<void, std::string> parse_media_level_line(media_description& media, char type, std::string_view value)
{
    switch (type)
    {
        case 'i':
            return {};

        case 'c':
        {
            auto connection = parse_connection_information_line(value);
            if (!connection)
            {
                return make_error(connection.error());
            }

            media.connection = *connection;
            return {};
        }

        case 'b':
        {
            auto validation = validate_bandwidth_line(value);
            if (!validation)
            {
                return make_error(validation.error());
            }

            return {};
        }

        case 'k':
            return {};

        case 'a':
        {
            auto attribute = parse_attribute_line(value);
            if (!attribute)
            {
                return make_error(attribute.error());
            }

            media.attributes.push_back(*attribute);
            return {};
        }

        default:
            return make_error("unsupported media-level sdp line");
    }
}

std::expected<void, std::string> validate_required_session_lines(bool has_version, bool has_origin, bool has_session_name, bool has_timing)
{
    if (!has_version)
    {
        return make_error("missing v= line");
    }

    if (!has_origin)
    {
        return make_error("missing o= line");
    }

    if (!has_session_name)
    {
        return make_error("missing s= line");
    }

    if (!has_timing)
    {
        return make_error("missing t= line");
    }

    return {};
}
}    // namespace

session_description_result parse_session_description(std::string_view text)
{
    sdp_lexer lexer(text);
    session_description description;

    bool has_version = false;
    bool has_origin = false;
    bool has_session_name = false;
    bool has_timing = false;

    media_description* current_media = nullptr;

    while (true)
    {
        lexer.skip_line_breaks();
        if (lexer.eof())
        {
            break;
        }

        auto type = lexer.read_type();
        if (!type)
        {
            return make_error(type.error());
        }

        auto value = lexer.read_line();
        if (!value)
        {
            return make_error(value.error());
        }

        if (*type == 'm')
        {
            auto media_name = parse_media_name_line(*value);
            if (!media_name)
            {
                return make_error(media_name.error());
            }

            media_description media;
            media.media_name = *media_name;
            description.media_descriptions.push_back(std::move(media));
            current_media = &description.media_descriptions.back();
            continue;
        }

        if (current_media == nullptr)
        {
            auto parse_result = parse_session_level_line(description, has_version, has_origin, has_session_name, has_timing, *type, *value);

            if (!parse_result)
            {
                return make_error(parse_result.error());
            }
        }
        else
        {
            if (*type == 'v' || *type == 'o' || *type == 's' || *type == 'u' || *type == 'e' || *type == 'p' || *type == 't' || *type == 'r' ||
                *type == 'z')
            {
                return make_error("session-level line appears after media section");
            }

            auto parse_result = parse_media_level_line(*current_media, *type, *value);
            if (!parse_result)
            {
                return make_error(parse_result.error());
            }
        }
    }

    auto validate_result = validate_required_session_lines(has_version, has_origin, has_session_name, has_timing);
    if (!validate_result)
    {
        return make_error(validate_result.error());
    }

    return description;
}
}    // namespace webrtc::sdp
