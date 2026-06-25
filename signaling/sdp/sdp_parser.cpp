#include "signaling/sdp/sdp_parser.h"

#include <charconv>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "signaling/sdp/sdp_lexer.h"

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

uint64_t parse_uint64_text(std::string_view value, std::string_view field_name)
{
    value = trim(value);
    if (value.empty())
    {
        throw std::invalid_argument(std::string(field_name) + " is empty");
    }

    uint64_t number = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), number);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size())
    {
        throw std::invalid_argument(std::string(field_name) + " is invalid");
    }

    return number;
}

int32_t parse_int32_text(std::string_view value, std::string_view field_name)
{
    value = trim(value);
    if (value.empty())
    {
        throw std::invalid_argument(std::string(field_name) + " is empty");
    }

    int32_t number = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), number);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size())
    {
        throw std::invalid_argument(std::string(field_name) + " is invalid");
    }

    return number;
}

sdp_attribute parse_attribute_line(std::string_view value)
{
    value = trim(value);
    if (value.empty())
    {
        throw std::invalid_argument("empty attribute");
    }

    const auto colon_position = value.find(':');
    if (colon_position == std::string_view::npos || colon_position == 0)
    {
        return make_property_attribute(std::string(value));
    }

    return make_attribute(std::string(value.substr(0, colon_position)), std::string(value.substr(colon_position + 1)));
}

connection_information parse_connection_information_line(std::string_view value)
{
    const auto fields = split_whitespace(value);

    if (fields.size() < 2)
    {
        throw std::invalid_argument("invalid connection information");
    }

    connection_information connection;
    connection.network_type = std::string(fields[0]);
    connection.address_type = std::string(fields[1]);

    if (!is_any_of(connection.network_type, {"IN"}))
    {
        throw std::invalid_argument("invalid connection network type");
    }

    if (!is_any_of(connection.address_type, {"IP4", "IP6"}))
    {
        throw std::invalid_argument("invalid connection address type");
    }

    if (fields.size() >= 3)
    {
        sdp_address address;
        address.address = std::string(fields[2]);
        connection.address = address;
    }

    return connection;
}

bandwidth_line parse_bandwidth_line(std::string_view value)
{
    value = trim(value);

    const auto colon_position = value.find(':');
    if (colon_position == std::string_view::npos || colon_position == 0 || colon_position + 1 >= value.size())
    {
        throw std::invalid_argument("invalid bandwidth line");
    }

    auto type = value.substr(0, colon_position);
    const auto bandwidth_value = value.substr(colon_position + 1);

    bandwidth_line line;

    if (type.starts_with("X-"))
    {
        line.experimental = true;
        type = type.substr(2);
    }
    else if (!is_any_of(type, {"CT", "AS", "TIAS", "RS", "RR"}))
    {
        throw std::invalid_argument("invalid bandwidth type");
    }

    line.type = std::string(type);
    line.value = parse_uint64_text(bandwidth_value, "bandwidth value");

    return line;
}

timing_line parse_timing_line(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.size() != 2)
    {
        throw std::invalid_argument("invalid timing line");
    }

    timing_line timing;
    timing.start_time = parse_uint64_text(fields[0], "timing start time");
    timing.stop_time = parse_uint64_text(fields[1], "timing stop time");

    return timing;
}

repeat_time parse_repeat_time_line(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.size() < 2)
    {
        throw std::invalid_argument("invalid repeat time line");
    }

    repeat_time repeat;
    repeat.interval = parse_time_units(fields[0]);
    repeat.duration = parse_time_units(fields[1]);

    for (std::size_t i = 2; i < fields.size(); ++i)
    {
        repeat.offsets.push_back(parse_time_units(fields[i]));
    }

    return repeat;
}

std::vector<time_zone> parse_time_zone_line(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.empty() || fields.size() % 2 != 0)
    {
        throw std::invalid_argument("invalid time zone line");
    }

    std::vector<time_zone> result;

    for (std::size_t i = 0; i < fields.size(); i += 2)
    {
        time_zone zone;
        zone.adjustment_time = parse_uint64_text(fields[i], "time zone adjustment time");
        zone.offset = parse_time_units(fields[i + 1]);
        result.push_back(zone);
    }

    return result;
}

ranged_port parse_ranged_port(std::string_view value)
{
    ranged_port port;

    const auto slash_position = value.find('/');
    const auto port_text = slash_position == std::string_view::npos ? value : value.substr(0, slash_position);

    const int parsed_port = parse_port(port_text);
    if (parsed_port < 0)
    {
        throw std::invalid_argument("invalid media port");
    }

    port.value = parsed_port;

    if (slash_position != std::string_view::npos)
    {
        const auto range_text = value.substr(slash_position + 1);
        port.range = parse_int32_text(range_text, "media port range");

        if (port.range.value() <= 0)
        {
            throw std::invalid_argument("invalid media port range");
        }
    }

    return port;
}

media_name_line parse_media_name_line(std::string_view value)
{
    const auto fields = split_whitespace(value);

    if (fields.size() < 4)
    {
        throw std::invalid_argument("invalid media line");
    }

    media_name_line media_name;

    if (!is_any_of(fields[0], {"audio", "video", "text", "application", "message"}))
    {
        throw std::invalid_argument("invalid media type");
    }

    media_name.media = std::string(fields[0]);
    media_name.port = parse_ranged_port(fields[1]);

    const auto protocols = split_by_char(fields[2], '/');
    if (protocols.empty())
    {
        throw std::invalid_argument("empty media protocol");
    }

    for (const auto protocol : protocols)
    {
        if (protocol.empty())
        {
            throw std::invalid_argument("invalid media protocol");
        }

        if (!is_any_of(protocol,
                       {"UDP", "RTP", "AVP", "SAVP", "SAVPF", "TLS", "DTLS", "SCTP", "AVPF", "TCP", "MSRP", "BFCP", "UDT", "IX", "MRCPv2", "FEC"}))
        {
            throw std::invalid_argument("unsupported media protocol");
        }

        media_name.protocols.emplace_back(protocol);
    }

    for (std::size_t i = 3; i < fields.size(); ++i)
    {
        media_name.formats.emplace_back(fields[i]);
    }

    return media_name;
}

origin_line parse_origin_line(std::string_view value)
{
    const auto fields = split_whitespace(value);

    if (fields.size() != 6)
    {
        throw std::invalid_argument("invalid origin line");
    }

    origin_line origin;
    origin.username = std::string(fields[0]);
    origin.session_id = parse_uint64_text(fields[1], "origin session id");
    origin.session_version = parse_uint64_text(fields[2], "origin session version");
    origin.network_type = std::string(fields[3]);
    origin.address_type = std::string(fields[4]);
    origin.unicast_address = std::string(fields[5]);

    if (!is_any_of(origin.network_type, {"IN"}))
    {
        throw std::invalid_argument("invalid origin network type");
    }

    if (!is_any_of(origin.address_type, {"IP4", "IP6"}))
    {
        throw std::invalid_argument("invalid origin address type");
    }

    return origin;
}

void parse_session_level_line(session_description& description,
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
            const auto version = parse_uint64_text(value, "sdp version");
            if (version != 0)
            {
                throw std::invalid_argument("unsupported sdp version");
            }

            description.version.value = 0;
            has_version = true;
            break;
        }

        case 'o':
            description.origin = parse_origin_line(value);
            has_origin = true;
            break;

        case 's':
            description.session_name = std::string(value);
            has_session_name = true;
            break;

        case 'i':
            description.session_information = std::string(value);
            break;

        case 'u':
            if (trim(value).empty())
            {
                throw std::invalid_argument("empty uri line");
            }

            description.uri = std::string(value);
            break;

        case 'e':
            description.email_address = std::string(value);
            break;

        case 'p':
            description.phone_number = std::string(value);
            break;

        case 'c':
            description.connection = parse_connection_information_line(value);
            break;

        case 'b':
            description.bandwidth_lines.push_back(parse_bandwidth_line(value));
            break;

        case 't':
        {
            time_description time;
            time.timing = parse_timing_line(value);
            description.time_descriptions.push_back(time);
            has_timing = true;
            break;
        }

        case 'r':
            if (description.time_descriptions.empty())
            {
                throw std::invalid_argument("repeat time appears before timing");
            }

            description.time_descriptions.back().repeat_times.push_back(parse_repeat_time_line(value));
            break;

        case 'z':
        {
            auto zones = parse_time_zone_line(value);
            description.time_zones.insert(description.time_zones.end(), zones.begin(), zones.end());
            break;
        }

        case 'k':
            description.encryption_key = std::string(value);
            break;

        case 'a':
            description.attributes.push_back(parse_attribute_line(value));
            break;

        default:
            throw std::invalid_argument("unsupported session-level sdp line");
    }
}

void parse_media_level_line(media_description& media, char type, std::string_view value)
{
    switch (type)
    {
        case 'i':
            media.media_title = std::string(value);
            break;

        case 'c':
            media.connection = parse_connection_information_line(value);
            break;

        case 'b':
            media.bandwidth_lines.push_back(parse_bandwidth_line(value));
            break;

        case 'k':
            media.encryption_key = std::string(value);
            break;

        case 'a':
            media.attributes.push_back(parse_attribute_line(value));
            break;

        default:
            throw std::invalid_argument("unsupported media-level sdp line");
    }
}

void validate_required_session_lines(bool has_version, bool has_origin, bool has_session_name, bool has_timing)
{
    if (!has_version)
    {
        throw std::invalid_argument("missing v= line");
    }

    if (!has_origin)
    {
        throw std::invalid_argument("missing o= line");
    }

    if (!has_session_name)
    {
        throw std::invalid_argument("missing s= line");
    }

    if (!has_timing)
    {
        throw std::invalid_argument("missing t= line");
    }
}
}    // namespace

sdp_parse_result parse_session_description(std::string_view text)
{
    sdp_parse_result result;

    try
    {
        sdp_lexer lexer(text);

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

            const char type = lexer.read_type();
            const std::string_view value = lexer.read_line();

            if (type == 'm')
            {
                media_description media;
                media.media_name = parse_media_name_line(value);
                result.description.media_descriptions.push_back(std::move(media));
                current_media = &result.description.media_descriptions.back();
                continue;
            }

            if (current_media == nullptr)
            {
                parse_session_level_line(result.description, has_version, has_origin, has_session_name, has_timing, type, value);
            }
            else
            {
                if (type == 'v' || type == 'o' || type == 's' || type == 'u' || type == 'e' || type == 'p' || type == 't' || type == 'r' ||
                    type == 'z')
                {
                    throw std::invalid_argument("session-level line appears after media section");
                }

                parse_media_level_line(*current_media, type, value);
            }
        }

        validate_required_session_lines(has_version, has_origin, has_session_name, has_timing);

        result.success = true;
        return result;
    }
    catch (const std::exception& e)
    {
        result.success = false;
        result.error = e.what();
        result.description = session_description{};
        return result;
    }
}
}    // namespace webrtc::sdp
