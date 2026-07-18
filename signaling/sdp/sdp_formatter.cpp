#include "signaling/sdp/sdp_formatter.h"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webrtc::sdp
{
namespace
{
using format_result = std::expected<void, std::string>;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_field_error(std::string_view field_name, std::string_view message)
{
    std::string error;
    error.reserve(field_name.size() + message.size() + 2);
    error.append(field_name);
    error.append(": ");
    error.append(message);
    return std::unexpected(std::move(error));
}

bool contains_line_break(std::string_view value)
{
    for (const char ch : value)
    {
        if (ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

bool contains_whitespace(std::string_view value)
{
    for (const char ch : value)
    {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

format_result validate_line_value(std::string_view value, std::string_view field_name, bool allow_empty)
{
    if (!allow_empty && value.empty())
    {
        return make_field_error(field_name, "must not be empty");
    }

    if (contains_line_break(value))
    {
        return make_field_error(field_name, "must not contain line breaks");
    }

    return {};
}

format_result validate_token(std::string_view value, std::string_view field_name)
{
    if (value.empty())
    {
        return make_field_error(field_name, "must not be empty");
    }

    if (contains_whitespace(value))
    {
        return make_field_error(field_name, "must not contain whitespace");
    }

    return {};
}

void append_raw_line(std::string& output, char type, std::string_view value)
{
    output.push_back(type);
    output.push_back('=');
    output.append(value);
    output.append("\r\n");
}

void append_origin(std::string& output, uint64_t session_id, uint64_t session_version)
{
    std::string value;
    value.reserve(64);
    value.append("- ");
    value.append(std::to_string(session_id));
    value.push_back(' ');
    value.append(std::to_string(session_version));
    value.append(" IN IP4 0.0.0.0");

    append_raw_line(output, 'o', value);
}

format_result append_connection(std::string& output, std::string_view address)
{
    auto validation = validate_token(address, "connection address");
    if (!validation)
    {
        return std::unexpected(validation.error());
    }

    std::string value;
    value.reserve(address.size() + 7);
    value.append("IN IP4 ");
    value.append(address);

    append_raw_line(output, 'c', value);
    return {};
}

format_result append_attribute(std::string& output, const sdp_attribute& attribute)
{
    auto key_result = validate_token(attribute.key, "attribute key");

    if (!key_result)
    {
        return std::unexpected(key_result.error());
    }

    if (attribute.key.find(':') != std::string::npos)
    {
        return make_error("attribute key must not contain colon");
    }

    auto value_result = validate_line_value(attribute.value, "attribute value", true);

    if (!value_result)
    {
        return std::unexpected(value_result.error());
    }

    std::string value;
    value.reserve(attribute.key.size() + attribute.value.size() + 1);

    value.append(attribute.key);

    if (!attribute.value.empty())
    {
        value.push_back(':');
        value.append(attribute.value);
    }

    append_raw_line(output, 'a', value);
    return {};
}

format_result append_attributes(std::string& output, const std::vector<sdp_attribute>& attributes)
{
    for (const auto& attribute : attributes)
    {
        auto result = append_attribute(output, attribute);
        if (!result)
        {
            return std::unexpected(result.error());
        }
    }

    return {};
}

format_result append_media_name(std::string& output, const media_name_line& media_name)
{
    auto media_result = validate_token(media_name.media, "media type");

    if (!media_result)
    {
        return std::unexpected(media_result.error());
    }

    if (media_name.port < 0 || media_name.port > 65535)
    {
        return make_error("media port is out of range");
    }

    if (media_name.formats.empty())
    {
        return make_error("media format list is empty");
    }

    std::string value;
    value.reserve(128);

    value.append(media_name.media);
    value.push_back(' ');
    value.append(std::to_string(media_name.port));
    value.append(" UDP/TLS/RTP/SAVPF");

    for (const auto& format : media_name.formats)
    {
        auto format_result_value = validate_token(format, "media format");

        if (!format_result_value)
        {
            return std::unexpected(format_result_value.error());
        }

        value.push_back(' ');
        value.append(format);
    }

    append_raw_line(output, 'm', value);
    return {};
}

format_result append_media_description(std::string& output, const media_description& media)
{
    auto media_name_result = append_media_name(output, media.media_name);

    if (!media_name_result)
    {
        return std::unexpected(media_name_result.error());
    }

    auto connection_result = append_connection(output, media.connection_address);

    if (!connection_result)
    {
        return std::unexpected(connection_result.error());
    }

    auto attributes_result = append_attributes(output, media.attributes);

    if (!attributes_result)
    {
        return std::unexpected(attributes_result.error());
    }

    return {};
}

format_result append_media_descriptions(std::string& output, const std::vector<media_description>& media_descriptions)
{
    for (const auto& media : media_descriptions)
    {
        auto result = append_media_description(output, media);

        if (!result)
        {
            return std::unexpected(result.error());
        }
    }

    return {};
}
}    // namespace

sdp_format_result format_session_description(const session_description& description)
{
    std::string output;
    output.reserve(2048);

    append_raw_line(output, 'v', "0");
    append_origin(output, description.session_id, description.session_version);
    append_raw_line(output, 's', "-");
    append_raw_line(output, 't', "0 0");

    auto attributes_result = append_attributes(output, description.attributes);

    if (!attributes_result)
    {
        return std::unexpected(attributes_result.error());
    }

    auto media_result = append_media_descriptions(output, description.media_descriptions);

    if (!media_result)
    {
        return std::unexpected(media_result.error());
    }

    return output;
}
}    // namespace webrtc::sdp
