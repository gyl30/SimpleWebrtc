#include "signaling/sdp/sdp_formatter.h"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
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

template <typename value_type>
bool is_negative(value_type value)
{
    if constexpr (std::is_signed_v<value_type>)
    {
        return value < 0;
    }

    return false;
}

template <typename value_type>
const value_type* get_optional_pointer(const value_type& value)
{
    return &value;
}

template <typename value_type>
const value_type* get_optional_pointer(const std::optional<value_type>& value)
{
    if (!value.has_value())
    {
        return nullptr;
    }

    return &value.value();
}

const connection_information* get_present_connection_pointer(const std::optional<connection_information>& connection)
{
    if (!connection.has_value())
    {
        return nullptr;
    }

    return &connection.value();
}

void append_raw_line(std::string& output, char type, std::string_view value)
{
    output.push_back(type);
    output.push_back('=');
    output.append(value);
    output.append("\r\n");
}

format_result append_text_line(std::string& output, char type, std::string_view value, std::string_view field_name, bool allow_empty)
{
    auto validation_result = validate_line_value(value, field_name, allow_empty);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    append_raw_line(output, type, value);
    return {};
}

format_result append_version(std::string& output, const sdp_version& version)
{
    if (version.value != 0)
    {
        return make_error("unsupported sdp version");
    }

    append_raw_line(output, 'v', "0");
    return {};
}

format_result append_origin(std::string& output, const origin_line& origin)
{
    auto username_result = validate_token(origin.username, "origin username");

    if (!username_result)
    {
        return std::unexpected(username_result.error());
    }

    auto network_type_result = validate_token(origin.network_type, "origin network type");

    if (!network_type_result)
    {
        return std::unexpected(network_type_result.error());
    }

    auto address_type_result = validate_token(origin.address_type, "origin address type");

    if (!address_type_result)
    {
        return std::unexpected(address_type_result.error());
    }

    auto address_result = validate_token(origin.unicast_address, "origin unicast address");

    if (!address_result)
    {
        return std::unexpected(address_result.error());
    }

    std::string value;
    value.reserve(origin.username.size() + origin.network_type.size() + origin.address_type.size() + origin.unicast_address.size() + 48);

    value.append(origin.username);
    value.push_back(' ');
    value.append(std::to_string(origin.session_id));
    value.push_back(' ');
    value.append(std::to_string(origin.session_version));
    value.push_back(' ');
    value.append(origin.network_type);
    value.push_back(' ');
    value.append(origin.address_type);
    value.push_back(' ');
    value.append(origin.unicast_address);

    append_raw_line(output, 'o', value);
    return {};
}

format_result append_connection(std::string& output, const connection_information& connection)
{
    auto network_type_result = validate_token(connection.network_type, "connection network type");

    if (!network_type_result)
    {
        return std::unexpected(network_type_result.error());
    }

    auto address_type_result = validate_token(connection.address_type, "connection address type");

    if (!address_type_result)
    {
        return std::unexpected(address_type_result.error());
    }

    std::string value;
    value.reserve(connection.network_type.size() + connection.address_type.size() + 64);

    value.append(connection.network_type);
    value.push_back(' ');
    value.append(connection.address_type);

    const auto* address = get_optional_pointer(connection.address);

    if (address != nullptr)
    {
        auto address_result = validate_token(address->address, "connection address");

        if (!address_result)
        {
            return std::unexpected(address_result.error());
        }

        value.push_back(' ');
        value.append(address->address);
    }

    append_raw_line(output, 'c', value);
    return {};
}

template <typename connection_type>
format_result append_optional_connection(std::string& output, const connection_type& connection)
{
    const auto* connection_value = get_present_connection_pointer(connection);

    if (connection_value == nullptr)
    {
        return {};
    }

    return append_connection(output, *connection_value);
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

    using port_type = std::remove_cvref_t<decltype(media_name.port.value)>;

    if (is_negative<port_type>(media_name.port.value) || static_cast<uint64_t>(media_name.port.value) > 65535)
    {
        return make_error("media port is out of range");
    }

    if (media_name.protocols.empty())
    {
        return make_error("media protocol list is empty");
    }

    if (media_name.formats.empty())
    {
        return make_error("media format list is empty");
    }

    std::string value;
    value.reserve(128);

    value.append(media_name.media);
    value.push_back(' ');
    value.append(std::to_string(media_name.port.value));

    value.push_back(' ');

    for (std::size_t index = 0; index < media_name.protocols.size(); ++index)
    {
        const auto& protocol = media_name.protocols[index];

        auto protocol_result = validate_token(protocol, "media protocol");

        if (!protocol_result)
        {
            return std::unexpected(protocol_result.error());
        }

        if (protocol.find('/') != std::string::npos)
        {
            return make_error("media protocol must not contain slash");
        }

        if (index != 0)
        {
            value.push_back('/');
        }

        value.append(protocol);
    }

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

    auto connection_result = append_optional_connection(output, media.connection);

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

    auto version_result = append_version(output, description.version);

    if (!version_result)
    {
        return std::unexpected(version_result.error());
    }

    auto origin_result = append_origin(output, description.origin);

    if (!origin_result)
    {
        return std::unexpected(origin_result.error());
    }

    auto session_name_result = append_text_line(output, 's', description.session_name, "session name", true);

    if (!session_name_result)
    {
        return std::unexpected(session_name_result.error());
    }

    auto connection_result = append_optional_connection(output, description.connection);

    if (!connection_result)
    {
        return std::unexpected(connection_result.error());
    }

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
