#include "signaling/sdp/sdp_formatter.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc::sdp
{
namespace
{
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

void append_connection(std::string& output, std::string_view address)
{
    std::string value;
    value.reserve(address.size() + 7);
    value.append("IN IP4 ");
    value.append(address);

    append_raw_line(output, 'c', value);
}

void append_attribute(std::string& output, const sdp_attribute& attribute)
{
    std::string value;
    value.reserve(attribute.key.size() + attribute.value.size() + 1);

    value.append(attribute.key);

    if (!attribute.value.empty())
    {
        value.push_back(':');
        value.append(attribute.value);
    }

    append_raw_line(output, 'a', value);
}

void append_attributes(std::string& output, const std::vector<sdp_attribute>& attributes)
{
    for (const auto& attribute : attributes)
    {
        append_attribute(output, attribute);
    }
}

void append_media_name(std::string& output, const media_name_line& media_name)
{
    std::string value;
    value.reserve(128);

    value.append(media_name.media);
    value.push_back(' ');
    value.append(std::to_string(media_name.port));
    value.append(" UDP/TLS/RTP/SAVPF");

    for (const auto& format : media_name.formats)
    {
        value.push_back(' ');
        value.append(format);
    }

    append_raw_line(output, 'm', value);
}

void append_media_description(std::string& output, const media_description& media)
{
    append_media_name(output, media.media_name);
    append_connection(output, media.connection_address);
    append_attributes(output, media.attributes);
}

void append_media_descriptions(std::string& output, const std::vector<media_description>& media_descriptions)
{
    for (const auto& media : media_descriptions)
    {
        append_media_description(output, media);
    }
}
}    // namespace

std::string format_session_description(const session_description& description)
{
    std::string output;
    output.reserve(2048);

    append_raw_line(output, 'v', "0");
    append_origin(output, description.session_id, description.session_version);
    append_raw_line(output, 's', "-");
    append_raw_line(output, 't', "0 0");
    append_attributes(output, description.attributes);
    append_media_descriptions(output, description.media_descriptions);

    return output;
}
}    // namespace webrtc::sdp
