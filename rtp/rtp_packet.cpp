#include "rtp/rtp_packet.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace webrtc
{
namespace
{
constexpr std::size_t k_rtp_fixed_header_size = 12;
constexpr std::size_t k_rtp_csrc_size = 4;
constexpr std::size_t k_rtp_extension_header_size = 4;

constexpr uint16_t k_one_byte_extension_profile = 0xBEDE;
constexpr uint16_t k_two_byte_extension_profile_mask = 0xFFF0;
constexpr uint16_t k_two_byte_extension_profile_value = 0x1000;

constexpr uint8_t k_one_byte_extension_reserved_id = 15;

constexpr std::string_view k_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";

constexpr std::string_view k_rid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";

constexpr std::string_view k_repaired_rid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

constexpr std::string_view k_transport_wide_cc_extension_uri = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

constexpr std::string_view k_transport_wide_cc_extension_uri_02 = "http://www.webrtc.org/experiments/rtp-hdrext/transport-wide-cc-02";

constexpr std::string_view k_absolute_send_time_extension_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

constexpr std::string_view k_audio_level_extension_uri = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_field_error(std::string_view field_name, std::string_view message)
{
    std::string error;

    error.reserve(field_name.size() + message.size() + 1);

    error.append(field_name);
    error.push_back(' ');
    error.append(message);

    return std::unexpected(std::move(error));
}

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_u24(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 16U) | (static_cast<uint32_t>(data[offset + 1]) << 8U) | static_cast<uint32_t>(data[offset + 2]);
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

bool has_rtp_version(std::span<const uint8_t> data)
{
    if (data.empty())
    {
        return false;
    }

    return (data[0] >> 6U) == 2U;
}

bool contains_forbidden_text_extension_character(uint8_t value) { return value == 0 || value == '\r' || value == '\n'; }

rtp_header_extension_format make_extension_format(uint16_t profile)
{
    if (is_one_byte_rtp_header_extension_profile(profile))
    {
        return rtp_header_extension_format::one_byte;
    }

    if (is_two_byte_rtp_header_extension_profile(profile))
    {
        return rtp_header_extension_format::two_byte;
    }

    return rtp_header_extension_format::unknown;
}

std::expected<void, std::string> parse_one_byte_header_extensions(std::span<const uint8_t> packet,
                                                                  std::size_t extension_payload_offset,
                                                                  std::size_t extension_payload_size,
                                                                  rtp_packet_header& header)
{
    const std::size_t extension_end = extension_payload_offset + extension_payload_size;

    if (extension_end > packet.size())
    {
        return make_error("rtp one-byte extension payload is truncated");
    }

    std::size_t offset = extension_payload_offset;

    while (offset < extension_end)
    {
        const uint8_t value = packet[offset];

        if (value == 0)
        {
            offset += 1;

            continue;
        }

        const uint8_t id = static_cast<uint8_t>(value >> 4U);

        if (id == k_one_byte_extension_reserved_id)
        {
            return make_error("rtp one-byte extension id 15 is reserved");
        }

        const std::size_t size = static_cast<std::size_t>(value & 0x0FU) + 1;

        offset += 1;

        if (offset + size > extension_end)
        {
            return make_error("rtp one-byte extension element is truncated");
        }

        rtp_header_extension_entry entry;

        entry.id = id;
        entry.offset = offset;
        entry.size = size;

        header.header_extensions.push_back(entry);

        offset += size;
    }

    return {};
}

std::expected<void, std::string> parse_two_byte_header_extensions(std::span<const uint8_t> packet,
                                                                  std::size_t extension_payload_offset,
                                                                  std::size_t extension_payload_size,
                                                                  rtp_packet_header& header)
{
    const std::size_t extension_end = extension_payload_offset + extension_payload_size;

    if (extension_end > packet.size())
    {
        return make_error("rtp two-byte extension payload is truncated");
    }

    std::size_t offset = extension_payload_offset;

    while (offset < extension_end)
    {
        const uint8_t id = packet[offset];

        offset += 1;

        if (id == 0)
        {
            continue;
        }

        if (offset >= extension_end)
        {
            return make_error("rtp two-byte extension length is truncated");
        }

        const std::size_t size = static_cast<std::size_t>(packet[offset]);

        offset += 1;

        if (offset + size > extension_end)
        {
            return make_error("rtp two-byte extension element is truncated");
        }

        rtp_header_extension_entry entry;

        entry.id = id;
        entry.offset = offset;
        entry.size = size;

        header.header_extensions.push_back(entry);

        offset += size;
    }

    return {};
}

std::expected<void, std::string> parse_header_extensions(std::span<const uint8_t> packet,
                                                         rtp_packet_header& header,
                                                         std::size_t extension_header_offset)
{
    if (extension_header_offset + k_rtp_extension_header_size > packet.size())
    {
        return make_error("rtp extension header is truncated");
    }

    header.extension_header_offset = extension_header_offset;

    header.extension_profile = read_u16(packet, extension_header_offset);

    const uint16_t extension_length_words = read_u16(packet, extension_header_offset + 2);

    header.extension_payload_offset = extension_header_offset + k_rtp_extension_header_size;

    header.extension_payload_size = static_cast<std::size_t>(extension_length_words) * 4;

    const std::size_t extension_total_size = k_rtp_extension_header_size + header.extension_payload_size;

    if (extension_header_offset + extension_total_size > packet.size())
    {
        return make_error("rtp extension payload is truncated");
    }

    header.extension_format = make_extension_format(header.extension_profile);

    switch (header.extension_format)
    {
        case rtp_header_extension_format::one_byte:
            return parse_one_byte_header_extensions(packet, header.extension_payload_offset, header.extension_payload_size, header);

        case rtp_header_extension_format::two_byte:
            return parse_two_byte_header_extensions(packet, header.extension_payload_offset, header.extension_payload_size, header);

        case rtp_header_extension_format::unknown:
            return {};
    }

    return {};
}

std::expected<void, std::string> parse_rtp_padding(std::span<const uint8_t> packet, rtp_packet_header& header)
{
    if (!header.padding)
    {
        return {};
    }

    if (header.payload_size == 0)
    {
        return make_error("rtp padding flag set but payload is empty");
    }

    const std::size_t padding_size = static_cast<std::size_t>(packet[packet.size() - 1]);

    if (padding_size == 0)
    {
        return make_error("rtp padding size is zero");
    }

    if (padding_size > header.payload_size)
    {
        return make_error("rtp padding exceeds payload size");
    }

    header.padding_size = padding_size;

    header.payload_size -= padding_size;

    return {};
}

std::optional<uint8_t> find_rtp_header_extension_id_any(const sdp::media_summary& media, std::initializer_list<std::string_view> uris)
{
    for (std::string_view uri : uris)
    {
        auto id = find_rtp_header_extension_id(media, uri);

        if (id.has_value())
        {
            return id;
        }
    }

    return std::nullopt;
}

std::optional<std::span<const uint8_t>> find_configured_rtp_header_extension_payload(std::span<const uint8_t> packet,
                                                                                     const rtp_packet_header& header,
                                                                                     const sdp::media_summary& media,
                                                                                     std::initializer_list<std::string_view> uris)
{
    auto extension_id = find_rtp_header_extension_id_any(media, uris);

    if (!extension_id.has_value())
    {
        return std::nullopt;
    }

    return find_rtp_header_extension(packet, header, *extension_id);
}

std::expected<std::string, std::string> parse_text_header_extension(std::span<const uint8_t> payload, std::string_view field_name)
{
    if (payload.empty())
    {
        return make_field_error(field_name, "extension is empty");
    }

    if (payload.size() > 255)
    {
        return make_field_error(field_name, "extension is too large");
    }

    std::string value;

    value.reserve(payload.size());

    for (uint8_t byte : payload)
    {
        if (contains_forbidden_text_extension_character(byte))
        {
            return make_field_error(field_name, "extension contains invalid characters");
        }

        value.push_back(static_cast<char>(byte));
    }

    return value;
}

std::expected<uint16_t, std::string> parse_transport_wide_sequence_number(std::span<const uint8_t> payload)
{
    if (payload.size() != 2)
    {
        return make_error("rtp transport-wide-cc extension size is invalid");
    }

    return read_u16(payload, 0);
}

std::expected<uint32_t, std::string> parse_absolute_send_time(std::span<const uint8_t> payload)
{
    if (payload.size() != 3)
    {
        return make_error("rtp abs-send-time extension size is invalid");
    }

    return read_u24(payload, 0);
}

std::expected<void, std::string> parse_audio_level(std::span<const uint8_t> payload, rtp_header_extension_values& values)
{
    if (payload.size() != 1)
    {
        return make_error("rtp audio-level extension size is invalid");
    }

    values.voice_activity = (payload[0] & 0x80U) != 0;

    values.audio_level = static_cast<uint8_t>(payload[0] & 0x7FU);

    return {};
}
}    // namespace

bool is_rtp_or_rtcp_packet(std::span<const uint8_t> data)
{
    if (data.empty())
    {
        return false;
    }

    return data[0] >= 128U && data[0] <= 191U;
}

bool is_rtcp_packet(std::span<const uint8_t> data)
{
    if (!is_rtp_or_rtcp_packet(data))
    {
        return false;
    }

    if (data.size() < 2)
    {
        return false;
    }

    return data[1] >= 192U && data[1] <= 223U;
}

bool is_rtp_packet(std::span<const uint8_t> data)
{
    if (!is_rtp_or_rtcp_packet(data))
    {
        return false;
    }

    return !is_rtcp_packet(data);
}

rtp_packet_header_result parse_rtp_packet_header(std::span<const uint8_t> data)
{
    if (data.size() < k_rtp_fixed_header_size)
    {
        return make_error("rtp packet is shorter than fixed header");
    }

    if (!has_rtp_version(data))
    {
        return make_error("rtp version is invalid");
    }

    if (is_rtcp_packet(data))
    {
        return make_error("packet is rtcp not rtp");
    }

    rtp_packet_header header;

    header.version = static_cast<uint8_t>(data[0] >> 6U);

    header.padding = (data[0] & 0x20U) != 0;

    header.extension = (data[0] & 0x10U) != 0;

    header.csrc_count = static_cast<uint8_t>(data[0] & 0x0FU);

    header.marker = (data[1] & 0x80U) != 0;

    header.payload_type = static_cast<uint8_t>(data[1] & 0x7FU);

    header.sequence_number = read_u16(data, 2);

    header.timestamp = read_u32(data, 4);

    header.ssrc = read_u32(data, 8);

    std::size_t header_size = k_rtp_fixed_header_size + static_cast<std::size_t>(header.csrc_count) * k_rtp_csrc_size;

    if (header_size > data.size())
    {
        return make_error("rtp csrc list is truncated");
    }

    if (header.extension)
    {
        auto extension_result = parse_header_extensions(data, header, header_size);

        if (!extension_result)
        {
            return std::unexpected(extension_result.error());
        }

        header_size += k_rtp_extension_header_size + header.extension_payload_size;
    }

    header.header_size = header_size;

    header.payload_offset = header_size;

    if (header_size > data.size())
    {
        return make_error("rtp header exceeds packet size");
    }

    header.payload_size = data.size() - header_size;

    auto padding_result = parse_rtp_padding(data, header);

    if (!padding_result)
    {
        return std::unexpected(padding_result.error());
    }

    return header;
}

rtcp_packet_header_result parse_rtcp_packet_header(std::span<const uint8_t> data)
{
    if (data.size() < 4)
    {
        return make_error("rtcp packet is shorter than fixed header");
    }

    if (!has_rtp_version(data))
    {
        return make_error("rtcp version is invalid");
    }

    if (!is_rtcp_packet(data))
    {
        return make_error("packet is not rtcp");
    }

    rtcp_packet_header header;

    header.version = static_cast<uint8_t>(data[0] >> 6U);

    header.padding = (data[0] & 0x20U) != 0;

    header.count = static_cast<uint8_t>(data[0] & 0x1FU);

    header.packet_type = data[1];

    header.length = read_u16(data, 2);

    header.packet_size = (static_cast<std::size_t>(header.length) + 1) * 4;

    if (header.packet_size > data.size())
    {
        return make_error("rtcp packet is truncated");
    }

    if (header.packet_size >= 8)
    {
        header.has_ssrc = true;

        header.ssrc = read_u32(data, 4);
    }

    return header;
}

std::optional<std::span<const uint8_t>> find_rtp_header_extension(std::span<const uint8_t> packet,
                                                                  const rtp_packet_header& header,
                                                                  uint8_t extension_id)
{
    if (extension_id == 0)
    {
        return std::nullopt;
    }

    for (const auto& extension : header.header_extensions)
    {
        if (extension.id != extension_id)
        {
            continue;
        }

        if (extension.offset + extension.size > packet.size())
        {
            return std::nullopt;
        }

        return packet.subspan(extension.offset, extension.size);
    }

    return std::nullopt;
}

std::optional<uint8_t> find_rtp_header_extension_id(const sdp::media_summary& media, std::string_view uri)
{
    if (uri.empty())
    {
        return std::nullopt;
    }

    for (const auto& extension : media.header_extensions)
    {
        if (extension.id == 0)
        {
            continue;
        }

        if (extension.uri == uri)
        {
            return extension.id;
        }
    }

    return std::nullopt;
}

rtp_header_extension_values_result parse_rtp_header_extension_values(std::span<const uint8_t> packet,
                                                                     const rtp_packet_header& header,
                                                                     const sdp::media_summary& media)
{
    rtp_header_extension_values values;

    auto mid_payload = find_configured_rtp_header_extension_payload(packet, header, media, {k_mid_extension_uri});

    if (mid_payload.has_value())
    {
        auto parsed_mid = parse_text_header_extension(*mid_payload, "rtp mid");

        if (!parsed_mid)
        {
            return std::unexpected(parsed_mid.error());
        }

        values.mid = std::move(*parsed_mid);
    }

    auto rid_payload = find_configured_rtp_header_extension_payload(packet, header, media, {k_rid_extension_uri});

    if (rid_payload.has_value())
    {
        auto parsed_rid = parse_text_header_extension(*rid_payload, "rtp rid");

        if (!parsed_rid)
        {
            return std::unexpected(parsed_rid.error());
        }

        values.rid = std::move(*parsed_rid);
    }

    auto repaired_rid_payload = find_configured_rtp_header_extension_payload(packet, header, media, {k_repaired_rid_extension_uri});

    if (repaired_rid_payload.has_value())
    {
        auto parsed_repaired_rid = parse_text_header_extension(*repaired_rid_payload, "rtp repaired-rid");

        if (!parsed_repaired_rid)
        {
            return std::unexpected(parsed_repaired_rid.error());
        }

        values.repaired_rid = std::move(*parsed_repaired_rid);
    }

    auto transport_wide_cc_payload = find_configured_rtp_header_extension_payload(
        packet, header, media, {k_transport_wide_cc_extension_uri, k_transport_wide_cc_extension_uri_02});

    if (transport_wide_cc_payload.has_value())
    {
        auto sequence_number = parse_transport_wide_sequence_number(*transport_wide_cc_payload);

        if (!sequence_number)
        {
            return std::unexpected(sequence_number.error());
        }

        values.transport_wide_sequence_number = *sequence_number;
    }

    auto absolute_send_time_payload = find_configured_rtp_header_extension_payload(packet, header, media, {k_absolute_send_time_extension_uri});

    if (absolute_send_time_payload.has_value())
    {
        auto absolute_send_time = parse_absolute_send_time(*absolute_send_time_payload);

        if (!absolute_send_time)
        {
            return std::unexpected(absolute_send_time.error());
        }

        values.absolute_send_time = *absolute_send_time;
    }

    auto audio_level_payload = find_configured_rtp_header_extension_payload(packet, header, media, {k_audio_level_extension_uri});

    if (audio_level_payload.has_value())
    {
        auto audio_level_result = parse_audio_level(*audio_level_payload, values);

        if (!audio_level_result)
        {
            return std::unexpected(audio_level_result.error());
        }
    }

    return values;
}

bool is_one_byte_rtp_header_extension_profile(uint16_t profile) { return profile == k_one_byte_extension_profile; }

bool is_two_byte_rtp_header_extension_profile(uint16_t profile)
{
    return (profile & k_two_byte_extension_profile_mask) == k_two_byte_extension_profile_value;
}

bool is_mid_rtp_header_extension_uri(std::string_view uri) { return uri == k_mid_extension_uri; }

bool is_rid_rtp_header_extension_uri(std::string_view uri) { return uri == k_rid_extension_uri; }

bool is_repaired_rid_rtp_header_extension_uri(std::string_view uri) { return uri == k_repaired_rid_extension_uri; }

bool is_transport_wide_cc_rtp_header_extension_uri(std::string_view uri)
{
    return uri == k_transport_wide_cc_extension_uri || uri == k_transport_wide_cc_extension_uri_02;
}

bool is_absolute_send_time_rtp_header_extension_uri(std::string_view uri) { return uri == k_absolute_send_time_extension_uri; }

bool is_audio_level_rtp_header_extension_uri(std::string_view uri) { return uri == k_audio_level_extension_uri; }

std::string rtp_header_extension_format_to_string(rtp_header_extension_format format)
{
    switch (format)
    {
        case rtp_header_extension_format::one_byte:
            return "one_byte";

        case rtp_header_extension_format::two_byte:
            return "two_byte";

        case rtp_header_extension_format::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string rtcp_packet_type_to_string(uint8_t packet_type)
{
    switch (packet_type)
    {
        case 192:
            return "fir";

        case 193:
            return "nack";

        case 200:
            return "sr";

        case 201:
            return "rr";

        case 202:
            return "sdes";

        case 203:
            return "bye";

        case 204:
            return "app";

        case 205:
            return "rtpfb";

        case 206:
            return "psfb";

        case 207:
            return "xr";

        default:
            return "unknown";
    }
}
}    // namespace webrtc
