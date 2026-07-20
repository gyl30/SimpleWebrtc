#include "rtp/rtp_packet.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace webrtc
{
namespace
{
constexpr std::size_t k_rtp_fixed_header_size = 12;
constexpr std::size_t k_rtp_csrc_size = 4;
constexpr std::size_t k_rtp_extension_header_size = 4;
constexpr std::size_t k_rtcp_common_header_size = 4;

constexpr uint16_t k_one_byte_extension_profile = 0xBEDE;
constexpr uint16_t k_two_byte_extension_profile_mask = 0xFFF0;
constexpr uint16_t k_two_byte_extension_profile_value = 0x1000;
constexpr uint8_t k_one_byte_extension_reserved_id = 15;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
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

bool is_one_byte_extension_profile(uint16_t profile) { return profile == k_one_byte_extension_profile; }

bool is_two_byte_extension_profile(uint16_t profile) { return (profile & k_two_byte_extension_profile_mask) == k_two_byte_extension_profile_value; }

std::expected<void, std::string> validate_one_byte_header_extensions(std::span<const uint8_t> packet,
                                                                     std::size_t extension_payload_offset,
                                                                     std::size_t extension_payload_size)
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

        offset += size;
    }

    return {};
}

std::expected<void, std::string> validate_two_byte_header_extensions(std::span<const uint8_t> packet,
                                                                     std::size_t extension_payload_offset,
                                                                     std::size_t extension_payload_size)
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

        offset += size;
    }

    return {};
}

std::expected<std::size_t, std::string> validate_header_extensions(std::span<const uint8_t> packet, std::size_t extension_header_offset)
{
    if (extension_header_offset + k_rtp_extension_header_size > packet.size())
    {
        return make_error("rtp extension header is truncated");
    }

    const uint16_t extension_profile = read_u16(packet, extension_header_offset);
    const uint16_t extension_length_words = read_u16(packet, extension_header_offset + 2);
    const std::size_t extension_payload_offset = extension_header_offset + k_rtp_extension_header_size;
    const std::size_t extension_payload_size = static_cast<std::size_t>(extension_length_words) * 4;
    const std::size_t extension_total_size = k_rtp_extension_header_size + extension_payload_size;

    if (extension_header_offset + extension_total_size > packet.size())
    {
        return make_error("rtp extension payload is truncated");
    }

    std::expected<void, std::string> validation_result;

    if (is_one_byte_extension_profile(extension_profile))
    {
        validation_result = validate_one_byte_header_extensions(packet, extension_payload_offset, extension_payload_size);
    }
    else if (is_two_byte_extension_profile(extension_profile))
    {
        validation_result = validate_two_byte_header_extensions(packet, extension_payload_offset, extension_payload_size);
    }

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    return extension_total_size;
}

std::expected<void, std::string> validate_rtp_padding(std::span<const uint8_t> packet, bool padding, std::size_t payload_size)
{
    if (!padding)
    {
        return {};
    }

    if (payload_size == 0)
    {
        return make_error("rtp padding flag set but payload is empty");
    }

    const std::size_t padding_size = static_cast<std::size_t>(packet[packet.size() - 1]);

    if (padding_size == 0)
    {
        return make_error("rtp padding size is zero");
    }

    if (padding_size > payload_size)
    {
        return make_error("rtp padding exceeds payload size");
    }

    return {};
}

}    // namespace

rtp_packet_layout_result inspect_rtp_packet_layout(std::span<const uint8_t> data)
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

    const bool padding = (data[0] & 0x20U) != 0;
    const bool extension = (data[0] & 0x10U) != 0;
    const uint8_t csrc_count = static_cast<uint8_t>(data[0] & 0x0FU);

    std::size_t header_size = k_rtp_fixed_header_size + static_cast<std::size_t>(csrc_count) * k_rtp_csrc_size;

    if (header_size > data.size())
    {
        return make_error("rtp csrc list is truncated");
    }

    if (extension)
    {
        auto extension_result = validate_header_extensions(data, header_size);

        if (!extension_result)
        {
            return std::unexpected(extension_result.error());
        }

        header_size += *extension_result;
    }

    if (header_size > data.size())
    {
        return make_error("rtp header exceeds packet size");
    }

    const std::size_t wire_payload_size = data.size() - header_size;
    auto padding_result = validate_rtp_padding(data, padding, wire_payload_size);

    if (!padding_result)
    {
        return std::unexpected(padding_result.error());
    }

    const std::size_t padding_size = padding ? static_cast<std::size_t>(data.back()) : 0U;

    return rtp_packet_layout{
        .header_size = header_size,
        .media_payload_size = wire_payload_size - padding_size,
        .padding_size = padding_size,
        .padding = padding,
    };
}

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

rtp_packet_header_result parse_rtp_packet_header(std::span<const uint8_t> data)
{
    auto layout = inspect_rtp_packet_layout(data);

    if (!layout)
    {
        return std::unexpected(layout.error());
    }

    return rtp_packet_header{
        .marker = (data[1] & 0x80U) != 0,
        .payload_type = static_cast<uint8_t>(data[1] & 0x7FU),
        .sequence_number = read_u16(data, 2),
        .timestamp = read_u32(data, 4),
        .ssrc = read_u32(data, 8),
    };
}

rtcp_packet_header_result parse_rtcp_packet_header(std::span<const uint8_t> data)
{
    if (data.size() < k_rtcp_common_header_size)
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

    header.padding = (data[0] & 0x20U) != 0;
    header.count = static_cast<uint8_t>(data[0] & 0x1FU);
    header.packet_type = data[1];
    header.length = read_u16(data, 2);
    header.packet_size = (static_cast<std::size_t>(header.length) + 1) * 4;

    if (header.packet_size > data.size())
    {
        return make_error("rtcp packet is truncated");
    }

    if (header.padding)
    {
        if (header.packet_size <= k_rtcp_common_header_size)
        {
            return make_error("rtcp padding packet is too short");
        }

        const std::size_t padding_size = data[header.packet_size - 1];

        if (padding_size == 0)
        {
            return make_error("rtcp padding size is zero");
        }

        if (padding_size > header.packet_size - k_rtcp_common_header_size)
        {
            return make_error("rtcp padding exceeds packet size");
        }
    }

    if (header.packet_size >= 8)
    {
        header.has_ssrc = true;
        header.ssrc = read_u32(data, 4);
    }

    return header;
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
