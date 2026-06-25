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
    if (data.size() < 12)
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

    std::size_t header_size = 12 + static_cast<std::size_t>(header.csrc_count) * 4;

    if (header_size > data.size())
    {
        return make_error("rtp csrc list is truncated");
    }

    if (header.extension)
    {
        if (header_size + 4 > data.size())
        {
            return make_error("rtp extension header is truncated");
        }

        const uint16_t extension_length_words = read_u16(data, header_size + 2);

        const std::size_t extension_size = 4 + static_cast<std::size_t>(extension_length_words) * 4;

        if (header_size + extension_size > data.size())
        {
            return make_error("rtp extension payload is truncated");
        }

        header_size += extension_size;
    }

    header.header_size = header_size;
    header.payload_offset = header_size;

    if (header_size > data.size())
    {
        return make_error("rtp header exceeds packet size");
    }

    std::size_t payload_size = data.size() - header_size;

    if (header.padding)
    {
        if (payload_size == 0)
        {
            return make_error("rtp padding flag set but payload is empty");
        }

        const std::size_t padding_size = static_cast<std::size_t>(data[data.size() - 1]);

        if (padding_size == 0)
        {
            return make_error("rtp padding size is zero");
        }

        if (padding_size > payload_size)
        {
            return make_error("rtp padding exceeds payload size");
        }

        header.padding_size = padding_size;
        payload_size -= padding_size;
    }

    header.payload_size = payload_size;

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

    if (header.packet_size < 4)
    {
        return make_error("rtcp packet size is invalid");
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
