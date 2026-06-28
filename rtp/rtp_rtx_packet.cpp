#include "rtp/rtp_rtx_packet.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void write_u16(std::vector<uint8_t>& packet, std::size_t offset, uint16_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 8U) & 0xffU);

    packet[offset + 1] = static_cast<uint8_t>(value & 0xffU);
}

void write_u32(std::vector<uint8_t>& packet, std::size_t offset, uint32_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 24U) & 0xffU);

    packet[offset + 1] = static_cast<uint8_t>((value >> 16U) & 0xffU);

    packet[offset + 2] = static_cast<uint8_t>((value >> 8U) & 0xffU);

    packet[offset + 3] = static_cast<uint8_t>(value & 0xffU);
}
}    // namespace

rtp_rtx_packet_result make_rtp_rtx_packet(std::span<const uint8_t> primary_packet, const rtp_rtx_packet_options& options)
{
    if (primary_packet.empty())
    {
        return make_error("rtx primary packet is empty");
    }

    if (options.payload_type > 127)
    {
        return make_error("rtx payload type is out of range");
    }

    if (options.ssrc == 0)
    {
        return make_error("rtx ssrc is zero");
    }

    auto primary_header = parse_rtp_packet_header(primary_packet);

    if (!primary_header)
    {
        std::string message = "rtx primary packet parse failed: ";

        message.append(primary_header.error());

        return std::unexpected(std::move(message));
    }

    if (primary_header->payload_size == 0)
    {
        return make_error("rtx primary packet payload is empty");
    }

    if (primary_header->payload_offset + primary_header->payload_size > primary_packet.size())
    {
        return make_error("rtx primary packet payload is truncated");
    }

    std::vector<uint8_t> rtx_packet;

    rtx_packet.reserve(primary_header->payload_offset + 2 + primary_header->payload_size);

    rtx_packet.insert(rtx_packet.end(), primary_packet.begin(), primary_packet.begin() + static_cast<std::ptrdiff_t>(primary_header->payload_offset));

    /*
     * RTX 包不复制 primary packet 的 RTP padding。
     * 如果 primary packet 带 padding，需要清掉 RTP header 的 padding bit。
     */
    rtx_packet[0] = static_cast<uint8_t>(rtx_packet[0] & static_cast<uint8_t>(~0x20U));

    rtx_packet[1] = static_cast<uint8_t>((rtx_packet[1] & 0x80U) | options.payload_type);

    write_u16(rtx_packet, 2, options.sequence_number);

    write_u32(rtx_packet, 4, options.timestamp);

    write_u32(rtx_packet, 8, options.ssrc);

    write_u16(rtx_packet, rtx_packet.size(), primary_header->sequence_number);

    const auto payload_begin = primary_packet.begin() + static_cast<std::ptrdiff_t>(primary_header->payload_offset);

    const auto payload_end = payload_begin + static_cast<std::ptrdiff_t>(primary_header->payload_size);

    rtx_packet.insert(rtx_packet.end(), payload_begin, payload_end);

    return rtx_packet;
}
}    // namespace webrtc
