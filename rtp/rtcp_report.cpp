#include "rtp/rtcp_report.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
{
inline constexpr uint8_t k_rtcp_packet_type_sender_report = 200;
inline constexpr uint8_t k_rtcp_packet_type_receiver_report = 201;
inline constexpr std::size_t k_rtcp_common_header_size = 4;
inline constexpr std::size_t k_rtcp_sender_ssrc_size = 4;
inline constexpr std::size_t k_rtcp_sender_info_size = 20;
inline constexpr std::size_t k_rtcp_report_block_size = 24;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

int32_t read_i24(std::span<const uint8_t> data, std::size_t offset)
{
    uint32_t value =
        (static_cast<uint32_t>(data[offset]) << 16U) | (static_cast<uint32_t>(data[offset + 1]) << 8U) | static_cast<uint32_t>(data[offset + 2]);

    if ((value & 0x800000U) != 0)
    {
        value |= 0xff000000U;
    }

    return static_cast<int32_t>(value);
}

bool is_report_packet_type(uint8_t packet_type)
{
    return packet_type == k_rtcp_packet_type_sender_report || packet_type == k_rtcp_packet_type_receiver_report;
}

rtcp_sender_info parse_sender_info(std::span<const uint8_t> data, std::size_t offset)
{
    rtcp_sender_info sender_info;
    sender_info.ntp_msw = read_u32(data, offset);
    sender_info.ntp_lsw = read_u32(data, offset + 4);
    sender_info.rtp_timestamp = read_u32(data, offset + 8);
    sender_info.sender_packet_count = read_u32(data, offset + 12);
    sender_info.sender_octet_count = read_u32(data, offset + 16);
    return sender_info;
}

rtcp_report_block parse_report_block(std::span<const uint8_t> data, std::size_t offset)
{
    rtcp_report_block block;
    block.ssrc = read_u32(data, offset);
    block.fraction_lost = data[offset + 4];
    block.cumulative_lost = read_i24(data, offset + 5);
    block.extended_highest_sequence_number = read_u32(data, offset + 8);
    block.jitter = read_u32(data, offset + 12);
    block.last_sender_report = read_u32(data, offset + 16);
    block.delay_since_last_sender_report = read_u32(data, offset + 20);
    return block;
}

std::expected<std::size_t, std::string> rtcp_report_payload_end(const rtcp_packet_header& header, std::span<const uint8_t> data)
{
    if (header.packet_size > data.size())
    {
        return make_error("rtcp report packet exceeds buffer size");
    }

    std::size_t payload_end = header.packet_size;

    if (!header.padding)
    {
        return payload_end;
    }

    if (payload_end <= k_rtcp_common_header_size)
    {
        return make_error("rtcp report padding packet is too short");
    }

    const std::size_t padding_size = data[payload_end - 1];

    if (padding_size == 0)
    {
        return make_error("rtcp report padding size is zero");
    }

    if (padding_size > payload_end - k_rtcp_common_header_size)
    {
        return make_error("rtcp report padding exceeds packet size");
    }

    payload_end -= padding_size;

    return payload_end;
}
}    // namespace

bool is_rtcp_report_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return false;
    }

    return is_report_packet_type(header->packet_type);
}

rtcp_report_packet_result parse_rtcp_report_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    if (!is_report_packet_type(header->packet_type))
    {
        return make_error("rtcp packet is not report");
    }

    auto payload_end = rtcp_report_payload_end(*header, data);

    if (!payload_end)
    {
        return std::unexpected(payload_end.error());
    }

    if (*payload_end < k_rtcp_common_header_size + k_rtcp_sender_ssrc_size)
    {
        return make_error("rtcp report packet is too short");
    }

    rtcp_report_packet packet;
    packet.version = header->version;
    packet.padding = header->padding;
    packet.report_count = header->count;
    packet.packet_type = header->packet_type;
    packet.length = header->length;
    packet.packet_size = header->packet_size;
    packet.sender_ssrc = read_u32(data, k_rtcp_common_header_size);
    packet.is_sender_report = header->packet_type == k_rtcp_packet_type_sender_report;
    packet.is_receiver_report = header->packet_type == k_rtcp_packet_type_receiver_report;

    std::size_t report_block_offset = k_rtcp_common_header_size + k_rtcp_sender_ssrc_size;

    if (packet.is_sender_report)
    {
        if (*payload_end < report_block_offset + k_rtcp_sender_info_size)
        {
            return make_error("rtcp sender report sender info is truncated");
        }

        packet.has_sender_info = true;
        packet.sender_info = parse_sender_info(data, report_block_offset);

        report_block_offset += k_rtcp_sender_info_size;
    }
    const std::size_t report_block_bytes = static_cast<std::size_t>(packet.report_count) * k_rtcp_report_block_size;
    const std::size_t report_block_end = report_block_offset + report_block_bytes;

    if (report_block_end > *payload_end)
    {
        return make_error("rtcp report block list is truncated");
    }

    packet.report_blocks.reserve(packet.report_count);
    for (std::size_t i = 0; i < packet.report_count; ++i)
    {
        const std::size_t offset = report_block_offset + i * k_rtcp_report_block_size;

        packet.report_blocks.push_back(parse_report_block(data, offset));
    }

    return packet;
}
}    // namespace webrtc
