#include "rtp/rtcp_feedback.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
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

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

bool is_feedback_packet_type(uint8_t packet_type)
{
    return packet_type == k_rtcp_packet_type_transport_feedback || packet_type == k_rtcp_packet_type_payload_feedback;
}

bool is_remb_fci(std::span<const uint8_t> data, std::size_t offset, std::size_t end)
{
    if (offset + 4 > end)
    {
        return false;
    }

    return data[offset] == static_cast<uint8_t>('R') && data[offset + 1] == static_cast<uint8_t>('E') &&
           data[offset + 2] == static_cast<uint8_t>('M') && data[offset + 3] == static_cast<uint8_t>('B');
}

std::expected<void, std::string> parse_generic_nack_items(std::span<const uint8_t> data,
                                                          std::size_t offset,
                                                          std::size_t end,
                                                          rtcp_feedback_packet& packet)
{
    const std::size_t fci_size = end - offset;

    if (fci_size % 4 != 0)
    {
        return make_error("rtcp nack fci size is invalid");
    }

    packet.has_generic_nack = true;

    for (std::size_t current = offset; current < end; current += 4)
    {
        rtcp_nack_item item;
        item.packet_id = read_u16(data, current);
        item.lost_packet_bitmask = read_u16(data, current + 2);
        packet.nack_items.push_back(item);
    }

    return {};
}

std::expected<void, std::string> parse_pli(std::size_t offset, std::size_t end, rtcp_feedback_packet& packet)
{
    if (offset != end)
    {
        return make_error("rtcp pli fci must be empty");
    }

    packet.has_keyframe_request = true;

    return {};
}

std::expected<void, std::string> parse_fir_items(std::span<const uint8_t> data, std::size_t offset, std::size_t end, rtcp_feedback_packet& packet)
{
    const std::size_t fci_size = end - offset;

    if (fci_size % 8 != 0)
    {
        return make_error("rtcp fir fci size is invalid");
    }

    packet.has_keyframe_request = true;

    for (std::size_t current = offset; current < end; current += 8)
    {
        rtcp_fir_item item;
        item.ssrc = read_u32(data, current);
        item.sequence_number = data[current + 4];
        packet.fir_items.push_back(item);
    }

    return {};
}

std::expected<void, std::string> parse_remb(std::span<const uint8_t> data, std::size_t offset, std::size_t end, rtcp_feedback_packet& packet)
{
    if (!is_remb_fci(data, offset, end))
    {
        return {};
    }

    if (offset + 8 > end)
    {
        return make_error("rtcp remb fci is truncated");
    }

    rtcp_remb_info remb;
    remb.ssrc_count = data[offset + 4];
    remb.bitrate_exponent = static_cast<uint8_t>(data[offset + 5] >> 2U);

    remb.bitrate_mantissa = (static_cast<uint32_t>(data[offset + 5] & 0x03U) << 16U) | (static_cast<uint32_t>(data[offset + 6]) << 8U) |
                            static_cast<uint32_t>(data[offset + 7]);

    remb.bitrate_bps = static_cast<uint64_t>(remb.bitrate_mantissa) << remb.bitrate_exponent;

    const std::size_t ssrc_offset = offset + 8;

    const std::size_t required_size = ssrc_offset + static_cast<std::size_t>(remb.ssrc_count) * 4;

    if (required_size > end)
    {
        return make_error("rtcp remb ssrc list is truncated");
    }

    remb.ssrcs.reserve(remb.ssrc_count);

    for (std::size_t i = 0; i < remb.ssrc_count; ++i)
    {
        const std::size_t current = ssrc_offset + i * 4;

        remb.ssrcs.push_back(read_u32(data, current));
    }

    packet.remb = std::move(remb);

    return {};
}

std::expected<void, std::string> parse_transport_feedback(std::span<const uint8_t> data,
                                                          std::size_t offset,
                                                          std::size_t end,
                                                          rtcp_feedback_packet& packet)
{
    switch (packet.format)
    {
        case k_rtcp_transport_feedback_generic_nack:
            return parse_generic_nack_items(data, offset, end, packet);

        case k_rtcp_transport_feedback_transport_cc:
            packet.has_transport_cc = true;
            return {};

        case k_rtcp_transport_feedback_tmmbr:
        case k_rtcp_transport_feedback_tmmbn:
            return {};

        default:
            return {};
    }
}

std::expected<void, std::string> parse_payload_feedback(std::span<const uint8_t> data,
                                                        std::size_t offset,
                                                        std::size_t end,
                                                        rtcp_feedback_packet& packet)
{
    switch (packet.format)
    {
        case k_rtcp_payload_feedback_pli:
            return parse_pli(offset, end, packet);

        case k_rtcp_payload_feedback_fir:
            return parse_fir_items(data, offset, end, packet);

        case k_rtcp_payload_feedback_afb:
            return parse_remb(data, offset, end, packet);

        case k_rtcp_payload_feedback_sli:
        case k_rtcp_payload_feedback_rpsi:
            return {};

        default:
            return {};
    }
}
}    // namespace

bool is_rtcp_feedback_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return false;
    }

    return is_feedback_packet_type(header->packet_type);
}

rtcp_feedback_packet_result parse_rtcp_feedback_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    if (!is_feedback_packet_type(header->packet_type))
    {
        return make_error("rtcp packet is not feedback");
    }

    if (header->packet_size < 12)
    {
        return make_error("rtcp feedback packet is shorter than feedback header");
    }

    rtcp_feedback_packet packet;
    packet.version = header->version;
    packet.padding = header->padding;
    packet.format = header->count;
    packet.packet_type = header->packet_type;
    packet.length = header->length;
    packet.packet_size = header->packet_size;
    packet.sender_ssrc = read_u32(data, 4);
    packet.media_ssrc = read_u32(data, 8);

    const std::size_t fci_offset = 12;
    const std::size_t packet_end = header->packet_size;

    std::expected<void, std::string> parse_result;

    if (packet.packet_type == k_rtcp_packet_type_transport_feedback)
    {
        parse_result = parse_transport_feedback(data, fci_offset, packet_end, packet);
    }
    else
    {
        parse_result = parse_payload_feedback(data, fci_offset, packet_end, packet);
    }

    if (!parse_result)
    {
        return std::unexpected(parse_result.error());
    }

    return packet;
}

std::string rtcp_feedback_format_to_string(uint8_t packet_type, uint8_t format)
{
    if (packet_type == k_rtcp_packet_type_transport_feedback)
    {
        switch (format)
        {
            case k_rtcp_transport_feedback_generic_nack:
                return "generic_nack";

            case k_rtcp_transport_feedback_tmmbr:
                return "tmmbr";

            case k_rtcp_transport_feedback_tmmbn:
                return "tmmbn";

            case k_rtcp_transport_feedback_transport_cc:
                return "transport_cc";

            default:
                return "transport_feedback_unknown";
        }
    }

    if (packet_type == k_rtcp_packet_type_payload_feedback)
    {
        switch (format)
        {
            case k_rtcp_payload_feedback_pli:
                return "pli";

            case k_rtcp_payload_feedback_sli:
                return "sli";

            case k_rtcp_payload_feedback_rpsi:
                return "rpsi";

            case k_rtcp_payload_feedback_fir:
                return "fir";

            case k_rtcp_payload_feedback_afb:
                return "afb";

            default:
                return "payload_feedback_unknown";
        }
    }

    return "unknown";
}
}    // namespace webrtc
