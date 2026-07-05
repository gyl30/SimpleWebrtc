#include "rtp/rtcp_feedback.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <algorithm>
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
        {
            constexpr std::size_t k_transport_cc_fixed_fci_size = 8;

            if (offset + k_transport_cc_fixed_fci_size > end)
            {
                return make_error("rtcp transport cc feedback fci is truncated");
            }

            packet.has_transport_cc = true;
            packet.transport_cc_base_sequence_number = read_u16(data, offset);
            packet.transport_cc_packet_status_count = read_u16(data, offset + 2);

            packet.transport_cc_reference_time_64ms = (static_cast<uint32_t>(data[offset + 4]) << 16U) |
                                                      (static_cast<uint32_t>(data[offset + 5]) << 8U) | static_cast<uint32_t>(data[offset + 6]);

            packet.transport_cc_feedback_packet_count = data[offset + 7];

            return {};
        }

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

void write_u32(std::vector<uint8_t>& data, std::size_t offset, uint32_t value)
{
    data[offset] = static_cast<uint8_t>((value >> 24U) & 0xffU);
    data[offset + 1] = static_cast<uint8_t>((value >> 16U) & 0xffU);
    data[offset + 2] = static_cast<uint8_t>((value >> 8U) & 0xffU);
    data[offset + 3] = static_cast<uint8_t>(value & 0xffU);
}

std::expected<void, std::string> validate_block_rewrite(std::span<const uint8_t> packet, const rtcp_feedback_block_rewrite& rewrite)
{
    if (rewrite.block_size < 12)
    {
        return make_error("rtcp feedback block rewrite block is too small");
    }

    if (rewrite.block_offset > packet.size())
    {
        return make_error("rtcp feedback block rewrite offset exceeds packet size");
    }

    if (rewrite.block_size > packet.size() - rewrite.block_offset)
    {
        return make_error("rtcp feedback block rewrite size exceeds packet size");
    }

    std::span<const uint8_t> block = packet.subspan(rewrite.block_offset, rewrite.block_size);

    auto header = parse_rtcp_packet_header(block);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    if (!is_feedback_packet_type(header->packet_type))
    {
        return make_error("rtcp feedback block rewrite block is not feedback");
    }

    if (header->packet_size != rewrite.block_size)
    {
        return make_error("rtcp feedback block rewrite size mismatch");
    }

    return {};
}

std::expected<void, std::string> apply_media_ssrc_rewrite(std::vector<uint8_t>& packet, const rtcp_feedback_block_rewrite& rewrite)
{
    if (!rewrite.rewrite_media_ssrc)
    {
        return {};
    }

    if (rewrite.source_media_ssrc == 0)
    {
        return make_error("rtcp feedback block rewrite source media ssrc is zero");
    }

    if (rewrite.target_media_ssrc == 0)
    {
        return make_error("rtcp feedback block rewrite target media ssrc is zero");
    }

    const std::size_t media_ssrc_offset = rewrite.block_offset + 8;

    const uint32_t current_ssrc = read_u32(packet, media_ssrc_offset);

    if (current_ssrc != rewrite.source_media_ssrc)
    {
        return make_error("rtcp feedback block rewrite source media ssrc mismatch");
    }

    write_u32(packet, media_ssrc_offset, rewrite.target_media_ssrc);

    return {};
}

std::expected<void, std::string> apply_fci_ssrc_rewrites(std::vector<uint8_t>& packet, const rtcp_feedback_block_rewrite& rewrite)
{
    for (const auto& fci_rewrite : rewrite.fci_ssrc_rewrites)
    {
        if (fci_rewrite.source_ssrc == 0)
        {
            return make_error("rtcp feedback block rewrite fci source ssrc is zero");
        }

        if (fci_rewrite.target_ssrc == 0)
        {
            return make_error("rtcp feedback block rewrite fci target ssrc is zero");
        }

        if (fci_rewrite.offset > rewrite.block_size)
        {
            return make_error("rtcp feedback block rewrite fci offset exceeds block size");
        }

        if (4 > rewrite.block_size - fci_rewrite.offset)
        {
            return make_error("rtcp feedback block rewrite fci ssrc exceeds block size");
        }

        const std::size_t absolute_offset = rewrite.block_offset + fci_rewrite.offset;

        const uint32_t current_ssrc = read_u32(packet, absolute_offset);

        if (current_ssrc != fci_rewrite.source_ssrc)
        {
            return make_error("rtcp feedback block rewrite fci source ssrc mismatch");
        }

        write_u32(packet, absolute_offset, fci_rewrite.target_ssrc);
    }

    return {};
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

struct rtcp_feedback_block_drop_range
{
    std::size_t begin = 0;
    std::size_t end = 0;
};

std::expected<std::vector<rtcp_feedback_block_drop_range>, std::string> make_feedback_block_drop_ranges(
    std::span<const rtcp_feedback_block_rewrite> rewrites)
{
    std::vector<rtcp_feedback_block_drop_range> ranges;

    ranges.reserve(rewrites.size());

    for (const auto& rewrite : rewrites)
    {
        if (!rewrite.drop_block)
        {
            continue;
        }

        rtcp_feedback_block_drop_range range;

        range.begin = rewrite.block_offset;
        range.end = rewrite.block_offset + rewrite.block_size;

        ranges.push_back(range);
    }

    std::sort(ranges.begin(),
              ranges.end(),
              [](const rtcp_feedback_block_drop_range& left, const rtcp_feedback_block_drop_range& right) { return left.begin < right.begin; });

    std::size_t previous_end = 0;

    for (const auto& range : ranges)
    {
        if (range.begin < previous_end)
        {
            return make_error("rtcp feedback block drop ranges overlap");
        }

        previous_end = range.end;
    }

    return ranges;
}

std::vector<uint8_t> copy_without_feedback_block_ranges(std::span<const uint8_t> packet, const std::vector<rtcp_feedback_block_drop_range>& ranges)
{
    std::vector<uint8_t> filtered;

    filtered.reserve(packet.size());

    std::size_t cursor = 0;

    for (const auto& range : ranges)
    {
        if (cursor < range.begin)
        {
            filtered.insert(
                filtered.end(), packet.begin() + static_cast<std::ptrdiff_t>(cursor), packet.begin() + static_cast<std::ptrdiff_t>(range.begin));
        }

        cursor = range.end;
    }

    if (cursor < packet.size())
    {
        filtered.insert(filtered.end(), packet.begin() + static_cast<std::ptrdiff_t>(cursor), packet.end());
    }

    return filtered;
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

rtcp_feedback_rewrite_result rewrite_rtcp_feedback_blocks(std::span<const uint8_t> packet, std::span<const rtcp_feedback_block_rewrite> rewrites)
{
    if (packet.empty())
    {
        return make_error("rtcp feedback block rewrite packet is empty");
    }

    if (rewrites.empty())
    {
        std::vector<uint8_t> copied;

        copied.assign(packet.begin(), packet.end());

        return copied;
    }

    std::vector<uint8_t> rewritten;

    rewritten.assign(packet.begin(), packet.end());

    for (const auto& rewrite : rewrites)
    {
        auto validation_result = validate_block_rewrite(packet, rewrite);

        if (!validation_result)
        {
            return std::unexpected(validation_result.error());
        }

        if (rewrite.drop_block)
        {
            continue;
        }

        auto media_rewrite_result = apply_media_ssrc_rewrite(rewritten, rewrite);

        if (!media_rewrite_result)
        {
            return std::unexpected(media_rewrite_result.error());
        }

        auto fci_rewrite_result = apply_fci_ssrc_rewrites(rewritten, rewrite);

        if (!fci_rewrite_result)
        {
            return std::unexpected(fci_rewrite_result.error());
        }
    }

    auto drop_ranges = make_feedback_block_drop_ranges(rewrites);

    if (!drop_ranges)
    {
        return std::unexpected(drop_ranges.error());
    }

    if (!drop_ranges->empty())
    {
        return copy_without_feedback_block_ranges(std::span<const uint8_t>(rewritten.data(), rewritten.size()), *drop_ranges);
    }

    return rewritten;
}
}    // namespace webrtc
