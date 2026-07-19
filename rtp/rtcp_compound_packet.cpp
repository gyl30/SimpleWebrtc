#include "rtp/rtcp_compound_packet.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rtp/rtcp_feedback.h"
#include "rtp/rtcp_report.h"
#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
{
inline constexpr uint8_t k_rtcp_packet_type_sdes = 202;
inline constexpr uint8_t k_rtcp_packet_type_bye = 203;
inline constexpr uint8_t k_rtcp_sdes_item_end = 0;
inline constexpr uint8_t k_rtcp_sdes_item_cname = 1;
inline constexpr std::size_t k_rtcp_common_header_size = 4;
inline constexpr std::size_t k_rtcp_ssrc_size = 4;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

bool trailing_bytes_are_zero(std::span<const uint8_t> data, std::size_t offset, std::size_t end)
{
    if (offset > end || end > data.size())
    {
        return false;
    }

    for (; offset < end; ++offset)
    {
        if (data[offset] != 0)
        {
            return false;
        }
    }

    return true;
}

std::expected<std::size_t, std::string> rtcp_payload_end(const rtcp_packet_header& header,
                                                          std::span<const uint8_t> data,
                                                          std::string_view packet_name)
{
    if (header.packet_size > data.size())
    {
        std::string message("rtcp ");
        message.append(packet_name);
        message.append(" packet exceeds buffer size");
        return make_error(message);
    }

    std::size_t payload_end = header.packet_size;

    if (!header.padding)
    {
        return payload_end;
    }

    if (payload_end <= k_rtcp_common_header_size)
    {
        std::string message("rtcp ");
        message.append(packet_name);
        message.append(" padding packet is too short");
        return make_error(message);
    }

    const std::size_t padding_size = data[payload_end - 1];

    if (padding_size == 0)
    {
        std::string message("rtcp ");
        message.append(packet_name);
        message.append(" padding size is zero");
        return make_error(message);
    }

    if (padding_size > payload_end - k_rtcp_common_header_size)
    {
        std::string message("rtcp ");
        message.append(packet_name);
        message.append(" padding exceeds packet size");
        return make_error(message);
    }

    payload_end -= padding_size;
    return payload_end;
}

void fill_feedback_block(const rtcp_feedback_packet& feedback, rtcp_compound_block& block)
{
    block.is_feedback = true;
    block.feedback_name = rtcp_feedback_format_to_string(feedback.packet_type, feedback.format);

    if (feedback.remb_bitrate_bps.has_value())
    {
        block.feedback_name = "remb";
    }

    block.feedback_sender_ssrc = feedback.sender_ssrc;
    block.feedback_media_ssrc = feedback.media_ssrc;

    block.nack_count = feedback.nack_count;
    block.fir_count = feedback.fir_count;

    block.has_generic_nack = feedback.has_generic_nack;
    block.has_keyframe_request = feedback.has_keyframe_request;
    block.has_transport_cc = feedback.has_transport_cc;
    block.nack_entries = feedback.nack_entries;
    block.nack_sequence_numbers = feedback.nack_sequence_numbers;
    block.keyframe_request_media_ssrcs = feedback.keyframe_request_media_ssrcs;
    block.fir_entries = feedback.fir_entries;

    block.has_remb = feedback.remb_bitrate_bps.has_value();
    block.remb_bitrate_bps = feedback.remb_bitrate_bps.value_or(0);
}

void aggregate_feedback_block(const rtcp_compound_block& block, rtcp_compound_packet& packet)
{
    if (!block.is_feedback)
    {
        return;
    }

    packet.has_feedback = true;
    packet.feedback_block_count += 1;

    if (block.feedback_name == "pli")
    {
        packet.pli_count += 1;
    }
    else if (block.feedback_name == "fir")
    {
        packet.fir_block_count += 1;
    }

    packet.nack_count += block.nack_count;
    packet.fir_count += block.fir_count;

    if (block.has_generic_nack)
    {
        packet.generic_nack_block_count += 1;
    }

    if (block.has_transport_cc)
    {
        packet.transport_cc_block_count += 1;
    }

    if (block.has_remb)
    {
        packet.remb_block_count += 1;
    }

    const bool feedback_is_classified =
        block.feedback_name == "pli" || block.feedback_name == "fir" || block.has_generic_nack ||
        block.has_transport_cc || block.has_remb;

    if (!feedback_is_classified)
    {
        packet.other_feedback_block_count += 1;
    }

    packet.has_generic_nack = packet.has_generic_nack || block.has_generic_nack;
    packet.has_keyframe_request = packet.has_keyframe_request || block.has_keyframe_request;
    packet.has_transport_cc = packet.has_transport_cc || block.has_transport_cc;
    packet.nack_entries.insert(packet.nack_entries.end(), block.nack_entries.begin(), block.nack_entries.end());
    packet.nack_sequence_numbers.insert(packet.nack_sequence_numbers.end(),
                                        block.nack_sequence_numbers.begin(),
                                        block.nack_sequence_numbers.end());

    for (const uint32_t media_ssrc : block.keyframe_request_media_ssrcs)
    {
        if (std::find(packet.keyframe_request_media_ssrcs.begin(),
                      packet.keyframe_request_media_ssrcs.end(),
                      media_ssrc) == packet.keyframe_request_media_ssrcs.end())
        {
            packet.keyframe_request_media_ssrcs.push_back(media_ssrc);
        }
    }

    packet.fir_entries.insert(packet.fir_entries.end(), block.fir_entries.begin(), block.fir_entries.end());

    packet.has_remb = packet.has_remb || block.has_remb;
    packet.remb_bitrate_bps = std::max(packet.remb_bitrate_bps, block.remb_bitrate_bps);
}

void aggregate_report_packet(rtcp_report_packet report, rtcp_compound_packet& packet)
{
    packet.report_packet_count += 1;

    if (report.sender_info.has_value())
    {
        packet.sender_report_count += 1;
    }
    else
    {
        packet.receiver_report_count += 1;
    }

    packet.report_block_count += report.report_blocks.size();
    packet.report_packets.push_back(std::move(report));
}

rtcp_compound_block make_block_from_header(const rtcp_packet_header& header)
{
    rtcp_compound_block block;
    block.count = header.count;
    block.packet_type = header.packet_type;
    block.length = header.length;
    block.has_ssrc = header.has_ssrc;
    block.ssrc = header.ssrc;
    block.packet_type_name = rtcp_packet_type_to_string(header.packet_type);

    return block;
}

std::expected<std::vector<rtcp_sdes_chunk>, std::string> parse_rtcp_sdes_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    if (header->packet_type != k_rtcp_packet_type_sdes)
    {
        return make_error("rtcp packet is not sdes");
    }

    auto payload_end = rtcp_payload_end(*header, data, "sdes");

    if (!payload_end)
    {
        return std::unexpected(payload_end.error());
    }

    std::vector<rtcp_sdes_chunk> chunks;
    chunks.reserve(header->count);
    std::size_t offset = k_rtcp_common_header_size;

    for (std::size_t index = 0; index < header->count; ++index)
    {
        if (offset + k_rtcp_ssrc_size > *payload_end)
        {
            return make_error("rtcp sdes chunk ssrc is truncated");
        }

        rtcp_sdes_chunk chunk;
        chunk.ssrc = read_u32(data, offset);
        offset += k_rtcp_ssrc_size;

        bool end_item_seen = false;

        while (offset < *payload_end)
        {
            const uint8_t item_type = data[offset];
            offset += 1;

            if (item_type == k_rtcp_sdes_item_end)
            {
                end_item_seen = true;

                const std::size_t aligned_offset = (offset + 3U) & ~std::size_t{3U};

                if (aligned_offset > *payload_end)
                {
                    return make_error("rtcp sdes chunk padding is truncated");
                }

                if (!trailing_bytes_are_zero(data, offset, aligned_offset))
                {
                    return make_error("rtcp sdes chunk padding is not zero");
                }

                offset = aligned_offset;
                break;
            }

            if (offset >= *payload_end)
            {
                return make_error("rtcp sdes item length is truncated");
            }

            const std::size_t item_size = data[offset];
            offset += 1;

            if (offset + item_size > *payload_end)
            {
                return make_error("rtcp sdes item value is truncated");
            }

            rtcp_sdes_item item;
            item.type = item_type;
            item.value.assign(data.begin() + static_cast<std::ptrdiff_t>(offset),
                              data.begin() + static_cast<std::ptrdiff_t>(offset + item_size));

            if (item_type == k_rtcp_sdes_item_cname && chunk.cname.empty())
            {
                chunk.cname.assign(reinterpret_cast<const char*>(data.data() + offset), item_size);
            }

            chunk.items.push_back(std::move(item));
            offset += item_size;
        }

        if (!end_item_seen)
        {
            return make_error("rtcp sdes chunk end item is missing");
        }

        chunks.push_back(std::move(chunk));
    }

    if (offset != *payload_end)
    {
        return make_error("rtcp sdes packet has trailing payload bytes");
    }

    return chunks;
}

std::expected<rtcp_bye_packet, std::string> parse_rtcp_bye_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    if (header->packet_type != k_rtcp_packet_type_bye)
    {
        return make_error("rtcp packet is not bye");
    }

    auto payload_end = rtcp_payload_end(*header, data, "bye");

    if (!payload_end)
    {
        return std::unexpected(payload_end.error());
    }

    rtcp_bye_packet packet;
    packet.ssrcs.reserve(header->count);
    std::size_t offset = k_rtcp_common_header_size;

    for (std::size_t index = 0; index < header->count; ++index)
    {
        if (offset + k_rtcp_ssrc_size > *payload_end)
        {
            return make_error("rtcp bye ssrc list is truncated");
        }

        packet.ssrcs.push_back(read_u32(data, offset));
        offset += k_rtcp_ssrc_size;
    }

    if (offset == *payload_end)
    {
        return packet;
    }

    const std::size_t reason_size = data[offset];
    offset += 1;

    if (offset + reason_size > *payload_end)
    {
        return make_error("rtcp bye reason is truncated");
    }

    packet.reason.assign(reinterpret_cast<const char*>(data.data() + offset), reason_size);
    offset += reason_size;

    if (!trailing_bytes_are_zero(data, offset, *payload_end))
    {
        return make_error("rtcp bye reason padding is not zero");
    }

    return packet;
}
}    // namespace

rtcp_compound_packet_result parse_rtcp_compound_packet(std::span<const uint8_t> data)
{
    if (data.empty())
    {
        return make_error("rtcp compound packet is empty");
    }

    rtcp_compound_packet packet;
    std::size_t offset = 0;

    while (offset < data.size())
    {
        if (data.size() - offset < k_rtcp_common_header_size)
        {
            return make_error("rtcp compound trailing bytes are invalid");
        }

        std::span<const uint8_t> remaining = data.subspan(offset);

        auto header = parse_rtcp_packet_header(remaining);

        if (!header)
        {
            std::string message = "rtcp compound block parse failed: ";
            message.append(header.error());
            return std::unexpected(std::move(message));
        }

        if (header->packet_size == 0)
        {
            return make_error("rtcp compound block size is zero");
        }

        if (header->packet_size > remaining.size())
        {
            return make_error("rtcp compound block exceeds remaining size");
        }

        const bool is_last_block = offset + header->packet_size == data.size();

        if (header->padding && !is_last_block)
        {
            return make_error("rtcp compound padding is only allowed on the last block");
        }

        rtcp_compound_block block = make_block_from_header(*header);
        std::span<const uint8_t> block_data = data.subspan(offset, header->packet_size);

        if (is_rtcp_feedback_packet(block_data))
        {
            auto feedback = parse_rtcp_feedback_packet(block_data);

            if (!feedback)
            {
                std::string message = "rtcp compound feedback parse failed: ";
                message.append(feedback.error());
                return std::unexpected(std::move(message));
            }

            fill_feedback_block(*feedback, block);
            aggregate_feedback_block(block, packet);
        }
        else if (is_rtcp_report_packet(block_data))
        {
            auto report = parse_rtcp_report_packet(block_data);

            if (!report)
            {
                std::string message = "rtcp compound report parse failed: ";
                message.append(report.error());
                return std::unexpected(std::move(message));
            }

            block.is_report = true;
            aggregate_report_packet(std::move(*report), packet);
        }
        else if (header->packet_type == k_rtcp_packet_type_sdes)
        {
            auto chunks = parse_rtcp_sdes_packet(block_data);

            if (!chunks)
            {
                std::string message = "rtcp compound sdes parse failed: ";
                message.append(chunks.error());
                return std::unexpected(std::move(message));
            }

            block.is_sdes = true;
            packet.sdes_packet_count += 1;
            packet.sdes_chunks.insert(packet.sdes_chunks.end(),
                                      std::make_move_iterator(chunks->begin()),
                                      std::make_move_iterator(chunks->end()));
        }
        else if (header->packet_type == k_rtcp_packet_type_bye)
        {
            auto bye = parse_rtcp_bye_packet(block_data);

            if (!bye)
            {
                std::string message = "rtcp compound bye parse failed: ";
                message.append(bye.error());
                return std::unexpected(std::move(message));
            }

            block.is_bye = true;
            packet.has_bye = true;
            packet.bye_packets.push_back(std::move(*bye));
        }
        else
        {
            block.is_unknown = true;
            packet.unknown_block_count += 1;
        }

        packet.blocks.push_back(std::move(block));
        offset += header->packet_size;
    }

    if (packet.blocks.empty())
    {
        return make_error("rtcp compound packet has no blocks");
    }

    return packet;
}

std::string rtcp_compound_feedback_summary_to_string(const rtcp_compound_packet& packet)
{
    if (packet.has_bye)
    {
        return "bye";
    }

    if (!packet.has_feedback)
    {
        return "none";
    }

    if (packet.has_remb)
    {
        return "remb";
    }

    if (packet.has_keyframe_request)
    {
        return "keyframe_request";
    }

    if (packet.has_generic_nack)
    {
        return "generic_nack";
    }

    if (packet.has_transport_cc)
    {
        return "transport_cc";
    }

    return "feedback";
}
}    // namespace webrtc
