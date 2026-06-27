#include "rtp/rtcp_compound_packet.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "rtp/rtcp_feedback.h"
#include "rtp/rtcp_report.h"
#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
{
inline constexpr uint8_t k_rtcp_packet_type_bye = 203;
inline constexpr std::size_t k_rtcp_common_header_size = 4;
inline constexpr std::size_t k_rtcp_ssrc_size = 4;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void fill_feedback_block(const rtcp_feedback_packet& feedback, rtcp_compound_block& block)
{
    block.is_feedback = true;
    block.feedback_format = feedback.format;
    block.feedback_name = rtcp_feedback_format_to_string(feedback.packet_type, feedback.format);

    if (feedback.remb.has_value())
    {
        block.feedback_name = "remb";
    }

    block.feedback_sender_ssrc = feedback.sender_ssrc;
    block.feedback_media_ssrc = feedback.media_ssrc;

    block.nack_count = feedback.nack_items.size();
    block.fir_count = feedback.fir_items.size();

    block.nack_items = feedback.nack_items;
    block.fir_items = feedback.fir_items;

    block.has_generic_nack = feedback.has_generic_nack;
    block.has_keyframe_request = feedback.has_keyframe_request;
    block.has_transport_cc = feedback.has_transport_cc;
    block.has_remb = feedback.remb.has_value();

    if (feedback.remb.has_value())
    {
        block.remb_bitrate_bps = feedback.remb->bitrate_bps;
        block.remb_ssrcs = feedback.remb->ssrcs;
    }
}

void aggregate_feedback_block(const rtcp_compound_block& block, rtcp_compound_packet& packet)
{
    if (!block.is_feedback)
    {
        return;
    }

    packet.has_feedback = true;
    packet.feedback_block_count += 1;

    packet.nack_count += block.nack_count;
    packet.fir_count += block.fir_count;

    packet.nack_items.insert(packet.nack_items.end(), block.nack_items.begin(), block.nack_items.end());

    packet.fir_items.insert(packet.fir_items.end(), block.fir_items.begin(), block.fir_items.end());

    packet.has_generic_nack = packet.has_generic_nack || block.has_generic_nack;

    packet.has_keyframe_request = packet.has_keyframe_request || block.has_keyframe_request;

    packet.has_transport_cc = packet.has_transport_cc || block.has_transport_cc;

    packet.has_remb = packet.has_remb || block.has_remb;

    packet.remb_bitrate_bps = std::max(packet.remb_bitrate_bps, block.remb_bitrate_bps);
}

void fill_report_block(const rtcp_report_packet& report, rtcp_compound_block& block)
{
    block.is_report = true;
    block.is_sender_report = report.is_sender_report;
    block.is_receiver_report = report.is_receiver_report;
    block.has_sender_info = report.has_sender_info;
    block.report_sender_ssrc = report.sender_ssrc;
    block.sender_info = report.sender_info;
    block.report_blocks = report.report_blocks;
}

void aggregate_report_block(const rtcp_compound_block& block, rtcp_compound_packet& packet)
{
    if (!block.is_report)
    {
        return;
    }

    packet.report_packet_count += 1;
    packet.report_block_count += block.report_blocks.size();

    packet.has_sender_report = packet.has_sender_report || block.is_sender_report;

    packet.has_receiver_report = packet.has_receiver_report || block.is_receiver_report;

    packet.report_sender_ssrc = block.report_sender_ssrc;

    if (block.has_sender_info)
    {
        packet.has_sender_info = true;
        packet.sender_info = block.sender_info;
    }

    packet.report_blocks.insert(packet.report_blocks.end(), block.report_blocks.begin(), block.report_blocks.end());
}

rtcp_compound_block make_block_from_header(const rtcp_packet_header& header, std::size_t offset)
{
    rtcp_compound_block block;
    block.offset = offset;
    block.packet_size = header.packet_size;
    block.version = header.version;
    block.padding = header.padding;
    block.count = header.count;
    block.packet_type = header.packet_type;
    block.length = header.length;
    block.has_ssrc = header.has_ssrc;
    block.ssrc = header.ssrc;
    block.packet_type_name = rtcp_packet_type_to_string(header.packet_type);

    return block;
}
struct rtcp_bye_packet
{
    std::vector<uint32_t> ssrcs;

    std::string reason;
};

using rtcp_bye_packet_result = std::expected<rtcp_bye_packet, std::string>;

uint32_t read_network_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

rtcp_bye_packet_result parse_rtcp_bye_packet(std::span<const uint8_t> data)
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

    if (header->packet_size > data.size())
    {
        return make_error("rtcp bye packet is truncated");
    }

    std::size_t payload_end = header->packet_size;

    if (header->padding)
    {
        if (payload_end == 0)
        {
            return make_error("rtcp bye padding packet is empty");
        }

        const std::size_t padding_size = data[payload_end - 1];

        if (padding_size == 0)
        {
            return make_error("rtcp bye padding size is zero");
        }

        if (padding_size > payload_end - k_rtcp_common_header_size)
        {
            return make_error("rtcp bye padding exceeds packet size");
        }

        payload_end -= padding_size;
    }

    std::size_t offset = k_rtcp_common_header_size;

    const std::size_t ssrc_count = header->count;

    const std::size_t ssrc_bytes = ssrc_count * k_rtcp_ssrc_size;

    if (offset + ssrc_bytes > payload_end)
    {
        return make_error("rtcp bye ssrc list is truncated");
    }

    rtcp_bye_packet packet;

    packet.ssrcs.reserve(ssrc_count);

    for (std::size_t index = 0; index < ssrc_count; ++index)
    {
        packet.ssrcs.push_back(read_network_u32(data, offset));

        offset += k_rtcp_ssrc_size;
    }

    if (offset < payload_end)
    {
        const std::size_t reason_size = data[offset];

        offset += 1;

        if (offset + reason_size > payload_end)
        {
            return make_error("rtcp bye reason is truncated");
        }

        if (reason_size != 0)
        {
            packet.reason.assign(reinterpret_cast<const char*>(data.data() + offset), reason_size);
        }
    }

    return packet;
}

void fill_bye_block(const rtcp_bye_packet& bye, rtcp_compound_block& block)
{
    block.is_bye = true;
    block.bye_ssrcs = bye.ssrcs;
    block.bye_reason = bye.reason;
}

void aggregate_bye_block(const rtcp_compound_block& block, rtcp_compound_packet& packet)
{
    if (!block.is_bye)
    {
        return;
    }

    packet.has_bye = true;

    packet.bye_packet_count += 1;

    packet.bye_ssrcs.insert(packet.bye_ssrcs.end(), block.bye_ssrcs.begin(), block.bye_ssrcs.end());

    if (packet.bye_reason.empty() && !block.bye_reason.empty())
    {
        packet.bye_reason = block.bye_reason;
    }
}
}    // namespace

rtcp_compound_packet_result parse_rtcp_compound_packet(std::span<const uint8_t> data)
{
    if (data.empty())
    {
        return make_error("rtcp compound packet is empty");
    }

    rtcp_compound_packet packet;
    packet.packet_size = data.size();

    std::size_t offset = 0;

    while (offset < data.size())
    {
        if (data.size() - offset < 4)
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

        rtcp_compound_block block = make_block_from_header(*header, offset);

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

            fill_report_block(*report, block);

            aggregate_report_block(block, packet);
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

            fill_bye_block(*bye, block);

            aggregate_bye_block(block, packet);
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
    if (!packet.has_feedback)
    {
        return "none";
    }

    if (packet.has_bye)
    {
        return "bye";
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
