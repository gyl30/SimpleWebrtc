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
#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
{
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

    block.has_generic_nack = feedback.has_generic_nack;
    block.has_keyframe_request = feedback.has_keyframe_request;
    block.has_transport_cc = feedback.has_transport_cc;
    block.has_remb = feedback.remb.has_value();

    if (feedback.remb.has_value())
    {
        block.remb_bitrate_bps = feedback.remb->bitrate_bps;
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

    packet.has_generic_nack = packet.has_generic_nack || block.has_generic_nack;

    packet.has_keyframe_request = packet.has_keyframe_request || block.has_keyframe_request;

    packet.has_transport_cc = packet.has_transport_cc || block.has_transport_cc;

    packet.has_remb = packet.has_remb || block.has_remb;

    packet.remb_bitrate_bps = std::max(packet.remb_bitrate_bps, block.remb_bitrate_bps);
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
