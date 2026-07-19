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
    block.keyframe_request_media_ssrcs = feedback.keyframe_request_media_ssrcs;

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

    packet.nack_count += block.nack_count;
    packet.fir_count += block.fir_count;

    packet.has_generic_nack = packet.has_generic_nack || block.has_generic_nack;
    packet.has_keyframe_request = packet.has_keyframe_request || block.has_keyframe_request;
    packet.has_transport_cc = packet.has_transport_cc || block.has_transport_cc;

    for (const uint32_t media_ssrc : block.keyframe_request_media_ssrcs)
    {
        if (std::find(packet.keyframe_request_media_ssrcs.begin(),
                      packet.keyframe_request_media_ssrcs.end(),
                      media_ssrc) == packet.keyframe_request_media_ssrcs.end())
        {
            packet.keyframe_request_media_ssrcs.push_back(media_ssrc);
        }
    }

    packet.has_remb = packet.has_remb || block.has_remb;
    packet.remb_bitrate_bps = std::max(packet.remb_bitrate_bps, block.remb_bitrate_bps);
}

void aggregate_report_packet(const rtcp_report_packet& report, rtcp_compound_packet& packet)
{
    packet.report_packet_count += 1;
    packet.report_block_count += report.report_blocks.size();

    if (!report.report_blocks.empty())
    {
        packet.last_report_block = report.report_blocks.back();
    }
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

std::expected<void, std::string> validate_rtcp_bye_packet(std::span<const uint8_t> data)
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
    const std::size_t ssrc_bytes = static_cast<std::size_t>(header->count) * k_rtcp_ssrc_size;

    if (offset + ssrc_bytes > payload_end)
    {
        return make_error("rtcp bye ssrc list is truncated");
    }

    offset += ssrc_bytes;

    if (offset < payload_end)
    {
        const std::size_t reason_size = data[offset];

        offset += 1;

        if (offset + reason_size > payload_end)
        {
            return make_error("rtcp bye reason is truncated");
        }
    }

    return {};
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

            aggregate_report_packet(*report, packet);
        }
        else if (header->packet_type == k_rtcp_packet_type_bye)
        {
            auto bye = validate_rtcp_bye_packet(block_data);

            if (!bye)
            {
                std::string message = "rtcp compound bye parse failed: ";

                message.append(bye.error());

                return std::unexpected(std::move(message));
            }

            packet.has_bye = true;
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
