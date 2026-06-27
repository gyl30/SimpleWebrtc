#include "media/rtcp_feedback_router.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "media/media_router.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
namespace
{
rtcp_feedback_event_type choose_feedback_event_type(const srtp_packet_process_result& packet)
{
    if (packet.rtcp_has_remb)
    {
        return rtcp_feedback_event_type::remb;
    }

    if (packet.rtcp_has_keyframe_request)
    {
        return rtcp_feedback_event_type::keyframe_request;
    }

    if (packet.rtcp_has_generic_nack)
    {
        return rtcp_feedback_event_type::generic_nack;
    }

    if (packet.rtcp_has_transport_cc)
    {
        return rtcp_feedback_event_type::transport_cc;
    }

    return rtcp_feedback_event_type::compound_feedback;
}
rtcp_feedback_event_type choose_feedback_event_type(const rtcp_compound_block& block)
{
    if (block.has_remb)
    {
        return rtcp_feedback_event_type::remb;
    }

    if (block.has_keyframe_request)
    {
        return rtcp_feedback_event_type::keyframe_request;
    }

    if (block.has_generic_nack)
    {
        return rtcp_feedback_event_type::generic_nack;
    }

    if (block.has_transport_cc)
    {
        return rtcp_feedback_event_type::transport_cc;
    }

    return rtcp_feedback_event_type::compound_feedback;
}
}    // namespace

std::optional<rtcp_feedback_route_event> make_rtcp_feedback_route_event(const srtp_packet_process_result& packet, const media_route_result& route)
{
    if (packet.kind != srtp_packet_kind::rtcp)
    {
        return std::nullopt;
    }

    if (!packet.rtcp_is_feedback)
    {
        return std::nullopt;
    }

    if (!route.known_peer)
    {
        return std::nullopt;
    }

    if (route.action == media_route_action::none)
    {
        return std::nullopt;
    }

    rtcp_feedback_route_event event;
    event.valid = true;
    event.event_type = choose_feedback_event_type(packet);
    event.action = route.action;
    event.source = route.source;

    event.packet_type = packet.payload_type;
    event.feedback_format = packet.rtcp_feedback_format;
    event.feedback_name = packet.rtcp_feedback_name;

    event.ssrc = packet.ssrc;
    event.sender_ssrc = packet.rtcp_sender_ssrc;
    event.media_ssrc = packet.rtcp_media_ssrc;

    event.nack_count = packet.rtcp_nack_count;
    event.fir_count = packet.rtcp_fir_count;

    event.nack_items = packet.rtcp_nack_items;
    event.fir_items = packet.rtcp_fir_items;

    event.has_generic_nack = packet.rtcp_has_generic_nack;
    event.has_keyframe_request = packet.rtcp_has_keyframe_request;
    event.has_transport_cc = packet.rtcp_has_transport_cc;
    event.has_remb = packet.rtcp_has_remb;
    event.remb_bitrate_bps = packet.rtcp_remb_bitrate_bps;

    event.target_endpoints = route.target_endpoints;

    return event;
}
std::optional<rtcp_feedback_route_event> make_rtcp_feedback_route_event(const rtcp_compound_block& block, const media_route_result& route)
{
    if (!block.is_feedback)
    {
        return std::nullopt;
    }

    if (!route.known_peer)
    {
        return std::nullopt;
    }

    if (route.action == media_route_action::none)
    {
        return std::nullopt;
    }

    rtcp_feedback_route_event event;

    event.valid = true;
    event.event_type = choose_feedback_event_type(block);
    event.action = route.action;
    event.source = route.source;

    event.packet_type = block.packet_type;
    event.feedback_format = block.feedback_format;
    event.feedback_name = block.feedback_name;

    event.block_offset = block.offset;
    event.block_size = block.packet_size;

    event.ssrc = block.has_ssrc ? block.ssrc : block.feedback_sender_ssrc;
    event.sender_ssrc = block.feedback_sender_ssrc;
    event.media_ssrc = block.feedback_media_ssrc;

    event.nack_count = block.nack_count;
    event.fir_count = block.fir_count;

    event.nack_items = block.nack_items;
    event.fir_items = block.fir_items;

    event.has_generic_nack = block.has_generic_nack;
    event.has_keyframe_request = block.has_keyframe_request;
    event.has_transport_cc = block.has_transport_cc;
    event.has_remb = block.has_remb;
    event.remb_bitrate_bps = block.remb_bitrate_bps;
    event.remb_ssrcs = block.remb_ssrcs;
    event.target_endpoints = route.target_endpoints;

    return event;
}

std::vector<rtcp_feedback_route_event> make_rtcp_feedback_route_events(const srtp_packet_process_result& packet, const media_route_result& route)
{
    std::vector<rtcp_feedback_route_event> events;

    if (packet.kind != srtp_packet_kind::rtcp)
    {
        return events;
    }

    if (!packet.rtcp_is_feedback)
    {
        return events;
    }

    if (!route.known_peer)
    {
        return events;
    }

    if (route.action == media_route_action::none)
    {
        return events;
    }

    if (!packet.rtcp_feedback_blocks.empty())
    {
        events.reserve(packet.rtcp_feedback_blocks.size());

        for (const auto& block : packet.rtcp_feedback_blocks)
        {
            auto event = make_rtcp_feedback_route_event(block, route);

            if (!event.has_value())
            {
                continue;
            }

            events.push_back(std::move(*event));
        }

        return events;
    }

    auto legacy_event = make_rtcp_feedback_route_event(packet, route);

    if (legacy_event.has_value())
    {
        events.push_back(std::move(*legacy_event));
    }

    return events;
}

std::string rtcp_feedback_event_type_to_string(rtcp_feedback_event_type event_type)
{
    switch (event_type)
    {
        case rtcp_feedback_event_type::generic_nack:
            return "generic_nack";

        case rtcp_feedback_event_type::keyframe_request:
            return "keyframe_request";

        case rtcp_feedback_event_type::transport_cc:
            return "transport_cc";

        case rtcp_feedback_event_type::remb:
            return "remb";

        case rtcp_feedback_event_type::compound_feedback:
            return "compound_feedback";

        case rtcp_feedback_event_type::none:
            return "none";
    }

    return "none";
}
}    // namespace webrtc
