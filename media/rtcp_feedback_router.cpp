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
