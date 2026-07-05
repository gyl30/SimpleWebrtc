#ifndef SIMPLE_WEBRTC_MEDIA_RTCP_FEEDBACK_ROUTER_H
#define SIMPLE_WEBRTC_MEDIA_RTCP_FEEDBACK_ROUTER_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "rtp/rtcp_feedback.h"
#include "media/media_router.h"
#include "srtp/srtp_transport.h"
#include "rtp/rtcp_compound_packet.h"

namespace webrtc
{
enum class rtcp_feedback_event_type
{
    none,
    generic_nack,
    keyframe_request,
    transport_cc,
    remb,
    compound_feedback,
};

struct rtcp_feedback_route_event
{
    bool valid = false;

    rtcp_feedback_event_type event_type = rtcp_feedback_event_type::none;

    media_route_action action = media_route_action::none;
    media_peer_info source;

    uint8_t packet_type = 0;
    uint8_t feedback_format = 0;
    std::string feedback_name;

    std::size_t block_offset = 0;
    std::size_t block_size = 0;

    uint32_t ssrc = 0;
    uint32_t sender_ssrc = 0;
    uint32_t media_ssrc = 0;

    std::size_t nack_count = 0;
    std::size_t fir_count = 0;

    std::vector<rtcp_nack_item> nack_items;
    std::vector<rtcp_fir_item> fir_items;

    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;

    uint16_t transport_cc_base_sequence_number = 0;
    uint16_t transport_cc_packet_status_count = 0;
    uint32_t transport_cc_reference_time_64ms = 0;
    uint8_t transport_cc_feedback_packet_count = 0;

    std::size_t transport_cc_received_packet_count = 0;
    std::size_t transport_cc_not_received_packet_count = 0;
    std::size_t transport_cc_small_delta_count = 0;
    std::size_t transport_cc_large_delta_count = 0;

    std::vector<rtcp_transport_cc_packet_status> transport_cc_packet_statuses;
    bool has_remb = false;
    uint64_t remb_bitrate_bps = 0;
    std::vector<uint32_t> remb_ssrcs;

    std::vector<std::string> target_endpoints;
};

[[nodiscard]] std::optional<rtcp_feedback_route_event> make_rtcp_feedback_route_event(const srtp_packet_process_result& packet,
                                                                                      const media_route_result& route);

[[nodiscard]] std::optional<rtcp_feedback_route_event> make_rtcp_feedback_route_event(const rtcp_compound_block& block,
                                                                                      const media_route_result& route);

[[nodiscard]] std::vector<rtcp_feedback_route_event> make_rtcp_feedback_route_events(const srtp_packet_process_result& packet,
                                                                                     const media_route_result& route);

[[nodiscard]] std::string rtcp_feedback_event_type_to_string(rtcp_feedback_event_type event_type);
}    // namespace webrtc

#endif
