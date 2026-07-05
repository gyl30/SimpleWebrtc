#ifndef SIMPLE_WEBRTC_RTP_RTCP_COMPOUND_PACKET_H
#define SIMPLE_WEBRTC_RTP_RTCP_COMPOUND_PACKET_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

#include "rtp/rtcp_feedback.h"
#include "rtp/rtcp_report.h"

namespace webrtc
{
struct rtcp_compound_block
{
    std::size_t offset = 0;
    std::size_t packet_size = 0;

    uint8_t version = 0;
    bool padding = false;

    uint8_t count = 0;
    uint8_t packet_type = 0;
    uint16_t length = 0;

    bool has_ssrc = false;
    uint32_t ssrc = 0;

    std::string packet_type_name;

    bool is_feedback = false;
    uint8_t feedback_format = 0;
    std::string feedback_name;

    uint32_t feedback_sender_ssrc = 0;
    uint32_t feedback_media_ssrc = 0;

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

    bool is_report = false;
    bool is_sender_report = false;
    bool is_receiver_report = false;
    bool has_sender_info = false;
    uint32_t report_sender_ssrc = 0;
    rtcp_sender_info sender_info;
    std::vector<rtcp_report_block> report_blocks;

    bool is_bye = false;
    std::vector<uint32_t> bye_ssrcs;
    std::string bye_reason;
};

struct rtcp_compound_packet
{
    std::size_t packet_size = 0;

    std::vector<rtcp_compound_block> blocks;

    std::size_t feedback_block_count = 0;
    std::size_t nack_count = 0;
    std::size_t fir_count = 0;

    std::vector<rtcp_nack_item> nack_items;
    std::vector<rtcp_fir_item> fir_items;

    bool has_feedback = false;
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

    std::size_t report_packet_count = 0;
    std::size_t report_block_count = 0;
    bool has_sender_report = false;
    bool has_receiver_report = false;
    bool has_sender_info = false;
    uint32_t report_sender_ssrc = 0;
    rtcp_sender_info sender_info;
    std::vector<rtcp_report_block> report_blocks;

    std::size_t bye_packet_count = 0;
    bool has_bye = false;
    std::vector<uint32_t> bye_ssrcs;
    std::string bye_reason;
};

using rtcp_compound_packet_result = std::expected<rtcp_compound_packet, std::string>;

[[nodiscard]] rtcp_compound_packet_result parse_rtcp_compound_packet(std::span<const uint8_t> data);

[[nodiscard]] std::string rtcp_compound_feedback_summary_to_string(const rtcp_compound_packet& packet);
}    // namespace webrtc

#endif
