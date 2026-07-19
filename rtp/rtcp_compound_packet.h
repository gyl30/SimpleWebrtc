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
struct rtcp_sdes_item
{
    uint8_t type = 0;
    std::vector<uint8_t> value;
};

struct rtcp_sdes_chunk
{
    uint32_t ssrc = 0;
    std::string cname;
    std::vector<rtcp_sdes_item> items;
};

struct rtcp_bye_packet
{
    std::vector<uint32_t> ssrcs;
    std::string reason;
};

struct rtcp_compound_block
{
    uint8_t count = 0;
    uint8_t packet_type = 0;
    uint16_t length = 0;

    bool has_ssrc = false;
    uint32_t ssrc = 0;

    std::string packet_type_name;

    bool is_feedback = false;
    bool is_report = false;
    bool is_sdes = false;
    bool is_bye = false;
    bool is_unknown = false;
    std::string feedback_name;

    uint32_t feedback_sender_ssrc = 0;
    uint32_t feedback_media_ssrc = 0;

    std::size_t nack_count = 0;
    std::size_t fir_count = 0;

    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;
    std::vector<uint32_t> keyframe_request_media_ssrcs;
    std::vector<rtcp_fir_entry> fir_entries;

    bool has_remb = false;
    uint64_t remb_bitrate_bps = 0;
};

struct rtcp_compound_packet
{
    std::vector<rtcp_compound_block> blocks;

    std::size_t feedback_block_count = 0;
    std::size_t nack_count = 0;
    std::size_t fir_count = 0;

    bool has_feedback = false;
    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;
    std::vector<uint32_t> keyframe_request_media_ssrcs;
    std::vector<rtcp_fir_entry> fir_entries;

    bool has_remb = false;
    uint64_t remb_bitrate_bps = 0;

    std::size_t report_packet_count = 0;
    std::size_t report_block_count = 0;
    std::vector<rtcp_report_packet> report_packets;

    std::vector<rtcp_sdes_chunk> sdes_chunks;
    std::vector<rtcp_bye_packet> bye_packets;

    bool has_bye = false;
    std::size_t unknown_block_count = 0;
};

using rtcp_compound_packet_result = std::expected<rtcp_compound_packet, std::string>;

[[nodiscard]] rtcp_compound_packet_result parse_rtcp_compound_packet(std::span<const uint8_t> data);

[[nodiscard]] std::string rtcp_compound_feedback_summary_to_string(const rtcp_compound_packet& packet);
}    // namespace webrtc

#endif
