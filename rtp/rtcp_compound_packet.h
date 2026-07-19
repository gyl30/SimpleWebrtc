#ifndef SIMPLE_WEBRTC_RTP_RTCP_COMPOUND_PACKET_H
#define SIMPLE_WEBRTC_RTP_RTCP_COMPOUND_PACKET_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "rtp/rtcp_report.h"

namespace webrtc
{
struct rtcp_compound_block
{
    uint8_t count = 0;
    uint8_t packet_type = 0;
    uint16_t length = 0;

    bool has_ssrc = false;
    uint32_t ssrc = 0;

    std::string packet_type_name;

    bool is_feedback = false;
    std::string feedback_name;

    uint32_t feedback_sender_ssrc = 0;
    uint32_t feedback_media_ssrc = 0;

    std::size_t nack_count = 0;
    std::size_t fir_count = 0;

    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;
    std::vector<uint32_t> keyframe_request_media_ssrcs;

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

    bool has_remb = false;
    uint64_t remb_bitrate_bps = 0;

    std::size_t report_packet_count = 0;
    std::size_t report_block_count = 0;
    std::optional<rtcp_report_block> last_report_block;

    bool has_bye = false;
};

using rtcp_compound_packet_result = std::expected<rtcp_compound_packet, std::string>;

[[nodiscard]] rtcp_compound_packet_result parse_rtcp_compound_packet(std::span<const uint8_t> data);

[[nodiscard]] std::string rtcp_compound_feedback_summary_to_string(const rtcp_compound_packet& packet);
}    // namespace webrtc

#endif
