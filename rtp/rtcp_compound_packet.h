#ifndef SIMPLE_WEBRTC_RTP_RTCP_COMPOUND_PACKET_H
#define SIMPLE_WEBRTC_RTP_RTCP_COMPOUND_PACKET_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

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

    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;
    bool has_remb = false;
    uint64_t remb_bitrate_bps = 0;
};

struct rtcp_compound_packet
{
    std::size_t packet_size = 0;

    std::vector<rtcp_compound_block> blocks;

    std::size_t feedback_block_count = 0;
    std::size_t nack_count = 0;
    std::size_t fir_count = 0;

    bool has_feedback = false;
    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;
    bool has_remb = false;
    uint64_t remb_bitrate_bps = 0;
};

using rtcp_compound_packet_result = std::expected<rtcp_compound_packet, std::string>;

[[nodiscard]] rtcp_compound_packet_result parse_rtcp_compound_packet(std::span<const uint8_t> data);

[[nodiscard]] std::string rtcp_compound_feedback_summary_to_string(const rtcp_compound_packet& packet);
}    // namespace webrtc

#endif
