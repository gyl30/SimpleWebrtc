#ifndef SIMPLE_WEBRTC_RTP_RTCP_FEEDBACK_H
#define SIMPLE_WEBRTC_RTP_RTCP_FEEDBACK_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace webrtc
{
struct rtcp_fir_entry
{
    uint32_t media_ssrc = 0;
    uint8_t sequence_number = 0;
};

struct rtcp_feedback_packet
{
    uint8_t format = 0;
    uint8_t packet_type = 0;

    uint32_t sender_ssrc = 0;
    uint32_t media_ssrc = 0;

    std::size_t nack_count = 0;
    std::size_t fir_count = 0;

    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;

    std::vector<uint32_t> keyframe_request_media_ssrcs;
    std::vector<rtcp_fir_entry> fir_entries;
    std::optional<uint64_t> remb_bitrate_bps;
};

using rtcp_feedback_packet_result = std::expected<rtcp_feedback_packet, std::string>;

[[nodiscard]] bool is_rtcp_feedback_packet(std::span<const uint8_t> data);

[[nodiscard]] rtcp_feedback_packet_result parse_rtcp_feedback_packet(std::span<const uint8_t> data);

[[nodiscard]] std::string rtcp_feedback_format_to_string(uint8_t packet_type, uint8_t format);

}    // namespace webrtc

#endif
