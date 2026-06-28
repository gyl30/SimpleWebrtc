#ifndef SIMPLE_WEBRTC_RTP_RTP_RTX_PACKET_H
#define SIMPLE_WEBRTC_RTP_RTP_RTX_PACKET_H

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace webrtc
{
struct rtp_rtx_packet_options
{
    uint8_t payload_type = 0;
    uint32_t ssrc = 0;
    uint16_t sequence_number = 0;
    uint32_t timestamp = 0;
};

using rtp_rtx_packet_result = std::expected<std::vector<uint8_t>, std::string>;

[[nodiscard]]
rtp_rtx_packet_result make_rtp_rtx_packet(std::span<const uint8_t> primary_packet, const rtp_rtx_packet_options& options);
}    // namespace webrtc

#endif
