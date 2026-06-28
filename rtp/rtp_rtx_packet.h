#ifndef SIMPLE_WEBRTC_RTP_RTP_RTX_PACKET_H
#define SIMPLE_WEBRTC_RTP_RTP_RTX_PACKET_H

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>
#include "rtp/rtp_packet.h"
namespace webrtc
{
struct rtp_rtx_header_extension_id_rewrite
{
    uint8_t source_id = 0;
    uint8_t target_id = 0;
};

struct rtp_rtx_packet_options
{
    uint8_t payload_type = 0;
    uint32_t ssrc = 0;
    uint16_t sequence_number = 0;
    uint32_t timestamp = 0;

    std::vector<rtp_rtx_header_extension_id_rewrite> header_extension_id_rewrites;
};

struct rtp_rtx_packet_info
{
    rtp_packet_header header;

    uint16_t original_sequence_number = 0;

    std::size_t original_payload_offset = 0;
    std::size_t original_payload_size = 0;
};

using rtp_rtx_packet_result = std::expected<std::vector<uint8_t>, std::string>;

using rtp_rtx_packet_info_result = std::expected<rtp_rtx_packet_info, std::string>;

using rtp_rtx_packet_validation_result = std::expected<void, std::string>;

[[nodiscard]]
rtp_rtx_packet_result make_rtp_rtx_packet(std::span<const uint8_t> primary_packet, const rtp_rtx_packet_options& options);

[[nodiscard]]
rtp_rtx_packet_info_result parse_rtp_rtx_packet(std::span<const uint8_t> rtx_packet);

[[nodiscard]]
rtp_rtx_packet_validation_result validate_rtp_rtx_packet(std::span<const uint8_t> rtx_packet,
                                                         const rtp_rtx_packet_options& options,
                                                         uint16_t expected_original_sequence_number);
}    // namespace webrtc

#endif
