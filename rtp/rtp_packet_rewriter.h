#ifndef SIMPLE_WEBRTC_RTP_RTP_PACKET_REWRITER_H
#define SIMPLE_WEBRTC_RTP_RTP_PACKET_REWRITER_H

#include <cstdint>
#include <expected>
#include <optional>
#include <vector>

#include "rtp/rtp_packet.h"

namespace webrtc
{
struct rtp_header_extension_rewrite
{
    uint8_t id = 0;

    std::vector<uint8_t> payload;
};

struct rtp_header_extension_id_rewrite
{
    uint8_t source_id = 0;
    uint8_t target_id = 0;
};

struct rtp_packet_rewrite_options
{
    std::optional<uint8_t> payload_type;
    std::optional<uint32_t> ssrc;
    std::optional<uint16_t> sequence_number;
    std::optional<uint32_t> timestamp;

    std::vector<rtp_header_extension_rewrite> header_extensions;
    std::vector<rtp_header_extension_id_rewrite> header_extension_id_rewrites;
};
struct rtp_packet_rewrite_result
{
    std::vector<uint8_t> packet;

    bool changed = false;
};

using rtp_packet_rewrite_result_type = std::expected<rtp_packet_rewrite_result, std::string>;

[[nodiscard]]
rtp_packet_rewrite_result_type rewrite_rtp_packet(std::span<const uint8_t> packet, const rtp_packet_rewrite_options& options);

[[nodiscard]]
rtp_packet_rewrite_options make_payload_type_rewrite_options(uint8_t payload_type);

[[nodiscard]]
rtp_packet_rewrite_options make_payload_type_and_ssrc_rewrite_options(uint8_t payload_type, uint32_t ssrc);

[[nodiscard]]
bool rtp_payload_type_requires_rewrite(uint8_t source_payload_type, uint8_t target_payload_type);
}    // namespace webrtc

#endif
