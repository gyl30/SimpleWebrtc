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
inline constexpr uint8_t k_rtcp_packet_type_transport_feedback = 205;
inline constexpr uint8_t k_rtcp_packet_type_payload_feedback = 206;

inline constexpr uint8_t k_rtcp_transport_feedback_generic_nack = 1;
inline constexpr uint8_t k_rtcp_transport_feedback_tmmbr = 3;
inline constexpr uint8_t k_rtcp_transport_feedback_tmmbn = 4;
inline constexpr uint8_t k_rtcp_transport_feedback_transport_cc = 15;

inline constexpr uint8_t k_rtcp_payload_feedback_pli = 1;
inline constexpr uint8_t k_rtcp_payload_feedback_sli = 2;
inline constexpr uint8_t k_rtcp_payload_feedback_rpsi = 3;
inline constexpr uint8_t k_rtcp_payload_feedback_fir = 4;
inline constexpr uint8_t k_rtcp_payload_feedback_afb = 15;

struct rtcp_nack_item
{
    uint16_t packet_id = 0;
    uint16_t lost_packet_bitmask = 0;
};

struct rtcp_fir_item
{
    uint32_t ssrc = 0;
    uint8_t sequence_number = 0;
};

struct rtcp_remb_info
{
    uint8_t ssrc_count = 0;
    uint8_t bitrate_exponent = 0;
    uint32_t bitrate_mantissa = 0;
    uint64_t bitrate_bps = 0;

    std::vector<uint32_t> ssrcs;
};

struct rtcp_feedback_packet
{
    uint8_t version = 0;
    bool padding = false;

    uint8_t format = 0;
    uint8_t packet_type = 0;
    uint16_t length = 0;

    std::size_t packet_size = 0;

    uint32_t sender_ssrc = 0;
    uint32_t media_ssrc = 0;

    bool has_generic_nack = false;
    bool has_keyframe_request = false;
    bool has_transport_cc = false;

    std::vector<rtcp_nack_item> nack_items;
    std::vector<rtcp_fir_item> fir_items;
    std::optional<rtcp_remb_info> remb;
};

struct rtcp_feedback_block_ssrc_rewrite
{
    std::size_t offset = 0;
    uint32_t source_ssrc = 0;
    uint32_t target_ssrc = 0;
};

struct rtcp_feedback_block_rewrite
{
    std::size_t block_offset = 0;
    std::size_t block_size = 0;

    bool drop_block = false;

    bool rewrite_media_ssrc = false;
    uint32_t source_media_ssrc = 0;
    uint32_t target_media_ssrc = 0;

    std::vector<rtcp_feedback_block_ssrc_rewrite> fci_ssrc_rewrites;
};

using rtcp_feedback_rewrite_result = std::expected<std::vector<uint8_t>, std::string>;
using rtcp_feedback_packet_result = std::expected<rtcp_feedback_packet, std::string>;

[[nodiscard]]
rtcp_feedback_rewrite_result rewrite_rtcp_feedback_blocks(std::span<const uint8_t> packet, std::span<const rtcp_feedback_block_rewrite> rewrites);

[[nodiscard]] bool is_rtcp_feedback_packet(std::span<const uint8_t> data);

[[nodiscard]] rtcp_feedback_packet_result parse_rtcp_feedback_packet(std::span<const uint8_t> data);

[[nodiscard]] std::string rtcp_feedback_format_to_string(uint8_t packet_type, uint8_t format);
}    // namespace webrtc

#endif
