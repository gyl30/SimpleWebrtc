#ifndef SIMPLE_WEBRTC_RTP_RTCP_PACKET_BUILDER_H
#define SIMPLE_WEBRTC_RTP_RTCP_PACKET_BUILDER_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rtp/rtcp_report.h"

namespace webrtc
{
inline constexpr std::size_t k_default_rtcp_datagram_mtu = 1200;

struct rtcp_sender_report_data
{
    uint32_t sender_ssrc = 0;
    uint64_t ntp_timestamp = 0;
    uint32_t rtp_timestamp = 0;
    uint32_t sender_packet_count = 0;
    uint32_t sender_octet_count = 0;
    std::vector<rtcp_report_block> report_blocks;
};

struct rtcp_receiver_report_data
{
    uint32_t sender_ssrc = 0;
    std::vector<rtcp_report_block> report_blocks;
};

struct rtcp_fir_request
{
    uint32_t media_ssrc = 0;
    uint8_t sequence_number = 0;
};

using rtcp_packet_build_result = std::expected<std::vector<uint8_t>, std::string>;

[[nodiscard]] rtcp_packet_build_result build_rtcp_sender_report(
    const rtcp_sender_report_data& report);

[[nodiscard]] rtcp_packet_build_result build_rtcp_receiver_report(
    const rtcp_receiver_report_data& report);

[[nodiscard]] rtcp_packet_build_result build_rtcp_sdes_cname(uint32_t ssrc,
                                                              std::string_view cname);

[[nodiscard]] rtcp_packet_build_result build_rtcp_picture_loss_indication(
    uint32_t sender_ssrc, uint32_t media_ssrc);

[[nodiscard]] rtcp_packet_build_result build_rtcp_full_intra_request(
    uint32_t sender_ssrc, std::span<const rtcp_fir_request> requests);

[[nodiscard]] rtcp_packet_build_result build_rtcp_feedback_datagram(
    std::span<const uint8_t> feedback_packet,
    uint32_t sender_ssrc,
    std::string_view cname,
    bool reduced_size,
    std::size_t maximum_size = k_default_rtcp_datagram_mtu);

[[nodiscard]] rtcp_packet_build_result build_rtcp_bye(std::span<const uint32_t> ssrcs,
                                                       std::string_view reason = {});

[[nodiscard]] rtcp_packet_build_result build_rtcp_bye_datagram(
    std::span<const uint8_t> report_packet,
    uint32_t participant_ssrc,
    std::string_view cname,
    std::span<const uint32_t> bye_ssrcs,
    std::string_view reason = {},
    std::size_t maximum_size = k_default_rtcp_datagram_mtu);

[[nodiscard]] rtcp_packet_build_result build_rtcp_compound_packet(
    std::span<const std::vector<uint8_t>> packets,
    std::size_t maximum_size = k_default_rtcp_datagram_mtu);
}    // namespace webrtc

#endif
