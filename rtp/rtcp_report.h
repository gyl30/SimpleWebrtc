#ifndef SIMPLE_WEBRTC_RTP_RTCP_REPORT_H
#define SIMPLE_WEBRTC_RTP_RTCP_REPORT_H

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace webrtc
{
struct rtcp_sender_info
{
    uint32_t ntp_timestamp_msw = 0;
    uint32_t ntp_timestamp_lsw = 0;
    uint32_t rtp_timestamp = 0;
    uint32_t sender_packet_count = 0;
    uint32_t sender_octet_count = 0;
};

struct rtcp_report_block
{
    uint32_t source_ssrc = 0;
    uint8_t fraction_lost = 0;
    int32_t cumulative_lost = 0;
    uint32_t extended_highest_sequence_number = 0;
    uint32_t jitter = 0;
    uint32_t last_sender_report = 0;
    uint32_t delay_since_last_sender_report = 0;
};

struct rtcp_report_packet
{
    uint8_t packet_type = 0;
    uint32_t sender_ssrc = 0;
    std::optional<rtcp_sender_info> sender_info;
    std::vector<rtcp_report_block> report_blocks;
};

using rtcp_report_packet_result = std::expected<rtcp_report_packet, std::string>;

[[nodiscard]] bool is_rtcp_report_packet(std::span<const uint8_t> data);

[[nodiscard]] rtcp_report_packet_result parse_rtcp_report_packet(std::span<const uint8_t> data);
}    // namespace webrtc

#endif
