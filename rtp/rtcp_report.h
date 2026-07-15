#ifndef SIMPLE_WEBRTC_RTP_RTCP_REPORT_H
#define SIMPLE_WEBRTC_RTP_RTCP_REPORT_H

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace webrtc
{
struct rtcp_report_block
{
    uint8_t fraction_lost = 0;
    int32_t cumulative_lost = 0;
    uint32_t jitter = 0;
};

struct rtcp_report_packet
{
    std::vector<rtcp_report_block> report_blocks;
};

using rtcp_report_packet_result = std::expected<rtcp_report_packet, std::string>;

[[nodiscard]] bool is_rtcp_report_packet(std::span<const uint8_t> data);

[[nodiscard]] rtcp_report_packet_result parse_rtcp_report_packet(std::span<const uint8_t> data);
}    // namespace webrtc

#endif
