#ifndef SIMPLE_WEBRTC_RTP_RTCP_PACKET_WRITER_H
#define SIMPLE_WEBRTC_RTP_RTCP_PACKET_WRITER_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "rtp/rtcp_report.h"

namespace webrtc
{
struct rtcp_sdes_chunk
{
    uint32_t ssrc = 0;

    std::string cname;
};

struct rtcp_report_write_options
{
    bool sender_report = false;

    uint32_t sender_ssrc = 0;

    rtcp_sender_info sender_info;

    std::vector<rtcp_report_block> report_blocks;
};

struct rtcp_sdes_write_options
{
    std::vector<rtcp_sdes_chunk> chunks;
};

struct rtcp_compound_packet_write_options
{
    std::vector<rtcp_report_write_options> reports;

    std::vector<rtcp_sdes_chunk> sdes_chunks;
};

using rtcp_packet_write_result = std::expected<std::vector<uint8_t>, std::string>;

[[nodiscard]]
rtcp_packet_write_result write_rtcp_sender_report(const rtcp_report_write_options& options);

[[nodiscard]]
rtcp_packet_write_result write_rtcp_receiver_report(const rtcp_report_write_options& options);

[[nodiscard]]
rtcp_packet_write_result write_rtcp_sdes(const rtcp_sdes_write_options& options);

[[nodiscard]]
rtcp_packet_write_result write_rtcp_compound_packet(const rtcp_compound_packet_write_options& options);

[[nodiscard]]
rtcp_sender_info make_rtcp_sender_info_from_clock(uint64_t unix_time_milliseconds,
                                                  uint32_t rtp_timestamp,
                                                  uint32_t sender_packet_count,
                                                  uint32_t sender_octet_count);

[[nodiscard]]
uint32_t make_rtcp_last_sender_report(uint32_t ntp_msw, uint32_t ntp_lsw);

[[nodiscard]]
uint32_t make_rtcp_delay_since_last_sender_report(uint64_t elapsed_milliseconds);
}    // namespace webrtc

#endif
