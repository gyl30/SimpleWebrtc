#ifndef SIMPLE_WEBRTC_RTP_RTCP_REPORT_GENERATOR_H
#define SIMPLE_WEBRTC_RTP_RTCP_REPORT_GENERATOR_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "rtp/rtcp_session_stats.h"

namespace webrtc
{
struct rtcp_report_generation_request
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    uint32_t local_ssrc = 0;

    std::string cname;

    uint64_t now_milliseconds = 0;

    std::size_t max_report_blocks = 31;
};

struct rtcp_report_generation_result
{
    std::vector<uint8_t> packet;

    bool sender_report = false;
    bool receiver_report = false;
    bool sdes = false;

    std::size_t report_block_count = 0;

    uint32_t local_ssrc = 0;
};

using rtcp_report_generation_result_type = std::expected<rtcp_report_generation_result, std::string>;

[[nodiscard]]
rtcp_report_generation_result_type generate_rtcp_receiver_report(rtcp_session_stats& stats, const rtcp_report_generation_request& request);

[[nodiscard]]
rtcp_report_generation_result_type generate_rtcp_sender_report(rtcp_session_stats& stats, const rtcp_report_generation_request& request);

[[nodiscard]]
rtcp_report_generation_result_type generate_rtcp_report(rtcp_session_stats& stats, const rtcp_report_generation_request& request, bool sender_report);

[[nodiscard]]
std::string rtcp_report_generation_result_to_string(const rtcp_report_generation_result& result);
}    // namespace webrtc

#endif
