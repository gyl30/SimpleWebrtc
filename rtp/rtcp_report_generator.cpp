#include "rtp/rtcp_report_generator.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rtp/rtcp_packet_writer.h"
#include "rtp/rtcp_report.h"
#include "rtp/rtcp_session_stats.h"

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_rtcp_report_blocks = 31;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool contains_invalid_cname_character(char value) { return value == '\0' || value == '\r' || value == '\n'; }

std::expected<void, std::string> validate_generation_request(const rtcp_report_generation_request& request)
{
    if (request.session_id.empty())
    {
        return make_error("rtcp report generation session id is empty");
    }

    if (request.remote_endpoint.empty())
    {
        return make_error("rtcp report generation remote endpoint is empty");
    }

    if (request.local_ssrc == 0)
    {
        return make_error("rtcp report generation local ssrc is zero");
    }

    if (request.cname.empty())
    {
        return make_error("rtcp report generation cname is empty");
    }

    if (request.cname.size() > std::numeric_limits<uint8_t>::max())
    {
        return make_error("rtcp report generation cname is too large");
    }

    for (char value : request.cname)
    {
        if (contains_invalid_cname_character(value))
        {
            return make_error("rtcp report generation cname contains invalid characters");
        }
    }

    if (request.max_report_blocks > k_max_rtcp_report_blocks)
    {
        return make_error("rtcp report generation max report blocks is too large");
    }

    return {};
}

rtcp_sdes_chunk make_sdes_chunk(const rtcp_report_generation_request& request)
{
    rtcp_sdes_chunk chunk;

    chunk.ssrc = request.local_ssrc;

    chunk.cname = request.cname;

    return chunk;
}

rtcp_report_write_options make_receiver_report_options(const rtcp_report_generation_request& request, std::vector<rtcp_report_block> report_blocks)
{
    rtcp_report_write_options options;

    options.sender_report = false;

    options.sender_ssrc = request.local_ssrc;

    options.report_blocks = std::move(report_blocks);

    return options;
}

rtcp_report_write_options make_sender_report_options(const rtcp_report_generation_request& request,
                                                     const rtcp_sender_info& sender_info,
                                                     std::vector<rtcp_report_block> report_blocks)
{
    rtcp_report_write_options options;

    options.sender_report = true;

    options.sender_ssrc = request.local_ssrc;

    options.sender_info = sender_info;

    options.report_blocks = std::move(report_blocks);

    return options;
}

rtcp_report_generation_result_type make_compound_result(const rtcp_report_generation_request& request,
                                                        const rtcp_report_write_options& report_options)
{
    rtcp_compound_packet_write_options compound_options;

    compound_options.reports.push_back(report_options);

    compound_options.sdes_chunks.push_back(make_sdes_chunk(request));

    auto packet = write_rtcp_compound_packet(compound_options);

    if (!packet)
    {
        std::string message = "rtcp report generation write failed: ";

        message.append(packet.error());

        return std::unexpected(std::move(message));
    }

    rtcp_report_generation_result result;

    result.packet = std::move(*packet);

    result.sender_report = report_options.sender_report;

    result.receiver_report = !report_options.sender_report;

    result.sdes = true;

    result.report_block_count = report_options.report_blocks.size();

    result.local_ssrc = request.local_ssrc;

    return result;
}
}    // namespace

rtcp_report_generation_result_type generate_rtcp_receiver_report(rtcp_session_stats& stats, const rtcp_report_generation_request& request)
{
    return generate_rtcp_report(stats, request, false);
}

rtcp_report_generation_result_type generate_rtcp_sender_report(rtcp_session_stats& stats, const rtcp_report_generation_request& request)
{
    return generate_rtcp_report(stats, request, true);
}

rtcp_report_generation_result_type generate_rtcp_report(rtcp_session_stats& stats, const rtcp_report_generation_request& request, bool sender_report)
{
    auto validation_result = validate_generation_request(request);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    const std::size_t max_report_blocks = request.max_report_blocks == 0 ? k_max_rtcp_report_blocks : request.max_report_blocks;

    std::vector<rtcp_report_block> report_blocks =
        stats.make_report_blocks(request.session_id, request.remote_endpoint, request.now_milliseconds, max_report_blocks);

    if (!sender_report)
    {
        rtcp_report_write_options options = make_receiver_report_options(request, std::move(report_blocks));

        return make_compound_result(request, options);
    }

    auto sender_info = stats.make_sender_info(request.session_id, request.remote_endpoint, request.local_ssrc, request.now_milliseconds);

    if (!sender_info)
    {
        std::string message = "rtcp sender report generation failed: ";

        message.append(sender_info.error());

        return std::unexpected(std::move(message));
    }

    rtcp_report_write_options options = make_sender_report_options(request, *sender_info, std::move(report_blocks));

    return make_compound_result(request, options);
}

std::string rtcp_report_generation_result_to_string(const rtcp_report_generation_result& result)
{
    std::string value;

    value.reserve(128);

    value.append("local_ssrc=");
    value.append(std::to_string(result.local_ssrc));

    value.append(" sender_report=");
    value.append(result.sender_report ? "1" : "0");

    value.append(" receiver_report=");
    value.append(result.receiver_report ? "1" : "0");

    value.append(" sdes=");
    value.append(result.sdes ? "1" : "0");

    value.append(" report_blocks=");
    value.append(std::to_string(result.report_block_count));

    value.append(" packet_size=");
    value.append(std::to_string(result.packet.size()));

    return value;
}
}    // namespace webrtc
