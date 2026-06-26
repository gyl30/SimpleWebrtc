#include "rtp/rtcp_packet_writer.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rtp/rtcp_report.h"

namespace webrtc
{
namespace
{
constexpr uint8_t k_rtcp_version = 2;
constexpr uint8_t k_rtcp_packet_type_sender_report = 200;
constexpr uint8_t k_rtcp_packet_type_receiver_report = 201;
constexpr uint8_t k_rtcp_packet_type_sdes = 202;

constexpr uint8_t k_rtcp_sdes_item_type_end = 0;
constexpr uint8_t k_rtcp_sdes_item_type_cname = 1;

constexpr uint8_t k_rtcp_max_count = 31;

constexpr int32_t k_rtcp_report_cumulative_lost_min = -8388608;
constexpr int32_t k_rtcp_report_cumulative_lost_max = 8388607;

constexpr uint64_t k_ntp_unix_epoch_offset_seconds = 2208988800ULL;
constexpr uint64_t k_ntp_fraction_denominator = 1000ULL;
constexpr uint64_t k_ntp_fraction_scale = 0x100000000ULL;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void append_u8(std::vector<uint8_t>& packet, uint8_t value) { packet.push_back(value); }

void append_u16(std::vector<uint8_t>& packet, uint16_t value)
{
    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void append_u24(std::vector<uint8_t>& packet, uint32_t value)
{
    packet.push_back(static_cast<uint8_t>((value >> 16U) & 0xffU));

    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void append_u32(std::vector<uint8_t>& packet, uint32_t value)
{
    packet.push_back(static_cast<uint8_t>((value >> 24U) & 0xffU));

    packet.push_back(static_cast<uint8_t>((value >> 16U) & 0xffU));

    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void patch_u16(std::vector<uint8_t>& packet, std::size_t offset, uint16_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 8U) & 0xffU);

    packet[offset + 1] = static_cast<uint8_t>(value & 0xffU);
}

void append_rtcp_header(std::vector<uint8_t>& packet, uint8_t count, uint8_t packet_type, uint16_t length)
{
    append_u8(packet, static_cast<uint8_t>((k_rtcp_version << 6U) | (count & 0x1fU)));

    append_u8(packet, packet_type);

    append_u16(packet, length);
}

std::expected<void, std::string> validate_report_block(const rtcp_report_block& block)
{
    if (block.ssrc == 0)
    {
        return make_error("rtcp report block ssrc is zero");
    }

    if (block.cumulative_lost < k_rtcp_report_cumulative_lost_min || block.cumulative_lost > k_rtcp_report_cumulative_lost_max)
    {
        return make_error("rtcp report block cumulative lost is out of range");
    }

    return {};
}

std::expected<void, std::string> validate_report_options(const rtcp_report_write_options& options)
{
    if (options.sender_ssrc == 0)
    {
        return make_error("rtcp report sender ssrc is zero");
    }

    if (options.report_blocks.size() > k_rtcp_max_count)
    {
        return make_error("rtcp report block count is too large");
    }

    for (const auto& block : options.report_blocks)
    {
        auto validation_result = validate_report_block(block);

        if (!validation_result)
        {
            return std::unexpected(validation_result.error());
        }
    }

    return {};
}

void append_report_block(std::vector<uint8_t>& packet, const rtcp_report_block& block)
{
    append_u32(packet, block.ssrc);

    append_u8(packet, block.fraction_lost);

    const uint32_t cumulative_lost = static_cast<uint32_t>(block.cumulative_lost) & 0x00ffffffU;

    append_u24(packet, cumulative_lost);

    append_u32(packet, block.extended_highest_sequence_number);

    append_u32(packet, block.jitter);

    append_u32(packet, block.last_sender_report);

    append_u32(packet, block.delay_since_last_sender_report);
}

rtcp_packet_write_result write_rtcp_report_packet(const rtcp_report_write_options& options, bool sender_report)
{
    auto validation_result = validate_report_options(options);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    std::vector<uint8_t> packet;

    const uint8_t report_count = static_cast<uint8_t>(options.report_blocks.size());

    const uint8_t packet_type = sender_report ? k_rtcp_packet_type_sender_report : k_rtcp_packet_type_receiver_report;

    const std::size_t packet_size = sender_report ? 28 + options.report_blocks.size() * 24 : 8 + options.report_blocks.size() * 24;

    if ((packet_size % 4) != 0)
    {
        return make_error("rtcp report packet size is not aligned");
    }

    const std::size_t length_words = packet_size / 4 - 1;

    if (length_words > std::numeric_limits<uint16_t>::max())
    {
        return make_error("rtcp report packet is too large");
    }

    packet.reserve(packet_size);

    append_rtcp_header(packet, report_count, packet_type, static_cast<uint16_t>(length_words));

    append_u32(packet, options.sender_ssrc);

    if (sender_report)
    {
        append_u32(packet, options.sender_info.ntp_msw);

        append_u32(packet, options.sender_info.ntp_lsw);

        append_u32(packet, options.sender_info.rtp_timestamp);

        append_u32(packet, options.sender_info.sender_packet_count);

        append_u32(packet, options.sender_info.sender_octet_count);
    }

    for (const auto& block : options.report_blocks)
    {
        append_report_block(packet, block);
    }

    return packet;
}

bool contains_invalid_sdes_text_character(char value) { return value == '\0' || value == '\r' || value == '\n'; }

std::expected<void, std::string> validate_sdes_chunk(const rtcp_sdes_chunk& chunk)
{
    if (chunk.ssrc == 0)
    {
        return make_error("rtcp sdes chunk ssrc is zero");
    }

    if (chunk.cname.empty())
    {
        return make_error("rtcp sdes cname is empty");
    }

    if (chunk.cname.size() > std::numeric_limits<uint8_t>::max())
    {
        return make_error("rtcp sdes cname is too large");
    }

    for (char value : chunk.cname)
    {
        if (contains_invalid_sdes_text_character(value))
        {
            return make_error("rtcp sdes cname contains invalid characters");
        }
    }

    return {};
}

std::expected<void, std::string> validate_sdes_options(const rtcp_sdes_write_options& options)
{
    if (options.chunks.empty())
    {
        return make_error("rtcp sdes chunks is empty");
    }

    if (options.chunks.size() > k_rtcp_max_count)
    {
        return make_error("rtcp sdes chunk count is too large");
    }

    for (const auto& chunk : options.chunks)
    {
        auto validation_result = validate_sdes_chunk(chunk);

        if (!validation_result)
        {
            return std::unexpected(validation_result.error());
        }
    }

    return {};
}

void append_sdes_cname_chunk(std::vector<uint8_t>& packet, const rtcp_sdes_chunk& chunk)
{
    append_u32(packet, chunk.ssrc);

    append_u8(packet, k_rtcp_sdes_item_type_cname);

    append_u8(packet, static_cast<uint8_t>(chunk.cname.size()));

    for (char value : chunk.cname)
    {
        append_u8(packet, static_cast<uint8_t>(value));
    }

    append_u8(packet, k_rtcp_sdes_item_type_end);

    while ((packet.size() % 4) != 0)
    {
        append_u8(packet, 0);
    }
}
}    // namespace

rtcp_packet_write_result write_rtcp_sender_report(const rtcp_report_write_options& options) { return write_rtcp_report_packet(options, true); }

rtcp_packet_write_result write_rtcp_receiver_report(const rtcp_report_write_options& options) { return write_rtcp_report_packet(options, false); }

rtcp_packet_write_result write_rtcp_sdes(const rtcp_sdes_write_options& options)
{
    auto validation_result = validate_sdes_options(options);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    std::vector<uint8_t> packet;

    append_rtcp_header(packet, static_cast<uint8_t>(options.chunks.size()), k_rtcp_packet_type_sdes, 0);

    for (const auto& chunk : options.chunks)
    {
        append_sdes_cname_chunk(packet, chunk);
    }

    const std::size_t length_words = packet.size() / 4 - 1;

    if (length_words > std::numeric_limits<uint16_t>::max())
    {
        return make_error("rtcp sdes packet is too large");
    }

    patch_u16(packet, 2, static_cast<uint16_t>(length_words));

    return packet;
}

rtcp_packet_write_result write_rtcp_compound_packet(const rtcp_compound_packet_write_options& options)
{
    if (options.reports.empty() && options.sdes_chunks.empty())
    {
        return make_error("rtcp compound packet is empty");
    }

    std::vector<uint8_t> packet;

    for (const auto& report : options.reports)
    {
        rtcp_packet_write_result report_packet = report.sender_report ? write_rtcp_sender_report(report) : write_rtcp_receiver_report(report);

        if (!report_packet)
        {
            return std::unexpected(report_packet.error());
        }

        packet.insert(packet.end(), report_packet->begin(), report_packet->end());
    }

    if (!options.sdes_chunks.empty())
    {
        rtcp_sdes_write_options sdes_options;

        sdes_options.chunks = options.sdes_chunks;

        auto sdes_packet = write_rtcp_sdes(sdes_options);

        if (!sdes_packet)
        {
            return std::unexpected(sdes_packet.error());
        }

        packet.insert(packet.end(), sdes_packet->begin(), sdes_packet->end());
    }

    return packet;
}

rtcp_sender_info make_rtcp_sender_info_from_clock(uint64_t unix_time_milliseconds,
                                                  uint32_t rtp_timestamp,
                                                  uint32_t sender_packet_count,
                                                  uint32_t sender_octet_count)
{
    const uint64_t unix_seconds = unix_time_milliseconds / 1000ULL;

    const uint64_t unix_fraction_milliseconds = unix_time_milliseconds % 1000ULL;

    const uint64_t ntp_seconds = unix_seconds + k_ntp_unix_epoch_offset_seconds;

    const uint64_t ntp_fraction = (unix_fraction_milliseconds * k_ntp_fraction_scale) / k_ntp_fraction_denominator;

    rtcp_sender_info sender_info;

    sender_info.ntp_msw = static_cast<uint32_t>(ntp_seconds & 0xffffffffULL);

    sender_info.ntp_lsw = static_cast<uint32_t>(ntp_fraction & 0xffffffffULL);

    sender_info.rtp_timestamp = rtp_timestamp;

    sender_info.sender_packet_count = sender_packet_count;

    sender_info.sender_octet_count = sender_octet_count;

    return sender_info;
}

uint32_t make_rtcp_last_sender_report(uint32_t ntp_msw, uint32_t ntp_lsw)
{
    return static_cast<uint32_t>(((ntp_msw & 0x0000ffffU) << 16U) | ((ntp_lsw >> 16U) & 0x0000ffffU));
}

uint32_t make_rtcp_delay_since_last_sender_report(uint64_t elapsed_milliseconds)
{
    const uint64_t value = (elapsed_milliseconds * 65536ULL) / 1000ULL;

    if (value > std::numeric_limits<uint32_t>::max())
    {
        return std::numeric_limits<uint32_t>::max();
    }

    return static_cast<uint32_t>(value);
}
}    // namespace webrtc
