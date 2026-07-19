#include "rtp/rtcp_feedback.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
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

inline constexpr std::size_t k_rtcp_common_header_size = 4;
inline constexpr std::size_t k_rtcp_feedback_header_size = 12;
inline constexpr std::size_t k_transport_cc_fixed_fci_size = 8;
inline constexpr std::size_t k_transport_cc_status_chunk_size = 2;
inline constexpr std::size_t k_transport_cc_small_delta_size = 1;
inline constexpr std::size_t k_transport_cc_large_delta_size = 2;
inline constexpr std::size_t k_max_transport_cc_packet_status_count = 8192;

enum class transport_cc_packet_status_symbol : uint8_t
{
    not_received = 0,
    small_delta = 1,
    large_or_negative_delta = 2,
    reserved = 3,
};

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::expected<std::size_t, std::string> rtcp_feedback_payload_end(const rtcp_packet_header& header, std::span<const uint8_t> data)
{
    if (header.packet_size > data.size())
    {
        return make_error("rtcp feedback packet exceeds buffer size");
    }

    std::size_t payload_end = header.packet_size;

    if (!header.padding)
    {
        return payload_end;
    }

    if (payload_end <= k_rtcp_common_header_size)
    {
        return make_error("rtcp feedback padding packet is too short");
    }

    const std::size_t padding_size = data[payload_end - 1];

    if (padding_size == 0)
    {
        return make_error("rtcp feedback padding size is zero");
    }

    if (padding_size > payload_end - k_rtcp_common_header_size)
    {
        return make_error("rtcp feedback padding exceeds packet size");
    }

    payload_end -= padding_size;

    if (payload_end < k_rtcp_feedback_header_size)
    {
        return make_error("rtcp feedback payload is shorter than feedback header");
    }

    return payload_end;
}

bool rtcp_feedback_trailing_bytes_are_zero(std::span<const uint8_t> data, std::size_t offset, std::size_t end)
{
    if (offset > end || end > data.size())
    {
        return false;
    }

    for (std::size_t current = offset; current < end; ++current)
    {
        if (data[current] != 0)
        {
            return false;
        }
    }

    return true;
}

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

transport_cc_packet_status_symbol make_transport_cc_status_symbol(uint8_t value)
{
    switch (value & 0x03U)
    {
        case 0:
            return transport_cc_packet_status_symbol::not_received;

        case 1:
            return transport_cc_packet_status_symbol::small_delta;

        case 2:
            return transport_cc_packet_status_symbol::large_or_negative_delta;

        default:
            return transport_cc_packet_status_symbol::reserved;
    }
}

bool transport_cc_status_symbol_has_delta(transport_cc_packet_status_symbol symbol)
{
    return symbol == transport_cc_packet_status_symbol::small_delta || symbol == transport_cc_packet_status_symbol::large_or_negative_delta;
}

void append_transport_cc_status(std::vector<transport_cc_packet_status_symbol>& statuses,
                                transport_cc_packet_status_symbol symbol,
                                std::size_t packet_status_count)
{
    if (statuses.size() < packet_status_count)
    {
        statuses.push_back(symbol);
    }
}

void parse_transport_cc_run_length_chunk(uint16_t chunk,
                                         std::vector<transport_cc_packet_status_symbol>& statuses,
                                         std::size_t packet_status_count)
{
    const uint8_t raw_symbol = static_cast<uint8_t>((chunk >> 13U) & 0x03U);
    const uint16_t run_length = static_cast<uint16_t>(chunk & 0x1fffU);
    const transport_cc_packet_status_symbol symbol = make_transport_cc_status_symbol(raw_symbol);

    for (uint16_t i = 0; i < run_length && statuses.size() < packet_status_count; ++i)
    {
        append_transport_cc_status(statuses, symbol, packet_status_count);
    }
}

void parse_transport_cc_status_vector_chunk(uint16_t chunk,
                                            std::vector<transport_cc_packet_status_symbol>& statuses,
                                            std::size_t packet_status_count)
{
    const bool two_bit_symbols = ((chunk & 0x4000U) != 0);

    if (two_bit_symbols)
    {
        for (int bit_offset = 12; bit_offset >= 0 && statuses.size() < packet_status_count; bit_offset -= 2)
        {
            const uint8_t raw_symbol = static_cast<uint8_t>((chunk >> static_cast<unsigned>(bit_offset)) & 0x03U);

            append_transport_cc_status(statuses, make_transport_cc_status_symbol(raw_symbol), packet_status_count);
        }

        return;
    }

    for (int bit_offset = 13; bit_offset >= 0 && statuses.size() < packet_status_count; --bit_offset)
    {
        const uint8_t raw_symbol = static_cast<uint8_t>((chunk >> static_cast<unsigned>(bit_offset)) & 0x01U);

        append_transport_cc_status(statuses, make_transport_cc_status_symbol(raw_symbol), packet_status_count);
    }
}

std::expected<std::size_t, std::string> parse_transport_cc_status_chunks(std::span<const uint8_t> data,
                                                                         std::size_t offset,
                                                                         std::size_t end,
                                                                         std::size_t packet_status_count,
                                                                         std::vector<transport_cc_packet_status_symbol>& statuses)
{
    while (statuses.size() < packet_status_count)
    {
        if (offset + k_transport_cc_status_chunk_size > end)
        {
            return make_error("rtcp transport cc status chunk is truncated");
        }

        const uint16_t chunk = read_u16(data, offset);

        offset += k_transport_cc_status_chunk_size;

        if ((chunk & 0x8000U) != 0)
        {
            parse_transport_cc_status_vector_chunk(chunk, statuses, packet_status_count);
        }
        else
        {
            parse_transport_cc_run_length_chunk(chunk, statuses, packet_status_count);
        }
    }

    return offset;
}

std::expected<std::size_t, std::string> parse_transport_cc_recv_deltas(std::size_t offset,
                                                                       std::size_t end,
                                                                       const std::vector<transport_cc_packet_status_symbol>& statuses)
{
    for (const auto symbol : statuses)
    {
        if (!transport_cc_status_symbol_has_delta(symbol))
        {
            continue;
        }

        if (symbol == transport_cc_packet_status_symbol::small_delta)
        {
            if (offset + k_transport_cc_small_delta_size > end)
            {
                return make_error("rtcp transport cc small delta is truncated");
            }

            offset += k_transport_cc_small_delta_size;
        }
        else if (symbol == transport_cc_packet_status_symbol::large_or_negative_delta)
        {
            if (offset + k_transport_cc_large_delta_size > end)
            {
                return make_error("rtcp transport cc large delta is truncated");
            }

            offset += k_transport_cc_large_delta_size;
        }
    }

    return offset;
}

bool is_feedback_packet_type(uint8_t packet_type)
{
    return packet_type == k_rtcp_packet_type_transport_feedback || packet_type == k_rtcp_packet_type_payload_feedback;
}

bool is_remb_fci(std::span<const uint8_t> data, std::size_t offset, std::size_t end)
{
    if (offset + 4 > end)
    {
        return false;
    }

    return data[offset] == static_cast<uint8_t>('R') && data[offset + 1] == static_cast<uint8_t>('E') &&
           data[offset + 2] == static_cast<uint8_t>('M') && data[offset + 3] == static_cast<uint8_t>('B');
}

std::expected<void, std::string> parse_generic_nack(std::size_t offset, std::size_t end, rtcp_feedback_packet& packet)
{
    const std::size_t fci_size = end - offset;

    if (fci_size % 4 != 0)
    {
        return make_error("rtcp nack fci size is invalid");
    }

    packet.has_generic_nack = true;
    packet.nack_count = fci_size / 4;

    return {};
}

std::expected<void, std::string> parse_pli(std::size_t offset, std::size_t end, rtcp_feedback_packet& packet)
{
    if (offset != end)
    {
        return make_error("rtcp pli fci must be empty");
    }

    packet.has_keyframe_request = true;

    if (packet.media_ssrc != 0)
    {
        packet.keyframe_request_media_ssrcs.push_back(packet.media_ssrc);
    }

    return {};
}

std::expected<void, std::string> parse_fir(std::span<const uint8_t> data,
                                           std::size_t offset,
                                           std::size_t end,
                                           rtcp_feedback_packet& packet)
{
    const std::size_t fci_size = end - offset;

    if (fci_size % 8 != 0)
    {
        return make_error("rtcp fir fci size is invalid");
    }

    packet.has_keyframe_request = true;
    packet.fir_count = fci_size / 8;
    packet.keyframe_request_media_ssrcs.reserve(packet.fir_count);
    packet.fir_entries.reserve(packet.fir_count);

    for (std::size_t current = offset; current < end; current += 8)
    {
        rtcp_fir_entry entry;
        entry.media_ssrc = read_u32(data, current);
        entry.sequence_number = data[current + 4];
        packet.fir_entries.push_back(entry);

        if (entry.media_ssrc != 0)
        {
            packet.keyframe_request_media_ssrcs.push_back(entry.media_ssrc);
        }
    }

    return {};
}

std::expected<void, std::string> parse_remb(std::span<const uint8_t> data, std::size_t offset, std::size_t end, rtcp_feedback_packet& packet)
{
    if (!is_remb_fci(data, offset, end))
    {
        return {};
    }

    if (offset + 8 > end)
    {
        return make_error("rtcp remb fci is truncated");
    }

    const uint8_t ssrc_count = data[offset + 4];
    const uint8_t bitrate_exponent = static_cast<uint8_t>(data[offset + 5] >> 2U);
    const uint32_t bitrate_mantissa = (static_cast<uint32_t>(data[offset + 5] & 0x03U) << 16U) |
                                      (static_cast<uint32_t>(data[offset + 6]) << 8U) | static_cast<uint32_t>(data[offset + 7]);

    const std::size_t ssrc_offset = offset + 8;
    const std::size_t required_size = ssrc_offset + static_cast<std::size_t>(ssrc_count) * 4;

    if (required_size > end)
    {
        return make_error("rtcp remb ssrc list is truncated");
    }

    packet.remb_bitrate_bps = static_cast<uint64_t>(bitrate_mantissa) << bitrate_exponent;

    return {};
}

std::expected<void, std::string> parse_transport_feedback(std::span<const uint8_t> data,
                                                          std::size_t offset,
                                                          std::size_t end,
                                                          rtcp_feedback_packet& packet)
{
    switch (packet.format)
    {
        case k_rtcp_transport_feedback_generic_nack:
            return parse_generic_nack(offset, end, packet);

        case k_rtcp_transport_feedback_transport_cc:
        {
            if (offset + k_transport_cc_fixed_fci_size > end)
            {
                return make_error("rtcp transport cc fixed fci is truncated");
            }

            packet.has_transport_cc = true;

            const std::size_t packet_status_count = read_u16(data, offset + 2);

            if (packet_status_count > k_max_transport_cc_packet_status_count)
            {
                return make_error("rtcp transport cc packet status count exceeds limit");
            }

            std::vector<transport_cc_packet_status_symbol> statuses;
            statuses.reserve(packet_status_count);

            offset += k_transport_cc_fixed_fci_size;

            auto chunk_offset = parse_transport_cc_status_chunks(data, offset, end, packet_status_count, statuses);

            if (!chunk_offset)
            {
                return std::unexpected(chunk_offset.error());
            }

            auto delta_offset = parse_transport_cc_recv_deltas(*chunk_offset, end, statuses);

            if (!delta_offset)
            {
                return std::unexpected(delta_offset.error());
            }

            if (!rtcp_feedback_trailing_bytes_are_zero(data, *delta_offset, end))
            {
                return make_error("rtcp transport cc trailing padding is not zero");
            }

            return {};
        }

        case k_rtcp_transport_feedback_tmmbr:
        case k_rtcp_transport_feedback_tmmbn:
            return {};

        default:
            return {};
    }
}

std::expected<void, std::string> parse_payload_feedback(std::span<const uint8_t> data,
                                                        std::size_t offset,
                                                        std::size_t end,
                                                        rtcp_feedback_packet& packet)
{
    switch (packet.format)
    {
        case k_rtcp_payload_feedback_pli:
            return parse_pli(offset, end, packet);

        case k_rtcp_payload_feedback_fir:
            return parse_fir(data, offset, end, packet);

        case k_rtcp_payload_feedback_afb:
            return parse_remb(data, offset, end, packet);

        case k_rtcp_payload_feedback_sli:
        case k_rtcp_payload_feedback_rpsi:
            return {};

        default:
            return {};
    }
}

}    // namespace

bool is_rtcp_feedback_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return false;
    }

    return is_feedback_packet_type(header->packet_type);
}

rtcp_feedback_packet_result parse_rtcp_feedback_packet(std::span<const uint8_t> data)
{
    auto header = parse_rtcp_packet_header(data);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    if (!is_feedback_packet_type(header->packet_type))
    {
        return make_error("rtcp packet is not feedback");
    }

    if (header->packet_size < k_rtcp_feedback_header_size)
    {
        return make_error("rtcp feedback packet is shorter than feedback header");
    }

    auto payload_end = rtcp_feedback_payload_end(*header, data);

    if (!payload_end)
    {
        return std::unexpected(payload_end.error());
    }

    rtcp_feedback_packet packet;
    packet.format = header->count;
    packet.packet_type = header->packet_type;
    packet.sender_ssrc = read_u32(data, 4);
    packet.media_ssrc = read_u32(data, 8);

    const std::size_t fci_offset = k_rtcp_feedback_header_size;
    const std::size_t packet_end = *payload_end;
    std::expected<void, std::string> parse_result;

    if (packet.packet_type == k_rtcp_packet_type_transport_feedback)
    {
        parse_result = parse_transport_feedback(data, fci_offset, packet_end, packet);
    }
    else
    {
        parse_result = parse_payload_feedback(data, fci_offset, packet_end, packet);
    }

    if (!parse_result)
    {
        return std::unexpected(parse_result.error());
    }

    return packet;
}

std::string rtcp_feedback_format_to_string(uint8_t packet_type, uint8_t format)
{
    if (packet_type == k_rtcp_packet_type_transport_feedback)
    {
        switch (format)
        {
            case k_rtcp_transport_feedback_generic_nack:
                return "generic_nack";

            case k_rtcp_transport_feedback_tmmbr:
                return "tmmbr";

            case k_rtcp_transport_feedback_tmmbn:
                return "tmmbn";

            case k_rtcp_transport_feedback_transport_cc:
                return "transport_cc";

            default:
                return "transport_feedback_unknown";
        }
    }

    if (packet_type == k_rtcp_packet_type_payload_feedback)
    {
        switch (format)
        {
            case k_rtcp_payload_feedback_pli:
                return "pli";

            case k_rtcp_payload_feedback_sli:
                return "sli";

            case k_rtcp_payload_feedback_rpsi:
                return "rpsi";

            case k_rtcp_payload_feedback_fir:
                return "fir";

            case k_rtcp_payload_feedback_afb:
                return "afb";

            default:
                return "payload_feedback_unknown";
        }
    }

    return "unknown";
}

}    // namespace webrtc
