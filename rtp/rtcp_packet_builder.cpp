#include "rtp/rtcp_packet_builder.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc
{
namespace
{
inline constexpr uint8_t k_rtcp_version = 2;
inline constexpr uint8_t k_rtcp_packet_type_sender_report = 200;
inline constexpr uint8_t k_rtcp_packet_type_receiver_report = 201;
inline constexpr uint8_t k_rtcp_packet_type_sdes = 202;
inline constexpr uint8_t k_rtcp_packet_type_bye = 203;
inline constexpr uint8_t k_rtcp_packet_type_transport_feedback = 205;
inline constexpr uint8_t k_rtcp_packet_type_payload_feedback = 206;
inline constexpr uint8_t k_rtcp_payload_feedback_pli = 1;
inline constexpr uint8_t k_rtcp_payload_feedback_fir = 4;
inline constexpr uint8_t k_rtcp_sdes_item_cname = 1;
inline constexpr std::size_t k_rtcp_common_header_size = 4;
inline constexpr std::size_t k_rtcp_report_block_size = 24;
inline constexpr std::size_t k_rtcp_sender_info_size = 20;
inline constexpr std::size_t k_rtcp_feedback_header_size = 12;
inline constexpr std::size_t k_rtcp_fir_entry_size = 8;
inline constexpr std::size_t k_rtcp_max_count = 31;
inline constexpr int32_t k_rtcp_min_cumulative_lost = -8388608;
inline constexpr int32_t k_rtcp_max_cumulative_lost = 8388607;

std::unexpected<std::string> make_error(std::string_view message)
{
    return std::unexpected(std::string(message));
}

void write_u16(std::span<uint8_t> data, std::size_t offset, uint16_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 8U);
    data[offset + 1] = static_cast<uint8_t>(value);
}

void write_u24(std::span<uint8_t> data, std::size_t offset, uint32_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 16U);
    data[offset + 1] = static_cast<uint8_t>(value >> 8U);
    data[offset + 2] = static_cast<uint8_t>(value);
}

void write_u32(std::span<uint8_t> data, std::size_t offset, uint32_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 24U);
    data[offset + 1] = static_cast<uint8_t>(value >> 16U);
    data[offset + 2] = static_cast<uint8_t>(value >> 8U);
    data[offset + 3] = static_cast<uint8_t>(value);
}

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) |
                                 static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) |
           (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) |
           static_cast<uint32_t>(data[offset + 3]);
}

std::expected<void, std::string> write_common_header(std::span<uint8_t> packet,
                                                     uint8_t count,
                                                     uint8_t packet_type)
{
    if (packet.size() < k_rtcp_common_header_size || packet.size() % 4U != 0)
    {
        return make_error("rtcp packet size is invalid");
    }

    if (count > k_rtcp_max_count)
    {
        return make_error("rtcp packet count exceeds five-bit field");
    }

    const std::size_t length_words = packet.size() / 4U - 1U;

    if (length_words > std::numeric_limits<uint16_t>::max())
    {
        return make_error("rtcp packet length exceeds sixteen-bit field");
    }

    packet[0] = static_cast<uint8_t>((k_rtcp_version << 6U) | count);
    packet[1] = packet_type;
    write_u16(packet, 2, static_cast<uint16_t>(length_words));
    return {};
}

std::expected<void, std::string> write_report_blocks(std::span<uint8_t> packet,
                                                     std::size_t offset,
                                                     std::span<const rtcp_report_block> blocks)
{
    for (const auto& block : blocks)
    {
        if (block.cumulative_lost < k_rtcp_min_cumulative_lost ||
            block.cumulative_lost > k_rtcp_max_cumulative_lost)
        {
            return make_error("rtcp cumulative lost exceeds signed 24-bit field");
        }

        if (offset + k_rtcp_report_block_size > packet.size())
        {
            return make_error("rtcp report block output is truncated");
        }

        write_u32(packet, offset, block.source_ssrc);
        packet[offset + 4] = block.fraction_lost;
        write_u24(packet, offset + 5, static_cast<uint32_t>(block.cumulative_lost) & 0x00FFFFFFU);
        write_u32(packet, offset + 8, block.extended_highest_sequence_number);
        write_u32(packet, offset + 12, block.jitter);
        write_u32(packet, offset + 16, block.last_sender_report);
        write_u32(packet, offset + 20, block.delay_since_last_sender_report);
        offset += k_rtcp_report_block_size;
    }

    return {};
}

std::expected<uint8_t, std::string> validate_report(std::size_t report_count,
                                                    uint32_t sender_ssrc)
{
    if (sender_ssrc == 0)
    {
        return make_error("rtcp report sender ssrc is zero");
    }

    if (report_count > k_rtcp_max_count)
    {
        return make_error("rtcp report block count exceeds five-bit field");
    }

    return static_cast<uint8_t>(report_count);
}

std::expected<uint8_t, std::string> validate_rtcp_packet(std::span<const uint8_t> packet)
{
    if (packet.size() < k_rtcp_common_header_size || packet.size() % 4U != 0)
    {
        return make_error("rtcp compound member size is invalid");
    }

    if ((packet[0] >> 6U) != k_rtcp_version)
    {
        return make_error("rtcp compound member version is invalid");
    }

    const std::size_t declared_size = (static_cast<std::size_t>(read_u16(packet, 2)) + 1U) * 4U;

    if (declared_size != packet.size())
    {
        return make_error("rtcp compound member length does not match buffer");
    }

    return packet[1];
}
}    // namespace

rtcp_packet_build_result build_rtcp_sender_report(const rtcp_sender_report_data& report)
{
    auto report_count = validate_report(report.report_blocks.size(), report.sender_ssrc);

    if (!report_count)
    {
        return std::unexpected(report_count.error());
    }

    const std::size_t packet_size = k_rtcp_common_header_size + 4U + k_rtcp_sender_info_size +
                                    report.report_blocks.size() * k_rtcp_report_block_size;
    std::vector<uint8_t> packet(packet_size);
    auto header = write_common_header(packet, *report_count, k_rtcp_packet_type_sender_report);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    write_u32(packet, 4, report.sender_ssrc);
    write_u32(packet, 8, static_cast<uint32_t>(report.ntp_timestamp >> 32U));
    write_u32(packet, 12, static_cast<uint32_t>(report.ntp_timestamp));
    write_u32(packet, 16, report.rtp_timestamp);
    write_u32(packet, 20, report.sender_packet_count);
    write_u32(packet, 24, report.sender_octet_count);

    auto blocks = write_report_blocks(packet, 28, report.report_blocks);

    if (!blocks)
    {
        return std::unexpected(blocks.error());
    }

    return packet;
}

rtcp_packet_build_result build_rtcp_receiver_report(const rtcp_receiver_report_data& report)
{
    auto report_count = validate_report(report.report_blocks.size(), report.sender_ssrc);

    if (!report_count)
    {
        return std::unexpected(report_count.error());
    }

    const std::size_t packet_size = k_rtcp_common_header_size + 4U +
                                    report.report_blocks.size() * k_rtcp_report_block_size;
    std::vector<uint8_t> packet(packet_size);
    auto header = write_common_header(packet, *report_count, k_rtcp_packet_type_receiver_report);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    write_u32(packet, 4, report.sender_ssrc);
    auto blocks = write_report_blocks(packet, 8, report.report_blocks);

    if (!blocks)
    {
        return std::unexpected(blocks.error());
    }

    return packet;
}

rtcp_packet_build_result build_rtcp_sdes_cname(uint32_t ssrc, std::string_view cname)
{
    if (ssrc == 0)
    {
        return make_error("rtcp sdes ssrc is zero");
    }

    if (cname.empty())
    {
        return make_error("rtcp sdes cname is empty");
    }

    if (cname.size() > std::numeric_limits<uint8_t>::max())
    {
        return make_error("rtcp sdes cname exceeds eight-bit length field");
    }

    const std::size_t unaligned_size = k_rtcp_common_header_size + 4U + 2U + cname.size() + 1U;
    const std::size_t packet_size = (unaligned_size + 3U) & ~std::size_t{3U};
    std::vector<uint8_t> packet(packet_size);
    auto header = write_common_header(packet, 1, k_rtcp_packet_type_sdes);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    write_u32(packet, 4, ssrc);
    packet[8] = k_rtcp_sdes_item_cname;
    packet[9] = static_cast<uint8_t>(cname.size());
    std::copy(cname.begin(), cname.end(), packet.begin() + 10);
    packet[10 + cname.size()] = 0;
    return packet;
}

rtcp_packet_build_result build_rtcp_picture_loss_indication(uint32_t sender_ssrc,
                                                             uint32_t media_ssrc)
{
    if (sender_ssrc == 0)
    {
        return make_error("rtcp pli sender ssrc is zero");
    }

    if (media_ssrc == 0)
    {
        return make_error("rtcp pli media ssrc is zero");
    }

    std::vector<uint8_t> packet(k_rtcp_feedback_header_size);
    auto header = write_common_header(packet,
                                      k_rtcp_payload_feedback_pli,
                                      k_rtcp_packet_type_payload_feedback);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    write_u32(packet, 4, sender_ssrc);
    write_u32(packet, 8, media_ssrc);
    return packet;
}

rtcp_packet_build_result build_rtcp_full_intra_request(
    uint32_t sender_ssrc, std::span<const rtcp_fir_request> requests)
{
    if (sender_ssrc == 0)
    {
        return make_error("rtcp fir sender ssrc is zero");
    }

    if (requests.empty())
    {
        return make_error("rtcp fir request list is empty");
    }

    if (requests.size() >
        (std::numeric_limits<std::size_t>::max() - k_rtcp_feedback_header_size) /
            k_rtcp_fir_entry_size)
    {
        return make_error("rtcp fir request list is too large");
    }

    const std::size_t packet_size =
        k_rtcp_feedback_header_size + requests.size() * k_rtcp_fir_entry_size;
    std::vector<uint8_t> packet(packet_size);
    auto header = write_common_header(packet,
                                      k_rtcp_payload_feedback_fir,
                                      k_rtcp_packet_type_payload_feedback);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    write_u32(packet, 4, sender_ssrc);
    write_u32(packet, 8, 0);

    std::size_t offset = k_rtcp_feedback_header_size;

    for (const auto& request : requests)
    {
        if (request.media_ssrc == 0)
        {
            return make_error("rtcp fir media ssrc is zero");
        }

        write_u32(packet, offset, request.media_ssrc);
        packet[offset + 4] = request.sequence_number;
        offset += k_rtcp_fir_entry_size;
    }

    return packet;
}

rtcp_packet_build_result build_rtcp_feedback_datagram(
    std::span<const uint8_t> feedback_packet,
    uint32_t sender_ssrc,
    std::string_view cname,
    bool reduced_size,
    std::size_t maximum_size)
{
    if (sender_ssrc == 0)
    {
        return make_error("rtcp feedback sender ssrc is zero");
    }

    const auto packet_type = validate_rtcp_packet(feedback_packet);

    if (!packet_type)
    {
        return std::unexpected(packet_type.error());
    }

    if (*packet_type != k_rtcp_packet_type_transport_feedback &&
        *packet_type != k_rtcp_packet_type_payload_feedback)
    {
        return make_error("rtcp feedback datagram member is not a feedback packet");
    }

    if (feedback_packet.size() < k_rtcp_feedback_header_size ||
        read_u32(feedback_packet, 4) != sender_ssrc)
    {
        return make_error("rtcp feedback sender ssrc does not match datagram sender");
    }

    if (reduced_size)
    {
        if (feedback_packet.size() > maximum_size)
        {
            return make_error("rtcp reduced-size feedback exceeds maximum size");
        }

        return std::vector<uint8_t>(feedback_packet.begin(), feedback_packet.end());
    }

    auto receiver_report = build_rtcp_receiver_report(rtcp_receiver_report_data{
        .sender_ssrc = sender_ssrc,
        .report_blocks = {},
    });
    auto sdes = build_rtcp_sdes_cname(sender_ssrc, cname);

    if (!receiver_report)
    {
        return std::unexpected(receiver_report.error());
    }

    if (!sdes)
    {
        return std::unexpected(sdes.error());
    }

    std::array<std::vector<uint8_t>, 3> members{
        std::move(*receiver_report),
        std::move(*sdes),
        std::vector<uint8_t>(feedback_packet.begin(), feedback_packet.end()),
    };
    return build_rtcp_compound_packet(members, maximum_size);
}

rtcp_packet_build_result build_rtcp_bye(std::span<const uint32_t> ssrcs,
                                         std::string_view reason)
{
    if (ssrcs.empty())
    {
        return make_error("rtcp bye ssrc list is empty");
    }

    if (ssrcs.size() > k_rtcp_max_count)
    {
        return make_error("rtcp bye ssrc count exceeds five-bit field");
    }

    if (reason.size() > std::numeric_limits<uint8_t>::max())
    {
        return make_error("rtcp bye reason exceeds eight-bit length field");
    }

    for (const uint32_t ssrc : ssrcs)
    {
        if (ssrc == 0)
        {
            return make_error("rtcp bye ssrc is zero");
        }
    }

    std::size_t unaligned_size = k_rtcp_common_header_size + ssrcs.size() * 4U;

    if (!reason.empty())
    {
        unaligned_size += 1U + reason.size();
    }

    const std::size_t packet_size = (unaligned_size + 3U) & ~std::size_t{3U};
    std::vector<uint8_t> packet(packet_size);
    auto header = write_common_header(packet, static_cast<uint8_t>(ssrcs.size()), k_rtcp_packet_type_bye);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    std::size_t offset = k_rtcp_common_header_size;

    for (const uint32_t ssrc : ssrcs)
    {
        write_u32(packet, offset, ssrc);
        offset += 4U;
    }

    if (!reason.empty())
    {
        packet[offset] = static_cast<uint8_t>(reason.size());
        offset += 1U;
        std::copy(reason.begin(), reason.end(), packet.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    return packet;
}

rtcp_packet_build_result build_rtcp_compound_packet(std::span<const std::vector<uint8_t>> packets,
                                                     std::size_t maximum_size)
{
    if (packets.empty())
    {
        return make_error("rtcp compound packet list is empty");
    }

    if (maximum_size < k_rtcp_common_header_size)
    {
        return make_error("rtcp compound maximum size is too small");
    }

    std::size_t total_size = 0;
    bool has_sdes = false;

    for (std::size_t index = 0; index < packets.size(); ++index)
    {
        const auto packet_type = validate_rtcp_packet(packets[index]);

        if (!packet_type)
        {
            return std::unexpected(packet_type.error());
        }

        if (index == 0 && *packet_type != k_rtcp_packet_type_sender_report &&
            *packet_type != k_rtcp_packet_type_receiver_report)
        {
            return make_error("rtcp compound packet must begin with sender or receiver report");
        }

        if ((packets[index][0] & 0x20U) != 0 && index + 1U != packets.size())
        {
            return make_error("rtcp compound padding is only allowed on final member");
        }

        has_sdes = has_sdes || *packet_type == k_rtcp_packet_type_sdes;

        if (total_size > maximum_size || packets[index].size() > maximum_size - total_size)
        {
            return make_error("rtcp compound packet exceeds maximum size");
        }

        total_size += packets[index].size();
    }

    if (!has_sdes)
    {
        return make_error("rtcp compound packet is missing sdes");
    }

    std::vector<uint8_t> compound;
    compound.reserve(total_size);

    for (const auto& packet : packets)
    {
        compound.insert(compound.end(), packet.begin(), packet.end());
    }

    return compound;
}
}    // namespace webrtc
