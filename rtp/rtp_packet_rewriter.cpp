#include "rtp/rtp_packet_rewriter.h"

#include <algorithm>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void write_u16(std::vector<uint8_t>& packet, std::size_t offset, uint16_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 8U) & 0xFFU);

    packet[offset + 1] = static_cast<uint8_t>(value & 0xFFU);
}

void write_u32(std::vector<uint8_t>& packet, std::size_t offset, uint32_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 24U) & 0xFFU);

    packet[offset + 1] = static_cast<uint8_t>((value >> 16U) & 0xFFU);

    packet[offset + 2] = static_cast<uint8_t>((value >> 8U) & 0xFFU);

    packet[offset + 3] = static_cast<uint8_t>(value & 0xFFU);
}

std::expected<void, std::string> validate_rewrite_options(const rtp_packet_rewrite_options& options)
{
    if (options.payload_type.has_value() && *options.payload_type > 127)
    {
        return make_error("rtp rewrite payload type is out of range");
    }

    for (const auto& extension : options.header_extensions)
    {
        if (extension.id == 0)
        {
            return make_error("rtp rewrite header extension id is zero");
        }

        if (extension.payload.empty())
        {
            return make_error("rtp rewrite header extension payload is empty");
        }
    }

    return {};
}

std::expected<void, std::string> rewrite_header_extension(std::vector<uint8_t>& rewritten_packet,
                                                          const rtp_packet_header& header,
                                                          const rtp_header_extension_rewrite& rewrite)
{
    auto payload = find_rtp_header_extension(std::span<const uint8_t>(rewritten_packet.data(), rewritten_packet.size()), header, rewrite.id);

    if (!payload.has_value())
    {
        return make_error("rtp rewrite header extension is not present");
    }

    if (payload->size() != rewrite.payload.size())
    {
        return make_error("rtp rewrite header extension payload size mismatch");
    }

    const std::size_t offset = static_cast<std::size_t>(payload->data() - rewritten_packet.data());

    std::copy(rewrite.payload.begin(), rewrite.payload.end(), rewritten_packet.begin() + static_cast<std::ptrdiff_t>(offset));

    return {};
}

std::expected<void, std::string> rewrite_header_extensions(std::vector<uint8_t>& rewritten_packet,
                                                           const rtp_packet_header& header,
                                                           const rtp_packet_rewrite_options& options)
{
    for (const auto& extension : options.header_extensions)
    {
        auto rewrite_result = rewrite_header_extension(rewritten_packet, header, extension);

        if (!rewrite_result)
        {
            return std::unexpected(rewrite_result.error());
        }
    }

    return {};
}
}    // namespace

rtp_packet_rewrite_result_type rewrite_rtp_packet(std::span<const uint8_t> packet, const rtp_packet_rewrite_options& options)
{
    if (packet.empty())
    {
        return make_error("rtp rewrite packet is empty");
    }

    auto validation_result = validate_rewrite_options(options);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    auto header = parse_rtp_packet_header(packet);

    if (!header)
    {
        std::string message = "rtp rewrite parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    rtp_packet_rewrite_result result;

    result.packet.assign(packet.begin(), packet.end());

    if (options.payload_type.has_value() && *options.payload_type != header->payload_type)
    {
        result.packet[1] = static_cast<uint8_t>((result.packet[1] & 0x80U) | *options.payload_type);

        result.changed = true;
    }

    if (options.sequence_number.has_value() && *options.sequence_number != header->sequence_number)
    {
        write_u16(result.packet, 2, *options.sequence_number);

        result.changed = true;
    }

    if (options.timestamp.has_value() && *options.timestamp != header->timestamp)
    {
        write_u32(result.packet, 4, *options.timestamp);

        result.changed = true;
    }

    if (options.ssrc.has_value() && *options.ssrc != header->ssrc)
    {
        write_u32(result.packet, 8, *options.ssrc);

        result.changed = true;
    }

    if (!options.header_extensions.empty())
    {
        auto extension_result = rewrite_header_extensions(result.packet, *header, options);

        if (!extension_result)
        {
            return std::unexpected(extension_result.error());
        }

        result.changed = true;
    }

    return result;
}

rtp_packet_rewrite_options make_payload_type_rewrite_options(uint8_t payload_type)
{
    rtp_packet_rewrite_options options;

    options.payload_type = payload_type;

    return options;
}

rtp_packet_rewrite_options make_payload_type_and_ssrc_rewrite_options(uint8_t payload_type, uint32_t ssrc)
{
    rtp_packet_rewrite_options options;

    options.payload_type = payload_type;

    options.ssrc = ssrc;

    return options;
}

bool rtp_payload_type_requires_rewrite(uint8_t source_payload_type, uint8_t target_payload_type)
{
    return source_payload_type != target_payload_type;
}
}    // namespace webrtc
