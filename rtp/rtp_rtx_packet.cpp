#include "rtp/rtp_rtx_packet.h"

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
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

void append_u16(std::vector<uint8_t>& packet, uint16_t value)
{
    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void write_u16(std::vector<uint8_t>& packet, std::size_t offset, uint16_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 8U) & 0xffU);

    packet[offset + 1] = static_cast<uint8_t>(value & 0xffU);
}

void write_u32(std::vector<uint8_t>& packet, std::size_t offset, uint32_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 24U) & 0xffU);

    packet[offset + 1] = static_cast<uint8_t>((value >> 16U) & 0xffU);

    packet[offset + 2] = static_cast<uint8_t>((value >> 8U) & 0xffU);

    packet[offset + 3] = static_cast<uint8_t>(value & 0xffU);
}

struct rtp_rtx_header_extension_id_rewrite_plan_entry
{
    const rtp_header_extension_entry* extension = nullptr;

    uint8_t source_id = 0;
    uint8_t target_id = 0;
};

struct rtp_rtx_header_extension_id_rewrite_plan
{
    std::vector<rtp_rtx_header_extension_id_rewrite_plan_entry> entries;

    bool changed = false;
};

const rtp_header_extension_entry* find_header_extension_entry(const rtp_packet_header& header, uint8_t extension_id)
{
    if (extension_id == 0)
    {
        return nullptr;
    }

    for (const auto& extension : header.header_extensions)
    {
        if (extension.id == extension_id)
        {
            return &extension;
        }
    }

    return nullptr;
}

std::expected<void, std::string> validate_rtx_header_extension_target_id(rtp_header_extension_format format, uint8_t target_id)
{
    if (target_id == 0)
    {
        return make_error("rtx header extension target id is zero");
    }

    switch (format)
    {
        case rtp_header_extension_format::one_byte:
            if (target_id >= 15)
            {
                return make_error("rtx one-byte header extension target id is out of range");
            }

            return {};

        case rtp_header_extension_format::two_byte:
            return {};

        case rtp_header_extension_format::unknown:
            return make_error("rtx header extension format is unknown");
    }

    return make_error("rtx header extension format is unsupported");
}

std::expected<void, std::string> append_normalized_rtx_header_extension_id_rewrite(
    std::vector<rtp_rtx_header_extension_id_rewrite>& normalized_rewrites, const rtp_rtx_header_extension_id_rewrite& rewrite)
{
    if (rewrite.source_id == rewrite.target_id)
    {
        return {};
    }

    for (const auto& existing : normalized_rewrites)
    {
        if (existing.source_id != rewrite.source_id)
        {
            continue;
        }

        if (existing.target_id == rewrite.target_id)
        {
            return {};
        }

        return make_error("rtx header extension source id has conflicting rewrite targets");
    }

    normalized_rewrites.push_back(rewrite);

    return {};
}

bool find_normalized_rtx_target_id(const std::vector<rtp_rtx_header_extension_id_rewrite>& normalized_rewrites, uint8_t source_id, uint8_t& target_id)
{
    for (const auto& rewrite : normalized_rewrites)
    {
        if (rewrite.source_id == source_id)
        {
            target_id = rewrite.target_id;

            return true;
        }
    }

    return false;
}

bool rtx_final_header_extension_id_exists(const std::vector<uint8_t>& final_ids, uint8_t final_id)
{
    for (const auto& existing : final_ids)
    {
        if (existing == final_id)
        {
            return true;
        }
    }

    return false;
}

std::expected<void, std::string> validate_final_rtx_header_extension_ids(const rtp_packet_header& header,
                                                                         const std::vector<rtp_rtx_header_extension_id_rewrite>& normalized_rewrites)
{
    std::vector<uint8_t> final_ids;

    final_ids.reserve(header.header_extensions.size());

    for (const auto& extension : header.header_extensions)
    {
        uint8_t final_id = extension.id;

        uint8_t target_id = 0;

        if (find_normalized_rtx_target_id(normalized_rewrites, extension.id, target_id))
        {
            final_id = target_id;
        }

        auto validation_result = validate_rtx_header_extension_target_id(header.extension_format, final_id);

        if (!validation_result)
        {
            return std::unexpected(validation_result.error());
        }

        if (rtx_final_header_extension_id_exists(final_ids, final_id))
        {
            return make_error("rtx header extension rewrite plan has duplicate final id");
        }

        final_ids.push_back(final_id);
    }

    return {};
}

std::expected<rtp_rtx_header_extension_id_rewrite_plan, std::string> make_rtx_header_extension_id_rewrite_plan(const rtp_packet_header& header,
                                                                                                               const rtp_rtx_packet_options& options)
{
    rtp_rtx_header_extension_id_rewrite_plan plan;

    std::vector<rtp_rtx_header_extension_id_rewrite> normalized_rewrites;

    normalized_rewrites.reserve(options.header_extension_id_rewrites.size());

    for (const auto& rewrite : options.header_extension_id_rewrites)
    {
        if (rewrite.source_id == 0)
        {
            return make_error("rtx header extension source id is zero");
        }

        if (rewrite.target_id == 0)
        {
            return make_error("rtx header extension target id is zero");
        }

        if (rewrite.source_id == rewrite.target_id)
        {
            continue;
        }

        const rtp_header_extension_entry* source_extension = find_header_extension_entry(header, rewrite.source_id);

        if (source_extension == nullptr)
        {
            continue;
        }

        auto target_validation_result = validate_rtx_header_extension_target_id(header.extension_format, rewrite.target_id);

        if (!target_validation_result)
        {
            return std::unexpected(target_validation_result.error());
        }

        auto append_result = append_normalized_rtx_header_extension_id_rewrite(normalized_rewrites, rewrite);

        if (!append_result)
        {
            return std::unexpected(append_result.error());
        }
    }

    if (normalized_rewrites.empty())
    {
        return plan;
    }

    auto final_ids_validation_result = validate_final_rtx_header_extension_ids(header, normalized_rewrites);

    if (!final_ids_validation_result)
    {
        return std::unexpected(final_ids_validation_result.error());
    }

    plan.entries.reserve(normalized_rewrites.size());

    for (const auto& rewrite : normalized_rewrites)
    {
        const rtp_header_extension_entry* source_extension = find_header_extension_entry(header, rewrite.source_id);

        if (source_extension == nullptr)
        {
            continue;
        }

        rtp_rtx_header_extension_id_rewrite_plan_entry entry;

        entry.extension = source_extension;
        entry.source_id = rewrite.source_id;
        entry.target_id = rewrite.target_id;

        plan.entries.push_back(entry);

        plan.changed = true;
    }

    return plan;
}

std::expected<void, std::string> rewrite_one_byte_header_extension_id(std::vector<uint8_t>& packet,
                                                                      const rtp_header_extension_entry& extension,
                                                                      uint8_t target_id)
{
    if (target_id == 0 || target_id >= 15)
    {
        return make_error("rtx one-byte header extension target id is out of range");
    }

    if (extension.offset == 0)
    {
        return make_error("rtx one-byte header extension offset is invalid");
    }

    const std::size_t id_offset = extension.offset - 1;

    if (id_offset >= packet.size())
    {
        return make_error("rtx one-byte header extension id offset is truncated");
    }

    packet[id_offset] = static_cast<uint8_t>((target_id << 4U) | (packet[id_offset] & 0x0fU));

    return {};
}

std::expected<void, std::string> rewrite_two_byte_header_extension_id(std::vector<uint8_t>& packet,
                                                                      const rtp_header_extension_entry& extension,
                                                                      uint8_t target_id)
{
    if (target_id == 0)
    {
        return make_error("rtx two-byte header extension target id is zero");
    }

    if (extension.offset < 2)
    {
        return make_error("rtx two-byte header extension offset is invalid");
    }

    const std::size_t id_offset = extension.offset - 2;

    if (id_offset >= packet.size())
    {
        return make_error("rtx two-byte header extension id offset is truncated");
    }

    packet[id_offset] = target_id;

    return {};
}

std::expected<void, std::string> rewrite_header_extension_id(std::vector<uint8_t>& packet,
                                                             rtp_header_extension_format format,
                                                             const rtp_rtx_header_extension_id_rewrite_plan_entry& rewrite)
{
    if (rewrite.extension == nullptr)
    {
        return make_error("rtx header extension rewrite source extension is null");
    }

    if (rewrite.source_id == 0)
    {
        return make_error("rtx header extension source id is zero");
    }

    if (rewrite.target_id == 0)
    {
        return make_error("rtx header extension target id is zero");
    }

    if (rewrite.source_id == rewrite.target_id)
    {
        return {};
    }

    switch (format)
    {
        case rtp_header_extension_format::one_byte:
            return rewrite_one_byte_header_extension_id(packet, *rewrite.extension, rewrite.target_id);

        case rtp_header_extension_format::two_byte:
            return rewrite_two_byte_header_extension_id(packet, *rewrite.extension, rewrite.target_id);

        case rtp_header_extension_format::unknown:
            return make_error("rtx header extension format is unknown");
    }

    return make_error("rtx header extension format is unsupported");
}

std::expected<void, std::string> rewrite_header_extension_ids(std::vector<uint8_t>& packet,
                                                              const rtp_packet_header& header,
                                                              const rtp_rtx_packet_options& options)
{
    auto plan = make_rtx_header_extension_id_rewrite_plan(header, options);

    if (!plan)
    {
        return std::unexpected(plan.error());
    }

    if (!plan->changed)
    {
        return {};
    }

    for (const auto& rewrite : plan->entries)
    {
        auto rewrite_result = rewrite_header_extension_id(packet, header.extension_format, rewrite);

        if (!rewrite_result)
        {
            return std::unexpected(rewrite_result.error());
        }
    }

    return {};
}
}    // namespace

rtp_rtx_packet_result make_rtp_rtx_packet(std::span<const uint8_t> primary_packet, const rtp_rtx_packet_options& options)
{
    if (primary_packet.empty())
    {
        return make_error("rtx primary packet is empty");
    }

    if (options.payload_type > 127)
    {
        return make_error("rtx payload type is out of range");
    }

    if (options.ssrc == 0)
    {
        return make_error("rtx ssrc is zero");
    }

    auto primary_header = parse_rtp_packet_header(primary_packet);

    if (!primary_header)
    {
        std::string message = "rtx primary packet parse failed: ";

        message.append(primary_header.error());

        return std::unexpected(std::move(message));
    }

    if (primary_header->payload_size == 0)
    {
        return make_error("rtx primary packet payload is empty");
    }

    if (primary_header->payload_offset + primary_header->payload_size > primary_packet.size())
    {
        return make_error("rtx primary packet payload is truncated");
    }

    std::vector<uint8_t> rtx_packet;

    rtx_packet.reserve(primary_header->payload_offset + 2 + primary_header->payload_size);

    rtx_packet.insert(rtx_packet.end(), primary_packet.begin(), primary_packet.begin() + static_cast<std::ptrdiff_t>(primary_header->payload_offset));

    /*
     * RTX 包不复制 primary packet 的 RTP padding。
     * 如果 primary packet 带 padding，需要清掉 RTP header 的 padding bit。
     */
    rtx_packet[0] = static_cast<uint8_t>(rtx_packet[0] & static_cast<uint8_t>(~0x20U));

    rtx_packet[1] = static_cast<uint8_t>((rtx_packet[1] & 0x80U) | options.payload_type);

    const uint16_t original_sequence_number = options.original_sequence_number.value_or(primary_header->sequence_number);

    write_u16(rtx_packet, 2, options.sequence_number);
    write_u32(rtx_packet, 4, options.timestamp);
    write_u32(rtx_packet, 8, options.ssrc);
    append_u16(rtx_packet, original_sequence_number);

    const auto payload_begin = primary_packet.begin() + static_cast<std::ptrdiff_t>(primary_header->payload_offset);
    const auto payload_end = payload_begin + static_cast<std::ptrdiff_t>(primary_header->payload_size);

    rtx_packet.insert(rtx_packet.end(), payload_begin, payload_end);

    if (!options.header_extension_id_rewrites.empty())
    {
        auto rewrite_result = rewrite_header_extension_ids(rtx_packet, *primary_header, options);

        if (!rewrite_result)
        {
            return std::unexpected(rewrite_result.error());
        }
    }

    auto validation_result =
        validate_rtp_rtx_packet(std::span<const uint8_t>(rtx_packet.data(), rtx_packet.size()), options, original_sequence_number);
    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    return rtx_packet;
}
rtp_rtx_packet_info_result parse_rtp_rtx_packet(std::span<const uint8_t> rtx_packet)
{
    if (rtx_packet.empty())
    {
        return make_error("rtx packet is empty");
    }

    auto header = parse_rtp_packet_header(rtx_packet);

    if (!header)
    {
        std::string message = "rtx packet parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    if (header->payload_size < 2)
    {
        return make_error("rtx packet payload is shorter than osn");
    }

    if (header->payload_offset + 2 > rtx_packet.size())
    {
        return make_error("rtx packet osn is truncated");
    }

    rtp_rtx_packet_info info;

    info.header = *header;

    info.original_sequence_number = read_u16(rtx_packet, header->payload_offset);

    info.original_payload_offset = header->payload_offset + 2;

    info.original_payload_size = header->payload_size - 2;

    return info;
}

rtp_rtx_packet_validation_result validate_rtp_rtx_packet(std::span<const uint8_t> rtx_packet,
                                                         const rtp_rtx_packet_options& options,
                                                         uint16_t expected_original_sequence_number)
{
    auto info = parse_rtp_rtx_packet(rtx_packet);

    if (!info)
    {
        return std::unexpected(info.error());
    }

    if (info->header.padding)
    {
        return make_error("rtx packet must not use rtp padding");
    }

    if (info->header.payload_type != options.payload_type)
    {
        return make_error("rtx packet payload type does not match options");
    }

    if (info->header.ssrc != options.ssrc)
    {
        return make_error("rtx packet ssrc does not match options");
    }

    if (info->header.sequence_number != options.sequence_number)
    {
        return make_error("rtx packet sequence number does not match options");
    }

    if (info->header.timestamp != options.timestamp)
    {
        return make_error("rtx packet timestamp does not match options");
    }

    if (info->original_sequence_number != expected_original_sequence_number)
    {
        return make_error("rtx packet osn does not match primary sequence number");
    }

    return {};
}
}    // namespace webrtc
