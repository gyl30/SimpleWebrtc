#include "rtp/rtp_packet_rewriter.h"

#include <algorithm>
#include <cstddef>
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
struct rtp_header_extension_id_rewrite_plan_entry
{
    const rtp_header_extension_entry* extension = nullptr;

    uint8_t source_id = 0;
    uint8_t target_id = 0;
};

struct rtp_header_extension_id_rewrite_plan
{
    std::vector<rtp_header_extension_id_rewrite_plan_entry> entries;

    bool changed = false;
};

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

std::expected<void, std::string> validate_header_extension_target_id(rtp_header_extension_format format, uint8_t target_id)
{
    if (target_id == 0)
    {
        return make_error("rtp header extension target id is zero");
    }

    switch (format)
    {
        case rtp_header_extension_format::one_byte:
            if (target_id >= 15)
            {
                return make_error("rtp one-byte header extension target id is out of range");
            }

            return {};

        case rtp_header_extension_format::two_byte:
            return {};

        case rtp_header_extension_format::unknown:
            return make_error("rtp header extension format is unknown");
    }

    return make_error("rtp header extension format is unsupported");
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

    for (const auto& rewrite : options.header_extension_id_rewrites)
    {
        if (rewrite.source_id == 0)
        {
            return make_error("rtp rewrite header extension source id is zero");
        }

        if (rewrite.target_id == 0)
        {
            return make_error("rtp rewrite header extension target id is zero");
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

std::expected<void, std::string> append_normalized_header_extension_id_rewrite(std::vector<rtp_header_extension_id_rewrite>& normalized_rewrites,
                                                                               const rtp_header_extension_id_rewrite& rewrite)
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

        return make_error("rtp header extension source id has conflicting rewrite targets");
    }

    normalized_rewrites.push_back(rewrite);

    return {};
}

std::optional<uint8_t> find_normalized_target_id(const std::vector<rtp_header_extension_id_rewrite>& normalized_rewrites, uint8_t source_id)
{
    for (const auto& rewrite : normalized_rewrites)
    {
        if (rewrite.source_id == source_id)
        {
            return rewrite.target_id;
        }
    }

    return std::nullopt;
}

std::expected<void, std::string> validate_final_header_extension_ids(const rtp_packet_header& header,
                                                                     const std::vector<rtp_header_extension_id_rewrite>& normalized_rewrites)
{
    std::vector<uint8_t> final_ids;

    final_ids.reserve(header.header_extensions.size());

    for (const auto& extension : header.header_extensions)
    {
        uint8_t final_id = extension.id;

        auto target_id = find_normalized_target_id(normalized_rewrites, extension.id);

        if (target_id.has_value())
        {
            final_id = *target_id;
        }

        auto validation_result = validate_header_extension_target_id(header.extension_format, final_id);

        if (!validation_result)
        {
            return std::unexpected(validation_result.error());
        }

        const auto existing = std::find(final_ids.begin(), final_ids.end(), final_id);

        if (existing != final_ids.end())
        {
            return make_error("rtp header extension rewrite plan has duplicate final id");
        }

        final_ids.push_back(final_id);
    }

    return {};
}

std::expected<rtp_header_extension_id_rewrite_plan, std::string> make_header_extension_id_rewrite_plan(const rtp_packet_header& header,
                                                                                                       const rtp_packet_rewrite_options& options)
{
    rtp_header_extension_id_rewrite_plan plan;

    std::vector<rtp_header_extension_id_rewrite> normalized_rewrites;

    normalized_rewrites.reserve(options.header_extension_id_rewrites.size());

    for (const auto& rewrite : options.header_extension_id_rewrites)
    {
        if (rewrite.source_id == 0)
        {
            return make_error("rtp header extension source id is zero");
        }

        if (rewrite.target_id == 0)
        {
            return make_error("rtp header extension target id is zero");
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

        auto target_validation_result = validate_header_extension_target_id(header.extension_format, rewrite.target_id);

        if (!target_validation_result)
        {
            return std::unexpected(target_validation_result.error());
        }

        auto append_result = append_normalized_header_extension_id_rewrite(normalized_rewrites, rewrite);

        if (!append_result)
        {
            return std::unexpected(append_result.error());
        }
    }

    if (normalized_rewrites.empty())
    {
        return plan;
    }

    auto final_ids_validation_result = validate_final_header_extension_ids(header, normalized_rewrites);

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

        rtp_header_extension_id_rewrite_plan_entry entry;

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
        return make_error("rtp one-byte header extension target id is out of range");
    }

    if (extension.offset == 0)
    {
        return make_error("rtp one-byte header extension offset is invalid");
    }

    const std::size_t id_offset = extension.offset - 1;

    if (id_offset >= packet.size())
    {
        return make_error("rtp one-byte header extension id offset is truncated");
    }

    packet[id_offset] = static_cast<uint8_t>((target_id << 4U) | (packet[id_offset] & 0x0FU));

    return {};
}

std::expected<void, std::string> rewrite_two_byte_header_extension_id(std::vector<uint8_t>& packet,
                                                                      const rtp_header_extension_entry& extension,
                                                                      uint8_t target_id)
{
    if (target_id == 0)
    {
        return make_error("rtp two-byte header extension target id is zero");
    }

    if (extension.offset < 2)
    {
        return make_error("rtp two-byte header extension offset is invalid");
    }

    const std::size_t id_offset = extension.offset - 2;

    if (id_offset >= packet.size())
    {
        return make_error("rtp two-byte header extension id offset is truncated");
    }

    packet[id_offset] = target_id;

    return {};
}

std::expected<void, std::string> rewrite_header_extension_id(std::vector<uint8_t>& packet,
                                                             rtp_header_extension_format format,
                                                             const rtp_header_extension_id_rewrite_plan_entry& rewrite)
{
    if (rewrite.extension == nullptr)
    {
        return make_error("rtp header extension rewrite source extension is null");
    }

    if (rewrite.source_id == 0)
    {
        return make_error("rtp header extension source id is zero");
    }

    if (rewrite.target_id == 0)
    {
        return make_error("rtp header extension target id is zero");
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
            return make_error("rtp header extension format is unknown");
    }

    return make_error("rtp header extension format is unsupported");
}

std::expected<bool, std::string> rewrite_header_extension_ids(std::vector<uint8_t>& packet,
                                                              const rtp_packet_header& header,
                                                              const rtp_packet_rewrite_options& options)
{
    auto plan = make_header_extension_id_rewrite_plan(header, options);

    if (!plan)
    {
        return std::unexpected(plan.error());
    }

    if (!plan->changed)
    {
        return false;
    }

    for (const auto& rewrite : plan->entries)
    {
        auto rewrite_result = rewrite_header_extension_id(packet, header.extension_format, rewrite);

        if (!rewrite_result)
        {
            return std::unexpected(rewrite_result.error());
        }
    }

    return true;
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

    if (!options.header_extension_id_rewrites.empty())
    {
        auto extension_id_result = rewrite_header_extension_ids(result.packet, *header, options);

        if (!extension_id_result)
        {
            return std::unexpected(extension_id_result.error());
        }

        if (*extension_id_result)
        {
            result.changed = true;
        }
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
