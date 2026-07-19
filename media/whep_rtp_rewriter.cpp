#include "media/whep_rtp_rewriter.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "rtp/rtp_packet.h"
#include "signaling/sdp/sdp_codec_negotiator.h"

namespace webrtc
{
namespace
{
constexpr std::size_t k_rtp_fixed_header_size = 12;
constexpr std::size_t k_rtp_csrc_size = 4;
constexpr std::size_t k_rtp_extension_header_size = 4;
constexpr std::size_t k_rtx_original_sequence_size = 2;
constexpr std::size_t k_sequence_cache_limit = 4096;

constexpr uint16_t k_one_byte_extension_profile = 0xBEDE;
constexpr uint16_t k_two_byte_extension_profile_mask = 0xFFF0;
constexpr uint16_t k_two_byte_extension_profile_value = 0x1000;
constexpr uint8_t k_one_byte_extension_reserved_id = 15;

constexpr std::string_view k_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";
constexpr std::string_view k_transport_wide_cc_extension_uri =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
constexpr std::string_view k_transport_wide_cc_extension_uri_02 =
    "http://www.webrtc.org/experiments/rtp-hdrext/transport-wide-cc-02";
constexpr std::string_view k_absolute_send_time_extension_uri =
    "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
constexpr std::string_view k_rid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
constexpr std::string_view k_repaired_rid_extension_uri =
    "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_media_error(std::string_view target_mid, std::string_view message)
{
    std::string error;
    error.reserve(target_mid.size() + message.size() + 24);
    error.append("whep rtp media mid ");
    error.append(target_mid);
    error.push_back(' ');
    error.append(message);
    return std::unexpected(std::move(error));
}

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

void write_u16(std::vector<uint8_t>& data, std::size_t offset, uint16_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 8U);
    data[offset + 1] = static_cast<uint8_t>(value & 0xFFU);
}

void write_u32(std::vector<uint8_t>& data, std::size_t offset, uint32_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 24U);
    data[offset + 1] = static_cast<uint8_t>((value >> 16U) & 0xFFU);
    data[offset + 2] = static_cast<uint8_t>((value >> 8U) & 0xFFU);
    data[offset + 3] = static_cast<uint8_t>(value & 0xFFU);
}

bool is_one_byte_extension_profile(uint16_t profile) { return profile == k_one_byte_extension_profile; }

bool is_two_byte_extension_profile(uint16_t profile)
{
    return (profile & k_two_byte_extension_profile_mask) == k_two_byte_extension_profile_value;
}

bool is_transport_wide_cc_uri(std::string_view uri)
{
    return uri == k_transport_wide_cc_extension_uri || uri == k_transport_wide_cc_extension_uri_02;
}

bool header_extension_requires_regeneration(std::string_view uri)
{
    return is_transport_wide_cc_uri(uri) || uri == k_absolute_send_time_extension_uri ||
           uri == k_rid_extension_uri || uri == k_repaired_rid_extension_uri;
}

bool header_extension_uris_are_compatible(std::string_view left, std::string_view right)
{
    if (is_transport_wide_cc_uri(left) && is_transport_wide_cc_uri(right))
    {
        return true;
    }

    return left == right;
}

const sdp::rtp_header_extension* find_compatible_header_extension(const sdp::media_summary& media, std::string_view target_uri)
{
    for (const auto& extension : media.header_extensions)
    {
        if (extension.id <= 0 || extension.id > 255)
        {
            continue;
        }

        if (!header_extension_uris_are_compatible(extension.uri, target_uri))
        {
            continue;
        }

        return &extension;
    }

    return nullptr;
}

struct parsed_header_extension
{
    uint8_t id = 0;
    std::vector<uint8_t> value;
};

struct parsed_rtp_packet
{
    rtp_packet_header header;

    bool padding = false;
    std::size_t base_header_size = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_data_size = 0;

    std::vector<parsed_header_extension> header_extensions;
};

std::expected<std::vector<parsed_header_extension>, std::string> parse_one_byte_header_extensions(
    std::span<const uint8_t> packet, std::size_t offset, std::size_t size)
{
    std::vector<parsed_header_extension> extensions;
    const std::size_t end = offset + size;

    while (offset < end)
    {
        const uint8_t header = packet[offset];
        offset += 1;

        if (header == 0)
        {
            continue;
        }

        const uint8_t id = static_cast<uint8_t>(header >> 4U);

        if (id == k_one_byte_extension_reserved_id)
        {
            return make_error("rtp one-byte extension id 15 is reserved");
        }

        const std::size_t value_size = static_cast<std::size_t>(header & 0x0FU) + 1U;

        if (offset + value_size > end)
        {
            return make_error("rtp one-byte extension element is truncated");
        }

        parsed_header_extension extension;
        extension.id = id;
        extension.value.assign(packet.begin() + static_cast<std::ptrdiff_t>(offset),
                               packet.begin() + static_cast<std::ptrdiff_t>(offset + value_size));
        extensions.push_back(std::move(extension));

        offset += value_size;
    }

    return extensions;
}

std::expected<std::vector<parsed_header_extension>, std::string> parse_two_byte_header_extensions(
    std::span<const uint8_t> packet, std::size_t offset, std::size_t size)
{
    std::vector<parsed_header_extension> extensions;
    const std::size_t end = offset + size;

    while (offset < end)
    {
        const uint8_t id = packet[offset];
        offset += 1;

        if (id == 0)
        {
            continue;
        }

        if (offset >= end)
        {
            return make_error("rtp two-byte extension length is truncated");
        }

        const std::size_t value_size = static_cast<std::size_t>(packet[offset]);
        offset += 1;

        if (offset + value_size > end)
        {
            return make_error("rtp two-byte extension element is truncated");
        }

        parsed_header_extension extension;
        extension.id = id;
        extension.value.assign(packet.begin() + static_cast<std::ptrdiff_t>(offset),
                               packet.begin() + static_cast<std::ptrdiff_t>(offset + value_size));
        extensions.push_back(std::move(extension));

        offset += value_size;
    }

    return extensions;
}

std::expected<parsed_rtp_packet, std::string> parse_rewriteable_rtp_packet(std::span<const uint8_t> packet)
{
    auto header = parse_rtp_packet_header(packet);

    if (!header)
    {
        return std::unexpected(header.error());
    }

    const bool padding = (packet[0] & 0x20U) != 0;
    const bool extension = (packet[0] & 0x10U) != 0;
    const uint8_t csrc_count = static_cast<uint8_t>(packet[0] & 0x0FU);

    const std::size_t base_header_size =
        k_rtp_fixed_header_size + static_cast<std::size_t>(csrc_count) * k_rtp_csrc_size;

    std::size_t payload_offset = base_header_size;
    std::vector<parsed_header_extension> header_extensions;

    if (extension)
    {
        if (payload_offset + k_rtp_extension_header_size > packet.size())
        {
            return make_error("rtp extension header is truncated");
        }

        const uint16_t profile = read_u16(packet, payload_offset);
        const uint16_t length_words = read_u16(packet, payload_offset + 2U);
        const std::size_t extension_payload_offset = payload_offset + k_rtp_extension_header_size;
        const std::size_t extension_payload_size = static_cast<std::size_t>(length_words) * 4U;

        if (extension_payload_offset + extension_payload_size > packet.size())
        {
            return make_error("rtp extension payload is truncated");
        }

        std::expected<std::vector<parsed_header_extension>, std::string> parsed_extensions;

        if (is_one_byte_extension_profile(profile))
        {
            parsed_extensions = parse_one_byte_header_extensions(packet, extension_payload_offset, extension_payload_size);
        }
        else if (is_two_byte_extension_profile(profile))
        {
            parsed_extensions = parse_two_byte_header_extensions(packet, extension_payload_offset, extension_payload_size);
        }
        else
        {
            return make_error("rtp header extension profile is unsupported for rewrite");
        }

        if (!parsed_extensions)
        {
            return std::unexpected(parsed_extensions.error());
        }

        header_extensions = std::move(*parsed_extensions);
        payload_offset = extension_payload_offset + extension_payload_size;
    }

    if (payload_offset > packet.size())
    {
        return make_error("rtp payload offset exceeds packet size");
    }

    std::size_t payload_data_size = packet.size() - payload_offset;

    if (padding)
    {
        if (payload_data_size == 0)
        {
            return make_error("rtp padding is set without payload bytes");
        }

        const std::size_t padding_size = static_cast<std::size_t>(packet.back());

        if (padding_size == 0 || padding_size > payload_data_size)
        {
            return make_error("rtp padding size is invalid");
        }

        payload_data_size -= padding_size;
    }

    return parsed_rtp_packet{
        .header = *header,
        .padding = padding,
        .base_header_size = base_header_size,
        .payload_offset = payload_offset,
        .payload_data_size = payload_data_size,
        .header_extensions = std::move(header_extensions),
    };
}

const parsed_header_extension* find_parsed_header_extension(const parsed_rtp_packet& packet, uint8_t id)
{
    for (const auto& extension : packet.header_extensions)
    {
        if (extension.id == id)
        {
            return &extension;
        }
    }

    return nullptr;
}

const whep_rtp_header_extension_mapping* find_mid_extension_mapping(const whep_rtp_media_mapping& mapping)
{
    for (const auto& extension : mapping.header_extensions)
    {
        if (extension.uri == k_mid_extension_uri)
        {
            return &extension;
        }
    }

    return nullptr;
}

const whep_rtp_payload_type_mapping* find_payload_type_mapping(const whep_rtp_media_mapping& mapping, uint8_t source_payload_type)
{
    for (const auto& payload_type : mapping.payload_types)
    {
        if (payload_type.source_payload_type == source_payload_type)
        {
            return &payload_type;
        }
    }

    return nullptr;
}

const whep_rtp_header_extension_mapping* find_header_extension_mapping(const whep_rtp_media_mapping& mapping, uint8_t source_id)
{
    for (const auto& extension : mapping.header_extensions)
    {
        if (extension.source_id == source_id)
        {
            return &extension;
        }
    }

    return nullptr;
}

std::expected<std::vector<parsed_header_extension>, std::string> rewrite_header_extensions(
    const parsed_rtp_packet& packet, const whep_rtp_media_mapping& mapping)
{
    std::vector<parsed_header_extension> rewritten_extensions;
    std::array<bool, 256> used_target_ids{};

    for (const auto& source_extension : packet.header_extensions)
    {
        const auto* extension_mapping = find_header_extension_mapping(mapping, source_extension.id);

        if (extension_mapping == nullptr || extension_mapping->target_id == 0)
        {
            continue;
        }

        // 这些扩展绑定源发送时刻、源传输序列或源编码层，不能直接复制到独立的 WHEP 会话。
        if (header_extension_requires_regeneration(extension_mapping->uri))
        {
            continue;
        }

        if (used_target_ids[extension_mapping->target_id])
        {
            continue;
        }

        parsed_header_extension target_extension;
        target_extension.id = extension_mapping->target_id;

        if (extension_mapping->uri == k_mid_extension_uri)
        {
            target_extension.value.assign(mapping.target_mid.begin(), mapping.target_mid.end());
        }
        else
        {
            target_extension.value = source_extension.value;
        }

        if (target_extension.value.size() > 255U)
        {
            return make_media_error(mapping.target_mid, "header extension value is too large");
        }

        used_target_ids[target_extension.id] = true;
        rewritten_extensions.push_back(std::move(target_extension));
    }

    const auto* mid_mapping = find_mid_extension_mapping(mapping);

    if (mid_mapping != nullptr && !used_target_ids[mid_mapping->target_id])
    {
        parsed_header_extension mid_extension;
        mid_extension.id = mid_mapping->target_id;
        mid_extension.value.assign(mapping.target_mid.begin(), mapping.target_mid.end());

        used_target_ids[mid_extension.id] = true;
        rewritten_extensions.push_back(std::move(mid_extension));
    }

    std::sort(rewritten_extensions.begin(),
              rewritten_extensions.end(),
              [](const parsed_header_extension& left, const parsed_header_extension& right) { return left.id < right.id; });

    return rewritten_extensions;
}

bool extensions_fit_one_byte_format(std::span<const parsed_header_extension> extensions)
{
    for (const auto& extension : extensions)
    {
        if (extension.id == 0 || extension.id >= k_one_byte_extension_reserved_id)
        {
            return false;
        }

        if (extension.value.empty() || extension.value.size() > 16U)
        {
            return false;
        }
    }

    return true;
}

std::expected<std::vector<uint8_t>, std::string> build_header_extension_block(
    std::span<const parsed_header_extension> extensions, bool target_extmap_allow_mixed)
{
    if (extensions.empty())
    {
        return std::vector<uint8_t>{};
    }

    const bool use_one_byte_format = extensions_fit_one_byte_format(extensions);

    if (!use_one_byte_format && !target_extmap_allow_mixed)
    {
        return make_error("whep rtp target header extensions require two-byte format without extmap-allow-mixed");
    }

    std::vector<uint8_t> payload;

    if (use_one_byte_format)
    {
        for (const auto& extension : extensions)
        {
            payload.push_back(static_cast<uint8_t>((extension.id << 4U) | static_cast<uint8_t>(extension.value.size() - 1U)));
            payload.insert(payload.end(), extension.value.begin(), extension.value.end());
        }
    }
    else
    {
        for (const auto& extension : extensions)
        {
            payload.push_back(extension.id);
            payload.push_back(static_cast<uint8_t>(extension.value.size()));
            payload.insert(payload.end(), extension.value.begin(), extension.value.end());
        }
    }

    while ((payload.size() % 4U) != 0U)
    {
        payload.push_back(0);
    }

    const std::size_t length_words = payload.size() / 4U;

    if (length_words > static_cast<std::size_t>(std::numeric_limits<uint16_t>::max()))
    {
        return make_error("whep rtp header extension block is too large");
    }

    std::vector<uint8_t> block(k_rtp_extension_header_size);
    write_u16(block, 0, use_one_byte_format ? k_one_byte_extension_profile : k_two_byte_extension_profile_value);
    write_u16(block, 2, static_cast<uint16_t>(length_words));
    block.insert(block.end(), payload.begin(), payload.end());

    return block;
}

uint16_t make_initial_sequence_number(uint32_t target_ssrc)
{
    return static_cast<uint16_t>((target_ssrc ^ (target_ssrc >> 16U)) & 0xFFFFU);
}

uint32_t make_initial_timestamp_offset(uint32_t target_ssrc) { return target_ssrc * 0x9E3779B1U; }

bool timestamp_is_newer(uint32_t value, uint32_t reference)
{
    return static_cast<int32_t>(value - reference) > 0;
}

struct sequence_number_cache
{
    void remember(uint16_t source_sequence_number, uint16_t target_sequence_number)
    {
        order.emplace_back(source_sequence_number, target_sequence_number);
        values.insert_or_assign(source_sequence_number, target_sequence_number);

        while (order.size() > k_sequence_cache_limit)
        {
            const auto oldest = order.front();
            order.pop_front();

            const auto iterator = values.find(oldest.first);

            if (iterator != values.end() && iterator->second == oldest.second)
            {
                values.erase(iterator);
            }
        }
    }

    std::optional<uint16_t> find(uint16_t source_sequence_number) const
    {
        const auto iterator = values.find(source_sequence_number);

        if (iterator == values.end())
        {
            return std::nullopt;
        }

        return iterator->second;
    }

    void clear()
    {
        values.clear();
        order.clear();
    }

    std::unordered_map<uint16_t, uint16_t> values;
    std::deque<std::pair<uint16_t, uint16_t>> order;
};

struct media_runtime_state
{
    whep_rtp_media_mapping mapping;

    std::optional<uint32_t> source_primary_ssrc;
    std::optional<uint32_t> source_rtx_ssrc;
    std::optional<uint8_t> source_primary_payload_type;
    uint32_t source_clock_rate = 0;

    bool primary_sequence_initialized = false;
    bool rtx_sequence_initialized = false;
    uint16_t next_primary_sequence_number = 0;
    uint16_t next_rtx_sequence_number = 0;

    bool timestamp_initialized = false;
    uint32_t last_target_timestamp = 0;
    std::optional<uint32_t> source_timestamp_anchor;
    uint32_t target_timestamp_anchor = 0;

    sequence_number_cache primary_sequence_numbers;

    void clear_source_state()
    {
        source_primary_ssrc.reset();
        source_rtx_ssrc.reset();
        source_primary_payload_type.reset();
        source_clock_rate = 0;
        source_timestamp_anchor.reset();
        target_timestamp_anchor = 0;
        primary_sequence_numbers.clear();
    }

    void begin_primary_source(uint32_t source_ssrc,
                              uint8_t source_payload_type,
                              uint32_t source_timestamp,
                              uint32_t clock_rate)
    {
        source_primary_ssrc = source_ssrc;
        source_rtx_ssrc.reset();
        source_primary_payload_type = source_payload_type;
        source_clock_rate = clock_rate;
        primary_sequence_numbers.clear();
        source_timestamp_anchor = source_timestamp;

        if (timestamp_initialized)
        {
            const uint32_t timestamp_step = std::max<uint32_t>(1U, clock_rate / 100U);
            target_timestamp_anchor = last_target_timestamp + timestamp_step;
        }
        else
        {
            target_timestamp_anchor = source_timestamp + make_initial_timestamp_offset(mapping.target_ssrc);
            timestamp_initialized = true;
        }

        last_target_timestamp = target_timestamp_anchor;
    }

    uint16_t allocate_sequence_number(bool rtx)
    {
        if (rtx)
        {
            if (!rtx_sequence_initialized)
            {
                next_rtx_sequence_number = make_initial_sequence_number(mapping.target_rtx_ssrc);
                rtx_sequence_initialized = true;
            }

            const uint16_t value = next_rtx_sequence_number;
            next_rtx_sequence_number = static_cast<uint16_t>(next_rtx_sequence_number + 1U);
            return value;
        }

        if (!primary_sequence_initialized)
        {
            next_primary_sequence_number = make_initial_sequence_number(mapping.target_ssrc);
            primary_sequence_initialized = true;
        }

        const uint16_t value = next_primary_sequence_number;
        next_primary_sequence_number = static_cast<uint16_t>(next_primary_sequence_number + 1U);
        return value;
    }

    uint32_t translate_timestamp(uint32_t source_timestamp)
    {
        if (!source_timestamp_anchor.has_value())
        {
            begin_primary_source(source_primary_ssrc.value_or(0),
                                 source_primary_payload_type.value_or(0),
                                 source_timestamp,
                                 std::max<uint32_t>(1U, source_clock_rate));
        }

        const uint32_t target_timestamp =
            target_timestamp_anchor + (source_timestamp - *source_timestamp_anchor);

        if (timestamp_is_newer(target_timestamp, last_target_timestamp))
        {
            last_target_timestamp = target_timestamp;
        }

        return target_timestamp;
    }
};

struct source_ssrc_binding
{
    std::size_t media_index = 0;
    bool rtx = false;
};

struct resolved_media
{
    std::size_t media_index = 0;
    const whep_rtp_payload_type_mapping* payload_type = nullptr;
};

std::optional<resolved_media> resolve_media_by_mid(std::span<media_runtime_state> media,
                                                   const parsed_rtp_packet& packet)
{
    std::optional<resolved_media> resolved;

    for (std::size_t index = 0; index < media.size(); ++index)
    {
        auto& current = media[index];
        const auto* payload_type = find_payload_type_mapping(current.mapping, packet.header.payload_type);

        if (payload_type == nullptr)
        {
            continue;
        }

        const auto* mid_mapping = find_mid_extension_mapping(current.mapping);

        if (mid_mapping == nullptr)
        {
            continue;
        }

        const auto* mid_extension = find_parsed_header_extension(packet, mid_mapping->source_id);

        if (mid_extension == nullptr)
        {
            continue;
        }

        const std::string_view source_mid(reinterpret_cast<const char*>(mid_extension->value.data()), mid_extension->value.size());

        if (source_mid != current.mapping.source_mid)
        {
            continue;
        }

        if (resolved.has_value())
        {
            return std::nullopt;
        }

        resolved = resolved_media{.media_index = index, .payload_type = payload_type};
    }

    return resolved;
}

std::optional<resolved_media> resolve_media_by_payload_type(std::span<media_runtime_state> media,
                                                            uint8_t source_payload_type)
{
    std::optional<resolved_media> resolved;

    for (std::size_t index = 0; index < media.size(); ++index)
    {
        const auto* payload_type = find_payload_type_mapping(media[index].mapping, source_payload_type);

        if (payload_type == nullptr)
        {
            continue;
        }

        if (resolved.has_value())
        {
            return std::nullopt;
        }

        resolved = resolved_media{.media_index = index, .payload_type = payload_type};
    }

    return resolved;
}

whep_rtp_rewrite_result make_drop_result(const parsed_rtp_packet& packet, std::string reason)
{
    whep_rtp_rewrite_result result;
    result.state = whep_rtp_rewrite_state::dropped;
    result.reason = std::move(reason);
    result.source_ssrc = packet.header.ssrc;
    result.source_payload_type = packet.header.payload_type;
    result.source_sequence_number = packet.header.sequence_number;
    result.source_timestamp = packet.header.timestamp;
    return result;
}

}    // namespace

whep_rtp_rewriter_config_result make_whep_rtp_rewriter_config(
    std::string_view publisher_session_id,
    const sdp::webrtc_offer_summary& publisher_offer,
    const whep_rtp_rewriter_target& target)
{
    if (publisher_session_id.empty())
    {
        return make_error("whep rtp publisher session id is empty");
    }

    const auto& subscriber_offer = target.subscriber_offer;
    const auto& accepted_mline_indexes = target.accepted_mline_indexes;
    const auto& accepted_media_sources = target.accepted_media_sources;

    if (accepted_mline_indexes.size() != accepted_media_sources.size())
    {
        return make_error("whep rtp accepted media indexes and sources size mismatch");
    }

    whep_rtp_rewriter_config config;
    config.source_session_id = std::string(publisher_session_id);
    config.media.reserve(accepted_mline_indexes.size());

    for (std::size_t accepted_index = 0; accepted_index < accepted_mline_indexes.size(); ++accepted_index)
    {
        const int mline_index = accepted_mline_indexes[accepted_index];

        if (mline_index < 0 || static_cast<std::size_t>(mline_index) >= subscriber_offer.media.size())
        {
            return make_error("whep rtp accepted media mline index is invalid");
        }

        const auto& subscriber_media = subscriber_offer.media[static_cast<std::size_t>(mline_index)];
        const auto& media_source = accepted_media_sources[accepted_index];

        if (media_source.ssrc == 0)
        {
            return make_media_error(subscriber_media.mid, "target ssrc is zero");
        }

        if (media_source.mid != subscriber_media.mid || media_source.kind != subscriber_media.kind)
        {
            return make_media_error(subscriber_media.mid, "answer media source does not match subscriber media");
        }

        const auto* publisher_media =
            sdp::find_whep_forwarded_publisher_media(subscriber_media, subscriber_offer, publisher_offer);

        if (publisher_media == nullptr)
        {
            return make_media_error(subscriber_media.mid, "publisher media mapping is missing");
        }

        auto codec_mappings = sdp::negotiate_codec_payload_type_mappings(subscriber_media, *publisher_media);

        if (!codec_mappings)
        {
            return make_media_error(subscriber_media.mid, codec_mappings.error());
        }

        whep_rtp_media_mapping media_mapping;
        media_mapping.kind = subscriber_media.kind;
        media_mapping.source_mid = publisher_media->mid;
        media_mapping.target_mid = subscriber_media.mid;
        media_mapping.target_ssrc = media_source.ssrc;
        media_mapping.target_rtx_ssrc = media_source.rtx_repair_ssrc;
        media_mapping.target_extmap_allow_mixed = subscriber_media.extmap_allow_mixed;
        media_mapping.payload_types.reserve(codec_mappings->size());

        bool has_primary_payload_type = false;
        bool has_rtx_payload_type = false;

        for (const auto& codec_mapping : *codec_mappings)
        {
            if (codec_mapping.publisher_payload_type > 127U || codec_mapping.subscriber_payload_type > 127U)
            {
                return make_media_error(subscriber_media.mid, "payload type exceeds RTP range");
            }

            whep_rtp_payload_type_mapping payload_mapping;
            payload_mapping.source_payload_type = static_cast<uint8_t>(codec_mapping.publisher_payload_type);
            payload_mapping.target_payload_type = static_cast<uint8_t>(codec_mapping.subscriber_payload_type);
            payload_mapping.rtx = codec_mapping.publisher_associated_payload_type.has_value();

            uint16_t clock_rate_payload_type = codec_mapping.subscriber_payload_type;

            if (payload_mapping.rtx)
            {
                if (!codec_mapping.subscriber_associated_payload_type.has_value())
                {
                    return make_media_error(subscriber_media.mid, "rtx associated payload type mapping is incomplete");
                }

                if (*codec_mapping.publisher_associated_payload_type > 127U || *codec_mapping.subscriber_associated_payload_type > 127U)
                {
                    return make_media_error(subscriber_media.mid, "rtx associated payload type exceeds RTP range");
                }

                payload_mapping.source_associated_payload_type =
                    static_cast<uint8_t>(*codec_mapping.publisher_associated_payload_type);
                payload_mapping.target_associated_payload_type =
                    static_cast<uint8_t>(*codec_mapping.subscriber_associated_payload_type);
                clock_rate_payload_type = *codec_mapping.subscriber_associated_payload_type;
                has_rtx_payload_type = true;
            }
            else
            {
                has_primary_payload_type = true;
            }

            const auto target_codec = std::find_if(
                subscriber_media.codecs.begin(),
                subscriber_media.codecs.end(),
                [clock_rate_payload_type](const sdp::codec_info& codec)
                { return codec.payload_type == clock_rate_payload_type; });

            if (target_codec == subscriber_media.codecs.end() || target_codec->clock_rate == 0)
            {
                return make_media_error(subscriber_media.mid, "codec clock rate mapping is missing");
            }

            payload_mapping.clock_rate = target_codec->clock_rate;
            payload_mapping.codec_name = target_codec->name;
            media_mapping.payload_types.push_back(std::move(payload_mapping));
        }

        if (!has_primary_payload_type)
        {
            return make_media_error(subscriber_media.mid, "primary payload type mapping is missing");
        }

        if (has_rtx_payload_type && media_mapping.target_rtx_ssrc == 0)
        {
            return make_media_error(subscriber_media.mid, "target rtx ssrc is missing");
        }

        const auto selected_extensions = sdp::select_whep_answer_header_extensions(subscriber_media, *publisher_media);
        media_mapping.header_extensions.reserve(selected_extensions.size());

        for (const auto& target_extension : selected_extensions)
        {
            const auto* source_extension = find_compatible_header_extension(*publisher_media, target_extension.uri);

            if (source_extension == nullptr)
            {
                return make_media_error(subscriber_media.mid, "publisher header extension mapping is missing");
            }

            media_mapping.header_extensions.push_back(whep_rtp_header_extension_mapping{
                .source_id = static_cast<uint8_t>(source_extension->id),
                .target_id = static_cast<uint8_t>(target_extension.id),
                .uri = target_extension.uri,
            });
        }

        config.media.push_back(std::move(media_mapping));
    }

    if (config.media.empty())
    {
        return make_error("whep rtp rewriter has no accepted media");
    }

    return config;
}

struct whep_rtp_rewriter::impl
{
    void set_config(whep_rtp_rewriter_config config)
    {
        const bool same_source = source_available && source_session_id == config.source_session_id;
        std::vector<media_runtime_state> previous_media = std::move(media);

        media.clear();
        media.reserve(config.media.size());

        for (auto& mapping : config.media)
        {
            media_runtime_state next_state;

            const auto previous = std::find_if(
                previous_media.begin(),
                previous_media.end(),
                [&mapping](const media_runtime_state& current)
                { return current.mapping.kind == mapping.kind && current.mapping.target_ssrc == mapping.target_ssrc; });

            if (previous != previous_media.end())
            {
                const std::string previous_source_mid = previous->mapping.source_mid;
                const uint32_t previous_target_rtx_ssrc = previous->mapping.target_rtx_ssrc;

                next_state = std::move(*previous);
                next_state.mapping = std::move(mapping);

                if (previous_target_rtx_ssrc != next_state.mapping.target_rtx_ssrc)
                {
                    next_state.rtx_sequence_initialized = false;
                    next_state.next_rtx_sequence_number = 0;
                }

                if (!same_source || previous_source_mid != next_state.mapping.source_mid)
                {
                    next_state.clear_source_state();
                }
            }
            else
            {
                next_state.mapping = std::move(mapping);
            }

            media.push_back(std::move(next_state));
        }

        source_session_id = std::move(config.source_session_id);
        source_available = true;
        rebuild_bindings();
    }

    void clear_source()
    {
        source_available = false;
        source_session_id.clear();
        bindings.clear();

        for (auto& current : media)
        {
            current.clear_source_state();
        }
    }

    void rebuild_bindings()
    {
        bindings.clear();

        for (std::size_t index = 0; index < media.size(); ++index)
        {
            if (media[index].source_primary_ssrc.has_value())
            {
                bindings.insert_or_assign(*media[index].source_primary_ssrc,
                                          source_ssrc_binding{.media_index = index, .rtx = false});
            }

            if (media[index].source_rtx_ssrc.has_value())
            {
                bindings.insert_or_assign(*media[index].source_rtx_ssrc,
                                          source_ssrc_binding{.media_index = index, .rtx = true});
            }
        }
    }

    void erase_bindings_for_media(std::size_t media_index)
    {
        for (auto iterator = bindings.begin(); iterator != bindings.end();)
        {
            if (iterator->second.media_index == media_index)
            {
                iterator = bindings.erase(iterator);
                continue;
            }

            ++iterator;
        }
    }

    whep_rtp_rewrite_packet_result rewrite(std::span<const uint8_t> packet)
    {
        auto parsed = parse_rewriteable_rtp_packet(packet);

        if (!parsed)
        {
            return std::unexpected(parsed.error());
        }

        if (!source_available || media.empty())
        {
            return make_drop_result(*parsed, "publisher source is unavailable");
        }

        std::optional<resolved_media> resolved;

        const auto binding = bindings.find(parsed->header.ssrc);

        if (binding != bindings.end() && binding->second.media_index < media.size())
        {
            auto& bound_media = media[binding->second.media_index];
            const auto* payload_type = find_payload_type_mapping(bound_media.mapping, parsed->header.payload_type);

            if (payload_type != nullptr && payload_type->rtx == binding->second.rtx)
            {
                resolved = resolved_media{.media_index = binding->second.media_index, .payload_type = payload_type};
            }
        }

        if (!resolved.has_value())
        {
            resolved = resolve_media_by_mid(media, *parsed);
        }

        if (!resolved.has_value())
        {
            resolved = resolve_media_by_payload_type(media, parsed->header.payload_type);
        }

        if (!resolved.has_value() || resolved->payload_type == nullptr)
        {
            return make_drop_result(*parsed, "source media mapping is ambiguous or missing");
        }

        auto& current = media[resolved->media_index];
        const bool is_rtx = resolved->payload_type->rtx;
        bool keyframe_request_needed = false;

        if (is_rtx)
        {
            if (!current.source_primary_ssrc.has_value())
            {
                return make_drop_result(*parsed, "source rtx arrived before primary media");
            }

            if (!current.source_rtx_ssrc.has_value() || *current.source_rtx_ssrc != parsed->header.ssrc)
            {
                if (current.source_rtx_ssrc.has_value())
                {
                    bindings.erase(*current.source_rtx_ssrc);
                }

                current.source_rtx_ssrc = parsed->header.ssrc;
                bindings.insert_or_assign(parsed->header.ssrc,
                                          source_ssrc_binding{.media_index = resolved->media_index, .rtx = true});
            }
        }
        else
        {
            const bool source_changed = !current.source_primary_ssrc.has_value() ||
                                        *current.source_primary_ssrc != parsed->header.ssrc ||
                                        !current.source_primary_payload_type.has_value() ||
                                        *current.source_primary_payload_type != parsed->header.payload_type ||
                                        current.source_clock_rate != resolved->payload_type->clock_rate;

            if (source_changed)
            {
                // 发布端重新推流或更换编码源时，只重置源侧锚点，WHEP 输出序列和时间轴继续向前。
                erase_bindings_for_media(resolved->media_index);
                current.begin_primary_source(parsed->header.ssrc,
                                             parsed->header.payload_type,
                                             parsed->header.timestamp,
                                             resolved->payload_type->clock_rate);
                bindings.insert_or_assign(parsed->header.ssrc,
                                          source_ssrc_binding{.media_index = resolved->media_index, .rtx = false});
                keyframe_request_needed = current.mapping.kind == "video";
            }
            else if (!current.source_timestamp_anchor.has_value())
            {
                current.begin_primary_source(parsed->header.ssrc,
                                             parsed->header.payload_type,
                                             parsed->header.timestamp,
                                             resolved->payload_type->clock_rate);
            }
        }

        const uint32_t target_ssrc = is_rtx ? current.mapping.target_rtx_ssrc : current.mapping.target_ssrc;

        if (target_ssrc == 0)
        {
            return make_drop_result(*parsed, "target ssrc is missing");
        }

        std::optional<uint16_t> target_original_sequence_number;

        if (is_rtx)
        {
            if (parsed->payload_data_size < k_rtx_original_sequence_size)
            {
                return make_drop_result(*parsed, "source rtx payload is shorter than original sequence number");
            }

            const uint16_t source_original_sequence_number = read_u16(packet, parsed->payload_offset);
            target_original_sequence_number = current.primary_sequence_numbers.find(source_original_sequence_number);

            if (!target_original_sequence_number.has_value())
            {
                return make_drop_result(*parsed, "source rtx original sequence number is not cached");
            }
        }

        const uint16_t target_sequence_number = current.allocate_sequence_number(is_rtx);
        const uint32_t target_timestamp = current.translate_timestamp(parsed->header.timestamp);

        auto rewritten_extensions = rewrite_header_extensions(*parsed, current.mapping);

        if (!rewritten_extensions)
        {
            return std::unexpected(rewritten_extensions.error());
        }

        auto extension_block = build_header_extension_block(*rewritten_extensions, current.mapping.target_extmap_allow_mixed);

        if (!extension_block)
        {
            return std::unexpected(extension_block.error());
        }

        std::vector<uint8_t> rewritten_packet;
        rewritten_packet.reserve(parsed->base_header_size + extension_block->size() + packet.size() - parsed->payload_offset);
        rewritten_packet.insert(rewritten_packet.end(),
                                packet.begin(),
                                packet.begin() + static_cast<std::ptrdiff_t>(parsed->base_header_size));

        if (extension_block->empty())
        {
            rewritten_packet[0] = static_cast<uint8_t>(rewritten_packet[0] & static_cast<uint8_t>(~0x10U));
        }
        else
        {
            rewritten_packet[0] = static_cast<uint8_t>(rewritten_packet[0] | 0x10U);
            rewritten_packet.insert(rewritten_packet.end(), extension_block->begin(), extension_block->end());
        }

        rewritten_packet.insert(rewritten_packet.end(),
                                packet.begin() + static_cast<std::ptrdiff_t>(parsed->payload_offset),
                                packet.end());

        rewritten_packet[1] = static_cast<uint8_t>((rewritten_packet[1] & 0x80U) | resolved->payload_type->target_payload_type);
        write_u16(rewritten_packet, 2, target_sequence_number);
        write_u32(rewritten_packet, 4, target_timestamp);
        write_u32(rewritten_packet, 8, target_ssrc);

        if (target_original_sequence_number.has_value())
        {
            const std::size_t target_payload_offset = parsed->base_header_size + extension_block->size();
            write_u16(rewritten_packet, target_payload_offset, *target_original_sequence_number);
        }
        else
        {
            current.primary_sequence_numbers.remember(parsed->header.sequence_number, target_sequence_number);
        }

        whep_rtp_rewrite_result result;
        result.state = whep_rtp_rewrite_state::rewritten;
        result.packet = std::move(rewritten_packet);
        result.kind = current.mapping.kind;
        result.codec_name = resolved->payload_type->codec_name;
        result.rtx = is_rtx;
        result.keyframe_request_needed = keyframe_request_needed;
        result.source_ssrc = parsed->header.ssrc;
        result.target_ssrc = target_ssrc;
        result.source_payload_type = parsed->header.payload_type;
        result.target_payload_type = resolved->payload_type->target_payload_type;
        result.source_sequence_number = parsed->header.sequence_number;
        result.target_sequence_number = target_sequence_number;
        result.source_timestamp = parsed->header.timestamp;
        result.target_timestamp = target_timestamp;

        return result;
    }

    [[nodiscard]] std::optional<uint32_t> source_ssrc_for_target_ssrc(uint32_t target_ssrc) const
    {
        if (target_ssrc == 0)
        {
            return std::nullopt;
        }

        for (const auto& current : media)
        {
            if (current.mapping.target_ssrc == target_ssrc && current.source_primary_ssrc.has_value())
            {
                return current.source_primary_ssrc;
            }

            if (current.mapping.target_rtx_ssrc == target_ssrc && current.source_primary_ssrc.has_value())
            {
                return current.source_primary_ssrc;
            }
        }

        return std::nullopt;
    }

    bool source_available = false;
    std::string source_session_id;
    std::vector<media_runtime_state> media;
    std::unordered_map<uint32_t, source_ssrc_binding> bindings;
};

whep_rtp_rewriter::whep_rtp_rewriter() : impl_(std::make_unique<impl>()) {}

whep_rtp_rewriter::~whep_rtp_rewriter() = default;

void whep_rtp_rewriter::set_config(whep_rtp_rewriter_config config) { impl_->set_config(std::move(config)); }

void whep_rtp_rewriter::clear_source() { impl_->clear_source(); }

whep_rtp_rewrite_packet_result whep_rtp_rewriter::rewrite(std::span<const uint8_t> packet) { return impl_->rewrite(packet); }

std::optional<uint32_t> whep_rtp_rewriter::source_ssrc_for_target_ssrc(uint32_t target_ssrc) const
{
    return impl_->source_ssrc_for_target_ssrc(target_ssrc);
}

std::string_view whep_rtp_rewrite_state_to_string(whep_rtp_rewrite_state state)
{
    switch (state)
    {
        case whep_rtp_rewrite_state::rewritten:
            return "rewritten";

        case whep_rtp_rewrite_state::dropped:
            return "dropped";
    }

    return "dropped";
}
}    // namespace webrtc
