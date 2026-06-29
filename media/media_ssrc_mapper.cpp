#include "media/media_ssrc_mapper.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webrtc
{
namespace
{
constexpr uint64_t k_fnv_offset_basis = 1469598103934665603ULL;
constexpr uint64_t k_fnv_prime = 1099511628211ULL;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void append_key_part(std::string& key, std::string_view value)
{
    key.append(value);
    key.push_back('\n');
}

void hash_byte(uint64_t& hash, uint8_t value)
{
    hash ^= static_cast<uint64_t>(value);

    hash *= k_fnv_prime;
}

void hash_string(uint64_t& hash, std::string_view value)
{
    for (char item : value)
    {
        hash_byte(hash, static_cast<uint8_t>(item));
    }

    hash_byte(hash, 0xffU);
}

void hash_u32(uint64_t& hash, uint32_t value)
{
    hash_byte(hash, static_cast<uint8_t>((value >> 24U) & 0xffU));

    hash_byte(hash, static_cast<uint8_t>((value >> 16U) & 0xffU));

    hash_byte(hash, static_cast<uint8_t>((value >> 8U) & 0xffU));

    hash_byte(hash, static_cast<uint8_t>(value & 0xffU));
}

uint32_t fold_hash_to_ssrc(uint64_t value)
{
    const uint32_t high = static_cast<uint32_t>(value >> 32U);

    const uint32_t low = static_cast<uint32_t>(value & 0xffffffffULL);

    uint32_t result = high ^ low;

    if (result == 0)
    {
        result = 1;
    }

    return result;
}

uint32_t advance_ssrc_candidate(uint32_t value, uint32_t attempt)
{
    uint32_t result = value * 1664525U + 1013904223U + attempt;

    if (result == 0)
    {
        result = attempt + 1U;
    }

    return result;
}

std::expected<void, std::string> validate_mapping_input(std::string_view stream_id,
                                                        std::string_view publisher_session_id,
                                                        std::string_view subscriber_session_id,
                                                        std::string_view publisher_mid,
                                                        std::string_view subscriber_mid,
                                                        uint32_t publisher_ssrc)
{
    if (stream_id.empty())
    {
        return make_error("media ssrc mapping stream id is empty");
    }

    if (publisher_session_id.empty())
    {
        return make_error("media ssrc mapping publisher session id is empty");
    }

    if (subscriber_session_id.empty())
    {
        return make_error("media ssrc mapping subscriber session id is empty");
    }

    if (publisher_mid.empty())
    {
        return make_error("media ssrc mapping publisher mid is empty");
    }

    if (subscriber_mid.empty())
    {
        return make_error("media ssrc mapping subscriber mid is empty");
    }

    if (publisher_ssrc == 0)
    {
        return make_error("media ssrc mapping publisher ssrc is zero");
    }

    return {};
}
}    // namespace

media_ssrc_mapping_result media_ssrc_mapper::get_or_create_mapping(std::string_view stream_id,
                                                                   std::string_view publisher_session_id,
                                                                   std::string_view subscriber_session_id,
                                                                   std::string_view publisher_mid,
                                                                   std::string_view subscriber_mid,
                                                                   std::string_view kind,
                                                                   uint32_t publisher_ssrc,
                                                                   uint64_t now_milliseconds,
                                                                   bool rtx,
                                                                   uint32_t publisher_rtx_primary_ssrc,
                                                                   uint32_t publisher_rtx_repair_ssrc,
                                                                   const std::optional<std::string>& rid,
                                                                   const std::optional<std::string>& repaired_rid)
{
    auto validation_result =
        validate_mapping_input(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, subscriber_mid, publisher_ssrc);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    const std::string publisher_key = make_publisher_key(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, publisher_ssrc);

    std::lock_guard lock(mutex_);

    auto iterator = mappings_by_publisher_key_.find(publisher_key);

    if (iterator != mappings_by_publisher_key_.end())
    {
        iterator->second.last_used_at_milliseconds = now_milliseconds;

        iterator->second.rid = rid;

        iterator->second.repaired_rid = repaired_rid;

        iterator->second.rtx = rtx;

        iterator->second.publisher_rtx_primary_ssrc = publisher_rtx_primary_ssrc;

        iterator->second.publisher_rtx_repair_ssrc = publisher_rtx_repair_ssrc;

        iterator->second.packet_count += 1;

        return iterator->second;
    }

    media_ssrc_mapping mapping;

    mapping.stream_id = std::string(stream_id);

    mapping.publisher_session_id = std::string(publisher_session_id);

    mapping.subscriber_session_id = std::string(subscriber_session_id);

    mapping.publisher_mid = std::string(publisher_mid);

    mapping.subscriber_mid = std::string(subscriber_mid);

    mapping.kind = std::string(kind);

    mapping.rid = rid;

    mapping.repaired_rid = repaired_rid;

    mapping.rtx = rtx;

    mapping.publisher_rtx_primary_ssrc = publisher_rtx_primary_ssrc;

    mapping.publisher_rtx_repair_ssrc = publisher_rtx_repair_ssrc;

    mapping.publisher_ssrc = publisher_ssrc;

    mapping.subscriber_ssrc =
        generate_subscriber_ssrc_locked(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, subscriber_mid, kind, publisher_ssrc);

    mapping.created_at_milliseconds = now_milliseconds;

    mapping.last_used_at_milliseconds = now_milliseconds;

    mapping.packet_count = 1;

    const std::string subscriber_key = make_subscriber_key(subscriber_session_id, mapping.subscriber_ssrc);

    mappings_by_publisher_key_[publisher_key] = mapping;

    publisher_key_by_subscriber_key_[subscriber_key] = publisher_key;

    return mapping;
}

std::optional<media_ssrc_mapping> media_ssrc_mapper::find_by_publisher_ssrc(std::string_view stream_id,
                                                                            std::string_view publisher_session_id,
                                                                            std::string_view subscriber_session_id,
                                                                            std::string_view publisher_mid,
                                                                            uint32_t publisher_ssrc) const
{
    if (stream_id.empty() || publisher_session_id.empty() || subscriber_session_id.empty() || publisher_mid.empty() || publisher_ssrc == 0)
    {
        return std::nullopt;
    }

    const std::string publisher_key = make_publisher_key(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, publisher_ssrc);

    std::lock_guard lock(mutex_);

    const auto iterator = mappings_by_publisher_key_.find(publisher_key);

    if (iterator == mappings_by_publisher_key_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::optional<media_ssrc_mapping> media_ssrc_mapper::find_by_subscriber_ssrc(std::string_view subscriber_session_id, uint32_t subscriber_ssrc) const
{
    if (subscriber_session_id.empty() || subscriber_ssrc == 0)
    {
        return std::nullopt;
    }

    const std::string subscriber_key = make_subscriber_key(subscriber_session_id, subscriber_ssrc);

    std::lock_guard lock(mutex_);

    const auto reverse_iterator = publisher_key_by_subscriber_key_.find(subscriber_key);

    if (reverse_iterator == publisher_key_by_subscriber_key_.end())
    {
        return std::nullopt;
    }

    const auto mapping_iterator = mappings_by_publisher_key_.find(reverse_iterator->second);

    if (mapping_iterator == mappings_by_publisher_key_.end())
    {
        return std::nullopt;
    }

    return mapping_iterator->second;
}

void media_ssrc_mapper::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::vector<std::string> publisher_keys;

    std::lock_guard lock(mutex_);

    for (const auto& [publisher_key, mapping] : mappings_by_publisher_key_)
    {
        if (mapping.publisher_session_id == session_id || mapping.subscriber_session_id == session_id)
        {
            publisher_keys.push_back(publisher_key);
        }
    }

    for (const auto& publisher_key : publisher_keys)
    {
        erase_mapping_locked(publisher_key);
    }
}

void media_ssrc_mapper::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::vector<std::string> publisher_keys;

    std::lock_guard lock(mutex_);

    for (const auto& [publisher_key, mapping] : mappings_by_publisher_key_)
    {
        if (mapping.stream_id == stream_id)
        {
            publisher_keys.push_back(publisher_key);
        }
    }

    for (const auto& publisher_key : publisher_keys)
    {
        erase_mapping_locked(publisher_key);
    }
}

void media_ssrc_mapper::clear()
{
    std::lock_guard lock(mutex_);

    mappings_by_publisher_key_.clear();
    publisher_key_by_subscriber_key_.clear();
}

std::size_t media_ssrc_mapper::mapping_count() const
{
    std::lock_guard lock(mutex_);

    return mappings_by_publisher_key_.size();
}

std::string media_ssrc_mapper::make_publisher_key(std::string_view stream_id,
                                                  std::string_view publisher_session_id,
                                                  std::string_view subscriber_session_id,
                                                  std::string_view publisher_mid,
                                                  uint32_t publisher_ssrc)
{
    std::string key;

    key.reserve(stream_id.size() + publisher_session_id.size() + subscriber_session_id.size() + publisher_mid.size() + 32);

    append_key_part(key, stream_id);

    append_key_part(key, publisher_session_id);

    append_key_part(key, subscriber_session_id);

    append_key_part(key, publisher_mid);

    key.append(std::to_string(publisher_ssrc));

    return key;
}

std::string media_ssrc_mapper::make_subscriber_key(std::string_view subscriber_session_id, uint32_t subscriber_ssrc)
{
    std::string key;

    key.reserve(subscriber_session_id.size() + 16);

    key.append(subscriber_session_id);

    key.push_back('\n');

    key.append(std::to_string(subscriber_ssrc));

    return key;
}

uint64_t media_ssrc_mapper::hash_mapping_seed(std::string_view stream_id,
                                              std::string_view publisher_session_id,
                                              std::string_view subscriber_session_id,
                                              std::string_view publisher_mid,
                                              std::string_view subscriber_mid,
                                              std::string_view kind,
                                              uint32_t publisher_ssrc)
{
    uint64_t hash = k_fnv_offset_basis;

    hash_string(hash, stream_id);

    hash_string(hash, publisher_session_id);

    hash_string(hash, subscriber_session_id);

    hash_string(hash, publisher_mid);

    hash_string(hash, subscriber_mid);

    hash_string(hash, kind);

    hash_u32(hash, publisher_ssrc);

    return hash;
}

uint32_t media_ssrc_mapper::generate_subscriber_ssrc_locked(std::string_view stream_id,
                                                            std::string_view publisher_session_id,
                                                            std::string_view subscriber_session_id,
                                                            std::string_view publisher_mid,
                                                            std::string_view subscriber_mid,
                                                            std::string_view kind,
                                                            uint32_t publisher_ssrc) const
{
    uint32_t candidate = fold_hash_to_ssrc(
        hash_mapping_seed(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, subscriber_mid, kind, publisher_ssrc));

    for (uint32_t attempt = 0; attempt < 4096; ++attempt)
    {
        if (candidate == 0 || candidate == publisher_ssrc)
        {
            candidate = advance_ssrc_candidate(candidate, attempt + 1);

            continue;
        }

        const std::string subscriber_key = make_subscriber_key(subscriber_session_id, candidate);

        if (!publisher_key_by_subscriber_key_.contains(subscriber_key))
        {
            return candidate;
        }

        candidate = advance_ssrc_candidate(candidate, attempt + 1);
    }

    for (uint32_t candidate_value = 1; candidate_value < std::numeric_limits<uint32_t>::max(); ++candidate_value)
    {
        if (candidate_value == publisher_ssrc)
        {
            continue;
        }

        const std::string subscriber_key = make_subscriber_key(subscriber_session_id, candidate_value);

        if (!publisher_key_by_subscriber_key_.contains(subscriber_key))
        {
            return candidate_value;
        }
    }

    return 1;
}

void media_ssrc_mapper::erase_mapping_locked(const std::string& publisher_key)
{
    const auto iterator = mappings_by_publisher_key_.find(publisher_key);

    if (iterator == mappings_by_publisher_key_.end())
    {
        return;
    }

    const std::string subscriber_key = make_subscriber_key(iterator->second.subscriber_session_id, iterator->second.subscriber_ssrc);

    publisher_key_by_subscriber_key_.erase(subscriber_key);

    mappings_by_publisher_key_.erase(iterator);
}

bool media_ssrc_mapping_requires_rewrite(const media_ssrc_mapping& mapping) { return mapping.publisher_ssrc != mapping.subscriber_ssrc; }

bool media_ssrc_mapping_is_rtx(const media_ssrc_mapping& mapping) { return mapping.rtx; }

bool media_ssrc_mapping_is_primary_video(const media_ssrc_mapping& mapping) { return mapping.kind == "video" && !mapping.rtx; }

std::string media_ssrc_mapping_to_string(const media_ssrc_mapping& mapping)
{
    std::string result;

    result.reserve(256);

    result.append("stream=");
    result.append(mapping.stream_id);

    result.append(" publisher_session=");
    result.append(mapping.publisher_session_id);

    result.append(" subscriber_session=");
    result.append(mapping.subscriber_session_id);

    result.append(" publisher_mid=");
    result.append(mapping.publisher_mid);

    result.append(" subscriber_mid=");
    result.append(mapping.subscriber_mid);

    result.append(" kind=");
    result.append(mapping.kind);

    if (mapping.rid.has_value())
    {
        result.append(" rid=");
        result.append(*mapping.rid);
    }

    if (mapping.repaired_rid.has_value())
    {
        result.append(" repaired_rid=");
        result.append(*mapping.repaired_rid);
    }

    result.append(" rtx=");
    result.append(mapping.rtx ? "1" : "0");

    if (mapping.rtx)
    {
        result.append(" publisher_rtx_primary_ssrc=");
        result.append(std::to_string(mapping.publisher_rtx_primary_ssrc));

        result.append(" publisher_rtx_repair_ssrc=");
        result.append(std::to_string(mapping.publisher_rtx_repair_ssrc));
    }

    result.append(" publisher_ssrc=");
    result.append(std::to_string(mapping.publisher_ssrc));

    result.append(" subscriber_ssrc=");
    result.append(std::to_string(mapping.subscriber_ssrc));

    return result;
}

std::vector<media_ssrc_mapping> media_ssrc_mapper::find_by_subscriber_session(std::string_view subscriber_session_id) const
{
    std::vector<media_ssrc_mapping> mappings;

    if (subscriber_session_id.empty())
    {
        return mappings;
    }

    std::lock_guard lock(mutex_);

    for (const auto& [key, mapping] : mappings_by_publisher_key_)
    {
        (void)key;

        if (mapping.subscriber_session_id == subscriber_session_id)
        {
            mappings.push_back(mapping);
        }
    }

    return mappings;
}

std::vector<media_ssrc_mapping> media_ssrc_mapper::find_by_stream_id(std::string_view stream_id) const
{
    std::vector<media_ssrc_mapping> mappings;

    if (stream_id.empty())
    {
        return mappings;
    }

    std::lock_guard lock(mutex_);

    for (const auto& [key, mapping] : mappings_by_publisher_key_)
    {
        (void)key;

        if (mapping.stream_id == stream_id)
        {
            mappings.push_back(mapping);
        }
    }

    return mappings;
}
}    // namespace webrtc
