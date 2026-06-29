#include "media/rtx_retransmission_index.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
rtx_retransmission_index::rtx_retransmission_index() : rtx_retransmission_index(rtx_retransmission_index_config{}) {}

rtx_retransmission_index::rtx_retransmission_index(rtx_retransmission_index_config config) : config_(config) {}

void rtx_retransmission_index::remember(std::string_view stream_id,
                                        std::string_view subscriber_session_id,
                                        uint32_t rtx_ssrc,
                                        uint16_t rtx_sequence_number,
                                        uint32_t publisher_primary_ssrc,
                                        uint32_t subscriber_primary_ssrc,
                                        uint16_t primary_sequence_number,
                                        std::string_view publisher_mid,
                                        std::string_view subscriber_mid,
                                        std::string_view kind,
                                        const std::optional<std::string>& rid,
                                        const std::optional<std::string>& repaired_rid,
                                        uint64_t now_milliseconds)
{
    if (stream_id.empty() || subscriber_session_id.empty() || publisher_mid.empty() || subscriber_mid.empty() || kind.empty() || rtx_ssrc == 0 ||
        publisher_primary_ssrc == 0 || subscriber_primary_ssrc == 0 || config_.max_entries == 0)
    {
        return;
    }

    const std::string key = make_key(stream_id, subscriber_session_id, rtx_ssrc, rtx_sequence_number);

    std::lock_guard lock(mutex_);

    const bool exists = mappings_by_key_.contains(key);

    rtx_retransmission_mapping mapping;

    if (exists)
    {
        mapping = mappings_by_key_[key];

        mapping.last_used_at_milliseconds = now_milliseconds;
    }
    else
    {
        mapping.created_at_milliseconds = now_milliseconds;

        mapping.last_used_at_milliseconds = now_milliseconds;
    }

    mapping.stream_id = std::string(stream_id);

    mapping.subscriber_session_id = std::string(subscriber_session_id);

    mapping.publisher_mid = std::string(publisher_mid);

    mapping.subscriber_mid = std::string(subscriber_mid);

    mapping.kind = std::string(kind);

    mapping.rid = rid;

    mapping.repaired_rid = repaired_rid;

    mapping.rtx_ssrc = rtx_ssrc;

    mapping.rtx_sequence_number = rtx_sequence_number;

    mapping.publisher_primary_ssrc = publisher_primary_ssrc;

    mapping.subscriber_primary_ssrc = subscriber_primary_ssrc;

    mapping.primary_sequence_number = primary_sequence_number;

    mappings_by_key_[key] = std::move(mapping);

    if (!exists)
    {
        insertion_order_.push_back(key);
    }

    enforce_capacity_locked();
}

std::optional<rtx_retransmission_mapping> rtx_retransmission_index::find(std::string_view stream_id,
                                                                         std::string_view subscriber_session_id,
                                                                         uint32_t rtx_ssrc,
                                                                         uint16_t rtx_sequence_number) const
{
    if (stream_id.empty() || subscriber_session_id.empty() || rtx_ssrc == 0)
    {
        return std::nullopt;
    }

    const std::string key = make_key(stream_id, subscriber_session_id, rtx_ssrc, rtx_sequence_number);

    std::lock_guard lock(mutex_);

    const auto iterator = mappings_by_key_.find(key);

    if (iterator == mappings_by_key_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

void rtx_retransmission_index::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = mappings_by_key_.begin(); iterator != mappings_by_key_.end();)
    {
        if (iterator->second.subscriber_session_id == session_id)
        {
            iterator = mappings_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    std::deque<std::string> filtered_order;

    for (const auto& key : insertion_order_)
    {
        if (mappings_by_key_.contains(key))
        {
            filtered_order.push_back(key);
        }
    }

    insertion_order_ = std::move(filtered_order);
}

void rtx_retransmission_index::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = mappings_by_key_.begin(); iterator != mappings_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = mappings_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    std::deque<std::string> filtered_order;

    for (const auto& key : insertion_order_)
    {
        if (mappings_by_key_.contains(key))
        {
            filtered_order.push_back(key);
        }
    }

    insertion_order_ = std::move(filtered_order);
}

void rtx_retransmission_index::clear()
{
    std::lock_guard lock(mutex_);

    mappings_by_key_.clear();
    insertion_order_.clear();
}

std::size_t rtx_retransmission_index::size() const
{
    std::lock_guard lock(mutex_);

    return mappings_by_key_.size();
}

std::string rtx_retransmission_index::make_key(std::string_view stream_id,
                                               std::string_view subscriber_session_id,
                                               uint32_t rtx_ssrc,
                                               uint16_t rtx_sequence_number)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 48);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(std::to_string(rtx_ssrc));

    key.push_back('|');

    key.append(std::to_string(rtx_sequence_number));

    return key;
}

void rtx_retransmission_index::enforce_capacity_locked()
{
    while (mappings_by_key_.size() > config_.max_entries && !insertion_order_.empty())
    {
        const std::string key = insertion_order_.front();

        insertion_order_.pop_front();

        mappings_by_key_.erase(key);
    }
}
}    // namespace webrtc
