#include "media/rtp_packet_cache.h"

#include <algorithm>
#include <iterator>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "rtp/rtp_packet.h"

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }
}    // namespace

rtp_packet_cache::rtp_packet_cache() : rtp_packet_cache(rtp_packet_cache_config{}) {}

rtp_packet_cache::rtp_packet_cache(rtp_packet_cache_config config) : config_(config) {}

rtp_packet_cache_result rtp_packet_cache::put(std::string_view stream_id, std::span<const uint8_t> plain_packet)
{
    if (stream_id.empty())
    {
        return make_error("rtp packet cache stream id is empty");
    }

    if (plain_packet.empty())
    {
        return make_error("rtp packet cache packet is empty");
    }

    if (config_.max_packets == 0)
    {
        return make_error("rtp packet cache capacity is zero");
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "rtp packet cache parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    rtp_packet_cache_entry entry;
    entry.stream_id = std::string(stream_id);
    entry.ssrc = header->ssrc;
    entry.sequence_number = header->sequence_number;
    entry.payload_type = header->payload_type;
    entry.marker = header->marker;
    entry.timestamp = header->timestamp;
    entry.plain_packet.assign(plain_packet.begin(), plain_packet.end());

    const std::string key = make_key(stream_id, entry.ssrc, entry.sequence_number);

    {
        std::lock_guard lock(mutex_);

        const bool exists = cache_by_key_.contains(key);

        cache_by_key_[key] = entry;

        if (!exists)
        {
            insertion_order_.push_back(key);
        }

        enforce_capacity_locked();
    }

    return entry;
}

std::optional<rtp_packet_cache_entry> rtp_packet_cache::find(std::string_view stream_id, uint32_t ssrc, uint16_t sequence_number) const
{
    if (stream_id.empty())
    {
        return std::nullopt;
    }

    const std::string key = make_key(stream_id, ssrc, sequence_number);

    std::lock_guard lock(mutex_);

    const auto iterator = cache_by_key_.find(key);

    if (iterator == cache_by_key_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

void rtp_packet_cache::erase_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = cache_by_key_.begin(); iterator != cache_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = cache_by_key_.erase(iterator);
            continue;
        }

        ++iterator;
    }

    std::deque<std::string> filtered_order;

    for (const auto& key : insertion_order_)
    {
        if (cache_by_key_.contains(key))
        {
            filtered_order.push_back(key);
        }
    }

    insertion_order_ = std::move(filtered_order);
}

void rtp_packet_cache::clear()
{
    std::lock_guard lock(mutex_);

    cache_by_key_.clear();
    insertion_order_.clear();
}

std::size_t rtp_packet_cache::size() const
{
    std::lock_guard lock(mutex_);

    return cache_by_key_.size();
}

std::vector<rtp_packet_cache_stream_snapshot> rtp_packet_cache::stream_snapshot() const
{
    std::vector<rtp_packet_cache_stream_snapshot> snapshot;

    std::lock_guard lock(mutex_);

    for (const auto& [key, entry] : cache_by_key_)
    {
        (void)key;

        auto iterator = std::find_if(snapshot.begin(),
                                     snapshot.end(),
                                     [&entry](const rtp_packet_cache_stream_snapshot& current) { return current.stream_id == entry.stream_id; });

        if (iterator == snapshot.end())
        {
            rtp_packet_cache_stream_snapshot stream_entry;

            stream_entry.stream_id = entry.stream_id;
            stream_entry.min_ssrc = entry.ssrc;
            stream_entry.max_ssrc = entry.ssrc;

            snapshot.push_back(std::move(stream_entry));

            iterator = std::prev(snapshot.end());
        }

        iterator->packet_count += 1;
        iterator->byte_count += static_cast<uint64_t>(entry.plain_packet.size());

        if (entry.ssrc < iterator->min_ssrc)
        {
            iterator->min_ssrc = entry.ssrc;
        }

        if (entry.ssrc > iterator->max_ssrc)
        {
            iterator->max_ssrc = entry.ssrc;
        }
    }

    return snapshot;
}
std::string rtp_packet_cache::make_key(std::string_view stream_id, uint32_t ssrc, uint16_t sequence_number)
{
    std::string key(stream_id);
    key.push_back('#');
    key.append(std::to_string(ssrc));
    key.push_back('#');
    key.append(std::to_string(sequence_number));
    return key;
}

void rtp_packet_cache::enforce_capacity_locked()
{
    while (cache_by_key_.size() > config_.max_packets && !insertion_order_.empty())
    {
        const std::string key = insertion_order_.front();

        insertion_order_.pop_front();

        cache_by_key_.erase(key);
    }
}
}    // namespace webrtc
