#include "rtp/rtp_retransmission_cache.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace webrtc
{
rtp_retransmission_cache::rtp_retransmission_cache(rtp_retransmission_cache_config config) : config_(config)
{
    if (config_.max_age <= std::chrono::milliseconds::zero())
    {
        config_.max_age = std::chrono::milliseconds(2000);
    }

    if (config_.max_packets == 0)
    {
        config_.max_packets = 4096;
    }

    if (config_.max_bytes == 0)
    {
        config_.max_bytes = 8U * 1024U * 1024U;
    }

    if (config_.minimum_retransmit_interval < std::chrono::milliseconds::zero())
    {
        config_.minimum_retransmit_interval = std::chrono::milliseconds::zero();
    }
}

uint64_t rtp_retransmission_cache::make_key(uint32_t target_ssrc, uint16_t target_sequence_number)
{
    return (static_cast<uint64_t>(target_ssrc) << 16U) | static_cast<uint64_t>(target_sequence_number);
}

void rtp_retransmission_cache::erase_entry(uint64_t key, bool age_eviction)
{
    const auto iterator = entries_.find(key);

    if (iterator == entries_.end())
    {
        return;
    }

    byte_count_ -= iterator->second.packet.packet.size();
    entries_.erase(iterator);

    if (age_eviction)
    {
        evicted_age_ += 1;
    }
    else
    {
        evicted_capacity_ += 1;
    }
}

void rtp_retransmission_cache::prune(std::chrono::steady_clock::time_point now)
{
    while (!order_.empty())
    {
        const auto oldest = order_.front();
        const auto iterator = entries_.find(oldest.key);

        if (iterator == entries_.end() || iterator->second.serial != oldest.serial)
        {
            order_.pop_front();
            continue;
        }

        if (now - iterator->second.packet.stored_at <= config_.max_age)
        {
            break;
        }

        order_.pop_front();
        erase_entry(oldest.key, true);
    }

    while (entries_.size() > config_.max_packets || byte_count_ > config_.max_bytes)
    {
        if (order_.empty())
        {
            break;
        }

        const auto oldest = order_.front();
        order_.pop_front();
        const auto iterator = entries_.find(oldest.key);

        if (iterator == entries_.end() || iterator->second.serial != oldest.serial)
        {
            continue;
        }

        erase_entry(oldest.key, false);
    }
}

void rtp_retransmission_cache::remember(rtp_retransmission_cache_packet packet,
                                        std::chrono::steady_clock::time_point now)
{
    if (packet.packet.empty() || packet.target_ssrc == 0)
    {
        return;
    }

    prune(now);
    packet.stored_at = now;
    const uint64_t key = make_key(packet.target_ssrc, packet.target_sequence_number);
    const auto existing = entries_.find(key);

    if (existing != entries_.end())
    {
        byte_count_ -= existing->second.packet.packet.size();
        replaced_ += 1;
    }
    else
    {
        inserted_ += 1;
    }

    entry next;
    next.packet = std::move(packet);
    next.serial = next_serial_++;
    byte_count_ += next.packet.packet.size();
    entries_.insert_or_assign(key, std::move(next));
    order_.push_back(order_entry{.key = key, .serial = entries_.at(key).serial});
    prune(now);
}

rtp_retransmission_cache_lookup rtp_retransmission_cache::lookup_for_retransmission(
    uint32_t target_ssrc,
    uint16_t target_sequence_number,
    std::chrono::steady_clock::time_point now)
{
    prune(now);
    const uint64_t key = make_key(target_ssrc, target_sequence_number);
    const auto iterator = entries_.find(key);

    if (iterator == entries_.end())
    {
        return {};
    }

    auto& cached = iterator->second;

    if (cached.last_retransmitted_at.has_value() &&
        now - *cached.last_retransmitted_at < config_.minimum_retransmit_interval)
    {
        return rtp_retransmission_cache_lookup{
            .state = rtp_retransmission_cache_lookup_state::suppressed,
            .packet = std::nullopt,
        };
    }

    cached.last_retransmitted_at = now;
    return rtp_retransmission_cache_lookup{
        .state = rtp_retransmission_cache_lookup_state::hit,
        .packet = cached.packet,
    };
}

void rtp_retransmission_cache::clear()
{
    entries_.clear();
    order_.clear();
    byte_count_ = 0;
    next_serial_ = 1;
    inserted_ = 0;
    replaced_ = 0;
    evicted_age_ = 0;
    evicted_capacity_ = 0;
}

rtp_retransmission_cache_snapshot rtp_retransmission_cache::snapshot(std::chrono::steady_clock::time_point now)
{
    prune(now);
    return rtp_retransmission_cache_snapshot{
        .packet_count = entries_.size(),
        .byte_count = byte_count_,
        .inserted = inserted_,
        .replaced = replaced_,
        .evicted_age = evicted_age_,
        .evicted_capacity = evicted_capacity_,
    };
}
}    // namespace webrtc
