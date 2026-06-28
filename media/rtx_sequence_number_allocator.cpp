#include "media/rtx_sequence_number_allocator.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
uint16_t rtx_sequence_number_allocator::allocate(std::string_view stream_id,
                                                 std::string_view subscriber_session_id,
                                                 uint32_t rtx_ssrc,
                                                 uint16_t seed_sequence_number)
{
    if (stream_id.empty() || subscriber_session_id.empty() || rtx_ssrc == 0)
    {
        return seed_sequence_number;
    }

    const std::string key = make_key(stream_id, subscriber_session_id, rtx_ssrc);

    std::lock_guard lock(mutex_);

    auto [iterator, inserted] = states_by_key_.try_emplace(key);

    (void)inserted;

    rtx_sequence_state& state = iterator->second;

    if (!state.initialized)
    {
        state.stream_id = std::string(stream_id);

        state.subscriber_session_id = std::string(subscriber_session_id);

        state.rtx_ssrc = rtx_ssrc;

        state.next_sequence_number = seed_sequence_number;

        state.initialized = true;
    }

    const uint16_t sequence_number = state.next_sequence_number;

    state.next_sequence_number = static_cast<uint16_t>(static_cast<uint32_t>(state.next_sequence_number) + 1U);

    return sequence_number;
}

void rtx_sequence_number_allocator::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = states_by_key_.begin(); iterator != states_by_key_.end();)
    {
        if (iterator->second.subscriber_session_id == session_id)
        {
            iterator = states_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void rtx_sequence_number_allocator::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = states_by_key_.begin(); iterator != states_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = states_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void rtx_sequence_number_allocator::clear()
{
    std::lock_guard lock(mutex_);

    states_by_key_.clear();
}

std::size_t rtx_sequence_number_allocator::size() const
{
    std::lock_guard lock(mutex_);

    return states_by_key_.size();
}

std::string rtx_sequence_number_allocator::make_key(std::string_view stream_id, std::string_view subscriber_session_id, uint32_t rtx_ssrc)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 32);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(std::to_string(rtx_ssrc));

    return key;
}
}    // namespace webrtc
