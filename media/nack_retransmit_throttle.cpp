#include "media/nack_retransmit_throttle.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace webrtc
{
nack_retransmit_throttle::nack_retransmit_throttle() : nack_retransmit_throttle(nack_retransmit_throttle_config{}) {}

nack_retransmit_throttle::nack_retransmit_throttle(nack_retransmit_throttle_config config) : config_(config) {}

nack_retransmit_throttle_decision nack_retransmit_throttle::check(std::string_view stream_id,
                                                                  std::string_view subscriber_session_id,
                                                                  uint32_t feedback_media_ssrc,
                                                                  uint32_t cache_media_ssrc,
                                                                  uint16_t feedback_sequence_number,
                                                                  uint16_t cache_sequence_number,
                                                                  bool rtx_feedback,
                                                                  uint64_t now_milliseconds)
{
    nack_retransmit_throttle_decision decision;

    if (stream_id.empty() || subscriber_session_id.empty() || feedback_media_ssrc == 0 || cache_media_ssrc == 0 ||
        config_.min_interval_milliseconds == 0 || config_.max_entries == 0)
    {
        return decision;
    }

    const std::string key = make_key(
        stream_id, subscriber_session_id, feedback_media_ssrc, cache_media_ssrc, feedback_sequence_number, cache_sequence_number, rtx_feedback);

    std::lock_guard lock(mutex_);

    expire_old_locked(now_milliseconds);

    const auto iterator = states_by_key_.find(key);

    if (iterator == states_by_key_.end())
    {
        return decision;
    }

    const nack_retransmit_throttle_state& state = iterator->second;

    decision.last_sent_at_milliseconds = state.last_sent_at_milliseconds;

    if (now_milliseconds <= state.last_sent_at_milliseconds)
    {
        decision.allowed = false;
        decision.elapsed_milliseconds = 0;
        decision.wait_milliseconds = config_.min_interval_milliseconds;

        return decision;
    }

    decision.elapsed_milliseconds = now_milliseconds - state.last_sent_at_milliseconds;

    if (decision.elapsed_milliseconds < config_.min_interval_milliseconds)
    {
        decision.allowed = false;
        decision.wait_milliseconds = config_.min_interval_milliseconds - decision.elapsed_milliseconds;

        return decision;
    }

    return decision;
}

void nack_retransmit_throttle::remember_sent(std::string_view stream_id,
                                             std::string_view subscriber_session_id,
                                             uint32_t feedback_media_ssrc,
                                             uint32_t cache_media_ssrc,
                                             uint16_t feedback_sequence_number,
                                             uint16_t cache_sequence_number,
                                             bool rtx_feedback,
                                             uint64_t now_milliseconds)
{
    if (stream_id.empty() || subscriber_session_id.empty() || feedback_media_ssrc == 0 || cache_media_ssrc == 0 || config_.max_entries == 0)
    {
        return;
    }

    const std::string key = make_key(
        stream_id, subscriber_session_id, feedback_media_ssrc, cache_media_ssrc, feedback_sequence_number, cache_sequence_number, rtx_feedback);

    std::lock_guard lock(mutex_);

    expire_old_locked(now_milliseconds);

    auto [iterator, inserted] = states_by_key_.try_emplace(key);

    nack_retransmit_throttle_state& state = iterator->second;

    if (inserted)
    {
        state.stream_id = std::string(stream_id);

        state.subscriber_session_id = std::string(subscriber_session_id);

        state.feedback_media_ssrc = feedback_media_ssrc;

        state.cache_media_ssrc = cache_media_ssrc;

        state.feedback_sequence_number = feedback_sequence_number;

        state.cache_sequence_number = cache_sequence_number;

        state.rtx_feedback = rtx_feedback;

        insertion_order_.push_back(key);
    }

    state.last_sent_at_milliseconds = now_milliseconds;

    state.sent_count += 1;

    enforce_capacity_locked();
}

void nack_retransmit_throttle::forget_session(std::string_view session_id)
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

    filter_insertion_order_locked();
}

void nack_retransmit_throttle::forget_stream(std::string_view stream_id)
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

    filter_insertion_order_locked();
}

void nack_retransmit_throttle::clear()
{
    std::lock_guard lock(mutex_);

    states_by_key_.clear();
    insertion_order_.clear();
}

std::size_t nack_retransmit_throttle::size() const
{
    std::lock_guard lock(mutex_);

    return states_by_key_.size();
}

std::string nack_retransmit_throttle::make_key(std::string_view stream_id,
                                               std::string_view subscriber_session_id,
                                               uint32_t feedback_media_ssrc,
                                               uint32_t cache_media_ssrc,
                                               uint16_t feedback_sequence_number,
                                               uint16_t cache_sequence_number,
                                               bool rtx_feedback)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 80);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(std::to_string(feedback_media_ssrc));

    key.push_back('|');

    key.append(std::to_string(cache_media_ssrc));

    key.push_back('|');

    key.append(std::to_string(feedback_sequence_number));

    key.push_back('|');

    key.append(std::to_string(cache_sequence_number));

    key.push_back('|');

    key.append(rtx_feedback ? "1" : "0");

    return key;
}

void nack_retransmit_throttle::expire_old_locked(uint64_t now_milliseconds)
{
    if (config_.max_age_milliseconds == 0)
    {
        return;
    }

    bool erased = false;

    for (auto iterator = states_by_key_.begin(); iterator != states_by_key_.end();)
    {
        const uint64_t last_sent_at_milliseconds = iterator->second.last_sent_at_milliseconds;

        if (last_sent_at_milliseconds != 0 && now_milliseconds > last_sent_at_milliseconds &&
            now_milliseconds - last_sent_at_milliseconds > config_.max_age_milliseconds)
        {
            iterator = states_by_key_.erase(iterator);

            erased = true;

            continue;
        }

        ++iterator;
    }

    if (erased)
    {
        filter_insertion_order_locked();
    }
}

void nack_retransmit_throttle::enforce_capacity_locked()
{
    while (states_by_key_.size() > config_.max_entries && !insertion_order_.empty())
    {
        const std::string key = insertion_order_.front();

        insertion_order_.pop_front();

        states_by_key_.erase(key);
    }
}

void nack_retransmit_throttle::filter_insertion_order_locked()
{
    std::deque<std::string> filtered_order;

    for (const auto& key : insertion_order_)
    {
        if (states_by_key_.contains(key))
        {
            filtered_order.push_back(key);
        }
    }

    insertion_order_ = std::move(filtered_order);
}
}    // namespace webrtc
