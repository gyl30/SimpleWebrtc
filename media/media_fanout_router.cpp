#include "media/media_fanout_router.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "log/log.h"

namespace webrtc
{
namespace
{
using namespace std::chrono_literals;
constexpr std::array k_keyframe_retry_delays{200ms, 500ms, 1000ms, 2000ms};

void hash_combine(std::size_t& seed, std::size_t value) noexcept { seed ^= value + 0x9E3779B9U + (seed << 6U) + (seed >> 2U); }
}    // namespace

media_fanout_router::media_fanout_router(boost::asio::io_context& io_context) : io_context_(io_context) {}

media_fanout_router::~media_fanout_router()
{
    for (auto& [key, state] : keyframe_requests_)
    {
        (void)key;
        cancel_keyframe_request_state(state);
    }
}

std::size_t media_fanout_router::keyframe_request_key_hash::operator()(const keyframe_request_key& key) const noexcept
{
    std::size_t seed = std::hash<std::string>{}(key.stream_id);
    hash_combine(seed, std::hash<std::string>{}(key.publisher_session_id));
    hash_combine(seed, std::hash<uint64_t>{}(key.source_generation));
    hash_combine(seed, std::hash<uint32_t>{}(key.media_ssrc));
    return seed;
}
void media_fanout_router::subscribe(std::string stream_id,
                                    std::string subscriber_session_id,
                                    media_rtp_handler rtp_handler,
                                    media_publisher_source_handler source_handler,
                                    media_publisher_sender_timing_handler sender_timing_handler,
                                    media_publisher_source_bye_handler source_bye_handler)
{
    if (stream_id.empty() || subscriber_session_id.empty() || !rtp_handler || !source_handler || !sender_timing_handler || !source_bye_handler)
    {
        return;
    }

    const std::string log_stream_id = stream_id;
    const std::string log_session_id = subscriber_session_id;
    const media_publisher_source_handler initial_source_handler = source_handler;
    const media_publisher_sender_timing_handler initial_sender_timing_handler = sender_timing_handler;
    media_publisher_source_update initial_update;
    std::vector<media_publisher_sender_timing> initial_sender_timings;

    {
        subscriptions_by_session_id_.insert_or_assign(subscriber_session_id,
                                                      subscription{
                                                          .stream_id = std::move(stream_id),
                                                          .rtp_handler = std::move(rtp_handler),
                                                          .source_handler = std::move(source_handler),
                                                          .sender_timing_handler = std::move(sender_timing_handler),
                                                          .source_bye_handler = std::move(source_bye_handler),
                                                      });

        const auto generation_iterator = publisher_source_generations_by_stream_id_.find(log_stream_id);

        if (generation_iterator != publisher_source_generations_by_stream_id_.end())
        {
            initial_update.generation = generation_iterator->second;
        }

        const auto source_iterator = publisher_sources_by_stream_id_.find(log_stream_id);

        if (source_iterator != publisher_sources_by_stream_id_.end())
        {
            initial_update.source = source_iterator->second;
        }

        const auto timing_iterator = publisher_sender_timings_by_stream_id_.find(log_stream_id);

        if (timing_iterator != publisher_sender_timings_by_stream_id_.end())
        {
            initial_sender_timings.reserve(timing_iterator->second.size());

            for (const auto& [source_ssrc, timing] : timing_iterator->second)
            {
                (void)source_ssrc;
                initial_sender_timings.push_back(timing);
            }
        }
    }

    WEBRTC_LOG_INFO("media fanout subscribe stream={} session={}", log_stream_id, log_session_id);

    initial_source_handler(std::move(initial_update));

    for (auto& timing : initial_sender_timings)
    {
        initial_sender_timing_handler(std::move(timing));
    }
}

void media_fanout_router::unsubscribe(std::string_view subscriber_session_id)
{
    if (subscriber_session_id.empty())
    {
        return;
    }

    std::string stream_id;

    {
        const auto iterator = subscriptions_by_session_id_.find(std::string(subscriber_session_id));

        if (iterator == subscriptions_by_session_id_.end())
        {
            return;
        }

        stream_id = iterator->second.stream_id;
        cancel_keyframe_requests_for_subscriber(subscriber_session_id);
        subscriptions_by_session_id_.erase(iterator);
    }

    WEBRTC_LOG_INFO("media fanout unsubscribe stream={} session={}", stream_id, subscriber_session_id);
}

uint64_t media_fanout_router::set_publisher_source(std::string stream_id,
                                                   std::string publisher_session_id,
                                                   sdp::webrtc_offer_summary publisher_offer,
                                                   media_keyframe_request_handler keyframe_request_handler)
{
    if (stream_id.empty() || publisher_session_id.empty() || !keyframe_request_handler)
    {
        return 0;
    }

    media_publisher_source_ptr source;
    std::vector<media_publisher_source_handler> handlers;

    {
        cancel_stream_keyframe_requests(stream_id);
        const uint64_t generation = allocate_source_generation();

        source = std::make_shared<media_publisher_source>(media_publisher_source{
            .stream_id = std::move(stream_id),
            .session_id = std::move(publisher_session_id),
            .generation = generation,
            .offer = std::move(publisher_offer),
            .keyframe_request_handler = std::move(keyframe_request_handler),
        });

        publisher_sources_by_stream_id_.insert_or_assign(source->stream_id, source);
        publisher_source_generations_by_stream_id_.insert_or_assign(source->stream_id, generation);
        publisher_sender_timings_by_stream_id_.erase(source->stream_id);
        handlers.reserve(subscriptions_by_session_id_.size());

        for (const auto& [subscriber_session_id, current] : subscriptions_by_session_id_)
        {
            (void)subscriber_session_id;

            if (current.stream_id == source->stream_id)
            {
                handlers.push_back(current.source_handler);
            }
        }
    }

    WEBRTC_LOG_INFO("media fanout publisher source set stream={} session={} source_generation={} subscribers={}",
                    source->stream_id,
                    source->session_id,
                    source->generation,
                    handlers.size());

    for (const auto& handler : handlers)
    {
        handler(media_publisher_source_update{.generation = source->generation, .source = source});
    }

    return source->generation;
}

void media_fanout_router::clear_publisher_source(std::string_view stream_id, std::string_view publisher_session_id)
{
    if (stream_id.empty() || publisher_session_id.empty())
    {
        return;
    }

    uint64_t generation = 0;
    std::vector<media_publisher_source_handler> handlers;

    {
        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() || source_iterator->second->session_id != publisher_session_id)
        {
            return;
        }

        cancel_stream_keyframe_requests(stream_id);
        generation = allocate_source_generation();
        publisher_sources_by_stream_id_.erase(source_iterator);
        publisher_source_generations_by_stream_id_.insert_or_assign(std::string(stream_id), generation);
        publisher_sender_timings_by_stream_id_.erase(std::string(stream_id));
        handlers.reserve(subscriptions_by_session_id_.size());

        for (const auto& [subscriber_session_id, current] : subscriptions_by_session_id_)
        {
            (void)subscriber_session_id;

            if (current.stream_id == stream_id)
            {
                handlers.push_back(current.source_handler);
            }
        }
    }

    WEBRTC_LOG_INFO("media fanout publisher source cleared stream={} session={} source_generation={} subscribers={}",
                    stream_id,
                    publisher_session_id,
                    generation,
                    handlers.size());

    for (const auto& handler : handlers)
    {
        handler(media_publisher_source_update{.generation = generation, .source = nullptr});
    }
}

bool media_fanout_router::request_keyframe(std::string_view stream_id,
                                           std::string_view subscriber_session_id,
                                           std::string_view publisher_session_id,
                                           uint64_t source_generation,
                                           uint32_t media_ssrc)
{
    if (stream_id.empty() || subscriber_session_id.empty() || publisher_session_id.empty() || source_generation == 0 || media_ssrc == 0)
    {
        return false;
    }

    media_keyframe_request_handler handler;
    std::size_t waiting_subscribers = 0;
    bool send_immediately = false;

    {
        const auto subscription_iterator = subscriptions_by_session_id_.find(std::string(subscriber_session_id));

        if (subscription_iterator == subscriptions_by_session_id_.end() || subscription_iterator->second.stream_id != stream_id)
        {
            return false;
        }

        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() || source_iterator->second->session_id != publisher_session_id ||
            source_iterator->second->generation != source_generation)
        {
            return false;
        }

        keyframe_request_key key{
            .stream_id = std::string(stream_id),
            .publisher_session_id = std::string(publisher_session_id),
            .source_generation = source_generation,
            .media_ssrc = media_ssrc,
        };
        auto [iterator, inserted] = keyframe_requests_.try_emplace(std::move(key));
        (void)inserted;
        auto& state = iterator->second;
        state.waiting_subscriber_session_ids.insert(std::string(subscriber_session_id));
        waiting_subscribers = state.waiting_subscriber_session_ids.size();

        if (!state.retry_active)
        {
            state.retry_active = true;
            state.next_retry_delay_index = 0;
            state.sent_count = 1;
            handler = source_iterator->second->keyframe_request_handler;
            send_immediately = true;
            schedule_keyframe_retry(iterator->first, state);
        }
    }

    if (send_immediately)
    {
        handler(media_ssrc);
        WEBRTC_LOG_DEBUG("media keyframe request dispatched stream={} publisher_session={} source_generation={} media_ssrc={} attempt=1 waiters={}",
                         stream_id,
                         publisher_session_id,
                         source_generation,
                         media_ssrc,
                         waiting_subscribers);
    }
    else
    {
        WEBRTC_LOG_TRACE(
            "media keyframe request coalesced stream={} publisher_session={} source_generation={} media_ssrc={} subscriber_session={} waiters={}",
            stream_id,
            publisher_session_id,
            source_generation,
            media_ssrc,
            subscriber_session_id,
            waiting_subscribers);
    }

    return true;
}

void media_fanout_router::complete_keyframe_request(std::string_view stream_id,
                                                    std::string_view subscriber_session_id,
                                                    std::string_view publisher_session_id,
                                                    uint64_t source_generation,
                                                    uint32_t media_ssrc)
{
    if (stream_id.empty() || subscriber_session_id.empty() || publisher_session_id.empty() || source_generation == 0 || media_ssrc == 0)
    {
        return;
    }

    std::size_t remaining = 0;
    bool completed = false;

    {
        const keyframe_request_key key{
            .stream_id = std::string(stream_id),
            .publisher_session_id = std::string(publisher_session_id),
            .source_generation = source_generation,
            .media_ssrc = media_ssrc,
        };
        const auto iterator = keyframe_requests_.find(key);

        if (iterator == keyframe_requests_.end())
        {
            return;
        }

        completed = iterator->second.waiting_subscriber_session_ids.erase(std::string(subscriber_session_id)) != 0U;
        remaining = iterator->second.waiting_subscriber_session_ids.size();

        if (remaining == 0)
        {
            cancel_keyframe_request_state(iterator->second);
            keyframe_requests_.erase(iterator);
        }
    }

    if (completed)
    {
        WEBRTC_LOG_DEBUG(
            "media keyframe subscriber ready stream={} publisher_session={} source_generation={} media_ssrc={} subscriber_session={} remaining={}",
            stream_id,
            publisher_session_id,
            source_generation,
            media_ssrc,
            subscriber_session_id,
            remaining);
    }
}

void media_fanout_router::cancel_keyframe_requests(std::string_view subscriber_session_id)
{
    if (subscriber_session_id.empty())
    {
        return;
    }

    cancel_keyframe_requests_for_subscriber(subscriber_session_id);
}

std::size_t media_fanout_router::publish_rtp(std::string_view stream_id, std::string_view publisher_session_id, std::span<const uint8_t> packet)
{
    if (stream_id.empty() || publisher_session_id.empty() || packet.empty())
    {
        return 0;
    }

    media_publisher_source_ptr source;
    std::vector<media_rtp_handler> handlers;

    {
        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() || source_iterator->second->session_id != publisher_session_id)
        {
            return 0;
        }

        source = source_iterator->second;
        handlers.reserve(subscriptions_by_session_id_.size());

        for (const auto& [subscriber_session_id, current] : subscriptions_by_session_id_)
        {
            (void)subscriber_session_id;

            if (current.stream_id == stream_id)
            {
                handlers.push_back(current.rtp_handler);
            }
        }
    }

    for (const auto& handler : handlers)
    {
        handler(source->generation, packet);
    }

    return handlers.size();
}

bool media_fanout_router::publish_source_bye(
    std::string_view stream_id, std::string_view publisher_session_id, uint64_t source_generation, uint32_t source_ssrc, std::string reason)
{
    if (stream_id.empty() || publisher_session_id.empty() || source_generation == 0 || source_ssrc == 0)
    {
        return false;
    }

    media_publisher_source_bye bye;
    std::vector<media_publisher_source_bye_handler> handlers;

    {
        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() || source_iterator->second->session_id != publisher_session_id ||
            source_iterator->second->generation != source_generation)
        {
            return false;
        }

        bye = media_publisher_source_bye{
            .publisher_session_id = source_iterator->second->session_id,
            .source_generation = source_iterator->second->generation,
            .source_ssrc = source_ssrc,
            .reason = std::move(reason),
        };

        const auto timing_iterator = publisher_sender_timings_by_stream_id_.find(std::string(stream_id));

        if (timing_iterator != publisher_sender_timings_by_stream_id_.end())
        {
            timing_iterator->second.erase(source_ssrc);

            if (timing_iterator->second.empty())
            {
                publisher_sender_timings_by_stream_id_.erase(timing_iterator);
            }
        }

        const keyframe_request_key key{
            .stream_id = std::string(stream_id),
            .publisher_session_id = std::string(publisher_session_id),
            .source_generation = source_generation,
            .media_ssrc = source_ssrc,
        };
        const auto request_iterator = keyframe_requests_.find(key);

        if (request_iterator != keyframe_requests_.end())
        {
            cancel_keyframe_request_state(request_iterator->second);
            keyframe_requests_.erase(request_iterator);
        }

        handlers.reserve(subscriptions_by_session_id_.size());

        for (const auto& [subscriber_session_id, current] : subscriptions_by_session_id_)
        {
            (void)subscriber_session_id;

            if (current.stream_id == stream_id)
            {
                handlers.push_back(current.source_bye_handler);
            }
        }
    }

    WEBRTC_LOG_INFO("media fanout publisher source BYE stream={} publisher_session={} source_generation={} source_ssrc={} reason={} subscribers={}",
                    stream_id,
                    publisher_session_id,
                    source_generation,
                    source_ssrc,
                    bye.reason,
                    handlers.size());

    for (const auto& handler : handlers)
    {
        handler(bye);
    }

    return true;
}

bool media_fanout_router::publish_sender_timing(std::string_view stream_id,
                                                std::string_view publisher_session_id,
                                                uint64_t source_generation,
                                                uint32_t source_ssrc,
                                                uint64_t ntp_timestamp,
                                                uint32_t source_rtp_timestamp,
                                                uint32_t sender_packet_count,
                                                uint32_t sender_octet_count)
{
    if (stream_id.empty() || publisher_session_id.empty() || source_generation == 0 || source_ssrc == 0)
    {
        return false;
    }

    media_publisher_sender_timing timing;
    std::vector<media_publisher_sender_timing_handler> handlers;

    {
        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() || source_iterator->second->session_id != publisher_session_id ||
            source_iterator->second->generation != source_generation)
        {
            return false;
        }

        timing = media_publisher_sender_timing{
            .publisher_session_id = source_iterator->second->session_id,
            .source_generation = source_iterator->second->generation,
            .source_ssrc = source_ssrc,
            .ntp_timestamp = ntp_timestamp,
            .source_rtp_timestamp = source_rtp_timestamp,
            .sender_packet_count = sender_packet_count,
            .sender_octet_count = sender_octet_count,
        };

        publisher_sender_timings_by_stream_id_[std::string(stream_id)].insert_or_assign(source_ssrc, timing);
        handlers.reserve(subscriptions_by_session_id_.size());

        for (const auto& [subscriber_session_id, current] : subscriptions_by_session_id_)
        {
            (void)subscriber_session_id;

            if (current.stream_id == stream_id)
            {
                handlers.push_back(current.sender_timing_handler);
            }
        }
    }

    for (const auto& handler : handlers)
    {
        handler(timing);
    }

    return true;
}

void media_fanout_router::schedule_keyframe_retry(const keyframe_request_key& key, keyframe_request_state& state)
{
    if (state.next_retry_delay_index >= k_keyframe_retry_delays.size())
    {
        state.retry_active = false;
        return;
    }

    if (state.retry_timer == nullptr)
    {
        state.retry_timer = std::make_shared<boost::asio::steady_timer>(io_context_);
    }

    const auto delay = k_keyframe_retry_delays[state.next_retry_delay_index++];
    const uint64_t timer_token = ++state.timer_token;
    state.retry_timer->expires_after(delay);
    const std::weak_ptr<media_fanout_router> weak_router = weak_from_this();

    state.retry_timer->async_wait(
        [weak_router, key, timer_token](const boost::system::error_code& error)
        {
            if (error == boost::asio::error::operation_aborted)
            {
                return;
            }

            if (const auto router = weak_router.lock())
            {
                router->handle_keyframe_retry(key, timer_token);
            }
        });
}

void media_fanout_router::handle_keyframe_retry(keyframe_request_key key, uint64_t timer_token)
{
    media_keyframe_request_handler handler;
    std::size_t attempt = 0;
    std::size_t waiting_subscribers = 0;

    {
        const auto request_iterator = keyframe_requests_.find(key);

        if (request_iterator == keyframe_requests_.end() || request_iterator->second.timer_token != timer_token ||
            request_iterator->second.waiting_subscriber_session_ids.empty())
        {
            return;
        }

        const auto source_iterator = publisher_sources_by_stream_id_.find(key.stream_id);

        if (source_iterator == publisher_sources_by_stream_id_.end() || source_iterator->second->session_id != key.publisher_session_id ||
            source_iterator->second->generation != key.source_generation)
        {
            cancel_keyframe_request_state(request_iterator->second);
            keyframe_requests_.erase(request_iterator);
            return;
        }

        auto& state = request_iterator->second;
        state.sent_count += 1;
        attempt = state.sent_count;
        waiting_subscribers = state.waiting_subscriber_session_ids.size();
        handler = source_iterator->second->keyframe_request_handler;
        schedule_keyframe_retry(request_iterator->first, state);
    }

    handler(key.media_ssrc);
    WEBRTC_LOG_DEBUG("media keyframe request retry stream={} publisher_session={} source_generation={} media_ssrc={} attempt={} waiters={}",
                     key.stream_id,
                     key.publisher_session_id,
                     key.source_generation,
                     key.media_ssrc,
                     attempt,
                     waiting_subscribers);
}

void media_fanout_router::cancel_keyframe_requests_for_subscriber(std::string_view subscriber_session_id)
{
    for (auto iterator = keyframe_requests_.begin(); iterator != keyframe_requests_.end();)
    {
        iterator->second.waiting_subscriber_session_ids.erase(std::string(subscriber_session_id));

        if (iterator->second.waiting_subscriber_session_ids.empty())
        {
            cancel_keyframe_request_state(iterator->second);
            iterator = keyframe_requests_.erase(iterator);
        }
        else
        {
            ++iterator;
        }
    }
}

void media_fanout_router::cancel_stream_keyframe_requests(std::string_view stream_id)
{
    for (auto iterator = keyframe_requests_.begin(); iterator != keyframe_requests_.end();)
    {
        if (iterator->first.stream_id == stream_id)
        {
            cancel_keyframe_request_state(iterator->second);
            iterator = keyframe_requests_.erase(iterator);
        }
        else
        {
            ++iterator;
        }
    }
}

void media_fanout_router::cancel_keyframe_request_state(keyframe_request_state& state)
{
    state.retry_active = false;
    state.timer_token += 1;

    if (state.retry_timer != nullptr)
    {
        state.retry_timer->cancel();
    }
}

uint64_t media_fanout_router::allocate_source_generation()
{
    const uint64_t generation = next_source_generation_;
    next_source_generation_ += 1;
    return generation;
}

}    // namespace webrtc
