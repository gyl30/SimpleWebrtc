#include "media/media_fanout_router.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "log/log.h"

namespace webrtc
{
void media_fanout_router::subscribe(std::string stream_id,
                                    std::string subscriber_session_id,
                                    media_rtp_handler rtp_handler,
                                    media_publisher_source_handler source_handler)
{
    if (stream_id.empty() || subscriber_session_id.empty() || !rtp_handler || !source_handler)
    {
        return;
    }

    const std::string log_stream_id = stream_id;
    const std::string log_session_id = subscriber_session_id;
    const media_publisher_source_handler initial_source_handler = source_handler;
    media_publisher_source_update initial_update;

    {
        std::lock_guard lock(mutex_);

        subscriptions_by_session_id_.insert_or_assign(subscriber_session_id,
                                                      subscription{
                                                          .stream_id = std::move(stream_id),
                                                          .rtp_handler = std::move(rtp_handler),
                                                          .source_handler = std::move(source_handler),
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
    }

    WEBRTC_LOG_INFO("media fanout subscribe stream={} session={}", log_stream_id, log_session_id);

    initial_source_handler(std::move(initial_update));
}

void media_fanout_router::unsubscribe(std::string_view subscriber_session_id)
{
    if (subscriber_session_id.empty())
    {
        return;
    }

    std::string stream_id;

    {
        std::lock_guard lock(mutex_);

        const auto iterator = subscriptions_by_session_id_.find(std::string(subscriber_session_id));

        if (iterator == subscriptions_by_session_id_.end())
        {
            return;
        }

        stream_id = iterator->second.stream_id;
        subscriptions_by_session_id_.erase(iterator);
    }

    WEBRTC_LOG_INFO("media fanout unsubscribe stream={} session={}", stream_id, subscriber_session_id);
}

void media_fanout_router::set_publisher_source(std::string stream_id,
                                                std::string publisher_session_id,
                                                sdp::webrtc_offer_summary publisher_offer,
                                                media_keyframe_request_handler keyframe_request_handler)
{
    if (stream_id.empty() || publisher_session_id.empty() || !keyframe_request_handler)
    {
        return;
    }

    media_publisher_source_ptr source;
    std::vector<media_publisher_source_handler> handlers;

    {
        std::lock_guard lock(mutex_);

        const uint64_t generation = allocate_source_generation_locked();

        source = std::make_shared<media_publisher_source>(media_publisher_source{
            .stream_id = std::move(stream_id),
            .session_id = std::move(publisher_session_id),
            .generation = generation,
            .offer = std::move(publisher_offer),
            .keyframe_request_handler = std::move(keyframe_request_handler),
        });

        publisher_sources_by_stream_id_.insert_or_assign(source->stream_id, source);
        publisher_source_generations_by_stream_id_.insert_or_assign(source->stream_id, generation);
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

    WEBRTC_LOG_INFO("media fanout publisher source set stream={} session={} generation={} subscribers={}",
                    source->stream_id,
                    source->session_id,
                    source->generation,
                    handlers.size());

    for (const auto& handler : handlers)
    {
        handler(media_publisher_source_update{.generation = source->generation, .source = source});
    }
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
        std::lock_guard lock(mutex_);

        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() ||
            source_iterator->second->session_id != publisher_session_id)
        {
            return;
        }

        generation = allocate_source_generation_locked();
        publisher_sources_by_stream_id_.erase(source_iterator);
        publisher_source_generations_by_stream_id_.insert_or_assign(std::string(stream_id), generation);
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

    WEBRTC_LOG_INFO("media fanout publisher source cleared stream={} session={} generation={} subscribers={}",
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
                                           std::string_view publisher_session_id,
                                           uint64_t source_generation,
                                           uint32_t media_ssrc)
{
    if (stream_id.empty() || publisher_session_id.empty() || source_generation == 0 || media_ssrc == 0)
    {
        return false;
    }

    media_keyframe_request_handler handler;

    {
        std::lock_guard lock(mutex_);

        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() ||
            source_iterator->second->session_id != publisher_session_id ||
            source_iterator->second->generation != source_generation)
        {
            return false;
        }

        handler = source_iterator->second->keyframe_request_handler;
    }

    handler(media_ssrc);
    return true;
}

std::size_t media_fanout_router::publish_rtp(std::string_view stream_id,
                                             std::string_view publisher_session_id,
                                             std::span<const uint8_t> packet)
{
    if (stream_id.empty() || publisher_session_id.empty() || packet.empty())
    {
        return 0;
    }

    media_publisher_source_ptr source;
    std::vector<media_rtp_handler> handlers;

    {
        std::lock_guard lock(mutex_);

        const auto source_iterator = publisher_sources_by_stream_id_.find(std::string(stream_id));

        if (source_iterator == publisher_sources_by_stream_id_.end() ||
            source_iterator->second->session_id != publisher_session_id)
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

uint64_t media_fanout_router::allocate_source_generation_locked()
{
    const uint64_t generation = next_source_generation_;
    next_source_generation_ += 1;
    return generation;
}

}    // namespace webrtc
