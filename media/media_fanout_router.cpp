#include "media/media_fanout_router.h"

#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "log/log.h"

namespace webrtc
{
void media_fanout_router::subscribe(std::string stream_id, std::string subscriber_session_id, media_rtp_handler handler)
{
    if (stream_id.empty() || subscriber_session_id.empty() || !handler)
    {
        return;
    }

    const std::string log_stream_id = stream_id;
    const std::string log_session_id = subscriber_session_id;

    {
        std::lock_guard lock(mutex_);

        subscriptions_by_session_id_.insert_or_assign(subscriber_session_id,
                                                      subscription{
                                                          .stream_id = std::move(stream_id),
                                                          .handler = std::move(handler),
                                                      });
    }

    WEBRTC_LOG_INFO("media fanout subscribe stream={} session={}", log_stream_id, log_session_id);
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

std::size_t media_fanout_router::publish_rtp(std::string_view stream_id, std::span<const uint8_t> packet)
{
    if (stream_id.empty() || packet.empty())
    {
        return 0;
    }

    std::vector<media_rtp_handler> handlers;

    {
        std::lock_guard lock(mutex_);

        handlers.reserve(subscriptions_by_session_id_.size());

        for (const auto& [subscriber_session_id, current] : subscriptions_by_session_id_)
        {
            (void)subscriber_session_id;

            if (current.stream_id != stream_id)
            {
                continue;
            }

            handlers.push_back(current.handler);
        }
    }

    for (const auto& handler : handlers)
    {
        handler(packet);
    }

    return handlers.size();
}

}    // namespace webrtc
