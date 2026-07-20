#include "session/stream_registry.h"

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "util/random.h"
#include "util/timestamp.h"

namespace webrtc
{
std::string_view stream_registry_error_to_string(stream_registry_error error)
{
    switch (error)
    {
        case stream_registry_error::stream_already_has_publisher:
            return "stream_already_has_publisher";

        case stream_registry_error::publisher_not_found:
            return "publisher_not_found";

        case stream_registry_error::publisher_session_not_found:
            return "publisher_session_not_found";

        case stream_registry_error::subscriber_session_not_found:
            return "subscriber_session_not_found";
    }

    return "unknown";
}

std::string_view stream_session_kind_to_string(stream_session_kind kind)
{
    switch (kind)
    {
        case stream_session_kind::publisher:
            return "publisher";

        case stream_session_kind::subscriber:
            return "subscriber";
    }

    return "unknown";
}

publisher_session_result stream_registry::create_publisher_session(std::string stream_id, sdp::webrtc_offer_summary remote_offer_summary)
{
    if (publishers_by_stream_id_.contains(stream_id))
    {
        return std::unexpected(stream_registry_error::stream_already_has_publisher);
    }

    const std::string session_id = make_unique_session_id();

    const uint64_t created_at = now_milliseconds();

    auto session = std::make_shared<publisher_session>(session_id, stream_id, std::move(remote_offer_summary), created_at);

    publishers_by_session_id_.emplace(session_id, session);
    publishers_by_stream_id_.emplace(std::move(stream_id), session);

    return session;
}

subscriber_session_result stream_registry::create_subscriber_session(std::string stream_id, sdp::webrtc_offer_summary remote_offer_summary)
{
    if (!publishers_by_stream_id_.contains(stream_id))
    {
        return std::unexpected(stream_registry_error::publisher_not_found);
    }

    const std::string session_id = make_unique_session_id();

    const uint64_t created_at = now_milliseconds();

    auto session = std::make_shared<subscriber_session>(session_id, stream_id, std::move(remote_offer_summary), created_at);

    subscribers_by_session_id_.emplace(session_id, session);

    return session;
}

std::shared_ptr<publisher_session> stream_registry::find_publisher_by_stream_id(std::string_view stream_id) const
{
    const auto iterator = publishers_by_stream_id_.find(std::string(stream_id));

    if (iterator == publishers_by_stream_id_.end())
    {
        return nullptr;
    }

    return iterator->second;
}

std::shared_ptr<publisher_session> stream_registry::find_publisher_by_session_id(std::string_view session_id) const
{
    const auto iterator = publishers_by_session_id_.find(std::string(session_id));

    if (iterator == publishers_by_session_id_.end())
    {
        return nullptr;
    }

    return iterator->second;
}

std::shared_ptr<subscriber_session> stream_registry::find_subscriber_by_session_id(std::string_view session_id) const
{
    const auto iterator = subscribers_by_session_id_.find(std::string(session_id));

    if (iterator == subscribers_by_session_id_.end())
    {
        return nullptr;
    }

    return iterator->second;
}

remove_session_result stream_registry::remove_publisher_session(std::string_view session_id)
{
    const auto publisher_iterator = publishers_by_session_id_.find(std::string(session_id));

    if (publisher_iterator == publishers_by_session_id_.end())
    {
        return std::unexpected(stream_registry_error::publisher_session_not_found);
    }

    const auto& publisher = publisher_iterator->second;

    const std::string stream_id = publisher->stream_id();

    /*
     * WHEP 订阅者归属于 stream，而不是某个具体的 publisher session。
     * 删除发布会话时保留订阅者，使同一 stream 后续重新发布后可以继续使用。
     */
    publishers_by_stream_id_.erase(stream_id);
    publishers_by_session_id_.erase(publisher_iterator);

    return {};
}

remove_session_result stream_registry::remove_subscriber_session(std::string_view session_id)
{
    const auto subscriber_iterator = subscribers_by_session_id_.find(std::string(session_id));

    if (subscriber_iterator == subscribers_by_session_id_.end())
    {
        return std::unexpected(stream_registry_error::subscriber_session_not_found);
    }

    subscribers_by_session_id_.erase(subscriber_iterator);

    return {};
}

std::vector<stream_session_lifecycle_snapshot> stream_registry::session_lifecycle_snapshots() const
{
    std::vector<stream_session_lifecycle_snapshot> snapshots;

    snapshots.reserve(publishers_by_session_id_.size() + subscribers_by_session_id_.size());

    for (const auto& [session_id, session] : publishers_by_session_id_)
    {
        (void)session_id;

        stream_session_lifecycle_snapshot snapshot;

        snapshot.kind = stream_session_kind::publisher;

        snapshot.stream_id = session->stream_id();

        snapshot.session_id = session->session_id();

        snapshot.created_at_milliseconds = session->created_at_milliseconds();

        snapshot.updated_at_milliseconds = session->updated_at_milliseconds();

        snapshots.push_back(std::move(snapshot));
    }

    for (const auto& [session_id, session] : subscribers_by_session_id_)
    {
        (void)session_id;

        stream_session_lifecycle_snapshot snapshot;

        snapshot.kind = stream_session_kind::subscriber;

        snapshot.stream_id = session->stream_id();

        snapshot.session_id = session->session_id();

        snapshot.created_at_milliseconds = session->created_at_milliseconds();

        snapshot.updated_at_milliseconds = session->updated_at_milliseconds();

        snapshots.push_back(std::move(snapshot));
    }

    return snapshots;
}

std::string stream_registry::make_unique_session_id() const
{
    for (;;)
    {
        std::string session_id = random_string(24);

        if (publishers_by_session_id_.contains(session_id))
        {
            continue;
        }

        if (subscribers_by_session_id_.contains(session_id))
        {
            continue;
        }

        return session_id;
    }
}

uint64_t stream_registry::now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }
}    // namespace webrtc
