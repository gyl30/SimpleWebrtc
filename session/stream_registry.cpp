#include "session/stream_registry.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "session/session_state.h"
#include "util/random.h"
#include "util/timestamp.h"

namespace webrtc
{
namespace
{
void notify_removed_sessions(const stream_session_removed_callback& callback, const std::vector<stream_removed_session>& removed_sessions)
{
    if (!callback)
    {
        return;
    }

    for (const auto& removed_session : removed_sessions)
    {
        callback(removed_session);
    }
}
}    // namespace

std::string_view stream_registry_error_to_string(stream_registry_error error)
{
    switch (error)
    {
        case stream_registry_error::none:
            return "none";

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

publisher_session_result stream_registry::create_publisher_session(std::string stream_id,
                                                                   std::string remote_sdp_offer,
                                                                   sdp::webrtc_offer_summary remote_offer_summary)
{
    std::lock_guard lock(mutex_);

    if (publishers_by_stream_id_.contains(stream_id))
    {
        return std::unexpected(stream_registry_error::stream_already_has_publisher);
    }

    const std::string session_id = make_unique_session_id_locked();

    const uint64_t created_at = now_milliseconds();

    auto session =
        std::make_shared<publisher_session>(session_id, stream_id, std::move(remote_sdp_offer), std::move(remote_offer_summary), created_at);

    publishers_by_session_id_.emplace(session_id, session);
    publishers_by_stream_id_.emplace(std::move(stream_id), session);

    return session;
}

subscriber_session_result stream_registry::create_subscriber_session(std::string stream_id,
                                                                     std::string remote_sdp_offer,
                                                                     sdp::webrtc_offer_summary remote_offer_summary)
{
    std::lock_guard lock(mutex_);

    if (!publishers_by_stream_id_.contains(stream_id))
    {
        return std::unexpected(stream_registry_error::publisher_not_found);
    }

    const std::string session_id = make_unique_session_id_locked();

    const uint64_t created_at = now_milliseconds();

    auto session =
        std::make_shared<subscriber_session>(session_id, stream_id, std::move(remote_sdp_offer), std::move(remote_offer_summary), created_at);

    subscribers_by_session_id_.emplace(session_id, session);
    subscriber_session_ids_by_stream_id_[stream_id].insert(session_id);

    return session;
}

std::shared_ptr<publisher_session> stream_registry::find_publisher_by_stream_id(std::string_view stream_id) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = publishers_by_stream_id_.find(std::string(stream_id));

    if (iterator == publishers_by_stream_id_.end())
    {
        return nullptr;
    }

    return iterator->second;
}

std::shared_ptr<publisher_session> stream_registry::find_publisher_by_session_id(std::string_view session_id) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = publishers_by_session_id_.find(std::string(session_id));

    if (iterator == publishers_by_session_id_.end())
    {
        return nullptr;
    }

    return iterator->second;
}

std::shared_ptr<subscriber_session> stream_registry::find_subscriber_by_session_id(std::string_view session_id) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = subscribers_by_session_id_.find(std::string(session_id));

    if (iterator == subscribers_by_session_id_.end())
    {
        return nullptr;
    }

    return iterator->second;
}

std::shared_ptr<publisher_session> stream_registry::find_publisher_by_local_ice_ufrag(std::string_view local_ice_ufrag) const
{
    if (local_ice_ufrag.empty())
    {
        return nullptr;
    }

    std::lock_guard lock(mutex_);

    for (const auto& [session_id, session] : publishers_by_session_id_)
    {
        (void)session_id;

        if (session != nullptr && session->local_ice().ufrag == local_ice_ufrag)
        {
            return session;
        }
    }

    return nullptr;
}

std::shared_ptr<subscriber_session> stream_registry::find_subscriber_by_local_ice_ufrag(std::string_view local_ice_ufrag) const
{
    if (local_ice_ufrag.empty())
    {
        return nullptr;
    }

    std::lock_guard lock(mutex_);

    for (const auto& [session_id, session] : subscribers_by_session_id_)
    {
        (void)session_id;

        if (session != nullptr && session->local_ice().ufrag == local_ice_ufrag)
        {
            return session;
        }
    }

    return nullptr;
}

remove_session_result stream_registry::remove_publisher_session(std::string_view session_id)
{
    std::vector<stream_removed_session> removed_sessions;
    stream_session_removed_callback callback;

    {
        std::lock_guard lock(mutex_);

        const auto publisher_iterator = publishers_by_session_id_.find(std::string(session_id));

        if (publisher_iterator == publishers_by_session_id_.end())
        {
            return std::unexpected(stream_registry_error::publisher_session_not_found);
        }

        const auto publisher = publisher_iterator->second;

        const std::string stream_id = publisher->stream_id();

        publisher->set_state(session_state::closed);

        stream_removed_session removed_publisher;
        removed_publisher.kind = stream_session_kind::publisher;
        removed_publisher.stream_id = stream_id;
        removed_publisher.session_id = publisher->session_id();
        removed_sessions.push_back(std::move(removed_publisher));

        const auto subscribers_iterator = subscriber_session_ids_by_stream_id_.find(stream_id);

        if (subscribers_iterator != subscriber_session_ids_by_stream_id_.end())
        {
            for (const auto& subscriber_session_id : subscribers_iterator->second)
            {
                const auto subscriber_iterator = subscribers_by_session_id_.find(subscriber_session_id);

                if (subscriber_iterator == subscribers_by_session_id_.end())
                {
                    continue;
                }

                const auto subscriber = subscriber_iterator->second;

                subscriber->set_state(session_state::closed);

                stream_removed_session removed_subscriber;
                removed_subscriber.kind = stream_session_kind::subscriber;
                removed_subscriber.stream_id = subscriber->stream_id();
                removed_subscriber.session_id = subscriber->session_id();
                removed_sessions.push_back(std::move(removed_subscriber));

                subscribers_by_session_id_.erase(subscriber_iterator);
            }

            subscriber_session_ids_by_stream_id_.erase(subscribers_iterator);
        }

        publishers_by_stream_id_.erase(stream_id);
        publishers_by_session_id_.erase(publisher_iterator);

        callback = session_removed_callback_;
    }

    notify_removed_sessions(callback, removed_sessions);

    return {};
}

remove_session_result stream_registry::remove_subscriber_session(std::string_view session_id)
{
    std::vector<stream_removed_session> removed_sessions;
    stream_session_removed_callback callback;

    {
        std::lock_guard lock(mutex_);

        const auto subscriber_iterator = subscribers_by_session_id_.find(std::string(session_id));

        if (subscriber_iterator == subscribers_by_session_id_.end())
        {
            return std::unexpected(stream_registry_error::subscriber_session_not_found);
        }

        const auto subscriber = subscriber_iterator->second;

        const std::string stream_id = subscriber->stream_id();

        const std::string subscriber_session_id = subscriber->session_id();

        subscriber->set_state(session_state::closed);

        stream_removed_session removed_subscriber;
        removed_subscriber.kind = stream_session_kind::subscriber;
        removed_subscriber.stream_id = stream_id;
        removed_subscriber.session_id = subscriber_session_id;
        removed_sessions.push_back(std::move(removed_subscriber));

        subscribers_by_session_id_.erase(subscriber_iterator);

        const auto stream_iterator = subscriber_session_ids_by_stream_id_.find(stream_id);

        if (stream_iterator != subscriber_session_ids_by_stream_id_.end())
        {
            stream_iterator->second.erase(subscriber_session_id);

            if (stream_iterator->second.empty())
            {
                subscriber_session_ids_by_stream_id_.erase(stream_iterator);
            }
        }

        callback = session_removed_callback_;
    }

    notify_removed_sessions(callback, removed_sessions);

    return {};
}

void stream_registry::set_session_removed_callback(stream_session_removed_callback callback)
{
    std::lock_guard lock(mutex_);

    session_removed_callback_ = std::move(callback);
}
std::vector<stream_session_lifecycle_snapshot> stream_registry::session_lifecycle_snapshots() const
{
    std::lock_guard lock(mutex_);

    std::vector<stream_session_lifecycle_snapshot> snapshots;

    snapshots.reserve(publishers_by_session_id_.size() + subscribers_by_session_id_.size());

    for (const auto& [session_id, session] : publishers_by_session_id_)
    {
        (void)session_id;

        if (session == nullptr)
        {
            continue;
        }

        stream_session_lifecycle_snapshot snapshot;

        snapshot.kind = stream_session_kind::publisher;

        snapshot.stream_id = session->stream_id();

        snapshot.session_id = session->session_id();

        snapshot.state = session->state();

        snapshot.created_at_milliseconds = session->created_at_milliseconds();

        snapshot.updated_at_milliseconds = session->updated_at_milliseconds();

        snapshots.push_back(std::move(snapshot));
    }

    for (const auto& [session_id, session] : subscribers_by_session_id_)
    {
        (void)session_id;

        if (session == nullptr)
        {
            continue;
        }

        stream_session_lifecycle_snapshot snapshot;

        snapshot.kind = stream_session_kind::subscriber;

        snapshot.stream_id = session->stream_id();

        snapshot.session_id = session->session_id();

        snapshot.state = session->state();

        snapshot.created_at_milliseconds = session->created_at_milliseconds();

        snapshot.updated_at_milliseconds = session->updated_at_milliseconds();

        snapshots.push_back(std::move(snapshot));
    }

    return snapshots;
}

std::size_t stream_registry::publisher_count() const
{
    std::lock_guard lock(mutex_);

    return publishers_by_session_id_.size();
}

std::size_t stream_registry::subscriber_count() const
{
    std::lock_guard lock(mutex_);

    return subscribers_by_session_id_.size();
}

std::string stream_registry::make_unique_session_id_locked() const
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
