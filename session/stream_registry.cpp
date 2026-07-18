#include "session/stream_registry.h"

#include <cstddef>
#include <cstdint>
#include <expected>
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
constexpr std::size_t k_max_removed_session_tombstones = 4096;
constexpr uint64_t k_removed_session_tombstone_ttl_milliseconds = 120000;
}    // namespace

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

        case stream_registry_error::subscriber_reconnect_stream_mismatch:
            return "subscriber_reconnect_stream_mismatch";
        case stream_registry_error::publisher_republish_stream_mismatch:
            return "publisher_republish_stream_mismatch";
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
                                                                   sdp::webrtc_offer_summary remote_offer_summary)
{
    std::lock_guard lock(mutex_);

    if (publishers_by_stream_id_.contains(stream_id))
    {
        return std::unexpected(stream_registry_error::stream_already_has_publisher);
    }

    const std::string session_id = make_unique_session_id_locked();

    const uint64_t created_at = now_milliseconds();

    auto session = std::make_shared<publisher_session>(session_id, stream_id, std::move(remote_offer_summary), created_at);

    publishers_by_session_id_.emplace(session_id, session);
    publishers_by_stream_id_.emplace(std::move(stream_id), session);

    return session;
}
publisher_session_result stream_registry::replace_publisher_session(std::string previous_session_id,
                                                                    std::string stream_id,
                                                                    sdp::webrtc_offer_summary remote_offer_summary)
{
    if (previous_session_id.empty())
    {
        return std::unexpected(stream_registry_error::publisher_session_not_found);
    }

    std::lock_guard lock(mutex_);

    const auto previous_iterator = publishers_by_session_id_.find(previous_session_id);

    if (previous_iterator == publishers_by_session_id_.end() || previous_iterator->second == nullptr)
    {
        return std::unexpected(stream_registry_error::publisher_session_not_found);
    }

    const std::shared_ptr<publisher_session> previous_session = previous_iterator->second;

    if (previous_session->stream_id() != stream_id)
    {
        return std::unexpected(stream_registry_error::publisher_republish_stream_mismatch);
    }

    const auto stream_iterator = publishers_by_stream_id_.find(stream_id);

    if (stream_iterator == publishers_by_stream_id_.end() || stream_iterator->second == nullptr ||
        stream_iterator->second->session_id() != previous_session_id)
    {
        return std::unexpected(stream_registry_error::publisher_republish_stream_mismatch);
    }

    remember_removed_session_locked(stream_session_kind::publisher, previous_session->session_id());

    publishers_by_session_id_.erase(previous_iterator);

    publishers_by_stream_id_.erase(stream_iterator);

    const std::string session_id = make_unique_session_id_locked();
    const uint64_t created_at = now_milliseconds();

    auto session = std::make_shared<publisher_session>(session_id, stream_id, std::move(remote_offer_summary), created_at);

    publishers_by_session_id_.emplace(session_id, session);

    publishers_by_stream_id_.emplace(std::move(stream_id), session);

    return session;
}

subscriber_session_result stream_registry::create_subscriber_session(std::string stream_id,
                                                                     sdp::webrtc_offer_summary remote_offer_summary)
{
    std::lock_guard lock(mutex_);

    if (!publishers_by_stream_id_.contains(stream_id))
    {
        return std::unexpected(stream_registry_error::publisher_not_found);
    }

    const std::string session_id = make_unique_session_id_locked();

    const uint64_t created_at = now_milliseconds();

    auto session = std::make_shared<subscriber_session>(session_id, stream_id, std::move(remote_offer_summary), created_at);

    subscribers_by_session_id_.emplace(session_id, session);
    subscriber_session_ids_by_stream_id_[stream_id].insert(session_id);

    return session;
}
subscriber_session_result stream_registry::replace_subscriber_session(std::string previous_session_id,
                                                                      std::string stream_id,
                                                                      sdp::webrtc_offer_summary remote_offer_summary)
{
    if (previous_session_id.empty())
    {
        return std::unexpected(stream_registry_error::subscriber_session_not_found);
    }

    std::lock_guard lock(mutex_);

    if (!publishers_by_stream_id_.contains(stream_id))
    {
        return std::unexpected(stream_registry_error::publisher_not_found);
    }

    const auto previous_iterator = subscribers_by_session_id_.find(previous_session_id);

    if (previous_iterator == subscribers_by_session_id_.end() || previous_iterator->second == nullptr)
    {
        return std::unexpected(stream_registry_error::subscriber_session_not_found);
    }

    const std::shared_ptr<subscriber_session> previous_session = previous_iterator->second;

    if (previous_session->stream_id() != stream_id)
    {
        return std::unexpected(stream_registry_error::subscriber_reconnect_stream_mismatch);
    }

    remember_removed_session_locked(stream_session_kind::subscriber, previous_session->session_id());

    subscribers_by_session_id_.erase(previous_iterator);

    const auto stream_iterator = subscriber_session_ids_by_stream_id_.find(stream_id);
    if (stream_iterator != subscriber_session_ids_by_stream_id_.end())
    {
        stream_iterator->second.erase(previous_session_id);

        if (stream_iterator->second.empty())
        {
            subscriber_session_ids_by_stream_id_.erase(stream_iterator);
        }
    }

    const std::string session_id = make_unique_session_id_locked();

    const uint64_t created_at = now_milliseconds();

    auto new_session = std::make_shared<subscriber_session>(session_id, stream_id, std::move(remote_offer_summary), created_at);

    subscribers_by_session_id_.emplace(session_id, new_session);

    subscriber_session_ids_by_stream_id_[stream_id].insert(session_id);

    return new_session;
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

std::optional<stream_session_kind> stream_registry::find_removed_session_kind(std::string_view session_id) const
{
    if (session_id.empty())
    {
        return std::nullopt;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(mutex_);

    const auto iterator = removed_session_tombstones_by_session_id_.find(std::string(session_id));

    if (iterator == removed_session_tombstones_by_session_id_.end())
    {
        return std::nullopt;
    }

    if (is_removed_session_tombstone_expired_locked(iterator->second, current_time_milliseconds))
    {
        return std::nullopt;
    }

    return iterator->second.kind;
}

bool stream_registry::is_removed_session_tombstone_expired_locked(const removed_session_tombstone& tombstone,
                                                                  uint64_t current_time_milliseconds) const
{
    if (tombstone.removed_at_milliseconds == 0)
    {
        return false;
    }

    if (current_time_milliseconds <= tombstone.removed_at_milliseconds)
    {
        return false;
    }

    return current_time_milliseconds - tombstone.removed_at_milliseconds >= k_removed_session_tombstone_ttl_milliseconds;
}
void stream_registry::remember_removed_session_locked(stream_session_kind kind, std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    removed_session_tombstones_by_session_id_[std::string(session_id)] = removed_session_tombstone{
        .kind = kind,
        .removed_at_milliseconds = current_time_milliseconds,
    };

    prune_removed_session_tombstones_locked(current_time_milliseconds);
}

void stream_registry::prune_removed_session_tombstones_locked(uint64_t current_time_milliseconds)
{
    for (auto iterator = removed_session_tombstones_by_session_id_.begin(); iterator != removed_session_tombstones_by_session_id_.end();)
    {
        if (is_removed_session_tombstone_expired_locked(iterator->second, current_time_milliseconds))
        {
            iterator = removed_session_tombstones_by_session_id_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    while (removed_session_tombstones_by_session_id_.size() > k_max_removed_session_tombstones)
    {
        auto oldest_iterator = removed_session_tombstones_by_session_id_.end();

        for (auto iterator = removed_session_tombstones_by_session_id_.begin(); iterator != removed_session_tombstones_by_session_id_.end();
             ++iterator)
        {
            if (oldest_iterator == removed_session_tombstones_by_session_id_.end() ||
                iterator->second.removed_at_milliseconds < oldest_iterator->second.removed_at_milliseconds)
            {
                oldest_iterator = iterator;
            }
        }

        if (oldest_iterator == removed_session_tombstones_by_session_id_.end())
        {
            return;
        }

        removed_session_tombstones_by_session_id_.erase(oldest_iterator);
    }
}

remove_session_result stream_registry::remove_publisher_session(std::string_view session_id)
{
    std::lock_guard lock(mutex_);

    const auto publisher_iterator = publishers_by_session_id_.find(std::string(session_id));

    if (publisher_iterator == publishers_by_session_id_.end())
    {
        return std::unexpected(stream_registry_error::publisher_session_not_found);
    }

    const auto publisher = publisher_iterator->second;

    if (publisher == nullptr)
    {
        return std::unexpected(stream_registry_error::publisher_session_not_found);
    }

    const std::string stream_id = publisher->stream_id();

    remember_removed_session_locked(stream_session_kind::publisher, publisher->session_id());

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
    std::lock_guard lock(mutex_);

    const auto subscriber_iterator = subscribers_by_session_id_.find(std::string(session_id));

    if (subscriber_iterator == subscribers_by_session_id_.end())
    {
        return std::unexpected(stream_registry_error::subscriber_session_not_found);
    }

    const auto subscriber = subscriber_iterator->second;

    if (subscriber == nullptr)
    {
        return std::unexpected(stream_registry_error::subscriber_session_not_found);
    }

    const std::string stream_id = subscriber->stream_id();
    const std::string subscriber_session_id = subscriber->session_id();

    remember_removed_session_locked(stream_session_kind::subscriber, subscriber_session_id);

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

    return {};
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
