#include "session/stream_registry.h"

#include <algorithm>
#include <utility>

#include "util/random.h"
#include "util/timestamp.h"

namespace webrtc
{
std::string_view stream_registry_error_to_string(stream_registry_error error)
{
    switch (error)
    {
        case stream_registry_error::none:
            return "none";
        case stream_registry_error::stream_already_has_publisher:
            return "stream already has publisher";
        case stream_registry_error::publisher_not_found:
            return "publisher not found";
        case stream_registry_error::publisher_session_not_found:
            return "publisher session not found";
        case stream_registry_error::subscriber_session_not_found:
            return "subscriber session not found";
    }

    return "unknown";
}

create_publisher_session_result stream_registry::create_publisher_session(std::string_view stream_id, std::string_view remote_sdp_offer)
{
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string stream_id_string(stream_id);

    if (publishers_by_stream_id_.contains(stream_id_string))
    {
        create_publisher_session_result result;
        result.error = stream_registry_error::stream_already_has_publisher;
        result.session = publishers_by_stream_id_.at(stream_id_string);
        return result;
    }

    const std::string session_id = make_session_id();
    const uint64_t now = now_milliseconds();

    auto session = std::make_shared<publisher_session>(session_id, stream_id_string, std::string(remote_sdp_offer), now);

    publishers_by_stream_id_.emplace(session->stream_id(), session);
    publishers_by_session_id_.emplace(session->session_id(), session);

    create_publisher_session_result result;
    result.error = stream_registry_error::none;
    result.session = std::move(session);
    return result;
}

create_subscriber_session_result stream_registry::create_subscriber_session(std::string_view stream_id, std::string_view remote_sdp_offer)
{
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string stream_id_string(stream_id);

    if (!publishers_by_stream_id_.contains(stream_id_string))
    {
        create_subscriber_session_result result;
        result.error = stream_registry_error::publisher_not_found;
        return result;
    }

    const std::string session_id = make_session_id();
    const uint64_t now = now_milliseconds();

    auto session = std::make_shared<subscriber_session>(session_id, stream_id_string, std::string(remote_sdp_offer), now);

    subscribers_by_session_id_.emplace(session->session_id(), session);
    subscriber_session_ids_by_stream_id_[session->stream_id()].push_back(session->session_id());

    create_subscriber_session_result result;
    result.error = stream_registry_error::none;
    result.session = std::move(session);
    return result;
}

std::shared_ptr<publisher_session> stream_registry::find_publisher_by_stream_id(std::string_view stream_id) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = publishers_by_stream_id_.find(std::string(stream_id));
    if (it == publishers_by_stream_id_.end())
    {
        return nullptr;
    }

    return it->second;
}

std::shared_ptr<publisher_session> stream_registry::find_publisher_by_session_id(std::string_view session_id) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = publishers_by_session_id_.find(std::string(session_id));
    if (it == publishers_by_session_id_.end())
    {
        return nullptr;
    }

    return it->second;
}

std::shared_ptr<subscriber_session> stream_registry::find_subscriber_by_session_id(std::string_view session_id) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = subscribers_by_session_id_.find(std::string(session_id));
    if (it == subscribers_by_session_id_.end())
    {
        return nullptr;
    }

    return it->second;
}

remove_session_result stream_registry::remove_publisher_session(std::string_view session_id)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto publisher_it = publishers_by_session_id_.find(std::string(session_id));
    if (publisher_it == publishers_by_session_id_.end())
    {
        remove_session_result result;
        result.error = stream_registry_error::publisher_session_not_found;
        return result;
    }

    const std::string stream_id = publisher_it->second->stream_id();

    publishers_by_stream_id_.erase(stream_id);
    publishers_by_session_id_.erase(publisher_it);

    auto subscribers_by_stream_it = subscriber_session_ids_by_stream_id_.find(stream_id);
    if (subscribers_by_stream_it != subscriber_session_ids_by_stream_id_.end())
    {
        for (const auto& subscriber_session_id : subscribers_by_stream_it->second)
        {
            subscribers_by_session_id_.erase(subscriber_session_id);
        }

        subscriber_session_ids_by_stream_id_.erase(subscribers_by_stream_it);
    }

    remove_session_result result;
    result.error = stream_registry_error::none;
    return result;
}

remove_session_result stream_registry::remove_subscriber_session(std::string_view session_id)
{
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string session_id_string(session_id);

    auto subscriber_it = subscribers_by_session_id_.find(session_id_string);
    if (subscriber_it == subscribers_by_session_id_.end())
    {
        remove_session_result result;
        result.error = stream_registry_error::subscriber_session_not_found;
        return result;
    }

    const std::string stream_id = subscriber_it->second->stream_id();

    subscribers_by_session_id_.erase(subscriber_it);

    auto subscribers_by_stream_it = subscriber_session_ids_by_stream_id_.find(stream_id);
    if (subscribers_by_stream_it != subscriber_session_ids_by_stream_id_.end())
    {
        auto& subscriber_session_ids = subscribers_by_stream_it->second;

        std::erase(subscriber_session_ids, session_id_string);

        if (subscriber_session_ids.empty())
        {
            subscriber_session_ids_by_stream_id_.erase(subscribers_by_stream_it);
        }
    }

    remove_session_result result;
    result.error = stream_registry_error::none;
    return result;
}

std::size_t stream_registry::publisher_count() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return publishers_by_session_id_.size();
}

std::size_t stream_registry::subscriber_count() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return subscribers_by_session_id_.size();
}

std::size_t stream_registry::subscriber_count(std::string_view stream_id) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = subscriber_session_ids_by_stream_id_.find(std::string(stream_id));
    if (it == subscriber_session_ids_by_stream_id_.end())
    {
        return 0;
    }

    return it->second.size();
}

std::string stream_registry::make_session_id() { return random_string(24); }

uint64_t stream_registry::now_milliseconds() { return timestamp::now().milliseconds(); }
}    // namespace webrtc
