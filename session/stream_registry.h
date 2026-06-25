#ifndef SIMPLE_WEBRTC_SESSION_STREAM_REGISTRY_H
#define SIMPLE_WEBRTC_SESSION_STREAM_REGISTRY_H

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "session/publisher_session.h"
#include "session/subscriber_session.h"

namespace webrtc
{
enum class stream_registry_error
{
    none,
    stream_already_has_publisher,
    publisher_not_found,
    publisher_session_not_found,
    subscriber_session_not_found,
};

std::string_view stream_registry_error_to_string(stream_registry_error error);

struct create_publisher_session_result
{
    stream_registry_error error = stream_registry_error::none;
    std::shared_ptr<publisher_session> session;
};

struct create_subscriber_session_result
{
    stream_registry_error error = stream_registry_error::none;
    std::shared_ptr<subscriber_session> session;
};

struct remove_session_result
{
    stream_registry_error error = stream_registry_error::none;
};

class stream_registry
{
   public:
    stream_registry() = default;

   public:
    create_publisher_session_result create_publisher_session(std::string_view stream_id, std::string_view remote_sdp_offer);
    create_subscriber_session_result create_subscriber_session(std::string_view stream_id, std::string_view remote_sdp_offer);

    std::shared_ptr<publisher_session> find_publisher_by_stream_id(std::string_view stream_id) const;
    std::shared_ptr<publisher_session> find_publisher_by_session_id(std::string_view session_id) const;
    std::shared_ptr<subscriber_session> find_subscriber_by_session_id(std::string_view session_id) const;

    remove_session_result remove_publisher_session(std::string_view session_id);
    remove_session_result remove_subscriber_session(std::string_view session_id);

    std::size_t publisher_count() const;
    std::size_t subscriber_count() const;
    std::size_t subscriber_count(std::string_view stream_id) const;

   private:
    static std::string make_session_id();
    static uint64_t now_milliseconds();

   private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<publisher_session>> publishers_by_stream_id_;
    std::unordered_map<std::string, std::shared_ptr<publisher_session>> publishers_by_session_id_;
    std::unordered_map<std::string, std::shared_ptr<subscriber_session>> subscribers_by_session_id_;
    std::unordered_map<std::string, std::vector<std::string>> subscriber_session_ids_by_stream_id_;
};
}    // namespace webrtc

#endif
