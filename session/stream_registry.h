#ifndef SIMPLE_WEBRTC_SESSION_STREAM_REGISTRY_H
#define SIMPLE_WEBRTC_SESSION_STREAM_REGISTRY_H

#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "session/session_state.h"
#include "signaling/sdp/sdp_summary.h"
#include "session/publisher_session.h"
#include "session/subscriber_session.h"

namespace webrtc
{
enum class stream_registry_error : uint8_t
{
    stream_already_has_publisher,
    publisher_not_found,
    publisher_session_not_found,
    subscriber_session_not_found,
    subscriber_reconnect_stream_mismatch,
    publisher_republish_stream_mismatch,
};

enum class stream_session_kind : uint8_t
{
    publisher,
    subscriber,
};

struct stream_session_lifecycle_snapshot
{
    stream_session_kind kind = stream_session_kind::publisher;
    std::string stream_id;
    std::string session_id;
    session_state state = session_state::sdp_received;
    uint64_t created_at_milliseconds = 0;
    uint64_t updated_at_milliseconds = 0;
};

[[nodiscard]] std::string_view stream_registry_error_to_string(stream_registry_error error);

[[nodiscard]] std::string_view stream_session_kind_to_string(stream_session_kind kind);

using publisher_session_result = std::expected<std::shared_ptr<publisher_session>, stream_registry_error>;

using subscriber_session_result = std::expected<std::shared_ptr<subscriber_session>, stream_registry_error>;

using remove_session_result = std::expected<void, stream_registry_error>;

class stream_registry
{
   public:
    stream_registry() = default;
    ~stream_registry() = default;

    stream_registry(const stream_registry&) = delete;
    stream_registry& operator=(const stream_registry&) = delete;

    stream_registry(stream_registry&&) = delete;
    stream_registry& operator=(stream_registry&&) = delete;

   public:
    [[nodiscard]] publisher_session_result create_publisher_session(std::string stream_id,
                                                                    sdp::webrtc_offer_summary remote_offer_summary);

    [[nodiscard]]
    publisher_session_result replace_publisher_session(std::string previous_session_id,
                                                       std::string stream_id,
                                                       sdp::webrtc_offer_summary remote_offer_summary);
    [[nodiscard]] subscriber_session_result create_subscriber_session(std::string stream_id,
                                                                      sdp::webrtc_offer_summary remote_offer_summary);
    [[nodiscard]]
    subscriber_session_result replace_subscriber_session(std::string previous_session_id,
                                                         std::string stream_id,
                                                         sdp::webrtc_offer_summary remote_offer_summary);

    [[nodiscard]] std::shared_ptr<publisher_session> find_publisher_by_stream_id(std::string_view stream_id) const;

    [[nodiscard]] std::shared_ptr<publisher_session> find_publisher_by_session_id(std::string_view session_id) const;

    [[nodiscard]] std::shared_ptr<subscriber_session> find_subscriber_by_session_id(std::string_view session_id) const;

    [[nodiscard]] std::optional<stream_session_kind> find_removed_session_kind(std::string_view session_id) const;

    [[nodiscard]] remove_session_result remove_publisher_session(std::string_view session_id);

    [[nodiscard]] remove_session_result remove_subscriber_session(std::string_view session_id);

    [[nodiscard]]
    std::vector<stream_session_lifecycle_snapshot> session_lifecycle_snapshots() const;

   private:
    struct removed_session_tombstone
    {
        stream_session_kind kind = stream_session_kind::publisher;
        uint64_t removed_at_milliseconds = 0;
    };

    [[nodiscard]]
    bool is_removed_session_tombstone_expired_locked(const removed_session_tombstone& tombstone, uint64_t current_time_milliseconds) const;

    void remember_removed_session_locked(stream_session_kind kind, std::string_view session_id);

    void prune_removed_session_tombstones_locked(uint64_t current_time_milliseconds);

    [[nodiscard]] std::string make_unique_session_id_locked() const;
    [[nodiscard]] static uint64_t now_milliseconds();

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, std::shared_ptr<publisher_session>> publishers_by_stream_id_;
    std::unordered_map<std::string, std::shared_ptr<publisher_session>> publishers_by_session_id_;
    std::unordered_map<std::string, std::shared_ptr<subscriber_session>> subscribers_by_session_id_;
    std::unordered_map<std::string, std::unordered_set<std::string>> subscriber_session_ids_by_stream_id_;
    std::unordered_map<std::string, removed_session_tombstone> removed_session_tombstones_by_session_id_;
};
}    // namespace webrtc

#endif
