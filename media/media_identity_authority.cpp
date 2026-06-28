#include "media/media_identity_authority.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }
}    // namespace

media_identity_result media_identity_authority::remember_track_resolution(const media_track_resolution& resolution, bool rtx)
{
    if (!resolution.resolved)
    {
        return make_error("media identity track resolution is unresolved");
    }

    media_identity_track_binding binding;

    binding.stream_id = resolution.stream_id;

    binding.session_id = resolution.session_id;

    binding.remote_endpoint = resolution.remote_endpoint;

    binding.mid = resolution.mid;

    binding.kind = resolution.kind;

    binding.rid = resolution.rid;

    binding.repaired_rid = resolution.repaired_rid;

    binding.ssrc = resolution.ssrc;

    binding.payload_type = resolution.payload_type;

    binding.rtx = rtx;

    binding.packet_count = 1;

    auto validation_result = validate_track_binding(binding);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    std::lock_guard lock(mutex_);

    const std::string key = make_peer_ssrc_key(binding.remote_endpoint, binding.ssrc);

    auto iterator = tracks_by_peer_ssrc_.find(key);

    if (iterator == tracks_by_peer_ssrc_.end())
    {
        tracks_by_peer_ssrc_.emplace(key, std::move(binding));

        return {};
    }

    if (iterator->second.stream_id != binding.stream_id || iterator->second.session_id != binding.session_id || iterator->second.mid != binding.mid ||
        iterator->second.kind != binding.kind || iterator->second.payload_type != binding.payload_type || iterator->second.rtx != binding.rtx)
    {
        return make_error("media identity track binding conflict");
    }

    iterator->second.rid = binding.rid;

    iterator->second.repaired_rid = binding.repaired_rid;

    iterator->second.packet_count += 1;

    return {};
}

media_identity_result media_identity_authority::remember_forward_mapping(const media_ssrc_mapping& ssrc_mapping,
                                                                         const media_payload_type_mapping& payload_mapping)
{
    media_identity_forward_binding binding;

    binding.stream_id = ssrc_mapping.stream_id;

    binding.publisher_session_id = ssrc_mapping.publisher_session_id;

    binding.subscriber_session_id = ssrc_mapping.subscriber_session_id;

    binding.publisher_mid = ssrc_mapping.publisher_mid;

    binding.subscriber_mid = ssrc_mapping.subscriber_mid;

    binding.kind = ssrc_mapping.kind;

    binding.publisher_ssrc = ssrc_mapping.publisher_ssrc;

    binding.subscriber_ssrc = ssrc_mapping.subscriber_ssrc;

    binding.publisher_payload_type = payload_mapping.publisher_payload_type;

    binding.subscriber_payload_type = payload_mapping.subscriber_payload_type;

    binding.rtx = ssrc_mapping.rtx || payload_mapping.rtx;

    binding.publisher_apt_payload_type = payload_mapping.publisher_apt_payload_type;

    binding.subscriber_apt_payload_type = payload_mapping.subscriber_apt_payload_type;

    binding.publisher_rtx_primary_ssrc = ssrc_mapping.publisher_rtx_primary_ssrc;

    binding.publisher_rtx_repair_ssrc = ssrc_mapping.publisher_rtx_repair_ssrc;

    binding.payload_type_rewrite_required = payload_mapping.payload_type_rewrite_required;

    binding.mid_rewrite_required = payload_mapping.mid_rewrite_required;

    binding.ssrc_rewrite_required = media_ssrc_mapping_requires_rewrite(ssrc_mapping);

    auto validation_result = validate_forward_binding(binding);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    if (payload_mapping.stream_id != binding.stream_id || payload_mapping.publisher_mid != binding.publisher_mid ||
        payload_mapping.subscriber_mid != binding.subscriber_mid || payload_mapping.kind != binding.kind)
    {
        return make_error("media identity forward mapping payload identity mismatched");
    }

    if (ssrc_mapping.rtx != payload_mapping.rtx)
    {
        return make_error("media identity forward mapping rtx state mismatched");
    }

    std::lock_guard lock(mutex_);

    const std::string publisher_key = make_publisher_forward_key(
        binding.stream_id, binding.publisher_session_id, binding.subscriber_session_id, binding.publisher_mid, binding.publisher_ssrc);

    const std::string subscriber_key = make_subscriber_forward_key(binding.subscriber_session_id, binding.subscriber_ssrc);

    auto subscriber_iterator = publisher_key_by_subscriber_key_.find(subscriber_key);

    if (subscriber_iterator != publisher_key_by_subscriber_key_.end() && subscriber_iterator->second != publisher_key)
    {
        return make_error("media identity forward mapping subscriber ssrc conflict");
    }

    auto publisher_iterator = forwards_by_publisher_key_.find(publisher_key);

    if (publisher_iterator != forwards_by_publisher_key_.end())
    {
        if (publisher_iterator->second.subscriber_ssrc != binding.subscriber_ssrc ||
            publisher_iterator->second.publisher_payload_type != binding.publisher_payload_type ||
            publisher_iterator->second.subscriber_payload_type != binding.subscriber_payload_type || publisher_iterator->second.rtx != binding.rtx)
        {
            return make_error("media identity forward mapping publisher identity conflict");
        }

        publisher_iterator->second.packet_count += 1;

        return {};
    }

    forwards_by_publisher_key_.emplace(publisher_key, std::move(binding));

    publisher_key_by_subscriber_key_[subscriber_key] = publisher_key;

    return {};
}

std::optional<media_identity_track_binding> media_identity_authority::find_track_by_peer_ssrc(std::string_view remote_endpoint, uint32_t ssrc) const
{
    if (remote_endpoint.empty() || ssrc == 0)
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const std::string key = make_peer_ssrc_key(remote_endpoint, ssrc);

    const auto iterator = tracks_by_peer_ssrc_.find(key);

    if (iterator == tracks_by_peer_ssrc_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::optional<media_identity_forward_binding> media_identity_authority::find_forward_by_publisher_ssrc(std::string_view stream_id,
                                                                                                       std::string_view publisher_session_id,
                                                                                                       std::string_view subscriber_session_id,
                                                                                                       std::string_view publisher_mid,
                                                                                                       uint32_t publisher_ssrc) const
{
    if (stream_id.empty() || publisher_session_id.empty() || subscriber_session_id.empty() || publisher_mid.empty() || publisher_ssrc == 0)
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const std::string key = make_publisher_forward_key(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, publisher_ssrc);

    const auto iterator = forwards_by_publisher_key_.find(key);

    if (iterator == forwards_by_publisher_key_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::optional<media_identity_forward_binding> media_identity_authority::find_forward_by_subscriber_ssrc(std::string_view subscriber_session_id,
                                                                                                        uint32_t subscriber_ssrc) const
{
    if (subscriber_session_id.empty() || subscriber_ssrc == 0)
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const std::string subscriber_key = make_subscriber_forward_key(subscriber_session_id, subscriber_ssrc);

    const auto key_iterator = publisher_key_by_subscriber_key_.find(subscriber_key);

    if (key_iterator == publisher_key_by_subscriber_key_.end())
    {
        return std::nullopt;
    }

    const auto mapping_iterator = forwards_by_publisher_key_.find(key_iterator->second);

    if (mapping_iterator == forwards_by_publisher_key_.end())
    {
        return std::nullopt;
    }

    return mapping_iterator->second;
}

void media_identity_authority::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = tracks_by_peer_ssrc_.begin(); iterator != tracks_by_peer_ssrc_.end();)
    {
        if (iterator->second.remote_endpoint == remote_endpoint)
        {
            iterator = tracks_by_peer_ssrc_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void media_identity_authority::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = tracks_by_peer_ssrc_.begin(); iterator != tracks_by_peer_ssrc_.end();)
    {
        if (iterator->second.session_id == session_id)
        {
            iterator = tracks_by_peer_ssrc_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    for (auto iterator = forwards_by_publisher_key_.begin(); iterator != forwards_by_publisher_key_.end();)
    {
        if (iterator->second.publisher_session_id == session_id || iterator->second.subscriber_session_id == session_id)
        {
            const std::string subscriber_key = make_subscriber_forward_key(iterator->second.subscriber_session_id, iterator->second.subscriber_ssrc);

            publisher_key_by_subscriber_key_.erase(subscriber_key);

            iterator = forwards_by_publisher_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void media_identity_authority::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = tracks_by_peer_ssrc_.begin(); iterator != tracks_by_peer_ssrc_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = tracks_by_peer_ssrc_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    for (auto iterator = forwards_by_publisher_key_.begin(); iterator != forwards_by_publisher_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            const std::string subscriber_key = make_subscriber_forward_key(iterator->second.subscriber_session_id, iterator->second.subscriber_ssrc);

            publisher_key_by_subscriber_key_.erase(subscriber_key);

            iterator = forwards_by_publisher_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void media_identity_authority::clear()
{
    std::lock_guard lock(mutex_);

    tracks_by_peer_ssrc_.clear();

    forwards_by_publisher_key_.clear();

    publisher_key_by_subscriber_key_.clear();
}

std::size_t media_identity_authority::track_binding_count() const
{
    std::lock_guard lock(mutex_);

    return tracks_by_peer_ssrc_.size();
}

std::size_t media_identity_authority::forward_binding_count() const
{
    std::lock_guard lock(mutex_);

    return forwards_by_publisher_key_.size();
}

std::string media_identity_authority::make_peer_ssrc_key(std::string_view remote_endpoint, uint32_t ssrc)
{
    std::string key;

    key.reserve(remote_endpoint.size() + 16);

    key.append(remote_endpoint);

    key.push_back('|');

    key.append(std::to_string(ssrc));

    return key;
}

std::string media_identity_authority::make_publisher_forward_key(std::string_view stream_id,
                                                                 std::string_view publisher_session_id,
                                                                 std::string_view subscriber_session_id,
                                                                 std::string_view publisher_mid,
                                                                 uint32_t publisher_ssrc)
{
    std::string key;

    key.reserve(stream_id.size() + publisher_session_id.size() + subscriber_session_id.size() + publisher_mid.size() + 48);

    key.append(stream_id);

    key.push_back('|');

    key.append(publisher_session_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(publisher_mid);

    key.push_back('|');

    key.append(std::to_string(publisher_ssrc));

    return key;
}

std::string media_identity_authority::make_subscriber_forward_key(std::string_view subscriber_session_id, uint32_t subscriber_ssrc)
{
    std::string key;

    key.reserve(subscriber_session_id.size() + 16);

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(std::to_string(subscriber_ssrc));

    return key;
}

media_identity_result media_identity_authority::validate_track_binding(const media_identity_track_binding& binding)
{
    if (binding.stream_id.empty())
    {
        return make_error("media identity track stream id is empty");
    }

    if (binding.session_id.empty())
    {
        return make_error("media identity track session id is empty");
    }

    if (binding.remote_endpoint.empty())
    {
        return make_error("media identity track remote endpoint is empty");
    }

    if (binding.mid.empty())
    {
        return make_error("media identity track mid is empty");
    }

    if (binding.kind.empty())
    {
        return make_error("media identity track kind is empty");
    }

    if (binding.ssrc == 0)
    {
        return make_error("media identity track ssrc is zero");
    }

    if (binding.payload_type == 0)
    {
        return make_error("media identity track payload type is zero");
    }

    if (binding.rtx && !binding.repaired_rid.has_value())
    {
        /*
         * Not every browser sends repaired-rid, so do not reject here.
         * RTX identity is still carried by payload type / SSRC mapping.
         */
    }

    return {};
}

media_identity_result media_identity_authority::validate_forward_binding(const media_identity_forward_binding& binding)
{
    if (binding.stream_id.empty())
    {
        return make_error("media identity forward stream id is empty");
    }

    if (binding.publisher_session_id.empty())
    {
        return make_error("media identity forward publisher session id is empty");
    }

    if (binding.subscriber_session_id.empty())
    {
        return make_error("media identity forward subscriber session id is empty");
    }

    if (binding.publisher_mid.empty())
    {
        return make_error("media identity forward publisher mid is empty");
    }

    if (binding.subscriber_mid.empty())
    {
        return make_error("media identity forward subscriber mid is empty");
    }

    if (binding.kind.empty())
    {
        return make_error("media identity forward kind is empty");
    }

    if (binding.publisher_ssrc == 0)
    {
        return make_error("media identity forward publisher ssrc is zero");
    }

    if (binding.subscriber_ssrc == 0)
    {
        return make_error("media identity forward subscriber ssrc is zero");
    }

    if (binding.publisher_payload_type == 0)
    {
        return make_error("media identity forward publisher payload type is zero");
    }

    if (binding.subscriber_payload_type == 0)
    {
        return make_error("media identity forward subscriber payload type is zero");
    }

    if (binding.rtx && (binding.publisher_apt_payload_type == 0 || binding.subscriber_apt_payload_type == 0))
    {
        return make_error("media identity forward rtx apt payload type is zero");
    }

    if (binding.rtx && binding.publisher_rtx_primary_ssrc == 0)
    {
        return make_error("media identity forward rtx primary ssrc is zero");
    }

    return {};
}

std::string media_identity_track_binding_to_string(const media_identity_track_binding& binding)
{
    std::string result;

    result.reserve(192);

    result.append("stream=");

    result.append(binding.stream_id);

    result.append(" session=");

    result.append(binding.session_id);

    result.append(" remote=");

    result.append(binding.remote_endpoint);

    result.append(" mid=");

    result.append(binding.mid);

    result.append(" kind=");

    result.append(binding.kind);

    result.append(" ssrc=");

    result.append(std::to_string(binding.ssrc));

    result.append(" pt=");

    result.append(std::to_string(binding.payload_type));

    result.append(" rtx=");

    result.append(binding.rtx ? "1" : "0");

    if (binding.rid.has_value())
    {
        result.append(" rid=");

        result.append(*binding.rid);
    }

    if (binding.repaired_rid.has_value())
    {
        result.append(" repaired_rid=");

        result.append(*binding.repaired_rid);
    }

    return result;
}

std::string media_identity_forward_binding_to_string(const media_identity_forward_binding& binding)
{
    std::string result;

    result.reserve(256);

    result.append("stream=");

    result.append(binding.stream_id);

    result.append(" publisher_session=");

    result.append(binding.publisher_session_id);

    result.append(" subscriber_session=");

    result.append(binding.subscriber_session_id);

    result.append(" publisher_mid=");

    result.append(binding.publisher_mid);

    result.append(" subscriber_mid=");

    result.append(binding.subscriber_mid);

    result.append(" kind=");

    result.append(binding.kind);

    result.append(" publisher_ssrc=");

    result.append(std::to_string(binding.publisher_ssrc));

    result.append(" subscriber_ssrc=");

    result.append(std::to_string(binding.subscriber_ssrc));

    result.append(" publisher_pt=");

    result.append(std::to_string(binding.publisher_payload_type));

    result.append(" subscriber_pt=");

    result.append(std::to_string(binding.subscriber_payload_type));

    result.append(" rtx=");

    result.append(binding.rtx ? "1" : "0");

    if (binding.rtx)
    {
        result.append(" publisher_apt=");

        result.append(std::to_string(binding.publisher_apt_payload_type));

        result.append(" subscriber_apt=");

        result.append(std::to_string(binding.subscriber_apt_payload_type));

        result.append(" publisher_rtx_primary_ssrc=");

        result.append(std::to_string(binding.publisher_rtx_primary_ssrc));

        result.append(" publisher_rtx_repair_ssrc=");

        result.append(std::to_string(binding.publisher_rtx_repair_ssrc));
    }

    return result;
}
}    // namespace webrtc
