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
media_ssrc_mapping make_ssrc_mapping_from_forward_binding(const media_identity_forward_binding& binding)
{
    media_ssrc_mapping mapping;

    mapping.stream_id = binding.stream_id;

    mapping.publisher_session_id = binding.publisher_session_id;

    mapping.subscriber_session_id = binding.subscriber_session_id;

    mapping.publisher_mid = binding.publisher_mid;

    mapping.subscriber_mid = binding.subscriber_mid;

    mapping.kind = binding.kind;

    mapping.rtx = binding.rtx;

    mapping.publisher_rtx_primary_ssrc = binding.publisher_rtx_primary_ssrc;

    mapping.publisher_rtx_repair_ssrc = binding.publisher_rtx_repair_ssrc;

    mapping.publisher_ssrc = binding.publisher_ssrc;

    mapping.subscriber_ssrc = binding.subscriber_ssrc;

    mapping.packet_count = binding.packet_count;

    return mapping;
}
}    // namespace

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
std::optional<media_identity_rid_layer_binding> media_identity_authority::find_rid_layer_by_rid(std::string_view stream_id,
                                                                                                std::string_view session_id,
                                                                                                std::string_view mid,
                                                                                                std::string_view rid) const
{
    if (stream_id.empty() || session_id.empty() || mid.empty() || rid.empty())
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const std::string key = make_rid_layer_key(stream_id, session_id, mid, rid);

    const auto iterator = rid_layers_by_key_.find(key);

    if (iterator == rid_layers_by_key_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::optional<media_identity_rid_layer_binding> media_identity_authority::find_preferred_rid_layer(
    std::string_view stream_id, std::string_view session_id, std::string_view mid, const std::vector<std::string>& preferred_rids) const
{
    if (stream_id.empty() || session_id.empty() || mid.empty() || preferred_rids.empty())
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    for (const auto& rid : preferred_rids)
    {
        if (rid.empty())
        {
            continue;
        }

        const std::string key = make_rid_layer_key(stream_id, session_id, mid, rid);

        const auto iterator = rid_layers_by_key_.find(key);

        if (iterator == rid_layers_by_key_.end())
        {
            continue;
        }

        return iterator->second;
    }

    return std::nullopt;
}

std::optional<media_identity_rid_layer_binding> media_identity_authority::find_rid_layer_by_primary_ssrc(std::string_view session_id,
                                                                                                         uint32_t primary_ssrc) const
{
    if (session_id.empty() || primary_ssrc == 0)
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const std::string ssrc_key = make_session_ssrc_key(session_id, primary_ssrc);

    const auto key_iterator = rid_layer_key_by_primary_ssrc_key_.find(ssrc_key);

    if (key_iterator == rid_layer_key_by_primary_ssrc_key_.end())
    {
        return std::nullopt;
    }

    const auto layer_iterator = rid_layers_by_key_.find(key_iterator->second);

    if (layer_iterator == rid_layers_by_key_.end())
    {
        return std::nullopt;
    }

    return layer_iterator->second;
}

std::optional<media_identity_rid_layer_binding> media_identity_authority::find_rid_layer_by_repair_ssrc(std::string_view session_id,
                                                                                                        uint32_t repair_ssrc) const
{
    if (session_id.empty() || repair_ssrc == 0)
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const std::string ssrc_key = make_session_ssrc_key(session_id, repair_ssrc);

    const auto key_iterator = rid_layer_key_by_repair_ssrc_key_.find(ssrc_key);

    if (key_iterator == rid_layer_key_by_repair_ssrc_key_.end())
    {
        return std::nullopt;
    }

    const auto layer_iterator = rid_layers_by_key_.find(key_iterator->second);

    if (layer_iterator == rid_layers_by_key_.end())
    {
        return std::nullopt;
    }

    return layer_iterator->second;
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
std::optional<media_ssrc_mapping> media_identity_authority::find_ssrc_mapping_by_publisher_ssrc(std::string_view stream_id,
                                                                                                std::string_view publisher_session_id,
                                                                                                std::string_view subscriber_session_id,
                                                                                                std::string_view publisher_mid,
                                                                                                uint32_t publisher_ssrc) const
{
    auto binding = find_forward_by_publisher_ssrc(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, publisher_ssrc);

    if (!binding.has_value())
    {
        return std::nullopt;
    }

    return make_ssrc_mapping_from_forward_binding(*binding);
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
std::optional<media_ssrc_mapping> media_identity_authority::find_ssrc_mapping_by_subscriber_ssrc(std::string_view subscriber_session_id,
                                                                                                 uint32_t subscriber_ssrc) const
{
    auto binding = find_forward_by_subscriber_ssrc(subscriber_session_id, subscriber_ssrc);

    if (!binding.has_value())
    {
        return std::nullopt;
    }

    return make_ssrc_mapping_from_forward_binding(*binding);
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
    for (auto iterator = rid_layers_by_key_.begin(); iterator != rid_layers_by_key_.end();)
    {
        if (iterator->second.remote_endpoint == remote_endpoint)
        {
            erase_rid_layer_indexes_locked(iterator->second);

            iterator = rid_layers_by_key_.erase(iterator);

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
    for (auto iterator = rid_layers_by_key_.begin(); iterator != rid_layers_by_key_.end();)
    {
        if (iterator->second.session_id == session_id)
        {
            erase_rid_layer_indexes_locked(iterator->second);

            iterator = rid_layers_by_key_.erase(iterator);

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

    for (auto iterator = rid_layers_by_key_.begin(); iterator != rid_layers_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            erase_rid_layer_indexes_locked(iterator->second);

            iterator = rid_layers_by_key_.erase(iterator);

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
    rid_layers_by_key_.clear();
    rid_layer_key_by_primary_ssrc_key_.clear();
    rid_layer_key_by_repair_ssrc_key_.clear();
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

std::size_t media_identity_authority::rid_layer_binding_count() const
{
    std::lock_guard lock(mutex_);
    return rid_layers_by_key_.size();
}
std::vector<media_identity_track_binding> media_identity_authority::track_binding_snapshot() const
{
    std::vector<media_identity_track_binding> snapshot;

    std::lock_guard lock(mutex_);

    snapshot.reserve(tracks_by_peer_ssrc_.size());

    for (const auto& [key, binding] : tracks_by_peer_ssrc_)
    {
        (void)key;

        snapshot.push_back(binding);
    }

    return snapshot;
}

std::vector<media_identity_rid_layer_binding> media_identity_authority::rid_layer_binding_snapshot() const
{
    std::vector<media_identity_rid_layer_binding> snapshot;

    std::lock_guard lock(mutex_);

    snapshot.reserve(rid_layers_by_key_.size());

    for (const auto& [key, binding] : rid_layers_by_key_)
    {
        (void)key;

        snapshot.push_back(binding);
    }

    return snapshot;
}

std::vector<media_identity_forward_binding> media_identity_authority::forward_binding_snapshot() const
{
    std::vector<media_identity_forward_binding> snapshot;

    std::lock_guard lock(mutex_);

    snapshot.reserve(forwards_by_publisher_key_.size());

    for (const auto& [key, binding] : forwards_by_publisher_key_)
    {
        (void)key;

        snapshot.push_back(binding);
    }

    return snapshot;
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
std::string media_identity_authority::make_rid_layer_key(std::string_view stream_id,
                                                         std::string_view session_id,
                                                         std::string_view mid,
                                                         std::string_view rid)
{
    std::string key;

    key.reserve(stream_id.size() + session_id.size() + mid.size() + rid.size() + 4);

    key.append(stream_id);

    key.push_back('|');

    key.append(session_id);

    key.push_back('|');

    key.append(mid);

    key.push_back('|');

    key.append(rid);

    return key;
}

std::string media_identity_authority::make_session_ssrc_key(std::string_view session_id, uint32_t ssrc)
{
    std::string key;

    key.reserve(session_id.size() + 16);

    key.append(session_id);

    key.push_back('|');

    key.append(std::to_string(ssrc));

    return key;
}
std::string make_track_identity_key(std::string_view stream_id,
                                    std::string_view session_id,
                                    std::string_view mid,
                                    std::string_view kind,
                                    const std::optional<std::string>& rid,
                                    const std::optional<std::string>& repaired_rid,
                                    uint32_t ssrc,
                                    bool rtx)
{
    std::string key;

    key.reserve(stream_id.size() + session_id.size() + mid.size() + kind.size() + 96);

    key.append(stream_id);

    key.push_back('|');

    key.append(session_id);

    key.push_back('|');

    key.append(mid);

    key.push_back('|');

    key.append(kind);

    key.push_back('|');

    key.append(rtx ? "rtx" : "media");

    key.push_back('|');

    if (rtx && repaired_rid.has_value() && !repaired_rid->empty())
    {
        key.append("repaired-rid:");

        key.append(*repaired_rid);
    }
    else if (!rtx && rid.has_value() && !rid->empty())
    {
        key.append("rid:");

        key.append(*rid);
    }
    else
    {
        key.append("ssrc:");

        key.append(std::to_string(ssrc));
    }

    return key;
}

std::string make_ssrc_track_identity_key(
    std::string_view stream_id, std::string_view session_id, std::string_view mid, std::string_view kind, uint32_t ssrc, bool rtx)
{
    return make_track_identity_key(stream_id, session_id, mid, kind, std::nullopt, std::nullopt, ssrc, rtx);
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

    binding.publisher_track_key = make_ssrc_track_identity_key(
        binding.stream_id, binding.publisher_session_id, binding.publisher_mid, binding.kind, binding.publisher_ssrc, binding.rtx);

    binding.subscriber_track_key = make_ssrc_track_identity_key(
        binding.stream_id, binding.subscriber_session_id, binding.subscriber_mid, binding.kind, binding.subscriber_ssrc, binding.rtx);

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
            publisher_iterator->second.subscriber_payload_type != binding.subscriber_payload_type || publisher_iterator->second.rtx != binding.rtx ||
            publisher_iterator->second.publisher_track_key != binding.publisher_track_key ||
            publisher_iterator->second.subscriber_track_key != binding.subscriber_track_key)
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

    binding.track_key = make_track_identity_key(
        binding.stream_id, binding.session_id, binding.mid, binding.kind, binding.rid, binding.repaired_rid, binding.ssrc, binding.rtx);

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
        auto rid_layer_result = remember_rid_layer_binding_locked(resolution, binding);

        if (!rid_layer_result)
        {
            return std::unexpected(rid_layer_result.error());
        }

        tracks_by_peer_ssrc_.emplace(key, std::move(binding));

        return {};
    }

    if (iterator->second.stream_id != binding.stream_id || iterator->second.session_id != binding.session_id ||
        iterator->second.remote_endpoint != binding.remote_endpoint || iterator->second.track_key != binding.track_key ||
        iterator->second.mid != binding.mid || iterator->second.kind != binding.kind || iterator->second.payload_type != binding.payload_type ||
        iterator->second.rtx != binding.rtx)
    {
        return make_error("media identity track binding conflict");
    }

    iterator->second.rid = binding.rid;

    iterator->second.repaired_rid = binding.repaired_rid;

    iterator->second.packet_count += 1;

    auto rid_layer_result = remember_rid_layer_binding_locked(resolution, iterator->second);

    if (!rid_layer_result)
    {
        return std::unexpected(rid_layer_result.error());
    }

    return {};
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

    if (binding.track_key.empty())
    {
        return make_error("media identity track key is empty");
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

    if (binding.publisher_track_key.empty())
    {
        return make_error("media identity forward publisher track key is empty");
    }

    if (binding.subscriber_track_key.empty())
    {
        return make_error("media identity forward subscriber track key is empty");
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

media_identity_result media_identity_authority::validate_rid_layer_binding(const media_identity_rid_layer_binding& binding)
{
    if (binding.stream_id.empty())
    {
        return make_error("media identity rid layer stream id is empty");
    }

    if (binding.session_id.empty())
    {
        return make_error("media identity rid layer session id is empty");
    }

    if (binding.remote_endpoint.empty())
    {
        return make_error("media identity rid layer remote endpoint is empty");
    }

    if (binding.mid.empty())
    {
        return make_error("media identity rid layer mid is empty");
    }

    if (binding.kind.empty())
    {
        return make_error("media identity rid layer kind is empty");
    }

    if (binding.rid.empty())
    {
        return make_error("media identity rid layer rid is empty");
    }

    if (binding.primary_ssrc == 0 && binding.repair_ssrc == 0)
    {
        return make_error("media identity rid layer has no ssrc");
    }

    /*
     * RTX repair packets can arrive before the primary RTP packet for the
     * same RID layer. In that case the layer may already know the primary
     * SSRC from the RTX OSN/apt binding, while the primary payload type is
     * still unknown. Keep the layer valid as long as the repair side is
     * complete; the primary payload type will be filled once primary RTP
     * for the same RID arrives.
     */
    if (binding.primary_ssrc != 0 && binding.primary_payload_type == 0 && binding.repair_ssrc == 0)
    {
        return make_error("media identity rid layer primary payload type is zero");
    }

    if (binding.repair_ssrc != 0 && binding.repair_payload_type == 0)
    {
        return make_error("media identity rid layer repair payload type is zero");
    }

    return {};
}

void media_identity_authority::erase_rid_layer_indexes_locked(const media_identity_rid_layer_binding& binding)
{
    if (binding.primary_ssrc != 0)
    {
        rid_layer_key_by_primary_ssrc_key_.erase(make_session_ssrc_key(binding.session_id, binding.primary_ssrc));
    }

    if (binding.repair_ssrc != 0)
    {
        rid_layer_key_by_repair_ssrc_key_.erase(make_session_ssrc_key(binding.session_id, binding.repair_ssrc));
    }
}

media_identity_result media_identity_authority::remember_rid_layer_binding_locked(const media_track_resolution& resolution,
                                                                                  const media_identity_track_binding& track_binding)
{
    std::optional<std::string> rid;

    if (!track_binding.rtx && track_binding.rid.has_value() && !track_binding.rid->empty())
    {
        rid = track_binding.rid;
    }
    else if (track_binding.rtx && track_binding.repaired_rid.has_value() && !track_binding.repaired_rid->empty())
    {
        rid = track_binding.repaired_rid;
    }
    else if (track_binding.rtx && resolution.rtx_primary_ssrc != 0)
    {
        const std::string primary_ssrc_key = make_session_ssrc_key(track_binding.session_id, resolution.rtx_primary_ssrc);

        const auto primary_iterator = rid_layer_key_by_primary_ssrc_key_.find(primary_ssrc_key);

        if (primary_iterator != rid_layer_key_by_primary_ssrc_key_.end())
        {
            const auto layer_iterator = rid_layers_by_key_.find(primary_iterator->second);

            if (layer_iterator != rid_layers_by_key_.end())
            {
                rid = layer_iterator->second.rid;
            }
        }
    }

    if (!rid.has_value() && track_binding.rtx && track_binding.ssrc != 0)
    {
        const std::string repair_ssrc_key = make_session_ssrc_key(track_binding.session_id, track_binding.ssrc);

        const auto repair_iterator = rid_layer_key_by_repair_ssrc_key_.find(repair_ssrc_key);

        if (repair_iterator != rid_layer_key_by_repair_ssrc_key_.end())
        {
            const auto layer_iterator = rid_layers_by_key_.find(repair_iterator->second);

            if (layer_iterator != rid_layers_by_key_.end())
            {
                rid = layer_iterator->second.rid;
            }
        }
    }

    if (!rid.has_value() || rid->empty())
    {
        return {};
    }

    const std::string layer_key = make_rid_layer_key(track_binding.stream_id, track_binding.session_id, track_binding.mid, *rid);

    media_identity_rid_layer_binding next_binding;

    next_binding.stream_id = track_binding.stream_id;

    next_binding.session_id = track_binding.session_id;

    next_binding.remote_endpoint = track_binding.remote_endpoint;

    next_binding.mid = track_binding.mid;

    next_binding.kind = track_binding.kind;

    next_binding.rid = *rid;

    if (track_binding.rtx)
    {
        next_binding.primary_ssrc = resolution.rtx_primary_ssrc;

        next_binding.repair_ssrc = track_binding.ssrc;

        next_binding.repair_payload_type = track_binding.payload_type;
    }
    else
    {
        next_binding.primary_ssrc = track_binding.ssrc;

        next_binding.primary_payload_type = track_binding.payload_type;
    }

    next_binding.packet_count = 1;

    auto iterator = rid_layers_by_key_.find(layer_key);

    if (iterator != rid_layers_by_key_.end())
    {
        media_identity_rid_layer_binding& current = iterator->second;

        if (current.stream_id != next_binding.stream_id || current.session_id != next_binding.session_id ||
            current.remote_endpoint != next_binding.remote_endpoint || current.mid != next_binding.mid || current.kind != next_binding.kind ||
            current.rid != next_binding.rid)
        {
            return make_error("media identity rid layer binding identity conflict");
        }

        if (next_binding.primary_ssrc != 0)
        {
            if (current.primary_ssrc != 0 && current.primary_ssrc != next_binding.primary_ssrc)
            {
                return make_error("media identity rid layer primary ssrc conflict");
            }

            current.primary_ssrc = next_binding.primary_ssrc;

            if (next_binding.primary_payload_type != 0)
            {
                current.primary_payload_type = next_binding.primary_payload_type;
            }
        }

        if (next_binding.repair_ssrc != 0)
        {
            if (current.repair_ssrc != 0 && current.repair_ssrc != next_binding.repair_ssrc)
            {
                return make_error("media identity rid layer repair ssrc conflict");
            }

            if (next_binding.primary_ssrc != 0 && current.primary_ssrc != 0 && current.primary_ssrc != next_binding.primary_ssrc)
            {
                return make_error("media identity rid layer rtx primary ssrc conflict");
            }

            if (current.primary_ssrc == 0)
            {
                current.primary_ssrc = next_binding.primary_ssrc;
            }

            current.repair_ssrc = next_binding.repair_ssrc;

            current.repair_payload_type = next_binding.repair_payload_type;
        }

        current.packet_count += 1;

        auto validation_result = validate_rid_layer_binding(current);

        if (!validation_result)
        {
            return std::unexpected(validation_result.error());
        }

        if (current.primary_ssrc != 0)
        {
            const std::string primary_ssrc_key = make_session_ssrc_key(current.session_id, current.primary_ssrc);

            const auto [index_iterator, inserted] = rid_layer_key_by_primary_ssrc_key_.try_emplace(primary_ssrc_key, layer_key);

            if (!inserted && index_iterator->second != layer_key)
            {
                return make_error("media identity rid layer primary ssrc index conflict");
            }
        }

        if (current.repair_ssrc != 0)
        {
            const std::string repair_ssrc_key = make_session_ssrc_key(current.session_id, current.repair_ssrc);

            const auto [index_iterator, inserted] = rid_layer_key_by_repair_ssrc_key_.try_emplace(repair_ssrc_key, layer_key);

            if (!inserted && index_iterator->second != layer_key)
            {
                return make_error("media identity rid layer repair ssrc index conflict");
            }
        }

        return {};
    }

    auto validation_result = validate_rid_layer_binding(next_binding);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    if (next_binding.primary_ssrc != 0)
    {
        const std::string primary_ssrc_key = make_session_ssrc_key(next_binding.session_id, next_binding.primary_ssrc);

        const auto [index_iterator, inserted] = rid_layer_key_by_primary_ssrc_key_.try_emplace(primary_ssrc_key, layer_key);

        if (!inserted && index_iterator->second != layer_key)
        {
            return make_error("media identity rid layer primary ssrc index conflict");
        }
    }

    if (next_binding.repair_ssrc != 0)
    {
        const std::string repair_ssrc_key = make_session_ssrc_key(next_binding.session_id, next_binding.repair_ssrc);

        const auto [index_iterator, inserted] = rid_layer_key_by_repair_ssrc_key_.try_emplace(repair_ssrc_key, layer_key);

        if (!inserted && index_iterator->second != layer_key)
        {
            return make_error("media identity rid layer repair ssrc index conflict");
        }
    }

    rid_layers_by_key_.emplace(layer_key, std::move(next_binding));

    return {};
}

std::string media_identity_track_binding_to_string(const media_identity_track_binding& binding)
{
    std::string result;

    result.reserve(256);

    result.append("stream=");

    result.append(binding.stream_id);

    result.append(" session=");

    result.append(binding.session_id);

    result.append(" remote=");

    result.append(binding.remote_endpoint);

    result.append(" track_key=");

    result.append(binding.track_key);

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

std::string media_identity_rid_layer_binding_to_string(const media_identity_rid_layer_binding& binding)
{
    std::string result;

    result.reserve(256);

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

    result.append(" rid=");

    result.append(binding.rid);

    result.append(" primary_ssrc=");

    result.append(std::to_string(binding.primary_ssrc));

    result.append(" repair_ssrc=");

    result.append(std::to_string(binding.repair_ssrc));

    result.append(" primary_pt=");

    result.append(std::to_string(binding.primary_payload_type));

    result.append(" repair_pt=");

    result.append(std::to_string(binding.repair_payload_type));

    return result;
}

std::string media_identity_forward_binding_to_string(const media_identity_forward_binding& binding)
{
    std::string result;

    result.reserve(384);

    result.append("stream=");

    result.append(binding.stream_id);

    result.append(" publisher_session=");

    result.append(binding.publisher_session_id);

    result.append(" subscriber_session=");

    result.append(binding.subscriber_session_id);

    result.append(" publisher_track_key=");

    result.append(binding.publisher_track_key);

    result.append(" subscriber_track_key=");

    result.append(binding.subscriber_track_key);

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
