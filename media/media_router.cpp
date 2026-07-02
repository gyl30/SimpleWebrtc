#include "media/media_router.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "log/log.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
namespace
{
inline constexpr uint64_t k_media_stats_log_interval = 5000;
inline constexpr uint16_t k_rtp_sequence_wrap_low_threshold = 1000;
inline constexpr uint16_t k_rtp_sequence_wrap_high_threshold = 64535;
inline constexpr uint64_t k_ntp_unix_epoch_offset_seconds = 2208988800ULL;
inline constexpr uint64_t k_ntp_fraction_units_per_second = 65536ULL;

media_peer_info make_peer_info(media_peer_role role, std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id)
{
    media_peer_info peer;
    peer.role = role;
    peer.remote_endpoint = std::string(remote_endpoint);
    peer.stream_id = std::string(stream_id);
    peer.session_id = std::string(session_id);
    return peer;
}

uint64_t get_total_inbound_packets(const media_peer_stats& stats) { return stats.inbound_rtp_packets + stats.inbound_rtcp_packets; }

uint64_t packet_plain_size(const srtp_packet_process_result& packet) { return static_cast<uint64_t>(packet.unprotected_size); }

uint16_t next_rtp_sequence_number(uint16_t sequence_number) { return static_cast<uint16_t>(sequence_number + 1U); }

int32_t rtp_sequence_delta(uint16_t sequence_number, uint16_t expected_sequence_number)
{
    const auto raw_delta = static_cast<uint16_t>(sequence_number - expected_sequence_number);
    if (raw_delta <= 0x7fffU)
    {
        return static_cast<int32_t>(raw_delta);
    }

    return static_cast<int32_t>(raw_delta) - 0x10000;
}

bool is_rtp_sequence_wrap(uint16_t previous_sequence_number, uint16_t current_sequence_number)
{
    return previous_sequence_number >= k_rtp_sequence_wrap_high_threshold && current_sequence_number <= k_rtp_sequence_wrap_low_threshold;
}
void remember_peer_rtp_sequence_summary(media_peer_stats& peer_stats, uint32_t ssrc, const media_rtp_sequence_state& sequence_state)
{
    peer_stats.has_rtp_sequence = sequence_state.has_sequence;
    peer_stats.expected_rtp_sequence_number = sequence_state.expected_sequence_number;
    peer_stats.last_rtp_ssrc = ssrc;
    peer_stats.last_rtp_sequence_number = sequence_state.last_sequence_number;
    peer_stats.last_rtp_timestamp = sequence_state.last_timestamp;
    peer_stats.last_rtp_payload_type = sequence_state.last_payload_type;
}

uint32_t current_ntp_compact()
{
    const auto now = std::chrono::system_clock::now();

    const auto duration = now.time_since_epoch();

    const uint64_t seconds = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(duration).count());

    const auto seconds_duration = std::chrono::seconds(seconds);

    const uint64_t fractional_microseconds =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds_duration).count());

    const uint64_t ntp_seconds = seconds + k_ntp_unix_epoch_offset_seconds;

    const uint64_t ntp_fraction = (fractional_microseconds * k_ntp_fraction_units_per_second) / 1000000ULL;

    return static_cast<uint32_t>(((ntp_seconds & 0xffffULL) << 16U) | (ntp_fraction & 0xffffULL));
}

std::optional<uint64_t> estimate_rtcp_rtt_ms(uint32_t last_sender_report, uint32_t delay_since_last_sender_report)
{
    if (last_sender_report == 0)
    {
        return std::nullopt;
    }

    const uint32_t now = current_ntp_compact();

    const uint32_t rtt_compact = now - last_sender_report - delay_since_last_sender_report;

    const uint64_t rtt_ms = (static_cast<uint64_t>(rtt_compact) * 1000ULL) / k_ntp_fraction_units_per_second;

    return rtt_ms;
}

void add_peer_to_snapshot(const media_peer_stats& peer, media_router_stats_snapshot& snapshot)
{
    snapshot.inbound_rtp_packets += peer.inbound_rtp_packets;
    snapshot.inbound_rtp_bytes += peer.inbound_rtp_bytes;
    snapshot.inbound_rtcp_packets += peer.inbound_rtcp_packets;
    snapshot.inbound_rtcp_bytes += peer.inbound_rtcp_bytes;

    snapshot.routed_target_packets += peer.routed_target_packets;
    snapshot.routed_target_bytes += peer.routed_target_bytes;

    snapshot.rtcp_feedback_packets += peer.rtcp_feedback_packets;
    snapshot.rtcp_report_packets += peer.rtcp_report_packets;
    snapshot.rtcp_report_blocks += peer.rtcp_report_blocks;
    snapshot.rtcp_nack_items += peer.rtcp_nack_items;
    snapshot.rtcp_fir_items += peer.rtcp_fir_items;
    snapshot.rtcp_keyframe_request_packets += peer.rtcp_keyframe_request_packets;
    snapshot.rtcp_generic_nack_packets += peer.rtcp_generic_nack_packets;
    snapshot.rtcp_transport_cc_packets += peer.rtcp_transport_cc_packets;
    snapshot.rtcp_remb_packets += peer.rtcp_remb_packets;

    snapshot.rtcp_rtt_sample_count += peer.rtcp_rtt_sample_count;
    snapshot.rtcp_rtt_sum_ms += peer.rtcp_rtt_sum_ms;

    if (peer.rtcp_last_rtt_ms != 0)
    {
        snapshot.rtcp_last_rtt_ms = peer.rtcp_last_rtt_ms;
    }

    if (peer.rtcp_max_rtt_ms > snapshot.rtcp_max_rtt_ms)
    {
        snapshot.rtcp_max_rtt_ms = peer.rtcp_max_rtt_ms;
    }

    snapshot.rtp_sequence_gap_events += peer.rtp_sequence_gap_events;
    snapshot.rtp_sequence_lost_packets += peer.rtp_sequence_lost_packets;
    snapshot.rtp_out_of_order_packets += peer.rtp_out_of_order_packets;
    snapshot.rtp_duplicate_packets += peer.rtp_duplicate_packets;
    snapshot.rtp_sequence_wraps += peer.rtp_sequence_wraps;
}

void finalize_snapshot(media_router_stats_snapshot& snapshot)
{
    if (snapshot.rtcp_rtt_sample_count == 0)
    {
        snapshot.rtcp_avg_rtt_ms = 0;
        return;
    }

    snapshot.rtcp_avg_rtt_ms = snapshot.rtcp_rtt_sum_ms / snapshot.rtcp_rtt_sample_count;
}
bool same_track_stats_key(const media_track_stats& stats, const media_peer_info& peer, const media_track_resolution& track_resolution)
{
    return stats.direction == "inbound" && stats.session_id == peer.session_id && stats.mid == track_resolution.mid &&
           stats.ssrc == track_resolution.ssrc;
}

bool same_outbound_track_stats_key(const media_track_stats& stats,
                                   const media_peer_info& peer,
                                   const media_ssrc_mapping& mapping,
                                   uint32_t outbound_ssrc)
{
    return stats.direction == "outbound" && stats.session_id == peer.session_id && stats.mid == mapping.subscriber_mid && stats.ssrc == outbound_ssrc;
}

uint32_t optional_uint16_to_uint32(const std::optional<uint16_t>& value)
{
    if (!value.has_value())
    {
        return 0;
    }

    return static_cast<uint32_t>(*value);
}

uint32_t optional_uint8_to_uint32(const std::optional<uint8_t>& value)
{
    if (!value.has_value())
    {
        return 0;
    }

    return static_cast<uint32_t>(*value);
}
bool contains_endpoint(const std::vector<std::string>& endpoints, std::string_view endpoint)
{
    for (const auto& current : endpoints)
    {
        if (current == endpoint)
        {
            return true;
        }
    }

    return false;
}
}    // namespace

void media_router::remember_publisher(std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id)
{
    if (remote_endpoint.empty() || stream_id.empty() || session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    remember_peer_locked(make_peer_info(media_peer_role::publisher, remote_endpoint, stream_id, session_id));
}

void media_router::remember_subscriber(std::string_view remote_endpoint, std::string_view stream_id, std::string_view session_id)
{
    if (remote_endpoint.empty() || stream_id.empty() || session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    remember_peer_locked(make_peer_info(media_peer_role::subscriber, remote_endpoint, stream_id, session_id));
}

void media_router::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    forget_peer_locked(remote_endpoint);
}

void media_router::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    const std::string session_key(session_id);

    std::vector<std::string> endpoints;

    {
        std::lock_guard lock(mutex_);

        for (const auto& [remote_endpoint, peer] : peers_by_endpoint_)
        {
            if (peer.session_id != session_key)
            {
                continue;
            }

            endpoints.push_back(remote_endpoint);
        }

        for (const auto& endpoint : endpoints)
        {
            forget_peer_locked(endpoint);
        }

        std::size_t peer_stats_sweep_count = 0;

        for (auto iterator = peer_stats_by_endpoint_.begin(); iterator != peer_stats_by_endpoint_.end();)
        {
            if (iterator->second.peer.session_id == session_key)
            {
                iterator = peer_stats_by_endpoint_.erase(iterator);

                peer_stats_sweep_count += 1;

                continue;
            }

            ++iterator;
        }

        WEBRTC_LOG_INFO(
            "media router session forgotten session={} endpoints={} peer_stats_sweep={}", session_key, endpoints.size(), peer_stats_sweep_count);
    }
}

void media_router::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    const std::string stream_key(stream_id);

    std::lock_guard lock(mutex_);

    std::vector<std::string> endpoints;

    const auto publisher_iterator = publisher_by_stream_.find(stream_key);

    if (publisher_iterator != publisher_by_stream_.end())
    {
        endpoints.push_back(publisher_iterator->second);
    }

    const auto subscribers_iterator = subscribers_by_stream_.find(stream_key);

    if (subscribers_iterator != subscribers_by_stream_.end())
    {
        for (const auto& endpoint : subscribers_iterator->second)
        {
            if (contains_endpoint(endpoints, endpoint))
            {
                continue;
            }

            endpoints.push_back(endpoint);
        }
    }

    for (const auto& endpoint : endpoints)
    {
        forget_peer_locked(endpoint);
    }

    std::size_t peer_sweep_count = 0;

    for (auto iterator = peers_by_endpoint_.begin(); iterator != peers_by_endpoint_.end();)
    {
        if (iterator->second.stream_id == stream_key)
        {
            peer_stats_by_endpoint_.erase(iterator->first);

            iterator = peers_by_endpoint_.erase(iterator);

            peer_sweep_count += 1;

            continue;
        }

        ++iterator;
    }

    std::size_t peer_stats_sweep_count = 0;

    for (auto iterator = peer_stats_by_endpoint_.begin(); iterator != peer_stats_by_endpoint_.end();)
    {
        if (iterator->second.peer.stream_id == stream_key)
        {
            iterator = peer_stats_by_endpoint_.erase(iterator);

            peer_stats_sweep_count += 1;

            continue;
        }

        ++iterator;
    }

    const std::size_t publisher_erased = publisher_by_stream_.erase(stream_key);

    const std::size_t subscriber_group_erased = subscribers_by_stream_.erase(stream_key);

    const std::size_t stream_stats_erased = stream_stats_by_stream_.erase(stream_key);

    WEBRTC_LOG_INFO(
        "media router stream forgotten stream={} endpoints={} peer_sweep={} peer_stats_sweep={} publisher_erased={} subscriber_group_erased={} "
        "stream_stats_erased={}",
        stream_key,
        endpoints.size(),
        peer_sweep_count,
        peer_stats_sweep_count,
        publisher_erased,
        subscriber_group_erased,
        stream_stats_erased);
}

void media_router::clear()
{
    std::lock_guard lock(mutex_);

    const std::size_t peer_count = peers_by_endpoint_.size();

    const std::size_t peer_stats_count = peer_stats_by_endpoint_.size();

    const std::size_t stream_stats_count = stream_stats_by_stream_.size();

    const std::size_t publisher_count = publisher_by_stream_.size();

    const std::size_t subscriber_stream_count = subscribers_by_stream_.size();

    peers_by_endpoint_.clear();
    peer_stats_by_endpoint_.clear();
    stream_stats_by_stream_.clear();
    publisher_by_stream_.clear();
    subscribers_by_stream_.clear();

    WEBRTC_LOG_INFO("media router cleared peers={} peer_stats={} stream_stats={} publishers={} subscriber_streams={}",
                    peer_count,
                    peer_stats_count,
                    stream_stats_count,
                    publisher_count,
                    subscriber_stream_count);
}

media_route_result media_router::handle_inbound_packet(std::string_view remote_endpoint, const srtp_packet_process_result& packet)
{
    media_route_result result;
    result.packet_kind = packet.kind;
    result.ssrc = packet.ssrc;
    result.payload_type = packet.payload_type;

    if (remote_endpoint.empty())
    {
        return result;
    }

    if (packet.state != srtp_packet_process_state::unprotected)
    {
        return result;
    }

    std::lock_guard lock(mutex_);

    const auto peer_iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

    if (peer_iterator == peers_by_endpoint_.end())
    {
        WEBRTC_LOG_WARN(
            "media router peer not found remote={} kind={} ssrc={}", remote_endpoint, srtp_packet_kind_to_string(packet.kind), packet.ssrc);

        return result;
    }

    result.known_peer = true;
    result.source = peer_iterator->second;

    if (result.source.role == media_peer_role::publisher)
    {
        result.action = media_route_action::fanout_to_subscribers;
        result.target_endpoints = get_subscriber_endpoints_locked(result.source.stream_id, remote_endpoint);

        update_inbound_stats_locked(result.source, packet, result.action, result.target_endpoints.size());

        WEBRTC_LOG_DEBUG("media router publisher packet stream={} session={} remote={} kind={} ssrc={} payload_type={} targets={}",
                         result.source.stream_id,
                         result.source.session_id,
                         remote_endpoint,
                         srtp_packet_kind_to_string(packet.kind),
                         packet.ssrc,
                         static_cast<unsigned int>(packet.payload_type),
                         result.target_endpoints.size());

        return result;
    }

    if (result.source.role == media_peer_role::subscriber && packet.kind == srtp_packet_kind::rtcp)
    {
        result.action = media_route_action::route_to_publisher;
        result.target_endpoints = get_publisher_endpoint_locked(result.source.stream_id, remote_endpoint);

        update_inbound_stats_locked(result.source, packet, result.action, result.target_endpoints.size());

        WEBRTC_LOG_DEBUG("media router subscriber rtcp stream={} session={} remote={} ssrc={} packet_type={} targets={}",
                         result.source.stream_id,
                         result.source.session_id,
                         remote_endpoint,
                         packet.ssrc,
                         static_cast<unsigned int>(packet.payload_type),
                         result.target_endpoints.size());

        return result;
    }

    result.action = media_route_action::none;

    update_inbound_stats_locked(result.source, packet, result.action, 0);

    WEBRTC_LOG_DEBUG("media router packet ignored stream={} session={} remote={} role={} kind={}",
                     result.source.stream_id,
                     result.source.session_id,
                     remote_endpoint,
                     media_peer_role_to_string(result.source.role),
                     srtp_packet_kind_to_string(packet.kind));

    return result;
}
void media_router::observe_inbound_track(const media_peer_info& peer,
                                         const srtp_packet_process_result& packet,
                                         const media_track_resolution& track_resolution)
{
    if (peer.role != media_peer_role::publisher)
    {
        return;
    }

    if (packet.kind != srtp_packet_kind::rtp)
    {
        return;
    }

    if (!track_resolution.resolved)
    {
        return;
    }
    if (track_resolution.rtx)
    {
        return;
    }

    if (track_resolution.stream_id.empty() || track_resolution.session_id.empty() || track_resolution.mid.empty() || track_resolution.kind.empty() ||
        track_resolution.ssrc == 0)
    {
        return;
    }

    std::lock_guard lock(mutex_);

    media_stream_stats& stream_stats = stream_stats_by_stream_[peer.stream_id];

    stream_stats.stream_id = peer.stream_id;

    media_track_stats& track_stats = get_or_create_track_stats_locked(stream_stats, peer, track_resolution);

    update_track_stats_locked(track_stats, packet, track_resolution);
}

void media_router::observe_outbound_track(const media_peer_info& peer,
                                          const media_ssrc_mapping& mapping,
                                          std::span<const uint8_t> outbound_plain_packet)
{
    if (peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (outbound_plain_packet.empty())
    {
        return;
    }

    if (mapping.stream_id.empty() || mapping.subscriber_session_id.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return;
    }
    if (media_ssrc_mapping_is_rtx(mapping))
    {
        return;
    }

    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        return;
    }

    std::lock_guard lock(mutex_);

    media_stream_stats& stream_stats = stream_stats_by_stream_[mapping.stream_id];

    stream_stats.stream_id = mapping.stream_id;

    media_track_stats& track_stats = get_or_create_outbound_track_stats_locked(stream_stats, peer, mapping, header->ssrc);

    update_outbound_track_stats_locked(track_stats, outbound_plain_packet);
}

std::optional<media_peer_info> media_router::get_peer(std::string_view remote_endpoint) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

    if (iterator == peers_by_endpoint_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::optional<media_peer_stats> media_router::get_peer_stats(std::string_view remote_endpoint) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = peer_stats_by_endpoint_.find(std::string(remote_endpoint));

    if (iterator == peer_stats_by_endpoint_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::optional<media_stream_stats> media_router::get_stream_stats(std::string_view stream_id) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = stream_stats_by_stream_.find(std::string(stream_id));

    if (iterator == stream_stats_by_stream_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

media_router_stats_snapshot media_router::get_stats_snapshot() const
{
    std::lock_guard lock(mutex_);

    media_router_stats_snapshot snapshot;
    snapshot.peer_count = peers_by_endpoint_.size();
    snapshot.stream_count = stream_stats_by_stream_.size();
    snapshot.active_publisher_count = publisher_by_stream_.size();

    snapshot.peers.reserve(peer_stats_by_endpoint_.size());
    snapshot.streams.reserve(stream_stats_by_stream_.size());

    for (const auto& [unused_endpoint, peer_stats] : peer_stats_by_endpoint_)
    {
        (void)unused_endpoint;

        if (peer_stats.peer.role == media_peer_role::subscriber)
        {
            snapshot.active_subscriber_count += 1;
        }

        add_peer_to_snapshot(peer_stats, snapshot);

        snapshot.peers.push_back(peer_stats);
    }

    for (const auto& [unused_stream_id, stream_stats] : stream_stats_by_stream_)
    {
        (void)unused_stream_id;

        snapshot.streams.push_back(stream_stats);
    }

    finalize_snapshot(snapshot);

    return snapshot;
}

std::size_t media_router::peer_count() const
{
    std::lock_guard lock(mutex_);

    return peers_by_endpoint_.size();
}

std::size_t media_router::subscriber_count(std::string_view stream_id) const
{
    std::lock_guard lock(mutex_);

    const auto iterator = subscribers_by_stream_.find(std::string(stream_id));

    if (iterator == subscribers_by_stream_.end())
    {
        return 0;
    }

    return iterator->second.size();
}

void media_router::remember_peer_locked(media_peer_info peer)
{
    forget_peer_locked(peer.remote_endpoint);

    if (peer.role == media_peer_role::publisher)
    {
        publisher_by_stream_[peer.stream_id] = peer.remote_endpoint;
    }
    else if (peer.role == media_peer_role::subscriber)
    {
        subscribers_by_stream_[peer.stream_id].insert(peer.remote_endpoint);
    }

    media_stream_stats& stream_stats = stream_stats_by_stream_[peer.stream_id];

    stream_stats.stream_id = peer.stream_id;

    media_peer_stats& peer_stats = peer_stats_by_endpoint_[peer.remote_endpoint];

    peer_stats.peer = peer;

    WEBRTC_LOG_INFO("media router remember peer remote={} role={} stream={} session={}",
                    peer.remote_endpoint,
                    media_peer_role_to_string(peer.role),
                    peer.stream_id,
                    peer.session_id);

    const std::string stream_id = peer.stream_id;

    peers_by_endpoint_[peer.remote_endpoint] = std::move(peer);

    update_stream_member_counts_locked(stream_id);
}

void media_router::forget_peer_locked(std::string_view remote_endpoint)
{
    const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

    if (iterator == peers_by_endpoint_.end())
    {
        return;
    }

    const media_peer_info peer = iterator->second;

    if (peer.role == media_peer_role::publisher)
    {
        const auto publisher_iterator = publisher_by_stream_.find(peer.stream_id);

        if (publisher_iterator != publisher_by_stream_.end() && publisher_iterator->second == peer.remote_endpoint)
        {
            publisher_by_stream_.erase(publisher_iterator);
        }
    }
    else if (peer.role == media_peer_role::subscriber)
    {
        const auto subscribers_iterator = subscribers_by_stream_.find(peer.stream_id);

        if (subscribers_iterator != subscribers_by_stream_.end())
        {
            subscribers_iterator->second.erase(peer.remote_endpoint);

            if (subscribers_iterator->second.empty())
            {
                subscribers_by_stream_.erase(subscribers_iterator);
            }
        }
    }

    WEBRTC_LOG_INFO("media router forget peer remote={} role={} stream={} session={}",
                    peer.remote_endpoint,
                    media_peer_role_to_string(peer.role),
                    peer.stream_id,
                    peer.session_id);

    peer_stats_by_endpoint_.erase(peer.remote_endpoint);
    peers_by_endpoint_.erase(iterator);

    update_stream_member_counts_locked(peer.stream_id);
}

void media_router::update_stream_member_counts_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    media_stream_stats& stats = stream_stats_by_stream_[std::string(stream_id)];

    stats.stream_id = std::string(stream_id);
    stats.active_publishers = 0;
    stats.active_subscribers = 0;

    const auto publisher_iterator = publisher_by_stream_.find(std::string(stream_id));

    if (publisher_iterator != publisher_by_stream_.end())
    {
        stats.active_publishers = 1;
    }

    const auto subscriber_iterator = subscribers_by_stream_.find(std::string(stream_id));

    if (subscriber_iterator != subscribers_by_stream_.end())
    {
        stats.active_subscribers = subscriber_iterator->second.size();
    }

    if (stats.active_publishers == 0 && stats.active_subscribers == 0 && stats.inbound_rtp_packets == 0 && stats.inbound_rtcp_packets == 0)
    {
        stream_stats_by_stream_.erase(std::string(stream_id));
    }
}
media_track_stats& media_router::get_or_create_track_stats_locked(media_stream_stats& stream_stats,
                                                                  const media_peer_info& peer,
                                                                  const media_track_resolution& track_resolution)
{
    for (auto& track_stats : stream_stats.tracks)
    {
        if (same_track_stats_key(track_stats, peer, track_resolution))
        {
            return track_stats;
        }
    }

    media_track_stats track_stats;

    track_stats.stream_id = peer.stream_id;
    track_stats.session_id = peer.session_id;
    track_stats.remote_endpoint = peer.remote_endpoint;
    track_stats.direction = "inbound";

    track_stats.mid = track_resolution.mid;
    track_stats.kind = track_resolution.kind;

    if (track_resolution.rid.has_value())
    {
        track_stats.rid = *track_resolution.rid;
    }

    if (track_resolution.repaired_rid.has_value())
    {
        track_stats.repaired_rid = *track_resolution.repaired_rid;
    }

    track_stats.ssrc = track_resolution.ssrc;
    track_stats.payload_type = static_cast<uint32_t>(track_resolution.payload_type);

    stream_stats.tracks.push_back(std::move(track_stats));

    return stream_stats.tracks.back();
}

void media_router::update_track_stats_locked(media_track_stats& track_stats,
                                             const srtp_packet_process_result& packet,
                                             const media_track_resolution& track_resolution)
{
    const uint64_t packet_size = static_cast<uint64_t>(packet.plain_packet.size());

    if (track_stats.inbound_rtp_packets == 0)
    {
        track_stats.first_rtp_sequence_number = static_cast<uint32_t>(packet.sequence_number);
    }

    track_stats.inbound_rtp_packets += 1;
    track_stats.inbound_rtp_bytes += packet_size;

    track_stats.payload_type = static_cast<uint32_t>(packet.payload_type);

    track_stats.last_rtp_sequence_number = static_cast<uint32_t>(packet.sequence_number);

    track_stats.last_rtp_timestamp = packet.timestamp;

    if (track_resolution.rid.has_value())
    {
        track_stats.rid = *track_resolution.rid;
    }

    if (track_resolution.repaired_rid.has_value())
    {
        track_stats.repaired_rid = *track_resolution.repaired_rid;
    }

    track_stats.has_transport_wide_sequence_number = track_resolution.transport_wide_sequence_number.has_value();

    track_stats.last_transport_wide_sequence_number = optional_uint16_to_uint32(track_resolution.transport_wide_sequence_number);

    track_stats.has_audio_level = track_resolution.audio_level.has_value();

    track_stats.last_audio_level = optional_uint8_to_uint32(track_resolution.audio_level);

    track_stats.has_voice_activity = track_resolution.voice_activity.has_value();

    if (track_resolution.voice_activity.has_value())
    {
        track_stats.last_voice_activity = *track_resolution.voice_activity;
    }
}
media_track_stats& media_router::get_or_create_outbound_track_stats_locked(media_stream_stats& stream_stats,
                                                                           const media_peer_info& peer,
                                                                           const media_ssrc_mapping& mapping,
                                                                           uint32_t outbound_ssrc)
{
    for (auto& track_stats : stream_stats.tracks)
    {
        if (same_outbound_track_stats_key(track_stats, peer, mapping, outbound_ssrc))
        {
            return track_stats;
        }
    }

    media_track_stats track_stats;

    track_stats.stream_id = mapping.stream_id;
    track_stats.session_id = peer.session_id;
    track_stats.remote_endpoint = peer.remote_endpoint;
    track_stats.direction = "outbound";

    track_stats.mid = mapping.subscriber_mid;
    track_stats.kind = mapping.kind;

    track_stats.ssrc = outbound_ssrc;
    track_stats.outbound_ssrc = outbound_ssrc;

    stream_stats.tracks.push_back(std::move(track_stats));

    return stream_stats.tracks.back();
}

void media_router::update_outbound_track_stats_locked(media_track_stats& track_stats, std::span<const uint8_t> outbound_plain_packet)
{
    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        return;
    }

    const uint64_t packet_size = static_cast<uint64_t>(outbound_plain_packet.size());

    if (track_stats.outbound_rtp_packets == 0)
    {
        track_stats.first_outbound_rtp_sequence_number = static_cast<uint32_t>(header->sequence_number);
    }

    track_stats.outbound_rtp_packets += 1;
    track_stats.outbound_rtp_bytes += packet_size;

    track_stats.outbound_ssrc = header->ssrc;

    track_stats.outbound_payload_type = static_cast<uint32_t>(header->payload_type);

    track_stats.payload_type = static_cast<uint32_t>(header->payload_type);

    track_stats.last_outbound_rtp_sequence_number = static_cast<uint32_t>(header->sequence_number);

    track_stats.last_outbound_rtp_timestamp = header->timestamp;
}

void media_router::update_inbound_stats_locked(const media_peer_info& peer,
                                               const srtp_packet_process_result& packet,
                                               media_route_action action,
                                               std::size_t target_count)
{
    media_peer_stats& peer_stats = peer_stats_by_endpoint_[peer.remote_endpoint];

    peer_stats.peer = peer;

    media_stream_stats& stream_stats = stream_stats_by_stream_[peer.stream_id];

    stream_stats.stream_id = peer.stream_id;

    const uint64_t packet_size = packet_plain_size(packet);

    if (packet.kind == srtp_packet_kind::rtp)
    {
        peer_stats.inbound_rtp_packets += 1;
        peer_stats.inbound_rtp_bytes += packet_size;

        stream_stats.inbound_rtp_packets += 1;
        stream_stats.inbound_rtp_bytes += packet_size;

        update_rtp_quality_stats_locked(peer_stats, stream_stats, packet);

        peer_stats.last_rtp_ssrc = packet.ssrc;
        peer_stats.last_rtp_sequence_number = packet.sequence_number;
        peer_stats.last_rtp_timestamp = packet.timestamp;
        peer_stats.last_rtp_payload_type = packet.payload_type;

        stream_stats.last_rtp_ssrc = packet.ssrc;
        stream_stats.last_rtp_sequence_number = packet.sequence_number;
        stream_stats.last_rtp_timestamp = packet.timestamp;

        if (peer.role == media_peer_role::publisher)
        {
            stream_stats.publisher_rtp_packets += 1;
        }
    }
    else if (packet.kind == srtp_packet_kind::rtcp)
    {
        peer_stats.inbound_rtcp_packets += 1;
        peer_stats.inbound_rtcp_bytes += packet_size;
        peer_stats.last_rtcp_ssrc = packet.ssrc;
        peer_stats.last_rtcp_packet_type = packet.payload_type;

        stream_stats.inbound_rtcp_packets += 1;
        stream_stats.inbound_rtcp_bytes += packet_size;
        stream_stats.last_rtcp_ssrc = packet.ssrc;

        if (peer.role == media_peer_role::subscriber)
        {
            stream_stats.subscriber_rtcp_packets += 1;
        }

        update_rtcp_stats_locked(peer_stats, stream_stats, packet);
    }

    if (target_count > 0)
    {
        const uint64_t target_packets = static_cast<uint64_t>(target_count);

        peer_stats.routed_target_packets += target_packets;
        peer_stats.routed_target_bytes += packet_size * target_packets;

        if (action == media_route_action::fanout_to_subscribers)
        {
            stream_stats.fanout_target_packets += target_packets;
        }
        else if (action == media_route_action::route_to_publisher)
        {
            stream_stats.route_to_publisher_packets += target_packets;
        }
    }

    update_stream_member_counts_locked(peer.stream_id);

    const uint64_t total_packets = get_total_inbound_packets(peer_stats);

    if (total_packets != 0 && total_packets % k_media_stats_log_interval == 0)
    {
        log_peer_stats_locked(peer_stats, stream_stats);
    }
}

void media_router::update_rtp_quality_stats_locked(media_peer_stats& peer_stats,
                                                   media_stream_stats& stream_stats,
                                                   const srtp_packet_process_result& packet)
{
    media_rtp_sequence_state& sequence_state = peer_stats.rtp_sequence_by_ssrc[packet.ssrc];

    if (!sequence_state.has_sequence)
    {
        sequence_state.has_sequence = true;
        sequence_state.expected_sequence_number = next_rtp_sequence_number(packet.sequence_number);
        sequence_state.last_sequence_number = packet.sequence_number;
        sequence_state.last_timestamp = packet.timestamp;
        sequence_state.last_payload_type = packet.payload_type;

        remember_peer_rtp_sequence_summary(peer_stats, packet.ssrc, sequence_state);

        return;
    }

    const uint16_t expected_sequence_number = sequence_state.expected_sequence_number;

    const int32_t delta = rtp_sequence_delta(packet.sequence_number, expected_sequence_number);

    if (delta == 0)
    {
        if (is_rtp_sequence_wrap(sequence_state.last_sequence_number, packet.sequence_number))
        {
            sequence_state.rtp_sequence_wraps += 1;
            peer_stats.rtp_sequence_wraps += 1;
            stream_stats.rtp_sequence_wraps += 1;
        }

        sequence_state.expected_sequence_number = next_rtp_sequence_number(packet.sequence_number);
        sequence_state.last_sequence_number = packet.sequence_number;
        sequence_state.last_timestamp = packet.timestamp;
        sequence_state.last_payload_type = packet.payload_type;

        remember_peer_rtp_sequence_summary(peer_stats, packet.ssrc, sequence_state);

        return;
    }

    if (delta > 0)
    {
        const uint64_t missing_packets = static_cast<uint64_t>(delta);

        sequence_state.rtp_sequence_gap_events += 1;
        sequence_state.rtp_sequence_lost_packets += missing_packets;

        peer_stats.rtp_sequence_gap_events += 1;
        peer_stats.rtp_sequence_lost_packets += missing_packets;

        stream_stats.rtp_sequence_gap_events += 1;
        stream_stats.rtp_sequence_lost_packets += missing_packets;

        if (is_rtp_sequence_wrap(expected_sequence_number, packet.sequence_number))
        {
            sequence_state.rtp_sequence_wraps += 1;
            peer_stats.rtp_sequence_wraps += 1;
            stream_stats.rtp_sequence_wraps += 1;
        }

        sequence_state.expected_sequence_number = next_rtp_sequence_number(packet.sequence_number);
        sequence_state.last_sequence_number = packet.sequence_number;
        sequence_state.last_timestamp = packet.timestamp;
        sequence_state.last_payload_type = packet.payload_type;

        remember_peer_rtp_sequence_summary(peer_stats, packet.ssrc, sequence_state);

        WEBRTC_LOG_DEBUG("media router rtp sequence gap remote={} stream={} session={} ssrc={} expected={} actual={} missing={}",
                         peer_stats.peer.remote_endpoint,
                         peer_stats.peer.stream_id,
                         peer_stats.peer.session_id,
                         packet.ssrc,
                         expected_sequence_number,
                         packet.sequence_number,
                         missing_packets);

        return;
    }

    if (packet.sequence_number == sequence_state.last_sequence_number)
    {
        sequence_state.rtp_duplicate_packets += 1;

        peer_stats.rtp_duplicate_packets += 1;
        stream_stats.rtp_duplicate_packets += 1;

        sequence_state.last_timestamp = packet.timestamp;
        sequence_state.last_payload_type = packet.payload_type;

        remember_peer_rtp_sequence_summary(peer_stats, packet.ssrc, sequence_state);

        WEBRTC_LOG_DEBUG("media router rtp duplicate remote={} stream={} session={} ssrc={} sequence={}",
                         peer_stats.peer.remote_endpoint,
                         peer_stats.peer.stream_id,
                         peer_stats.peer.session_id,
                         packet.ssrc,
                         packet.sequence_number);

        return;
    }

    sequence_state.rtp_out_of_order_packets += 1;

    peer_stats.rtp_out_of_order_packets += 1;
    stream_stats.rtp_out_of_order_packets += 1;

    sequence_state.last_sequence_number = packet.sequence_number;
    sequence_state.last_timestamp = packet.timestamp;
    sequence_state.last_payload_type = packet.payload_type;

    remember_peer_rtp_sequence_summary(peer_stats, packet.ssrc, sequence_state);

    WEBRTC_LOG_DEBUG("media router rtp out of order remote={} stream={} session={} ssrc={} expected={} actual={} delta={}",
                     peer_stats.peer.remote_endpoint,
                     peer_stats.peer.stream_id,
                     peer_stats.peer.session_id,
                     packet.ssrc,
                     expected_sequence_number,
                     packet.sequence_number,
                     delta);
}

void media_router::update_rtcp_stats_locked(media_peer_stats& peer_stats, media_stream_stats& stream_stats, const srtp_packet_process_result& packet)
{
    update_rtcp_feedback_stats_locked(peer_stats, stream_stats, packet);

    update_rtcp_report_stats_locked(peer_stats, stream_stats, packet);
}

void media_router::update_rtcp_feedback_stats_locked(media_peer_stats& peer_stats,
                                                     media_stream_stats& stream_stats,
                                                     const srtp_packet_process_result& packet)
{
    if (!packet.rtcp_is_feedback)
    {
        return;
    }

    peer_stats.rtcp_feedback_packets += 1;
    stream_stats.rtcp_feedback_packets += 1;

    peer_stats.rtcp_nack_items += packet.rtcp_nack_items.size();
    peer_stats.rtcp_fir_items += packet.rtcp_fir_items.size();

    stream_stats.rtcp_nack_items += packet.rtcp_nack_items.size();
    stream_stats.rtcp_fir_items += packet.rtcp_fir_items.size();

    if (packet.rtcp_has_generic_nack)
    {
        peer_stats.rtcp_generic_nack_packets += 1;
        stream_stats.rtcp_generic_nack_packets += 1;
    }

    if (packet.rtcp_has_keyframe_request)
    {
        peer_stats.rtcp_keyframe_request_packets += 1;
        stream_stats.rtcp_keyframe_request_packets += 1;
    }

    if (packet.rtcp_has_transport_cc)
    {
        peer_stats.rtcp_transport_cc_packets += 1;
        stream_stats.rtcp_transport_cc_packets += 1;
    }

    if (packet.rtcp_has_remb)
    {
        peer_stats.rtcp_remb_packets += 1;
        peer_stats.last_remb_bitrate_bps = packet.rtcp_remb_bitrate_bps;

        stream_stats.rtcp_remb_packets += 1;
        stream_stats.last_remb_bitrate_bps = packet.rtcp_remb_bitrate_bps;
    }
}

void media_router::update_rtcp_report_stats_locked(media_peer_stats& peer_stats,
                                                   media_stream_stats& stream_stats,
                                                   const srtp_packet_process_result& packet)
{
    if (packet.rtcp_report_packet_count == 0)
    {
        return;
    }

    peer_stats.rtcp_report_packets += packet.rtcp_report_packet_count;

    peer_stats.rtcp_report_blocks += packet.rtcp_report_block_count;

    stream_stats.rtcp_report_packets += packet.rtcp_report_packet_count;

    stream_stats.rtcp_report_blocks += packet.rtcp_report_block_count;

    if (packet.rtcp_has_sender_report)
    {
        peer_stats.rtcp_sender_report_packets += 1;
        stream_stats.rtcp_sender_report_packets += 1;
    }

    if (packet.rtcp_has_receiver_report)
    {
        peer_stats.rtcp_receiver_report_packets += 1;
        stream_stats.rtcp_receiver_report_packets += 1;
    }

    peer_stats.last_rtcp_report_ssrc = packet.rtcp_report_sender_ssrc;
    peer_stats.last_rtcp_fraction_lost = packet.rtcp_last_fraction_lost;
    peer_stats.last_rtcp_cumulative_lost = packet.rtcp_last_cumulative_lost;
    peer_stats.last_rtcp_jitter = packet.rtcp_last_jitter;

    stream_stats.last_rtcp_report_ssrc = packet.rtcp_report_sender_ssrc;
    stream_stats.last_rtcp_fraction_lost = packet.rtcp_last_fraction_lost;
    stream_stats.last_rtcp_cumulative_lost = packet.rtcp_last_cumulative_lost;
    stream_stats.last_rtcp_jitter = packet.rtcp_last_jitter;

    if (!packet.rtcp_report_blocks.empty())
    {
        const rtcp_report_block& last_report_block = packet.rtcp_report_blocks.back();

        peer_stats.last_rtcp_report_media_ssrc = last_report_block.ssrc;

        stream_stats.last_rtcp_report_media_ssrc = last_report_block.ssrc;
    }

    if (packet.rtcp_has_sender_info)
    {
        peer_stats.last_rtcp_sr_packet_count = packet.rtcp_sender_info_data.sender_packet_count;
        peer_stats.last_rtcp_sr_octet_count = packet.rtcp_sender_info_data.sender_octet_count;

        stream_stats.last_rtcp_sr_packet_count = packet.rtcp_sender_info_data.sender_packet_count;
        stream_stats.last_rtcp_sr_octet_count = packet.rtcp_sender_info_data.sender_octet_count;
    }

    for (const auto& report_block : packet.rtcp_report_blocks)
    {
        const auto rtt_ms = estimate_rtcp_rtt_ms(report_block.last_sender_report, report_block.delay_since_last_sender_report);

        if (!rtt_ms.has_value())
        {
            continue;
        }

        update_rtcp_rtt_stats_locked(peer_stats, stream_stats, *rtt_ms);
    }

    WEBRTC_LOG_DEBUG(
        "media router rtcp report remote={} stream={} reports={} blocks={} sr={} rr={} report_ssrc={} media_ssrc={} fraction_lost={} "
        "cumulative_lost={} jitter={} rtt_last_ms={} rtt_avg_ms={} rtt_max_ms={}",
        peer_stats.peer.remote_endpoint,
        peer_stats.peer.stream_id,
        packet.rtcp_report_packet_count,
        packet.rtcp_report_block_count,
        packet.rtcp_has_sender_report ? 1 : 0,
        packet.rtcp_has_receiver_report ? 1 : 0,
        peer_stats.last_rtcp_report_ssrc,
        peer_stats.last_rtcp_report_media_ssrc,
        static_cast<unsigned int>(packet.rtcp_last_fraction_lost),
        packet.rtcp_last_cumulative_lost,
        packet.rtcp_last_jitter,
        peer_stats.rtcp_last_rtt_ms,
        peer_stats.rtcp_avg_rtt_ms,
        peer_stats.rtcp_max_rtt_ms);
}

void media_router::update_rtcp_rtt_stats_locked(media_peer_stats& peer_stats, media_stream_stats& stream_stats, uint64_t rtt_ms)
{
    peer_stats.rtcp_rtt_sample_count += 1;
    peer_stats.rtcp_last_rtt_ms = rtt_ms;
    peer_stats.rtcp_rtt_sum_ms += rtt_ms;
    peer_stats.rtcp_avg_rtt_ms = peer_stats.rtcp_rtt_sum_ms / peer_stats.rtcp_rtt_sample_count;

    if (rtt_ms > peer_stats.rtcp_max_rtt_ms)
    {
        peer_stats.rtcp_max_rtt_ms = rtt_ms;
    }

    stream_stats.rtcp_rtt_sample_count += 1;
    stream_stats.rtcp_last_rtt_ms = rtt_ms;
    stream_stats.rtcp_rtt_sum_ms += rtt_ms;
    stream_stats.rtcp_avg_rtt_ms = stream_stats.rtcp_rtt_sum_ms / stream_stats.rtcp_rtt_sample_count;

    if (rtt_ms > stream_stats.rtcp_max_rtt_ms)
    {
        stream_stats.rtcp_max_rtt_ms = rtt_ms;
    }
}

void media_router::log_peer_stats_locked(const media_peer_stats& peer_stats, const media_stream_stats& stream_stats) const
{
    WEBRTC_LOG_INFO(
        "media stats peer remote={} role={} stream={} session={} rtp_packets={} rtcp_packets={} routed_targets={} feedback={} reports={} "
        "report_blocks={} fraction_lost={} cumulative_lost={} jitter={} rtt_last_ms={} rtt_avg_ms={} rtt_max_ms={} nack_items={} fir_items={} "
        "keyframe_requests={} generic_nacks={} transport_cc={} remb={} rtp_gap_events={} rtp_lost={} rtp_ooo={} rtp_duplicate={} rtp_wraps={} "
        "active_publishers={} active_subscribers={} stream_rtp={} stream_rtcp={} stream_fanout_targets={} stream_lost={} stream_ooo={} "
        "stream_duplicate={} stream_rtt_avg_ms={}",
        peer_stats.peer.remote_endpoint,
        media_peer_role_to_string(peer_stats.peer.role),
        peer_stats.peer.stream_id,
        peer_stats.peer.session_id,
        peer_stats.inbound_rtp_packets,
        peer_stats.inbound_rtcp_packets,
        peer_stats.routed_target_packets,
        peer_stats.rtcp_feedback_packets,
        peer_stats.rtcp_report_packets,
        peer_stats.rtcp_report_blocks,
        static_cast<unsigned int>(peer_stats.last_rtcp_fraction_lost),
        peer_stats.last_rtcp_cumulative_lost,
        peer_stats.last_rtcp_jitter,
        peer_stats.rtcp_last_rtt_ms,
        peer_stats.rtcp_avg_rtt_ms,
        peer_stats.rtcp_max_rtt_ms,
        peer_stats.rtcp_nack_items,
        peer_stats.rtcp_fir_items,
        peer_stats.rtcp_keyframe_request_packets,
        peer_stats.rtcp_generic_nack_packets,
        peer_stats.rtcp_transport_cc_packets,
        peer_stats.rtcp_remb_packets,
        peer_stats.rtp_sequence_gap_events,
        peer_stats.rtp_sequence_lost_packets,
        peer_stats.rtp_out_of_order_packets,
        peer_stats.rtp_duplicate_packets,
        peer_stats.rtp_sequence_wraps,
        stream_stats.active_publishers,
        stream_stats.active_subscribers,
        stream_stats.inbound_rtp_packets,
        stream_stats.inbound_rtcp_packets,
        stream_stats.fanout_target_packets,
        stream_stats.rtp_sequence_lost_packets,
        stream_stats.rtp_out_of_order_packets,
        stream_stats.rtp_duplicate_packets,
        stream_stats.rtcp_avg_rtt_ms);
}

std::vector<std::string> media_router::get_subscriber_endpoints_locked(std::string_view stream_id, std::string_view excluded_endpoint) const
{
    std::vector<std::string> endpoints;

    const auto iterator = subscribers_by_stream_.find(std::string(stream_id));

    if (iterator == subscribers_by_stream_.end())
    {
        return endpoints;
    }

    endpoints.reserve(iterator->second.size());

    for (const auto& endpoint : iterator->second)
    {
        if (endpoint != excluded_endpoint)
        {
            endpoints.push_back(endpoint);
        }
    }

    return endpoints;
}

std::vector<std::string> media_router::get_publisher_endpoint_locked(std::string_view stream_id, std::string_view excluded_endpoint) const
{
    std::vector<std::string> endpoints;

    const auto iterator = publisher_by_stream_.find(std::string(stream_id));

    if (iterator == publisher_by_stream_.end())
    {
        return endpoints;
    }

    if (iterator->second != excluded_endpoint)
    {
        endpoints.push_back(iterator->second);
    }

    return endpoints;
}

std::string media_peer_role_to_string(media_peer_role role)
{
    switch (role)
    {
        case media_peer_role::publisher:
            return "publisher";

        case media_peer_role::subscriber:
            return "subscriber";

        case media_peer_role::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string media_route_action_to_string(media_route_action action)
{
    switch (action)
    {
        case media_route_action::fanout_to_subscribers:
            return "fanout_to_subscribers";

        case media_route_action::route_to_publisher:
            return "route_to_publisher";

        case media_route_action::none:
            return "none";
    }

    return "none";
}
}    // namespace webrtc
