#include "ice/ice_udp_server.h"
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <map>
#include <vector>

#include <boost/system/error_code.hpp>

#include "dtls/dtls_context.h"
#include "dtls/dtls_packet.h"
#include "ice/stun_message.h"
#include "log/log.h"
#include "media/media_payload_type_mapper.h"
#include "media/media_router.h"
#include "media/media_ssrc_mapper.h"
#include "media/media_track_resolver.h"
#include "media/rtcp_feedback_router.h"
#include "media/rtcp_report_service.h"
#include "media/rtp_packet_cache.h"
#include "net/socket.h"
#include "rtp/rtcp_feedback.h"
#include "rtp/rtp_packet.h"
#include "rtp/rtp_rtx_packet.h"
#include "rtp/rtp_packet_rewriter.h"
#include "rtp/rtcp_packet_writer.h"
#include "session/session_state.h"
#include "util/timestamp.h"

namespace webrtc
{
namespace
{
inline constexpr std::size_t k_max_outbound_transport_cc_feedback_observations_per_window = 512;
constexpr std::size_t k_rtcp_bye_max_ssrcs_per_packet = 31;

constexpr std::size_t k_max_ice_username_fragment_size = 256;

constexpr std::size_t k_max_ice_username_size = (k_max_ice_username_fragment_size * 2) + 1;

constexpr auto k_minimum_dtls_timer_delay = std::chrono::milliseconds(1);

constexpr auto k_ice_consent_check_interval = std::chrono::seconds(5);

constexpr auto k_rtcp_report_interval = std::chrono::milliseconds(200);

constexpr auto k_rtcp_report_empty_generation_log_interval = std::chrono::seconds(60);

constexpr uint64_t k_ice_consent_timeout_milliseconds = 30000;
constexpr uint64_t k_ice_consent_request_interval_milliseconds = 15000;
constexpr uint64_t k_ice_consent_request_retry_milliseconds = 5000;

constexpr uint64_t k_unselected_candidate_pair_retention_milliseconds = 120000;

constexpr std::string_view k_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";
constexpr std::string_view k_absolute_send_time_extension_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
constexpr std::string_view k_audio_level_extension_uri = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

constexpr std::size_t k_max_retired_endpoints = 512;

constexpr std::size_t k_max_retired_ice_credentials = 512;

constexpr std::size_t k_max_pending_sessions = 256;

constexpr std::size_t k_max_orphan_subscriber_sessions = 256;

struct pending_session_cleanup_candidate
{
    std::string session_id;
    std::string stream_id;
    stream_session_kind kind = stream_session_kind::unknown;
    uint64_t reference_time_milliseconds = 0;
    uint64_t age_milliseconds = 0;
};

constexpr uint64_t k_fnv_offset_basis = 1469598103934665603ULL;

constexpr uint64_t k_fnv_prime = 1099511628211ULL;

constexpr auto k_endpoint_idle_cleanup_interval = std::chrono::seconds(5);

constexpr uint64_t k_retired_endpoint_retention_milliseconds = 15000;

constexpr uint64_t k_lifecycle_fast_convergence_check_delay_milliseconds = 3000;
constexpr uint64_t k_lifecycle_final_convergence_check_delay_milliseconds = k_retired_endpoint_retention_milliseconds + 1000;
constexpr uint64_t k_selected_rid_keyframe_request_pending_timeout_milliseconds = 10000;

constexpr uint64_t k_default_endpoint_idle_timeout_milliseconds = 120000;

constexpr std::size_t k_max_nack_retransmit_sequences = 128;

constexpr std::size_t k_nack_sequences_per_item = 17;

constexpr auto k_pending_session_cleanup_interval = std::chrono::seconds(5);

constexpr uint64_t k_default_pending_session_timeout_milliseconds = 60000;

constexpr uint64_t k_default_orphan_subscriber_timeout_milliseconds = 60000;

constexpr uint64_t k_keyframe_request_interval_milliseconds = 1000;

constexpr uint64_t k_republish_keyframe_request_pending_timeout_milliseconds = 8000;

constexpr std::size_t k_republish_keyframe_request_max_attempts_per_subscriber = 5;

constexpr std::size_t k_default_rtp_packet_cache_max_packets = 4096;

constexpr std::size_t k_min_rtp_packet_cache_max_packets = 128;

constexpr std::size_t k_max_rtp_packet_cache_max_packets = 262144;

inline constexpr std::size_t k_max_outbound_transport_cc_packet_identities = 65536;
inline constexpr std::size_t k_max_outbound_rtp_packet_identities = 65536;

constexpr uint64_t k_subscriber_downlink_republish_grace_milliseconds = 8000;
constexpr uint64_t k_subscriber_downlink_republish_grace_target_bitrate_bps = 2000000;

std::string make_subscriber_downlink_republish_grace_key(std::string_view stream_id, std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 1);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    return key;
}

bool subscriber_downlink_republish_grace_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return false;
    }

    const std::string prefix = std::string(stream_id) + "|";

    return key.starts_with(prefix);
}

bool subscriber_downlink_republish_grace_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (session_id.empty())
    {
        return false;
    }

    const std::string suffix = "|" + std::string(session_id);

    if (key.size() < suffix.size())
    {
        return false;
    }

    return key.ends_with(suffix);
}

uint64_t clamp_subscriber_downlink_republish_grace_bitrate(uint64_t bitrate_bps, uint64_t min_bitrate_bps, uint64_t max_bitrate_bps)
{
    if (max_bitrate_bps > 0)
    {
        bitrate_bps = std::min(bitrate_bps, max_bitrate_bps);
    }

    if (min_bitrate_bps > 0)
    {
        bitrate_bps = std::max(bitrate_bps, min_bitrate_bps);
    }

    return bitrate_bps;
}

struct ice_username_parts
{
    std::string_view recipient_ufrag;
    std::string_view sender_ufrag;
};

using optional_mid_rewrite_result = std::expected<std::optional<rtp_header_extension_rewrite>, std::string>;
using optional_rtx_header_extension_id_rewrite_result = std::expected<std::optional<rtp_rtx_header_extension_id_rewrite>, std::string>;

std::string make_keyframe_request_track_leaf(const media_track_resolution& track_resolution, uint32_t media_ssrc)
{
    if (track_resolution.rid.has_value() && !track_resolution.rid->empty())
    {
        std::string leaf;

        leaf.reserve(track_resolution.rid->size() + 4);

        leaf.append("rid:");

        leaf.append(*track_resolution.rid);

        return leaf;
    }

    if (track_resolution.repaired_rid.has_value() && !track_resolution.repaired_rid->empty())
    {
        std::string leaf;

        leaf.reserve(track_resolution.repaired_rid->size() + 13);

        leaf.append("repaired-rid:");

        leaf.append(*track_resolution.repaired_rid);

        return leaf;
    }

    std::string leaf;

    leaf.reserve(24);

    leaf.append("ssrc:");

    leaf.append(std::to_string(media_ssrc));

    return leaf;
}

std::string make_keyframe_request_key(const media_route_result& route,
                                      const media_peer_info& target_peer,
                                      const media_track_resolution& track_resolution,
                                      uint32_t media_ssrc)
{
    const std::string track_leaf = make_keyframe_request_track_leaf(track_resolution, media_ssrc);

    std::string key;

    key.reserve(route.source.stream_id.size() + route.source.session_id.size() + target_peer.session_id.size() + track_resolution.mid.size() +
                track_resolution.kind.size() + track_leaf.size() + 8);

    key.append(route.source.stream_id);

    key.push_back('|');

    key.append(route.source.session_id);

    key.push_back('|');

    key.append(target_peer.session_id);

    key.push_back('|');

    key.append(track_resolution.mid);

    key.push_back('|');

    key.append(track_resolution.kind);

    key.push_back('|');

    key.append(track_leaf);

    key.push_back('|');

    key.append(std::to_string(media_ssrc));

    return key;
}

std::string make_publisher_video_ssrc_state_key(std::string_view stream_id,
                                                std::string_view publisher_session_id,
                                                const media_track_resolution& track_resolution,
                                                uint32_t media_ssrc)
{
    const std::string track_leaf = make_keyframe_request_track_leaf(track_resolution, media_ssrc);

    std::string key;

    key.reserve(stream_id.size() + publisher_session_id.size() + track_resolution.mid.size() + track_resolution.kind.size() + track_leaf.size() + 6);
    key.append(stream_id);
    key.push_back('|');
    key.append(publisher_session_id);
    key.push_back('|');
    key.append(track_resolution.mid);
    key.push_back('|');
    key.append(track_resolution.kind);
    key.push_back('|');
    key.append(track_leaf);
    return key;
}

std::string make_selected_rid_layer_key(std::string_view stream_id,
                                        std::string_view publisher_session_id,
                                        std::string_view subscriber_session_id,
                                        std::string_view mid,
                                        std::string_view kind)
{
    std::string key;
    key.reserve(stream_id.size() + publisher_session_id.size() + subscriber_session_id.size() + mid.size() + kind.size() + 5);
    key.append(stream_id);
    key.push_back('|');
    key.append(publisher_session_id);
    key.push_back('|');
    key.append(subscriber_session_id);
    key.push_back('|');
    key.append(mid);
    key.push_back('|');
    key.append(kind);
    return key;
}

std::string make_extmap_rewrite_runtime_state_key(std::string_view stream_id,
                                                  std::string_view publisher_session_id,
                                                  std::string_view subscriber_session_id,
                                                  std::string_view subscriber_mid,
                                                  std::string_view uri)
{
    std::string key;

    key.reserve(stream_id.size() + publisher_session_id.size() + subscriber_session_id.size() + subscriber_mid.size() + uri.size() + 8);

    key.append(stream_id);

    key.push_back('|');

    key.append(publisher_session_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(subscriber_mid);

    key.push_back('|');

    key.append(uri);

    return key;
}

std::string make_outbound_transport_cc_sequence_key(std::string_view stream_id, std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 1);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    return key;
}
std::string make_outbound_transport_cc_feedback_window_key(std::string_view stream_id, std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 1);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    return key;
}
std::string make_subscriber_downlink_bandwidth_state_key(std::string_view stream_id, std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 1);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    return key;
}

bool outbound_transport_cc_feedback_window_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (key.empty() || session_id.empty())
    {
        return false;
    }

    std::string marker;

    marker.reserve(session_id.size() + 1);

    marker.push_back('|');

    marker.append(session_id);

    return key.ends_with(marker);
}

bool outbound_transport_cc_feedback_window_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    if (key.empty() || stream_id.empty())
    {
        return false;
    }

    std::string prefix;

    prefix.reserve(stream_id.size() + 1);

    prefix.append(stream_id);

    prefix.push_back('|');

    return key.starts_with(prefix);
}

bool subscriber_downlink_bandwidth_state_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (key.empty() || session_id.empty())
    {
        return false;
    }

    std::string marker;

    marker.reserve(session_id.size() + 1);

    marker.push_back('|');

    marker.append(session_id);

    return key.ends_with(marker);
}

bool subscriber_downlink_bandwidth_state_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    if (key.empty() || stream_id.empty())
    {
        return false;
    }

    std::string prefix;

    prefix.reserve(stream_id.size() + 1);

    prefix.append(stream_id);

    prefix.push_back('|');

    return key.starts_with(prefix);
}

std::string_view subscriber_downlink_control_state_to_string(ice_udp_server::subscriber_downlink_control_state state)
{
    switch (state)
    {
        case ice_udp_server::subscriber_downlink_control_state::probing:
            return "probing";

        case ice_udp_server::subscriber_downlink_control_state::steady:
            return "steady";

        case ice_udp_server::subscriber_downlink_control_state::recovering:
            return "recovering";

        case ice_udp_server::subscriber_downlink_control_state::constrained:
            return "constrained";

        case ice_udp_server::subscriber_downlink_control_state::hold_down:
            return "hold_down";
    }

    return "probing";
}

std::string_view subscriber_downlink_control_mode_to_string(ice_udp_server::subscriber_downlink_control_mode mode)
{
    switch (mode)
    {
        case ice_udp_server::subscriber_downlink_control_mode::disabled:
            return "disabled";

        case ice_udp_server::subscriber_downlink_control_mode::observe_only:
            return "observe_only";

        case ice_udp_server::subscriber_downlink_control_mode::enabled:
            return "enabled";
    }

    return "observe_only";
}

uint64_t scale_bitrate(uint64_t bitrate_bps, uint64_t numerator, uint64_t denominator)
{
    if (denominator == 0)
    {
        return bitrate_bps;
    }

    return static_cast<uint64_t>((static_cast<unsigned __int128>(bitrate_bps) * numerator) / denominator);
}

uint64_t clamp_bitrate(uint64_t bitrate_bps, uint64_t min_bitrate_bps, uint64_t max_bitrate_bps)
{
    if (bitrate_bps < min_bitrate_bps)
    {
        return min_bitrate_bps;
    }

    if (bitrate_bps > max_bitrate_bps)
    {
        return max_bitrate_bps;
    }

    return bitrate_bps;
}
uint64_t increase_bitrate_by_ppm(uint64_t bitrate_bps, uint64_t increase_ppm, uint64_t min_step_bps)
{
    if (bitrate_bps == 0)
    {
        return min_step_bps;
    }

    uint64_t step_bps = scale_bitrate(bitrate_bps, increase_ppm, 1000000U);

    step_bps = std::max(step_bps, min_step_bps);

    if (std::numeric_limits<uint64_t>::max() - bitrate_bps < step_bps)
    {
        return std::numeric_limits<uint64_t>::max();
    }

    return bitrate_bps + step_bps;
}

bool subscriber_downlink_state_duration_elapsed(const ice_udp_server::subscriber_downlink_bandwidth_state& state,
                                                uint64_t current_time_milliseconds,
                                                uint64_t duration_milliseconds)
{
    if (duration_milliseconds == 0)
    {
        return true;
    }

    if (state.state_entered_at_milliseconds == 0)
    {
        return true;
    }

    return current_time_milliseconds >= state.state_entered_at_milliseconds + duration_milliseconds;
}

ice_udp_server::subscriber_downlink_control_state select_subscriber_downlink_control_state(
    const ice_udp_server::subscriber_downlink_bandwidth_state& state,
    const ice_udp_server::subscriber_downlink_control_config& config,
    uint64_t current_time_milliseconds,
    uint64_t observation_count,
    uint64_t lookup_hit_rate_ppm,
    uint64_t loss_rate_ppm,
    uint64_t next_healthy_window_count,
    uint64_t next_bad_window_count)
{
    const bool has_enough_samples = observation_count >= config.probe_observation_count;
    const bool has_reliable_lookup = lookup_hit_rate_ppm >= config.min_reliable_lookup_hit_rate_ppm;

    if (!has_enough_samples || !has_reliable_lookup)
    {
        return ice_udp_server::subscriber_downlink_control_state::probing;
    }

    const bool bad_enough = next_bad_window_count >= config.constrained_required_bad_windows;

    if (loss_rate_ppm >= config.severe_loss_rate_ppm)
    {
        return ice_udp_server::subscriber_downlink_control_state::constrained;
    }

    switch (state.control_state)
    {
        case ice_udp_server::subscriber_downlink_control_state::probing:
            if (loss_rate_ppm >= config.constrained_loss_rate_ppm)
            {
                return ice_udp_server::subscriber_downlink_control_state::constrained;
            }

            if (loss_rate_ppm >= config.recovering_loss_rate_ppm)
            {
                return ice_udp_server::subscriber_downlink_control_state::recovering;
            }

            return ice_udp_server::subscriber_downlink_control_state::steady;

        case ice_udp_server::subscriber_downlink_control_state::steady:
            if (loss_rate_ppm >= config.constrained_loss_rate_ppm && bad_enough)
            {
                return ice_udp_server::subscriber_downlink_control_state::constrained;
            }

            if (loss_rate_ppm >= config.recovering_loss_rate_ppm)
            {
                return ice_udp_server::subscriber_downlink_control_state::recovering;
            }

            return ice_udp_server::subscriber_downlink_control_state::steady;

        case ice_udp_server::subscriber_downlink_control_state::recovering:
            if (loss_rate_ppm >= config.constrained_loss_rate_ppm)
            {
                return ice_udp_server::subscriber_downlink_control_state::constrained;
            }

            if (!subscriber_downlink_state_duration_elapsed(state, current_time_milliseconds, config.recovering_min_duration_milliseconds))
            {
                return ice_udp_server::subscriber_downlink_control_state::recovering;
            }

            if (next_healthy_window_count >= config.hold_down_required_healthy_windows)
            {
                return ice_udp_server::subscriber_downlink_control_state::hold_down;
            }

            return ice_udp_server::subscriber_downlink_control_state::recovering;

        case ice_udp_server::subscriber_downlink_control_state::constrained:
            if (loss_rate_ppm >= config.recovering_loss_rate_ppm)
            {
                return ice_udp_server::subscriber_downlink_control_state::constrained;
            }

            if (!subscriber_downlink_state_duration_elapsed(state, current_time_milliseconds, config.min_state_duration_milliseconds))
            {
                return ice_udp_server::subscriber_downlink_control_state::constrained;
            }

            if (next_healthy_window_count >= config.recovering_required_healthy_windows)
            {
                return ice_udp_server::subscriber_downlink_control_state::recovering;
            }

            return ice_udp_server::subscriber_downlink_control_state::constrained;

        case ice_udp_server::subscriber_downlink_control_state::hold_down:
            if (loss_rate_ppm >= config.constrained_loss_rate_ppm)
            {
                return ice_udp_server::subscriber_downlink_control_state::constrained;
            }

            if (state.hold_down_until_milliseconds != 0 && current_time_milliseconds < state.hold_down_until_milliseconds)
            {
                return ice_udp_server::subscriber_downlink_control_state::hold_down;
            }

            if (loss_rate_ppm >= config.recovering_loss_rate_ppm)
            {
                return ice_udp_server::subscriber_downlink_control_state::recovering;
            }

            return ice_udp_server::subscriber_downlink_control_state::steady;
    }

    return ice_udp_server::subscriber_downlink_control_state::probing;
}

std::string make_subscriber_downlink_transition_reason(ice_udp_server::subscriber_downlink_control_state state,
                                                       uint64_t observation_count,
                                                       uint64_t lookup_hit_rate_ppm,
                                                       uint64_t loss_rate_ppm,
                                                       uint64_t healthy_window_count,
                                                       uint64_t bad_window_count,
                                                       uint64_t unreliable_window_count)
{
    std::string reason;

    reason.reserve(192);

    reason.append("state=");
    reason.append(subscriber_downlink_control_state_to_string(state));

    reason.append(" observations=");
    reason.append(std::to_string(observation_count));

    reason.append(" lookup_hit_rate_ppm=");
    reason.append(std::to_string(lookup_hit_rate_ppm));

    reason.append(" loss_rate_ppm=");
    reason.append(std::to_string(loss_rate_ppm));

    reason.append(" healthy_windows=");
    reason.append(std::to_string(healthy_window_count));

    reason.append(" bad_windows=");
    reason.append(std::to_string(bad_window_count));

    reason.append(" unreliable_windows=");
    reason.append(std::to_string(unreliable_window_count));

    return reason;
}

uint64_t estimate_subscriber_downlink_target_bitrate_bps(const ice_udp_server::subscriber_downlink_bandwidth_state& state,
                                                         const ice_udp_server::subscriber_downlink_control_config& config,
                                                         ice_udp_server::subscriber_downlink_control_state next_state,
                                                         uint64_t loss_rate_ppm)
{
    uint64_t target_bitrate_bps = state.target_bitrate_bps;

    if (target_bitrate_bps == 0)
    {
        target_bitrate_bps = config.initial_target_bitrate_bps;
    }

    switch (next_state)
    {
        case ice_udp_server::subscriber_downlink_control_state::probing:
            break;

        case ice_udp_server::subscriber_downlink_control_state::steady:
            target_bitrate_bps = increase_bitrate_by_ppm(target_bitrate_bps, config.steady_increase_ppm, 50000U);
            break;

        case ice_udp_server::subscriber_downlink_control_state::recovering:
            target_bitrate_bps = increase_bitrate_by_ppm(target_bitrate_bps, config.recovering_increase_ppm, 25000U);
            break;

        case ice_udp_server::subscriber_downlink_control_state::hold_down:
            target_bitrate_bps = increase_bitrate_by_ppm(target_bitrate_bps, config.hold_down_increase_ppm, 10000U);
            break;

        case ice_udp_server::subscriber_downlink_control_state::constrained:
            if (loss_rate_ppm >= config.severe_loss_rate_ppm)
            {
                target_bitrate_bps = scale_bitrate(target_bitrate_bps, config.severe_constrained_decrease_ppm, 1000000U);
            }
            else
            {
                target_bitrate_bps = scale_bitrate(target_bitrate_bps, config.constrained_decrease_ppm, 1000000U);
            }
            break;
    }

    return clamp_bitrate(target_bitrate_bps, state.min_bitrate_bps, state.max_bitrate_bps);
}

bool subscriber_downlink_state_enables_bitrate_gate(ice_udp_server::subscriber_downlink_control_state state)
{
    switch (state)
    {
        case ice_udp_server::subscriber_downlink_control_state::probing:
            return false;

        case ice_udp_server::subscriber_downlink_control_state::steady:
        case ice_udp_server::subscriber_downlink_control_state::recovering:
        case ice_udp_server::subscriber_downlink_control_state::constrained:
        case ice_udp_server::subscriber_downlink_control_state::hold_down:
            return true;
    }

    return false;
}

uint64_t subscriber_downlink_bitrate_gate_max_budget_bytes(uint64_t target_bitrate_bps)
{
    constexpr uint64_t k_min_burst_budget_bytes = 32000;
    constexpr uint64_t k_burst_window_denominator = 16;

    const uint64_t half_second_budget = target_bitrate_bps / 8U / k_burst_window_denominator;

    return std::max<uint64_t>(half_second_budget, k_min_burst_budget_bytes);
}

uint64_t subscriber_downlink_bitrate_gate_refill_bytes(uint64_t target_bitrate_bps, uint64_t elapsed_milliseconds)
{
    constexpr uint64_t k_bits_per_byte = 8;
    constexpr uint64_t k_milliseconds_per_second = 1000;

    if (target_bitrate_bps == 0 || elapsed_milliseconds == 0)
    {
        return 0;
    }

    return static_cast<uint64_t>((static_cast<unsigned __int128>(target_bitrate_bps) * elapsed_milliseconds) /
                                 (k_bits_per_byte * k_milliseconds_per_second));
}

void refill_subscriber_downlink_bitrate_gate_budget(ice_udp_server::subscriber_downlink_bandwidth_state& state, uint64_t current_time_milliseconds)
{
    constexpr uint64_t k_max_refill_elapsed_milliseconds = 500;

    if (state.bitrate_gate_last_update_milliseconds == 0)
    {
        state.bitrate_gate_last_update_milliseconds = current_time_milliseconds;
        state.bitrate_gate_budget_bytes = subscriber_downlink_bitrate_gate_max_budget_bytes(state.target_bitrate_bps);

        return;
    }

    if (current_time_milliseconds <= state.bitrate_gate_last_update_milliseconds)
    {
        return;
    }

    const uint64_t elapsed_milliseconds =
        std::min<uint64_t>(current_time_milliseconds - state.bitrate_gate_last_update_milliseconds, k_max_refill_elapsed_milliseconds);

    state.bitrate_gate_last_update_milliseconds = current_time_milliseconds;

    const uint64_t refill_bytes = subscriber_downlink_bitrate_gate_refill_bytes(state.target_bitrate_bps, elapsed_milliseconds);

    const uint64_t max_budget_bytes = subscriber_downlink_bitrate_gate_max_budget_bytes(state.target_bitrate_bps);

    state.bitrate_gate_budget_bytes = std::min<uint64_t>(state.bitrate_gate_budget_bytes + refill_bytes, max_budget_bytes);
}
uint64_t subscriber_downlink_pacing_max_budget_bytes(uint64_t target_bitrate_bps)
{
    constexpr uint64_t k_min_pacing_burst_budget_bytes = 12000;
    constexpr uint64_t k_pacing_burst_window_denominator = 20;

    if (target_bitrate_bps == 0)
    {
        return k_min_pacing_burst_budget_bytes;
    }

    const uint64_t burst_budget = target_bitrate_bps / 8U / k_pacing_burst_window_denominator;

    return std::max<uint64_t>(burst_budget, k_min_pacing_burst_budget_bytes);
}

uint64_t subscriber_downlink_pacing_refill_bytes(uint64_t target_bitrate_bps, uint64_t elapsed_milliseconds)
{
    constexpr uint64_t k_bits_per_byte = 8;
    constexpr uint64_t k_milliseconds_per_second = 1000;

    if (target_bitrate_bps == 0 || elapsed_milliseconds == 0)
    {
        return 0;
    }

    return static_cast<uint64_t>((static_cast<unsigned __int128>(target_bitrate_bps) * elapsed_milliseconds) /
                                 (k_bits_per_byte * k_milliseconds_per_second));
}

void refill_subscriber_downlink_pacing_budget(ice_udp_server::subscriber_downlink_pacing_state& pacing_state,
                                              const ice_udp_server::subscriber_downlink_bandwidth_state* bandwidth_state,
                                              uint64_t current_time_milliseconds)
{
    constexpr uint64_t k_max_pacing_refill_elapsed_milliseconds = 100;

    const uint64_t target_bitrate_bps =
        bandwidth_state != nullptr && bandwidth_state->target_bitrate_bps != 0 ? bandwidth_state->target_bitrate_bps : 2000000U;

    if (pacing_state.pacing_last_update_milliseconds == 0)
    {
        pacing_state.pacing_last_update_milliseconds = current_time_milliseconds;
        pacing_state.pacing_budget_bytes = subscriber_downlink_pacing_max_budget_bytes(target_bitrate_bps) / 2U;

        return;
    }

    if (current_time_milliseconds <= pacing_state.pacing_last_update_milliseconds)
    {
        return;
    }

    const uint64_t elapsed_milliseconds =
        std::min<uint64_t>(current_time_milliseconds - pacing_state.pacing_last_update_milliseconds, k_max_pacing_refill_elapsed_milliseconds);

    pacing_state.pacing_last_update_milliseconds = current_time_milliseconds;

    const uint64_t refill_bytes = subscriber_downlink_pacing_refill_bytes(target_bitrate_bps, elapsed_milliseconds);

    const uint64_t max_budget_bytes = subscriber_downlink_pacing_max_budget_bytes(target_bitrate_bps);

    pacing_state.pacing_budget_bytes = std::min<uint64_t>(pacing_state.pacing_budget_bytes + refill_bytes, max_budget_bytes);
}
bool subscriber_downlink_keyframe_recovery_window_active(const ice_udp_server::subscriber_downlink_bandwidth_state& state,
                                                         uint64_t current_time_milliseconds)
{
    if (state.keyframe_recovery_until_milliseconds == 0)
    {
        return false;
    }

    return current_time_milliseconds <= state.keyframe_recovery_until_milliseconds;
}
bool subscriber_downlink_pacing_state_key_matches_session(std::string_view key, std::string_view session_id)
{
    return subscriber_downlink_bandwidth_state_key_matches_session(key, session_id);
}

bool subscriber_downlink_pacing_state_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    return subscriber_downlink_bandwidth_state_key_matches_stream(key, stream_id);
}
void reset_outbound_transport_cc_feedback_window_runtime(ice_udp_server::outbound_transport_cc_feedback_window_state& window,
                                                         uint64_t current_time_milliseconds)
{
    window.first_feedback_at_milliseconds = current_time_milliseconds;
    window.last_feedback_at_milliseconds = current_time_milliseconds;

    window.feedback_count = 0;
    window.feedback_packet_status_count = 0;

    window.lookup_hit_count = 0;
    window.lookup_miss_count = 0;

    window.received_count = 0;
    window.lost_count = 0;

    window.small_delta_count = 0;
    window.large_delta_count = 0;

    window.delta_microseconds_sum = 0;
    window.max_delta_microseconds = 0;
    window.min_delta_microseconds = 0;

    window.observations.clear();
}
void add_outbound_transport_cc_feedback_delta(ice_udp_server::outbound_transport_cc_feedback_window_state& window, int64_t delta_microseconds)
{
    if (window.small_delta_count + window.large_delta_count == 0)
    {
        window.min_delta_microseconds = delta_microseconds;
        window.max_delta_microseconds = delta_microseconds;
        window.delta_microseconds_sum = delta_microseconds;

        return;
    }

    window.delta_microseconds_sum += delta_microseconds;
    window.min_delta_microseconds = std::min(delta_microseconds, window.min_delta_microseconds);
    window.max_delta_microseconds = std::max(delta_microseconds, window.max_delta_microseconds);
}

void subtract_outbound_transport_cc_feedback_delta(ice_udp_server::outbound_transport_cc_feedback_window_state& window, int64_t delta_microseconds)
{
    window.delta_microseconds_sum -= delta_microseconds;
}

uint64_t make_rate_ppm(uint64_t numerator, uint64_t denominator)
{
    if (denominator == 0)
    {
        return 0;
    }

    return static_cast<uint64_t>((static_cast<unsigned __int128>(numerator) * 1000000U) / denominator);
}

int64_t make_average_delta_microseconds(const ice_udp_server::outbound_transport_cc_feedback_window_state& window)
{
    const uint64_t delta_count = window.small_delta_count + window.large_delta_count;

    if (delta_count == 0)
    {
        return 0;
    }

    return window.delta_microseconds_sum / static_cast<int64_t>(delta_count);
}

lifecycle_debug_transport_cc_feedback_window_entry make_transport_cc_feedback_window_debug_entry(
    const ice_udp_server::outbound_transport_cc_feedback_window_state& window)
{
    lifecycle_debug_transport_cc_feedback_window_entry entry;

    entry.stream_id = window.stream_id;
    entry.subscriber_session_id = window.subscriber_session_id;

    entry.first_feedback_at_milliseconds = window.first_feedback_at_milliseconds;
    entry.last_feedback_at_milliseconds = window.last_feedback_at_milliseconds;

    entry.feedback_count = window.feedback_count;
    entry.feedback_packet_status_count = window.feedback_packet_status_count;

    entry.lookup_hit_count = window.lookup_hit_count;
    entry.lookup_miss_count = window.lookup_miss_count;
    entry.lookup_hit_rate_ppm = make_rate_ppm(window.lookup_hit_count, window.lookup_hit_count + window.lookup_miss_count);

    entry.received_count = window.received_count;
    entry.lost_count = window.lost_count;
    entry.loss_rate_ppm = make_rate_ppm(window.lost_count, window.received_count + window.lost_count);

    entry.small_delta_count = window.small_delta_count;
    entry.large_delta_count = window.large_delta_count;

    entry.avg_delta_microseconds = make_average_delta_microseconds(window);
    entry.min_delta_microseconds = window.min_delta_microseconds;
    entry.max_delta_microseconds = window.max_delta_microseconds;

    entry.observation_count = static_cast<uint64_t>(window.observations.size());

    return entry;
}

lifecycle_debug_subscriber_downlink_bandwidth_entry make_subscriber_downlink_bandwidth_debug_entry(
    const ice_udp_server::subscriber_downlink_bandwidth_state& state,
    const ice_udp_server::subscriber_downlink_pacing_state* pacing_state,
    ice_udp_server::subscriber_downlink_control_mode control_mode)
{
    lifecycle_debug_subscriber_downlink_bandwidth_entry entry;

    entry.stream_id = state.stream_id;
    entry.subscriber_session_id = state.subscriber_session_id;
    entry.control_state = subscriber_downlink_control_state_to_string(state.control_state);
    entry.control_mode = subscriber_downlink_control_mode_to_string(control_mode);
    entry.created_at_milliseconds = state.created_at_milliseconds;
    entry.updated_at_milliseconds = state.updated_at_milliseconds;
    entry.last_feedback_at_milliseconds = state.last_feedback_at_milliseconds;
    entry.last_transition_at_milliseconds = state.last_transition_at_milliseconds;
    entry.state_entered_at_milliseconds = state.state_entered_at_milliseconds;
    entry.hold_down_until_milliseconds = state.hold_down_until_milliseconds;

    entry.transition_count = state.transition_count;
    entry.healthy_window_count = state.healthy_window_count;
    entry.bad_window_count = state.bad_window_count;
    entry.unreliable_window_count = state.unreliable_window_count;
    entry.last_transition_reason = state.last_transition_reason;
    entry.target_bitrate_bps = state.target_bitrate_bps;
    entry.min_bitrate_bps = state.min_bitrate_bps;
    entry.max_bitrate_bps = state.max_bitrate_bps;

    entry.feedback_count = state.feedback_count;
    entry.window_observation_count = state.window_observation_count;
    entry.window_packet_status_count = state.window_packet_status_count;

    entry.lookup_hit_rate_ppm = state.lookup_hit_rate_ppm;
    entry.loss_rate_ppm = state.loss_rate_ppm;

    entry.received_count = state.received_count;
    entry.lost_count = state.lost_count;

    entry.avg_delta_microseconds = state.avg_delta_microseconds;
    entry.min_delta_microseconds = state.min_delta_microseconds;
    entry.max_delta_microseconds = state.max_delta_microseconds;

    entry.bitrate_gate_last_update_milliseconds = state.bitrate_gate_last_update_milliseconds;
    entry.bitrate_gate_budget_bytes = state.bitrate_gate_budget_bytes;

    entry.bitrate_gate_observed_allowed_packet_count = state.bitrate_gate_observed_allowed_packet_count;
    entry.bitrate_gate_observed_dropped_packet_count = state.bitrate_gate_observed_dropped_packet_count;
    entry.bitrate_gate_observed_allowed_byte_count = state.bitrate_gate_observed_allowed_byte_count;
    entry.bitrate_gate_observed_dropped_byte_count = state.bitrate_gate_observed_dropped_byte_count;

    entry.bitrate_gate_allowed_packet_count = state.bitrate_gate_allowed_packet_count;
    entry.bitrate_gate_dropped_packet_count = state.bitrate_gate_dropped_packet_count;
    entry.bitrate_gate_allowed_byte_count = state.bitrate_gate_allowed_byte_count;
    entry.bitrate_gate_dropped_byte_count = state.bitrate_gate_dropped_byte_count;
    entry.bitrate_gate_keyframe_bypass_packet_count = state.bitrate_gate_keyframe_bypass_packet_count;
    entry.bitrate_gate_keyframe_bypass_byte_count = state.bitrate_gate_keyframe_bypass_byte_count;

    entry.bitrate_gate_keyframe_request_recovery_open_count = state.bitrate_gate_keyframe_request_recovery_open_count;
    entry.bitrate_gate_keyframe_request_recovery_refresh_count = state.bitrate_gate_keyframe_request_recovery_refresh_count;

    entry.bitrate_gate_recovery_bypass_packet_count = state.bitrate_gate_recovery_bypass_packet_count;
    entry.bitrate_gate_recovery_bypass_byte_count = state.bitrate_gate_recovery_bypass_byte_count;

    entry.last_keyframe_request_at_milliseconds = state.last_keyframe_request_at_milliseconds;

    entry.keyframe_recovery_until_milliseconds = state.keyframe_recovery_until_milliseconds;
    entry.keyframe_recovery_remaining_packet_count = state.keyframe_recovery_remaining_packet_count;
    if (pacing_state != nullptr)
    {
        entry.pacing_queue_packet_count = static_cast<uint64_t>(pacing_state->queue.size());
        entry.pacing_queue_byte_count = pacing_state->queue_byte_count;
        entry.pacing_budget_bytes = pacing_state->pacing_budget_bytes;
        entry.pacing_last_update_milliseconds = pacing_state->pacing_last_update_milliseconds;

        entry.pacing_observed_enqueued_packet_count = pacing_state->observed_enqueued_packet_count;
        entry.pacing_observed_enqueued_byte_count = pacing_state->observed_enqueued_byte_count;

        entry.pacing_enqueued_packet_count = pacing_state->enqueued_packet_count;
        entry.pacing_enqueued_byte_count = pacing_state->enqueued_byte_count;

        entry.pacing_sent_packet_count = pacing_state->sent_packet_count;
        entry.pacing_sent_byte_count = pacing_state->sent_byte_count;

        entry.pacing_dropped_packet_count = pacing_state->dropped_packet_count;
        entry.pacing_dropped_byte_count = pacing_state->dropped_byte_count;
    }

    return entry;
}
std::string make_subscriber_recovery_runtime_debug_key(std::string_view stream_id, std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 1);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    return key;
}

lifecycle_debug_subscriber_recovery_runtime_entry& get_or_create_subscriber_recovery_runtime_entry(
    lifecycle_debug_snapshot& snapshot,
    std::unordered_map<std::string, std::size_t>& index_by_key,
    std::string_view stream_id,
    std::string_view subscriber_session_id)
{
    const std::string key = make_subscriber_recovery_runtime_debug_key(stream_id, subscriber_session_id);

    const auto iterator = index_by_key.find(key);

    if (iterator != index_by_key.end())
    {
        return snapshot.subscriber_recovery_runtimes[iterator->second];
    }

    lifecycle_debug_subscriber_recovery_runtime_entry entry;

    entry.stream_id = stream_id;
    entry.subscriber_session_id = subscriber_session_id;

    snapshot.subscriber_recovery_runtimes.push_back(std::move(entry));

    const std::size_t index = snapshot.subscriber_recovery_runtimes.size() - 1;

    index_by_key.emplace(key, index);

    return snapshot.subscriber_recovery_runtimes[index];
}

void finish_subscriber_recovery_runtime_entry(lifecycle_debug_subscriber_recovery_runtime_entry& entry)
{
    const uint64_t lookup_total = entry.transport_cc_lookup_hit_count + entry.transport_cc_lookup_miss_count;

    entry.transport_cc_lookup_hit_rate_ppm = make_rate_ppm(entry.transport_cc_lookup_hit_count, lookup_total);

    const uint64_t packet_status_total = entry.transport_cc_received_count + entry.transport_cc_lost_count;

    entry.transport_cc_loss_rate_ppm = make_rate_ppm(entry.transport_cc_lost_count, packet_status_total);
}

uint64_t to_debug_count(std::size_t value) { return static_cast<uint64_t>(value); }

void append_runtime_resource_limit(lifecycle_debug_snapshot& snapshot, std::string_view name, uint64_t current, uint64_t limit)
{
    lifecycle_debug_resource_limit_entry entry;

    entry.name = std::string(name);
    entry.current = current;
    entry.limit = limit;
    entry.over_limit = limit != 0 && current > limit;

    if (entry.over_limit)
    {
        snapshot.runtime_resource_limit_over_count += 1;
    }

    snapshot.runtime_resource_limits.push_back(std::move(entry));
}

void update_runtime_acceptance_summary(lifecycle_debug_snapshot& snapshot)
{
    lifecycle_debug_runtime_acceptance_summary summary;

    summary.debug_schema_version = snapshot.debug_schema_version;

    summary.consistent = snapshot.consistent;
    summary.full_idle_clean = snapshot.full_idle_clean;
    summary.active_runtime_clean = snapshot.active_runtime_clean;
    summary.delayed_runtime_clean = snapshot.delayed_runtime_clean;

    summary.registry_session_count = snapshot.registry_session_count;
    summary.registry_publisher_count = snapshot.registry_publisher_count;
    summary.registry_subscriber_count = snapshot.registry_subscriber_count;
    summary.registry_pending_session_count = snapshot.registry_pending_session_count;

    summary.runtime_resource_limit_over_count = snapshot.runtime_resource_limit_over_count;

    summary.inconsistency_count = snapshot.inconsistency_count;
    summary.active_runtime_residual_count = to_debug_count(snapshot.residuals.size());
    summary.delayed_runtime_residual_count = snapshot.delayed_residual_count;

    summary.rtp_rtcp_drop_total = snapshot.rtp_rtcp_drop_total;
    summary.rtp_rtcp_drop_reason_count = snapshot.rtp_rtcp_drop_reason_count;

    summary.endpoint_count = snapshot.endpoint_count;
    summary.candidate_pair_count = snapshot.candidate_pair_count;
    summary.dtls_peer_count = snapshot.dtls_peer_count;
    summary.srtp_peer_count = snapshot.srtp_peer_count;

    summary.media_router_peer_count = snapshot.media_router_peer_count;
    summary.media_router_stream_count = snapshot.media_router_stream_count;
    summary.media_router_active_publisher_count = snapshot.media_router_active_publisher_count;
    summary.media_router_active_subscriber_count = snapshot.media_router_active_subscriber_count;

    summary.rtp_cache_packet_count = snapshot.rtp_cache_packet_count;
    summary.outbound_transport_cc_packet_count = snapshot.outbound_transport_cc_packet_count;

    summary.subscriber_downlink_bandwidth_state_count = snapshot.subscriber_downlink_bandwidth_state_count;
    summary.subscriber_downlink_pacing_state_count = snapshot.subscriber_downlink_pacing_state_count;
    summary.subscriber_downlink_pacing_queue_packet_count = snapshot.subscriber_downlink_pacing_queue_packet_count;
    summary.subscriber_downlink_pacing_queue_byte_count = snapshot.subscriber_downlink_pacing_queue_byte_count;

    summary.release_gate_pass = summary.consistent && summary.full_idle_clean && summary.runtime_resource_limit_over_count == 0 &&
                                summary.inconsistency_count == 0 && summary.active_runtime_residual_count == 0 &&
                                summary.delayed_runtime_residual_count == 0;

    snapshot.runtime_acceptance_summary = std::move(summary);
}

void log_lifecycle_acceptance_summary(std::string_view event,
                                      std::string_view reason,
                                      std::string_view stream_id,
                                      std::string_view session_id,
                                      const lifecycle_debug_snapshot& snapshot)
{
    const lifecycle_debug_runtime_acceptance_summary& summary = snapshot.runtime_acceptance_summary;

    WEBRTC_LOG_INFO(
        "flag_runtime_acceptance_summary event={} reason={} stream={} session={} schema={} release_gate_pass={} consistent={} "
        "full_idle_clean={} active_runtime_clean={} delayed_runtime_clean={} registry_sessions={} registry_publishers={} registry_subscribers={} "
        "registry_pending_sessions={} resource_limit_over={} inconsistencies={} active_residuals={} delayed_residuals={} rtp_rtcp_drops={} "
        "drop_reasons={} endpoints={} candidate_pairs={} dtls_peers={} srtp_peers={} media_router_peers={} media_router_streams={} "
        "media_router_active_publishers={} media_router_active_subscribers={} rtp_cache_packets={} outbound_twcc_packets={} "
        "downlink_bandwidth_states={} downlink_pacing_states={} downlink_pacing_queue_packets={} downlink_pacing_queue_bytes={}",
        event,
        reason,
        stream_id,
        session_id,
        summary.debug_schema_version,
        summary.release_gate_pass ? 1 : 0,
        summary.consistent ? 1 : 0,
        summary.full_idle_clean ? 1 : 0,
        summary.active_runtime_clean ? 1 : 0,
        summary.delayed_runtime_clean ? 1 : 0,
        summary.registry_session_count,
        summary.registry_publisher_count,
        summary.registry_subscriber_count,
        summary.registry_pending_session_count,
        summary.runtime_resource_limit_over_count,
        summary.inconsistency_count,
        summary.active_runtime_residual_count,
        summary.delayed_runtime_residual_count,
        summary.rtp_rtcp_drop_total,
        summary.rtp_rtcp_drop_reason_count,
        summary.endpoint_count,
        summary.candidate_pair_count,
        summary.dtls_peer_count,
        summary.srtp_peer_count,
        summary.media_router_peer_count,
        summary.media_router_stream_count,
        summary.media_router_active_publisher_count,
        summary.media_router_active_subscriber_count,
        summary.rtp_cache_packet_count,
        summary.outbound_transport_cc_packet_count,
        summary.subscriber_downlink_bandwidth_state_count,
        summary.subscriber_downlink_pacing_state_count,
        summary.subscriber_downlink_pacing_queue_packet_count,
        summary.subscriber_downlink_pacing_queue_byte_count);
}

void log_lifecycle_resource_limit_over_details(std::string_view event,
                                               std::string_view reason,
                                               std::string_view stream_id,
                                               std::string_view session_id,
                                               const lifecycle_debug_snapshot& snapshot)
{
    if (snapshot.runtime_resource_limit_over_count == 0)
    {
        return;
    }

    for (const auto& resource_limit : snapshot.runtime_resource_limits)
    {
        if (!resource_limit.over_limit)
        {
            continue;
        }

        WEBRTC_LOG_WARN("flag_resource_limit_over event={} reason={} stream={} session={} resource={} current={} limit={}",
                        event,
                        reason,
                        stream_id,
                        session_id,
                        resource_limit.name,
                        resource_limit.current,
                        resource_limit.limit);
    }
}
void log_lifecycle_downlink_summary(std::string_view event,
                                    std::string_view reason,
                                    std::string_view stream_id,
                                    std::string_view session_id,
                                    const lifecycle_debug_snapshot& snapshot)
{
    for (const auto& state : snapshot.subscriber_downlink_bandwidth_states)
    {
        WEBRTC_LOG_INFO(
            "flag_p2_downlink_summary event={} reason={} request_stream={} request_session={} stream={} subscriber={} control_mode={} "
            "control_state={} target_bitrate_bps={} min_bitrate_bps={} max_bitrate_bps={} lookup_hit_rate_ppm={} loss_rate_ppm={} "
            "received_packets={} lost_packets={} feedback_count={} window_observations={} window_packet_statuses={} healthy_windows={} "
            "bad_windows={} unreliable_windows={} transition_count={} state_entered_at={} hold_down_until={} last_feedback_at={} "
            "bitrate_gate_budget_bytes={} bitrate_gate_allowed_packets={} bitrate_gate_dropped_packets={} bitrate_gate_allowed_bytes={} "
            "bitrate_gate_dropped_bytes={} bitrate_gate_keyframe_bypass_packets={} bitrate_gate_keyframe_bypass_bytes={} "
            "bitrate_gate_recovery_bypass_packets={} bitrate_gate_recovery_bypass_bytes={} keyframe_recovery_until={} "
            "keyframe_recovery_remaining_packets={} last_keyframe_request_at={} pacing_queue_packets={} pacing_queue_bytes={} "
            "pacing_budget_bytes={} pacing_enqueued_packets={} pacing_enqueued_bytes={} pacing_sent_packets={} pacing_sent_bytes={} "
            "pacing_dropped_packets={} pacing_dropped_bytes={} last_transition_reason={}",
            event,
            reason,
            stream_id,
            session_id,
            state.stream_id,
            state.subscriber_session_id,
            state.control_mode,
            state.control_state,
            state.target_bitrate_bps,
            state.min_bitrate_bps,
            state.max_bitrate_bps,
            state.lookup_hit_rate_ppm,
            state.loss_rate_ppm,
            state.received_count,
            state.lost_count,
            state.feedback_count,
            state.window_observation_count,
            state.window_packet_status_count,
            state.healthy_window_count,
            state.bad_window_count,
            state.unreliable_window_count,
            state.transition_count,
            state.state_entered_at_milliseconds,
            state.hold_down_until_milliseconds,
            state.last_feedback_at_milliseconds,
            state.bitrate_gate_budget_bytes,
            state.bitrate_gate_allowed_packet_count,
            state.bitrate_gate_dropped_packet_count,
            state.bitrate_gate_allowed_byte_count,
            state.bitrate_gate_dropped_byte_count,
            state.bitrate_gate_keyframe_bypass_packet_count,
            state.bitrate_gate_keyframe_bypass_byte_count,
            state.bitrate_gate_recovery_bypass_packet_count,
            state.bitrate_gate_recovery_bypass_byte_count,
            state.keyframe_recovery_until_milliseconds,
            state.keyframe_recovery_remaining_packet_count,
            state.last_keyframe_request_at_milliseconds,
            state.pacing_queue_packet_count,
            state.pacing_queue_byte_count,
            state.pacing_budget_bytes,
            state.pacing_enqueued_packet_count,
            state.pacing_enqueued_byte_count,
            state.pacing_sent_packet_count,
            state.pacing_sent_byte_count,
            state.pacing_dropped_packet_count,
            state.pacing_dropped_byte_count,
            state.last_transition_reason);
    }
}
void append_subscriber_recovery_runtime_debug_entries(lifecycle_debug_snapshot& snapshot)
{
    std::unordered_map<std::string, std::size_t> index_by_key;

    snapshot.subscriber_recovery_runtimes.reserve(snapshot.subscriber_forward_groups.size());

    for (const auto& group : snapshot.subscriber_forward_groups)
    {
        auto& entry = get_or_create_subscriber_recovery_runtime_entry(snapshot, index_by_key, group.stream_id, group.subscriber_session_id);

        entry.publisher_session_id = group.publisher_session_id;
        entry.forward_group_present = true;

        entry.forward_binding_count = group.forward_binding_count;
        entry.primary_forward_binding_count = group.primary_forward_binding_count;
        entry.rtx_forward_binding_count = group.rtx_forward_binding_count;
        entry.audio_forward_binding_count = group.audio_forward_binding_count;
        entry.video_forward_binding_count = group.video_forward_binding_count;
        entry.forwarded_packet_count = group.packet_count;
    }

    for (const auto& group : snapshot.subscriber_rtcp_groups)
    {
        auto& entry = get_or_create_subscriber_recovery_runtime_entry(snapshot, index_by_key, group.stream_id, group.subscriber_session_id);

        entry.rtcp_group_present = true;

        entry.rtcp_report_source_count = group.rtcp_report_source_count;
        entry.twcc_feedback_source_count = group.twcc_feedback_source_count;
        entry.twcc_pending_packet_count = group.twcc_pending_packet_count;
    }

    for (const auto& window : snapshot.outbound_transport_cc_feedback_windows)
    {
        auto& entry = get_or_create_subscriber_recovery_runtime_entry(snapshot, index_by_key, window.stream_id, window.subscriber_session_id);

        entry.transport_cc_feedback_window_count += 1;
        entry.transport_cc_feedback_observation_count += window.observation_count;

        entry.transport_cc_lookup_hit_count += window.lookup_hit_count;
        entry.transport_cc_lookup_miss_count += window.lookup_miss_count;

        entry.transport_cc_received_count += window.received_count;
        entry.transport_cc_lost_count += window.lost_count;
    }

    for (const auto& state : snapshot.subscriber_downlink_bandwidth_states)
    {
        auto& entry = get_or_create_subscriber_recovery_runtime_entry(snapshot, index_by_key, state.stream_id, state.subscriber_session_id);

        entry.downlink_state_present = true;

        entry.downlink_control_state = state.control_state;
        entry.downlink_target_bitrate_bps = state.target_bitrate_bps;
        entry.downlink_transition_count = state.transition_count;

        entry.pacing_queue_packet_count = state.pacing_queue_packet_count;
        entry.pacing_queue_byte_count = state.pacing_queue_byte_count;
        entry.pacing_enqueued_packet_count = state.pacing_enqueued_packet_count;
        entry.pacing_sent_packet_count = state.pacing_sent_packet_count;
        entry.pacing_dropped_packet_count = state.pacing_dropped_packet_count;

        entry.bitrate_gate_allowed_packet_count = state.bitrate_gate_allowed_packet_count;
        entry.bitrate_gate_dropped_packet_count = state.bitrate_gate_dropped_packet_count;
    }

    for (auto& entry : snapshot.subscriber_recovery_runtimes)
    {
        finish_subscriber_recovery_runtime_entry(entry);
    }

    snapshot.subscriber_recovery_runtime_count = to_debug_count(snapshot.subscriber_recovery_runtimes.size());
}

std::string make_outbound_transport_cc_packet_key(std::string_view stream_id,
                                                  std::string_view subscriber_session_id,
                                                  uint16_t subscriber_transport_cc_sequence_number)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 16);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(std::to_string(subscriber_transport_cc_sequence_number));

    return key;
}
std::string make_outbound_transport_cc_rtp_packet_key(std::string_view stream_id,
                                                      std::string_view subscriber_session_id,
                                                      uint32_t subscriber_ssrc,
                                                      uint16_t subscriber_rtp_sequence_number)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 32);

    key.append(stream_id);
    key.push_back('|');
    key.append(subscriber_session_id);
    key.push_back('|');
    key.append(std::to_string(subscriber_ssrc));
    key.push_back('|');
    key.append(std::to_string(subscriber_rtp_sequence_number));

    return key;
}

bool outbound_transport_cc_rtp_packet_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return false;
    }

    std::string prefix(stream_id);
    prefix.push_back('|');

    return key.starts_with(prefix);
}

bool outbound_transport_cc_rtp_packet_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (session_id.empty())
    {
        return false;
    }

    std::string marker;
    marker.reserve(session_id.size() + 2);
    marker.push_back('|');
    marker.append(session_id);
    marker.push_back('|');

    return key.find(marker) != std::string_view::npos;
}

bool outbound_transport_cc_packet_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (key.empty() || session_id.empty())
    {
        return false;
    }

    std::string marker;

    marker.reserve(session_id.size() + 2);

    marker.push_back('|');

    marker.append(session_id);

    marker.push_back('|');

    return key.find(marker) != std::string_view::npos;
}

bool outbound_transport_cc_packet_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    if (key.empty() || stream_id.empty())
    {
        return false;
    }

    std::string prefix;

    prefix.reserve(stream_id.size() + 1);

    prefix.append(stream_id);

    prefix.push_back('|');

    return key.starts_with(prefix);
}

bool outbound_transport_cc_sequence_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (key.empty() || session_id.empty())
    {
        return false;
    }

    const std::size_t separator = key.find('|');

    if (separator == std::string_view::npos)
    {
        return false;
    }

    const std::string_view subscriber_session_id = key.substr(separator + 1);

    return subscriber_session_id == session_id;
}

bool outbound_transport_cc_sequence_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    if (key.empty() || stream_id.empty())
    {
        return false;
    }

    std::string prefix;

    prefix.reserve(stream_id.size() + 1);

    prefix.append(stream_id);

    prefix.push_back('|');

    return key.starts_with(prefix);
}
std::string make_outbound_rtp_sequence_key(std::string_view stream_id, std::string_view subscriber_session_id, uint32_t subscriber_ssrc)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 24);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(std::to_string(subscriber_ssrc));

    return key;
}
std::string make_outbound_rtp_packet_key(std::string_view stream_id,
                                         std::string_view subscriber_session_id,
                                         uint32_t subscriber_ssrc,
                                         uint16_t subscriber_sequence_number)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 48);

    key.append(stream_id);

    key.push_back('|');

    key.append(subscriber_session_id);

    key.push_back('|');

    key.append(std::to_string(subscriber_ssrc));

    key.push_back('|');

    key.append(std::to_string(subscriber_sequence_number));

    return key;
}

bool outbound_rtp_sequence_key_matches_stream(std::string_view key, std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return false;
    }

    const std::string prefix = std::string(stream_id) + "|";

    return key.starts_with(prefix);
}

bool outbound_rtp_sequence_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (session_id.empty())
    {
        return false;
    }

    const std::string needle = "|" + std::string(session_id) + "|";

    return key.find(needle) != std::string_view::npos;
}

bool keyframe_request_key_matches_session(std::string_view key, std::string_view session_id)
{
    if (key.empty() || session_id.empty())
    {
        return false;
    }

    const std::size_t first_separator = key.find('|');

    if (first_separator == std::string_view::npos)
    {
        return false;
    }

    const std::size_t second_separator = key.find('|', first_separator + 1);

    if (second_separator == std::string_view::npos)
    {
        return false;
    }

    const std::size_t third_separator = key.find('|', second_separator + 1);

    if (third_separator == std::string_view::npos)
    {
        return false;
    }

    const std::string_view publisher_session_id = key.substr(first_separator + 1, second_separator - first_separator - 1);

    const std::string_view subscriber_session_id = key.substr(second_separator + 1, third_separator - second_separator - 1);

    return publisher_session_id == session_id || subscriber_session_id == session_id;
}

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_field_error(std::string_view field, std::string_view message)
{
    std::string error;

    error.reserve(field.size() + message.size() + 2);

    error.append(field);
    error.push_back(' ');
    error.append(message);

    return std::unexpected(std::move(error));
}

uint64_t now_milliseconds() { return timestamp::now().milliseconds(); }

bool contains_string(const std::vector<std::string>& values, std::string_view value)
{
    return std::any_of(values.begin(), values.end(), [value](const std::string& candidate) { return candidate == value; });
}

bool contains_unordered_string(const std::unordered_set<std::string>& values, std::string_view value)
{
    return values.find(std::string(value)) != values.end();
}

bool pending_session_cleanup_candidate_is_older(const pending_session_cleanup_candidate& left, const pending_session_cleanup_candidate& right)
{
    if (left.reference_time_milliseconds != right.reference_time_milliseconds)
    {
        return left.reference_time_milliseconds < right.reference_time_milliseconds;
    }

    return left.session_id < right.session_id;
}

void append_pending_session_cleanup_candidate(std::vector<pending_session_cleanup_candidate>& candidates,
                                              const stream_session_lifecycle_snapshot& snapshot,
                                              uint64_t current_time_milliseconds)
{
    pending_session_cleanup_candidate candidate;

    candidate.session_id = snapshot.session_id;
    candidate.stream_id = snapshot.stream_id;
    candidate.kind = snapshot.kind;
    candidate.reference_time_milliseconds =
        snapshot.updated_at_milliseconds != 0 ? snapshot.updated_at_milliseconds : snapshot.created_at_milliseconds;
    candidate.age_milliseconds =
        current_time_milliseconds > candidate.reference_time_milliseconds ? current_time_milliseconds - candidate.reference_time_milliseconds : 0;

    candidates.push_back(std::move(candidate));
}

std::string make_subscriber_forward_group_key(std::string_view stream_id,
                                              std::string_view publisher_session_id,
                                              std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(stream_id.size() + publisher_session_id.size() + subscriber_session_id.size() + 2);

    key.append(stream_id);
    key.push_back('|');
    key.append(publisher_session_id);
    key.push_back('|');
    key.append(subscriber_session_id);

    return key;
}

void update_subscriber_forward_group(lifecycle_debug_subscriber_forward_group_entry& group, const media_identity_forward_binding& binding)
{
    group.forward_binding_count += 1;

    if (binding.kind == "audio")
    {
        group.audio_forward_binding_count += 1;

        if (media_identity_forward_binding_has_audio_ordinal_mismatch(binding))
        {
            group.audio_ordinal_mismatch_count += 1;
        }
    }

    if (binding.kind == "video")
    {
        group.video_forward_binding_count += 1;
    }

    if (binding.rtx)
    {
        group.rtx_forward_binding_count += 1;
    }
    else
    {
        group.primary_forward_binding_count += 1;
    }

    if (binding.payload_type_rewrite_required)
    {
        group.payload_type_rewrite_required_count += 1;
    }

    if (binding.mid_rewrite_required)
    {
        group.mid_rewrite_required_count += 1;
    }

    if (binding.ssrc_rewrite_required)
    {
        group.ssrc_rewrite_required_count += 1;
    }

    group.packet_count += binding.packet_count;
}

std::vector<lifecycle_debug_subscriber_forward_group_entry> make_subscriber_forward_groups(
    const std::vector<media_identity_forward_binding>& forward_bindings)
{
    std::vector<lifecycle_debug_subscriber_forward_group_entry> groups;
    std::vector<std::string> keys;

    groups.reserve(forward_bindings.size());
    keys.reserve(forward_bindings.size());

    for (const auto& binding : forward_bindings)
    {
        const std::string key = make_subscriber_forward_group_key(binding.stream_id, binding.publisher_session_id, binding.subscriber_session_id);

        auto iterator = std::find(keys.begin(), keys.end(), key);

        if (iterator == keys.end())
        {
            lifecycle_debug_subscriber_forward_group_entry group;

            group.stream_id = binding.stream_id;
            group.publisher_session_id = binding.publisher_session_id;
            group.subscriber_session_id = binding.subscriber_session_id;

            update_subscriber_forward_group(group, binding);

            keys.push_back(key);
            groups.push_back(std::move(group));

            continue;
        }

        const auto index = static_cast<std::size_t>(std::distance(keys.begin(), iterator));

        update_subscriber_forward_group(groups[index], binding);
    }

    return groups;
}
std::string make_subscriber_rtcp_group_key(std::string_view stream_id, std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(stream_id.size() + subscriber_session_id.size() + 1);

    key.append(stream_id);
    key.push_back('|');
    key.append(subscriber_session_id);

    return key;
}

lifecycle_debug_subscriber_rtcp_group_entry& get_or_create_subscriber_rtcp_group(std::vector<lifecycle_debug_subscriber_rtcp_group_entry>& groups,
                                                                                 std::vector<std::string>& keys,
                                                                                 std::string_view stream_id,
                                                                                 std::string_view subscriber_session_id)
{
    const std::string key = make_subscriber_rtcp_group_key(stream_id, subscriber_session_id);

    auto iterator = std::find(keys.begin(), keys.end(), key);

    if (iterator != keys.end())
    {
        const auto index = static_cast<std::size_t>(std::distance(keys.begin(), iterator));

        return groups[index];
    }

    lifecycle_debug_subscriber_rtcp_group_entry group;

    group.stream_id = std::string(stream_id);
    group.subscriber_session_id = std::string(subscriber_session_id);

    keys.push_back(key);
    groups.push_back(std::move(group));

    return groups.back();
}

bool lifecycle_debug_kind_is_audio(std::string_view kind) { return kind == "audio"; }

bool lifecycle_debug_kind_is_video(std::string_view kind) { return kind == "video"; }

void update_subscriber_rtcp_group_from_report_source(lifecycle_debug_subscriber_rtcp_group_entry& group, const rtcp_report_source_snapshot& source)
{
    group.rtcp_report_source_count += 1;

    if (lifecycle_debug_kind_is_audio(source.kind))
    {
        group.audio_rtcp_report_source_count += 1;
    }
    else if (lifecycle_debug_kind_is_video(source.kind))
    {
        group.video_rtcp_report_source_count += 1;
    }

    if (source.sender_report_enabled)
    {
        group.sender_report_enabled_count += 1;
    }

    if (source.receiver_report_enabled)
    {
        group.receiver_report_enabled_count += 1;
    }
}

void update_subscriber_rtcp_group_from_twcc_source(lifecycle_debug_subscriber_rtcp_group_entry& group,
                                                   const rtcp_transport_cc_feedback_source_snapshot& source)
{
    group.twcc_feedback_source_count += 1;

    if (lifecycle_debug_kind_is_audio(source.kind))
    {
        group.audio_twcc_feedback_source_count += 1;
    }
    else if (lifecycle_debug_kind_is_video(source.kind))
    {
        group.video_twcc_feedback_source_count += 1;
    }

    group.twcc_pending_packet_count += source.pending_packet_count;
}
void append_lifecycle_debug_drop_reason(lifecycle_debug_snapshot& snapshot, std::string_view category, std::string_view reason, uint64_t count)
{
    if (count == 0)
    {
        return;
    }

    lifecycle_debug_drop_reason_entry entry;

    entry.category = std::string(category);
    entry.reason = std::string(reason);
    entry.count = count;

    snapshot.rtp_rtcp_drop_total += count;
    snapshot.rtp_rtcp_drop_reasons.push_back(std::move(entry));
}

enum class inbound_srtp_ignored_drop_reason
{
    non_rtp_rtcp,
    dtls_identity_missing,
    dtls_not_ready,
    srtp_replay,
    srtp_unprotect_failed,
    other,
};

bool text_contains(std::string_view value, std::string_view pattern) { return value.find(pattern) != std::string_view::npos; }

inbound_srtp_ignored_drop_reason classify_inbound_srtp_ignored_drop_reason(std::string_view reason)
{
    if (text_contains(reason, "packet is not rtp or rtcp"))
    {
        return inbound_srtp_ignored_drop_reason::non_rtp_rtcp;
    }

    if (text_contains(reason, "dtls identity is missing"))
    {
        return inbound_srtp_ignored_drop_reason::dtls_identity_missing;
    }

    if (text_contains(reason, "dtls handshake is not complete"))
    {
        return inbound_srtp_ignored_drop_reason::dtls_not_ready;
    }

    if (text_contains(reason, "srtp replay ignored"))
    {
        return inbound_srtp_ignored_drop_reason::srtp_replay;
    }

    if (text_contains(reason, "srtp unprotect failed ignored"))
    {
        return inbound_srtp_ignored_drop_reason::srtp_unprotect_failed;
    }

    return inbound_srtp_ignored_drop_reason::other;
}
std::string optional_string_or_empty(const std::optional<std::string>& value)
{
    if (!value.has_value())
    {
        return {};
    }

    return *value;
}
void add_lifecycle_inconsistency(lifecycle_debug_snapshot& snapshot, std::string message)
{
    snapshot.consistent = false;

    snapshot.inconsistencies.push_back(std::move(message));

    snapshot.inconsistency_count = to_debug_count(snapshot.inconsistencies.size());
}

void add_lifecycle_residual(lifecycle_debug_snapshot& snapshot, std::string message) { snapshot.residuals.push_back(std::move(message)); }
void add_lifecycle_delayed_residual(lifecycle_debug_snapshot& snapshot, std::string message)
{
    snapshot.delayed_residuals.push_back(std::move(message));

    snapshot.delayed_residual_count = to_debug_count(snapshot.delayed_residuals.size());
}

bool lifecycle_active_runtime_state_is_empty(const lifecycle_debug_snapshot& snapshot)
{
    return snapshot.endpoint_count == 0 && snapshot.endpoint_session_index_count == 0 && snapshot.endpoint_reverse_index_count == 0 &&
           snapshot.endpoint_last_seen_count == 0 && snapshot.publisher_absent_stream_count == 0 && snapshot.candidate_pair_count == 0 &&
           snapshot.selected_candidate_pair_count == 0 && snapshot.candidate_pair_consent_in_flight_count == 0 &&
           snapshot.candidate_pair_consent_failure_count == 0 && snapshot.candidate_pair_consent_stale_count == 0 &&
           snapshot.payload_type_mapping_count == 0 && snapshot.keyframe_request_state_count == 0 && snapshot.dtls_peer_count == 0 &&
           snapshot.srtp_peer_count == 0 && snapshot.media_router_peer_count == 0 && snapshot.media_router_stream_count == 0 &&
           snapshot.media_router_active_publisher_count == 0 && snapshot.media_router_active_subscriber_count == 0 &&
           snapshot.track_binding_count == 0 && snapshot.ssrc_mapping_count == 0 && snapshot.identity_authority_rid_layer_binding_count == 0 &&
           snapshot.identity_authority_track_binding_count == 0 && snapshot.identity_authority_forward_binding_count == 0 &&
           snapshot.rtcp_report_source_count == 0 && snapshot.rtcp_report_stats_source_count == 0 && snapshot.rtcp_transport_cc_source_count == 0 &&
           snapshot.rtcp_transport_cc_pending_packet_count == 0 && snapshot.rtp_cache_packet_count == 0 &&
           snapshot.rtx_sequence_allocator_count == 0 && snapshot.rtx_retransmission_index_count == 0 &&
           snapshot.nack_retransmit_throttle_count == 0 && snapshot.fir_sequence_number_state_count == 0 &&
           snapshot.publisher_video_ssrc_state_count == 0 && snapshot.pending_republish_keyframe_request_count == 0 &&
           snapshot.selected_rid_layer_state_count == 0 && snapshot.pending_selected_rid_keyframe_request_count == 0 &&
           snapshot.selected_rid_keyframe_pending_metadata_count == 0 && snapshot.extmap_rewrite_state_count == 0 &&
           snapshot.outbound_transport_cc_sequence_count == 0 && snapshot.outbound_transport_cc_packet_count == 0 &&
           snapshot.outbound_transport_cc_feedback_window_count == 0 && snapshot.outbound_transport_cc_feedback_window_observation_count == 0 &&
           snapshot.subscriber_downlink_bandwidth_state_count == 0 && snapshot.subscriber_downlink_pacing_state_count == 0 &&
           snapshot.subscriber_downlink_pacing_queue_packet_count == 0 && snapshot.subscriber_downlink_pacing_queue_byte_count == 0;
}

bool lifecycle_delayed_runtime_state_is_empty(const lifecycle_debug_snapshot& snapshot)
{
    return snapshot.retired_endpoint_count == 0 && snapshot.retired_endpoint_suppressed_packet_count == 0 &&
           snapshot.retired_ice_credential_count == 0 && snapshot.retired_ice_credential_suppressed_stun_packet_count == 0;
}

lifecycle_debug_session_entry* find_lifecycle_debug_session_entry(std::vector<lifecycle_debug_session_entry>& sessions, std::string_view session_id)
{
    for (auto& session : sessions)
    {
        if (session.session_id == session_id)
        {
            return &session;
        }
    }

    return nullptr;
}

bool lifecycle_debug_endpoint_exists(const std::vector<lifecycle_debug_endpoint_entry>& endpoints, std::string_view endpoint)
{
    for (const auto& entry : endpoints)
    {
        if (entry.endpoint == endpoint)
        {
            return true;
        }
    }

    return false;
}

bool lifecycle_debug_session_exists(const std::vector<lifecycle_debug_session_entry>& sessions, std::string_view session_id)
{
    for (const auto& entry : sessions)
    {
        if (entry.session_id == session_id)
        {
            return true;
        }
    }

    return false;
}

uint16_t read_network_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

void hash_byte(uint64_t& hash, uint8_t value)
{
    hash ^= static_cast<uint64_t>(value);

    hash *= k_fnv_prime;
}

void hash_string(uint64_t& hash, std::string_view value)
{
    for (char item : value)
    {
        hash_byte(hash, static_cast<uint8_t>(item));
    }

    hash_byte(hash, 0xffU);
}

void hash_u32(uint64_t& hash, uint32_t value)
{
    hash_byte(hash, static_cast<uint8_t>((value >> 24U) & 0xffU));

    hash_byte(hash, static_cast<uint8_t>((value >> 16U) & 0xffU));

    hash_byte(hash, static_cast<uint8_t>((value >> 8U) & 0xffU));

    hash_byte(hash, static_cast<uint8_t>(value & 0xffU));
}

uint32_t fold_hash_to_u32(uint64_t value)
{
    const uint32_t high = static_cast<uint32_t>(value >> 32U);

    const uint32_t low = static_cast<uint32_t>(value & 0xffffffffULL);

    uint32_t result = high ^ low;

    if (result == 0)
    {
        result = 1;
    }

    return result;
}

uint32_t make_rtcp_report_local_ssrc(const media_peer_info& peer, uint32_t remote_ssrc)
{
    uint64_t hash = k_fnv_offset_basis;

    hash_string(hash, "simplewebrtc-rtcp-report");

    hash_string(hash, peer.stream_id);

    hash_string(hash, peer.session_id);

    hash_string(hash, peer.remote_endpoint);

    hash_string(hash, media_peer_role_to_string(peer.role));

    hash_u32(hash, remote_ssrc);

    uint32_t value = fold_hash_to_u32(hash);

    if (value == remote_ssrc)
    {
        value += 1;

        if (value == 0)
        {
            value = 1;
        }
    }

    return value;
}

bool is_valid_cname_character(char value) { return value != '\0' && value != '\r' && value != '\n'; }

std::string make_rtcp_cname(std::string_view session_id, uint32_t local_ssrc)
{
    std::string cname;

    cname.reserve(session_id.size() + 32);

    cname.append("simplewebrtc-");

    for (char value : session_id)
    {
        if (is_valid_cname_character(value))
        {
            cname.push_back(value);
        }
        else
        {
            cname.push_back('_');
        }
    }

    cname.push_back('-');

    cname.append(std::to_string(local_ssrc));

    return cname;
}
bool offer_ssrc_is_rtx_repair(const sdp::webrtc_offer_summary& offer, uint32_t ssrc)
{
    if (ssrc == 0)
    {
        return false;
    }

    for (const auto& media : offer.media)
    {
        if (sdp::media_ssrc_is_rtx_repair(media, ssrc))
        {
            return true;
        }
    }

    return false;
}

std::expected<std::size_t, std::string> compute_rtp_payload_size(std::span<const uint8_t> packet)
{
    if (packet.size() < 12)
    {
        return make_error("rtp payload size packet is too small");
    }

    const auto version = static_cast<uint8_t>(packet[0] >> 6U);

    if (version != 2)
    {
        return make_error("rtp payload size version is invalid");
    }

    const bool has_padding = (packet[0] & 0x20U) != 0;

    const bool has_extension = (packet[0] & 0x10U) != 0;

    const auto csrc_count = static_cast<uint8_t>(packet[0] & 0x0fU);

    std::size_t offset = 12 + (static_cast<std::size_t>(csrc_count) * 4);

    if (offset > packet.size())
    {
        return make_error("rtp payload size csrc is truncated");
    }

    if (has_extension)
    {
        if (offset + 4 > packet.size())
        {
            return make_error("rtp payload size extension header is truncated");
        }

        const uint16_t extension_length_words = read_network_u16(packet, offset + 2);

        offset += 4 + (static_cast<std::size_t>(extension_length_words) * 4);

        if (offset > packet.size())
        {
            return make_error("rtp payload size extension payload is truncated");
        }
    }

    std::size_t padding_size = 0;

    if (has_padding)
    {
        padding_size = packet.back();

        if (padding_size == 0 || padding_size > packet.size() - offset)
        {
            return make_error("rtp payload size padding is invalid");
        }
    }

    return packet.size() - offset - padding_size;
}

std::string make_candidate_pair_key(std::string_view session_id, std::string_view remote_address)
{
    std::string key;

    key.reserve(session_id.size() + remote_address.size() + 1);

    key.append(session_id);
    key.push_back('\n');
    key.append(remote_address);

    return key;
}

std::string make_ice_consent_username(std::string_view remote_ufrag, std::string_view local_ufrag)
{
    std::string username;

    username.reserve(remote_ufrag.size() + local_ufrag.size() + 1);

    username.append(remote_ufrag);

    username.push_back(':');

    username.append(local_ufrag);

    return username;
}

uint64_t make_ice_consent_tie_breaker(std::string_view session_id, std::string_view remote_address, uint64_t remote_tie_breaker)
{
    uint64_t value = remote_tie_breaker == 0 ? 0x5346575254430001ULL : remote_tie_breaker;

    for (const char character : session_id)
    {
        value ^= static_cast<uint8_t>(character);

        value *= 1099511628211ULL;
    }

    for (const char character : remote_address)
    {
        value ^= static_cast<uint8_t>(character);

        value *= 1099511628211ULL;
    }

    if (value == 0)
    {
        return 1;
    }

    return value;
}

std::string make_payload_type_mapping_key(std::string_view publisher_session_id, std::string_view subscriber_session_id)
{
    std::string key;

    key.reserve(publisher_session_id.size() + subscriber_session_id.size() + 1);

    key.append(publisher_session_id);
    key.push_back('\n');
    key.append(subscriber_session_id);

    return key;
}
uint64_t get_env_uint64_or_default(const char* name, uint64_t default_value)
{
    const char* value = std::getenv(name);

    if (value == nullptr || value[0] == '\0')
    {
        return default_value;
    }

    errno = 0;

    char* end = nullptr;

    const auto parsed = std::strtoull(value, &end, 10);

    if (errno != 0 || end == value || *end != '\0')
    {
        WEBRTC_LOG_WARN("rtcp report service env value invalid name={} value={} default={}", name, value, default_value);

        return default_value;
    }

    return static_cast<uint64_t>(parsed);
}

std::size_t get_env_size_or_default(const char* name, std::size_t default_value)
{
    const uint64_t parsed = get_env_uint64_or_default(name, static_cast<uint64_t>(default_value));

    if (parsed > static_cast<uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        WEBRTC_LOG_WARN("rtcp report service env value too large name={} value={} default={}", name, parsed, default_value);

        return default_value;
    }

    return static_cast<std::size_t>(parsed);
}
std::string normalize_env_token(const char* value)
{
    std::string token;

    if (value == nullptr)
    {
        return token;
    }

    token.reserve(std::char_traits<char>::length(value));

    for (const char* iterator = value; *iterator != '\0'; ++iterator)
    {
        const auto ch = static_cast<unsigned char>(*iterator);

        if (ch == '-' || ch == ' ')
        {
            token.push_back('_');
            continue;
        }

        token.push_back(static_cast<char>(std::tolower(ch)));
    }

    return token;
}

ice_udp_server::subscriber_downlink_control_mode make_subscriber_downlink_control_mode_from_env()
{
    const char* value = std::getenv("WEBRTC_SUBSCRIBER_DOWNLINK_CONTROL_MODE");

    if (value == nullptr || value[0] == '\0')
    {
        return ice_udp_server::subscriber_downlink_control_mode::observe_only;
    }

    const std::string token = normalize_env_token(value);

    if (token == "disabled" || token == "disable" || token == "off" || token == "0")
    {
        return ice_udp_server::subscriber_downlink_control_mode::disabled;
    }

    if (token == "observe_only" || token == "observe" || token == "dry_run" || token == "dryrun")
    {
        return ice_udp_server::subscriber_downlink_control_mode::observe_only;
    }

    if (token == "enabled" || token == "enable" || token == "on" || token == "1")
    {
        return ice_udp_server::subscriber_downlink_control_mode::enabled;
    }

    WEBRTC_LOG_WARN("subscriber downlink control mode invalid value={} default=observe_only", value);

    return ice_udp_server::subscriber_downlink_control_mode::observe_only;
}

ice_udp_server::subscriber_downlink_control_config make_subscriber_downlink_control_config_from_env()
{
    ice_udp_server::subscriber_downlink_control_config config;

    config.mode = make_subscriber_downlink_control_mode_from_env();

    config.initial_target_bitrate_bps =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_INITIAL_TARGET_BITRATE_BPS", config.initial_target_bitrate_bps);

    config.probe_observation_count = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_PROBE_OBSERVATION_COUNT", config.probe_observation_count);
    config.probe_observation_count = std::max<uint64_t>(config.probe_observation_count, 16);
    config.probe_observation_count = std::min<uint64_t>(config.probe_observation_count, 4096);

    config.min_reliable_lookup_hit_rate_ppm =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_MIN_LOOKUP_HIT_RATE_PPM", config.min_reliable_lookup_hit_rate_ppm);
    config.min_reliable_lookup_hit_rate_ppm = std::min<uint64_t>(config.min_reliable_lookup_hit_rate_ppm, 1000000);

    config.healthy_loss_rate_ppm = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_HEALTHY_LOSS_RATE_PPM", config.healthy_loss_rate_ppm);
    config.recovering_loss_rate_ppm =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_RECOVERING_LOSS_RATE_PPM", config.recovering_loss_rate_ppm);
    config.constrained_loss_rate_ppm =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_CONSTRAINED_LOSS_RATE_PPM", config.constrained_loss_rate_ppm);
    config.severe_loss_rate_ppm = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_SEVERE_LOSS_RATE_PPM", config.severe_loss_rate_ppm);

    config.healthy_loss_rate_ppm = std::min<uint64_t>(config.healthy_loss_rate_ppm, 1000000);
    config.recovering_loss_rate_ppm = std::min<uint64_t>(config.recovering_loss_rate_ppm, 1000000);
    config.constrained_loss_rate_ppm = std::min<uint64_t>(config.constrained_loss_rate_ppm, 1000000);
    config.severe_loss_rate_ppm = std::min<uint64_t>(config.severe_loss_rate_ppm, 1000000);

    if (config.recovering_loss_rate_ppm < config.healthy_loss_rate_ppm)
    {
        config.recovering_loss_rate_ppm = config.healthy_loss_rate_ppm;
    }

    if (config.constrained_loss_rate_ppm < config.recovering_loss_rate_ppm)
    {
        config.constrained_loss_rate_ppm = config.recovering_loss_rate_ppm;
    }

    if (config.severe_loss_rate_ppm < config.constrained_loss_rate_ppm)
    {
        config.severe_loss_rate_ppm = config.constrained_loss_rate_ppm;
    }

    config.min_state_duration_milliseconds =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_MIN_STATE_DURATION_MS", config.min_state_duration_milliseconds);
    config.recovering_min_duration_milliseconds =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_RECOVERING_MIN_DURATION_MS", config.recovering_min_duration_milliseconds);
    config.hold_down_duration_milliseconds =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_HOLD_DOWN_DURATION_MS", config.hold_down_duration_milliseconds);

    config.min_state_duration_milliseconds = std::min<uint64_t>(config.min_state_duration_milliseconds, 60000);
    config.recovering_min_duration_milliseconds = std::min<uint64_t>(config.recovering_min_duration_milliseconds, 60000);
    config.hold_down_duration_milliseconds = std::min<uint64_t>(config.hold_down_duration_milliseconds, 60000);

    config.recovering_required_healthy_windows =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_RECOVERING_REQUIRED_HEALTHY_WINDOWS", config.recovering_required_healthy_windows);
    config.hold_down_required_healthy_windows =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_HOLD_DOWN_REQUIRED_HEALTHY_WINDOWS", config.hold_down_required_healthy_windows);
    config.constrained_required_bad_windows =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_CONSTRAINED_REQUIRED_BAD_WINDOWS", config.constrained_required_bad_windows);

    config.recovering_required_healthy_windows = std::max<uint64_t>(config.recovering_required_healthy_windows, 1);
    config.hold_down_required_healthy_windows = std::max<uint64_t>(config.hold_down_required_healthy_windows, 1);
    config.constrained_required_bad_windows = std::max<uint64_t>(config.constrained_required_bad_windows, 1);

    config.steady_increase_ppm = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_STEADY_INCREASE_PPM", config.steady_increase_ppm);
    config.recovering_increase_ppm = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_RECOVERING_INCREASE_PPM", config.recovering_increase_ppm);
    config.hold_down_increase_ppm = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_HOLD_DOWN_INCREASE_PPM", config.hold_down_increase_ppm);
    config.constrained_decrease_ppm =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_CONSTRAINED_DECREASE_PPM", config.constrained_decrease_ppm);
    config.severe_constrained_decrease_ppm =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_SEVERE_CONSTRAINED_DECREASE_PPM", config.severe_constrained_decrease_ppm);

    config.steady_increase_ppm = std::min<uint64_t>(config.steady_increase_ppm, 200000);
    config.recovering_increase_ppm = std::min<uint64_t>(config.recovering_increase_ppm, 100000);
    config.hold_down_increase_ppm = std::min<uint64_t>(config.hold_down_increase_ppm, 50000);

    config.constrained_decrease_ppm = std::max<uint64_t>(config.constrained_decrease_ppm, 100000);
    config.constrained_decrease_ppm = std::min<uint64_t>(config.constrained_decrease_ppm, 1000000);

    config.severe_constrained_decrease_ppm = std::max<uint64_t>(config.severe_constrained_decrease_ppm, 100000);
    config.severe_constrained_decrease_ppm = std::min<uint64_t>(config.severe_constrained_decrease_ppm, config.constrained_decrease_ppm);

    config.min_bitrate_bps = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_MIN_BITRATE_BPS", config.min_bitrate_bps);

    config.max_bitrate_bps = get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_MAX_BITRATE_BPS", config.max_bitrate_bps);

    if (config.min_bitrate_bps < 64000)
    {
        WEBRTC_LOG_WARN("subscriber downlink min bitrate too small value={} clamped=64000", config.min_bitrate_bps);

        config.min_bitrate_bps = 64000;
    }

    if (config.max_bitrate_bps < config.min_bitrate_bps)
    {
        WEBRTC_LOG_WARN(
            "subscriber downlink max bitrate lower than min max={} min={} clamped_to_min", config.max_bitrate_bps, config.min_bitrate_bps);

        config.max_bitrate_bps = config.min_bitrate_bps;
    }

    if (config.max_bitrate_bps > 50000000)
    {
        WEBRTC_LOG_WARN("subscriber downlink max bitrate too large value={} clamped=50000000", config.max_bitrate_bps);

        config.max_bitrate_bps = 50000000;
    }

    config.initial_target_bitrate_bps = clamp_bitrate(config.initial_target_bitrate_bps, config.min_bitrate_bps, config.max_bitrate_bps);

    config.keyframe_recovery_bypass_duration_milliseconds = get_env_uint64_or_default(
        "WEBRTC_SUBSCRIBER_DOWNLINK_KEYFRAME_RECOVERY_BYPASS_DURATION_MS", config.keyframe_recovery_bypass_duration_milliseconds);

    config.keyframe_recovery_bypass_duration_milliseconds = std::min<uint64_t>(config.keyframe_recovery_bypass_duration_milliseconds, 10000);

    config.keyframe_recovery_bypass_packet_count =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_KEYFRAME_RECOVERY_BYPASS_PACKET_COUNT", config.keyframe_recovery_bypass_packet_count);

    config.keyframe_recovery_bypass_packet_count = std::min<uint64_t>(config.keyframe_recovery_bypass_packet_count, 2048);

    config.max_pacing_queue_packets_per_subscriber =
        get_env_size_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_PACING_MAX_QUEUE_PACKETS", config.max_pacing_queue_packets_per_subscriber);

    config.max_pacing_queue_packets_per_subscriber = std::max<std::size_t>(config.max_pacing_queue_packets_per_subscriber, 1);

    config.max_pacing_queue_packets_per_subscriber = std::min<std::size_t>(config.max_pacing_queue_packets_per_subscriber, 8192);

    config.max_pacing_queue_bytes_per_subscriber =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_PACING_MAX_QUEUE_BYTES", config.max_pacing_queue_bytes_per_subscriber);

    config.max_pacing_queue_bytes_per_subscriber = std::max<uint64_t>(config.max_pacing_queue_bytes_per_subscriber, 64000);

    config.max_pacing_queue_bytes_per_subscriber = std::min<uint64_t>(config.max_pacing_queue_bytes_per_subscriber, 16777216);

    config.max_pacing_packet_age_milliseconds =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_PACING_MAX_PACKET_AGE_MS", config.max_pacing_packet_age_milliseconds);

    config.max_pacing_packet_age_milliseconds = std::max<uint64_t>(config.max_pacing_packet_age_milliseconds, 100);

    config.max_pacing_packet_age_milliseconds = std::min<uint64_t>(config.max_pacing_packet_age_milliseconds, 10000);

    config.max_pacing_packets_per_tick =
        get_env_size_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_PACING_MAX_PACKETS_PER_TICK", config.max_pacing_packets_per_tick);

    config.max_pacing_packets_per_tick = std::max<std::size_t>(config.max_pacing_packets_per_tick, 1);

    config.max_pacing_packets_per_tick = std::min<std::size_t>(config.max_pacing_packets_per_tick, 256);

    config.max_pacing_packets_per_subscriber_per_tick = get_env_size_or_default(
        "WEBRTC_SUBSCRIBER_DOWNLINK_PACING_MAX_PACKETS_PER_SUBSCRIBER_PER_TICK", config.max_pacing_packets_per_subscriber_per_tick);

    config.max_pacing_packets_per_subscriber_per_tick = std::max<std::size_t>(config.max_pacing_packets_per_subscriber_per_tick, 1);

    config.max_pacing_packets_per_subscriber_per_tick =
        std::min<std::size_t>(config.max_pacing_packets_per_subscriber_per_tick, config.max_pacing_packets_per_tick);

    config.pacing_timer_interval_milliseconds =
        get_env_uint64_or_default("WEBRTC_SUBSCRIBER_DOWNLINK_PACING_TIMER_INTERVAL_MS", config.pacing_timer_interval_milliseconds);
    config.pacing_timer_interval_milliseconds = std::max<uint64_t>(config.pacing_timer_interval_milliseconds, 1);

    config.pacing_timer_interval_milliseconds = std::min<uint64_t>(config.pacing_timer_interval_milliseconds, 100);

    WEBRTC_LOG_INFO(
        "subscriber downlink control config mode={} initial_target_bitrate_bps={} min_bitrate_bps={} max_bitrate_bps={} "
        "keyframe_recovery_bypass_duration_ms={} keyframe_recovery_bypass_packet_count={} "
        "probe_observation_count={} min_lookup_hit_rate_ppm={} healthy_loss_rate_ppm={} recovering_loss_rate_ppm={} "
        "constrained_loss_rate_ppm={} severe_loss_rate_ppm={} min_state_duration_ms={} recovering_min_duration_ms={} "
        "hold_down_duration_ms={} recovering_required_healthy_windows={} hold_down_required_healthy_windows={} "
        "constrained_required_bad_windows={} steady_increase_ppm={} recovering_increase_ppm={} hold_down_increase_ppm={} "
        "constrained_decrease_ppm={} severe_constrained_decrease_ppm={} pacing_max_queue_packets={} pacing_max_queue_bytes={} "
        "pacing_max_packet_age_ms={} pacing_max_packets_per_tick={} pacing_max_packets_per_subscriber_per_tick={} "
        "pacing_timer_interval_ms={}",
        subscriber_downlink_control_mode_to_string(config.mode),
        config.initial_target_bitrate_bps,
        config.min_bitrate_bps,
        config.max_bitrate_bps,
        config.keyframe_recovery_bypass_duration_milliseconds,
        config.keyframe_recovery_bypass_packet_count,
        config.probe_observation_count,
        config.min_reliable_lookup_hit_rate_ppm,
        config.healthy_loss_rate_ppm,
        config.recovering_loss_rate_ppm,
        config.constrained_loss_rate_ppm,
        config.severe_loss_rate_ppm,
        config.min_state_duration_milliseconds,
        config.recovering_min_duration_milliseconds,
        config.hold_down_duration_milliseconds,
        config.recovering_required_healthy_windows,
        config.hold_down_required_healthy_windows,
        config.constrained_required_bad_windows,
        config.steady_increase_ppm,
        config.recovering_increase_ppm,
        config.hold_down_increase_ppm,
        config.constrained_decrease_ppm,
        config.severe_constrained_decrease_ppm,
        config.max_pacing_queue_packets_per_subscriber,
        config.max_pacing_queue_bytes_per_subscriber,
        config.max_pacing_packet_age_milliseconds,
        config.max_pacing_packets_per_tick,
        config.max_pacing_packets_per_subscriber_per_tick,
        config.pacing_timer_interval_milliseconds);
    return config;
}

rtcp_report_service_config make_rtcp_report_service_config_from_env()
{
    rtcp_report_service_config config;

    config.max_report_blocks = get_env_size_or_default("WEBRTC_RTCP_REPORT_MAX_REPORT_BLOCKS", config.max_report_blocks);

    config.report_interval_milliseconds = get_env_uint64_or_default("WEBRTC_RTCP_REPORT_INTERVAL_MS", config.report_interval_milliseconds);

    config.report_jitter_milliseconds = get_env_uint64_or_default("WEBRTC_RTCP_REPORT_JITTER_MS", config.report_jitter_milliseconds);

    config.max_packets_per_generation = get_env_size_or_default("WEBRTC_RTCP_REPORT_MAX_PACKETS_PER_GENERATION", config.max_packets_per_generation);

    config.stale_source_timeout_milliseconds =
        get_env_uint64_or_default("WEBRTC_RTCP_REPORT_STALE_SOURCE_TIMEOUT_MS", config.stale_source_timeout_milliseconds);

    if (config.max_report_blocks > 31)
    {
        WEBRTC_LOG_WARN("rtcp report service max report blocks clamped value={} clamped=31", config.max_report_blocks);

        config.max_report_blocks = 31;
    }

    if (config.report_interval_milliseconds == 0)
    {
        WEBRTC_LOG_WARN("rtcp report service interval is zero use default=5000");

        config.report_interval_milliseconds = 5000;
    }

    if (config.report_jitter_milliseconds > config.report_interval_milliseconds)
    {
        WEBRTC_LOG_WARN(
            "rtcp report service jitter clamped jitter={} interval={}", config.report_jitter_milliseconds, config.report_interval_milliseconds);

        config.report_jitter_milliseconds = config.report_interval_milliseconds;
    }

    WEBRTC_LOG_INFO(
        "rtcp report service config max_report_blocks={} interval_ms={} jitter_ms={} max_packets_per_generation={} stale_source_timeout_ms={}",
        config.max_report_blocks,
        config.report_interval_milliseconds,
        config.report_jitter_milliseconds,
        config.max_packets_per_generation,
        config.stale_source_timeout_milliseconds);

    return config;
}

std::shared_ptr<rtcp_report_service> make_rtcp_report_service_from_env()
{
    return std::make_shared<rtcp_report_service>(make_rtcp_report_service_config_from_env());
}

dtls_transport_config make_dtls_transport_config_from_env()
{
    dtls_transport_config config;

    const uint64_t handshake_timeout_milliseconds =
        get_env_uint64_or_default("WEBRTC_DTLS_HANDSHAKE_TIMEOUT_MS", static_cast<uint64_t>(config.handshake_timeout.count()));

    uint64_t clamped_handshake_timeout_milliseconds = handshake_timeout_milliseconds;

    if (clamped_handshake_timeout_milliseconds < 1000)
    {
        WEBRTC_LOG_WARN("dtls handshake timeout too small timeout_ms={} clamped=1000", clamped_handshake_timeout_milliseconds);

        clamped_handshake_timeout_milliseconds = 1000;
    }

    if (clamped_handshake_timeout_milliseconds > 120000)
    {
        WEBRTC_LOG_WARN("dtls handshake timeout too large timeout_ms={} clamped=120000", clamped_handshake_timeout_milliseconds);

        clamped_handshake_timeout_milliseconds = 120000;
    }

    config.handshake_timeout = std::chrono::milliseconds(static_cast<int64_t>(clamped_handshake_timeout_milliseconds));

    WEBRTC_LOG_INFO("dtls transport config handshake_timeout_ms={}", config.handshake_timeout.count());

    return config;
}

std::chrono::milliseconds make_ice_consent_check_interval_from_env()
{
    const uint64_t default_interval_milliseconds =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(k_ice_consent_check_interval).count());

    uint64_t interval_milliseconds = get_env_uint64_or_default("WEBRTC_ICE_CONSENT_CHECK_INTERVAL_MS", default_interval_milliseconds);

    if (interval_milliseconds < 1000)
    {
        WEBRTC_LOG_WARN("ice consent check interval too small interval_ms={} clamped=1000", interval_milliseconds);

        interval_milliseconds = 1000;
    }

    if (interval_milliseconds > 60000)
    {
        WEBRTC_LOG_WARN("ice consent check interval too large interval_ms={} clamped=60000", interval_milliseconds);

        interval_milliseconds = 60000;
    }

    WEBRTC_LOG_INFO("ice consent check config interval_ms={}", interval_milliseconds);

    return std::chrono::milliseconds(static_cast<int64_t>(interval_milliseconds));
}

uint64_t make_ice_consent_timeout_milliseconds_from_env()
{
    uint64_t timeout_milliseconds = get_env_uint64_or_default("WEBRTC_ICE_CONSENT_TIMEOUT_MS", k_ice_consent_timeout_milliseconds);

    if (timeout_milliseconds < 5000)
    {
        WEBRTC_LOG_WARN("ice consent timeout too small timeout_ms={} clamped=5000", timeout_milliseconds);

        timeout_milliseconds = 5000;
    }

    if (timeout_milliseconds > 300000)
    {
        WEBRTC_LOG_WARN("ice consent timeout too large timeout_ms={} clamped=300000", timeout_milliseconds);

        timeout_milliseconds = 300000;
    }

    WEBRTC_LOG_INFO("ice consent timeout config timeout_ms={}", timeout_milliseconds);

    return timeout_milliseconds;
}

std::chrono::milliseconds make_rtcp_report_timer_interval_from_env()
{
    const uint64_t default_interval_milliseconds =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(k_rtcp_report_interval).count());

    uint64_t interval_milliseconds = get_env_uint64_or_default("WEBRTC_RTCP_REPORT_TIMER_INTERVAL_MS", default_interval_milliseconds);

    if (interval_milliseconds < 50)
    {
        WEBRTC_LOG_WARN("rtcp report timer interval too small interval_ms={} clamped=50", interval_milliseconds);

        interval_milliseconds = 50;
    }

    if (interval_milliseconds > 10000)
    {
        WEBRTC_LOG_WARN("rtcp report timer interval too large interval_ms={} clamped=10000", interval_milliseconds);

        interval_milliseconds = 10000;
    }

    WEBRTC_LOG_INFO("rtcp report timer config interval_ms={}", interval_milliseconds);

    return std::chrono::milliseconds(static_cast<int64_t>(interval_milliseconds));
}

uint64_t make_unselected_candidate_pair_retention_milliseconds_from_env()
{
    uint64_t retention_milliseconds =
        get_env_uint64_or_default("WEBRTC_UNSELECTED_CANDIDATE_PAIR_RETENTION_MS", k_unselected_candidate_pair_retention_milliseconds);

    if (retention_milliseconds < 10000)
    {
        WEBRTC_LOG_WARN("ice unselected candidate pair retention too small retention_ms={} clamped=10000", retention_milliseconds);

        retention_milliseconds = 10000;
    }

    if (retention_milliseconds > 600000)
    {
        WEBRTC_LOG_WARN("ice unselected candidate pair retention too large retention_ms={} clamped=600000", retention_milliseconds);

        retention_milliseconds = 600000;
    }

    WEBRTC_LOG_INFO("ice unselected candidate pair config retention_ms={}", retention_milliseconds);

    return retention_milliseconds;
}

std::size_t make_rtp_packet_cache_max_packets_from_env()
{
    std::size_t max_packets = get_env_size_or_default("WEBRTC_RTP_CACHE_MAX_PACKETS", k_default_rtp_packet_cache_max_packets);

    max_packets = std::max(max_packets, k_min_rtp_packet_cache_max_packets);

    max_packets = std::min(max_packets, k_max_rtp_packet_cache_max_packets);

    return max_packets;
}
rtp_packet_cache_config make_rtp_packet_cache_config_from_env()
{
    rtp_packet_cache_config config;

    config.max_packets = make_rtp_packet_cache_max_packets_from_env();

    WEBRTC_LOG_INFO("rtp packet cache config max_packets={}", config.max_packets);

    return config;
}
rtx_retransmission_index_config make_rtx_retransmission_index_config_from_env()
{
    rtx_retransmission_index_config config;

    config.max_entries = get_env_size_or_default("WEBRTC_RTX_RETRANSMISSION_INDEX_MAX_ENTRIES", config.max_entries);

    config.max_entries = std::max<std::size_t>(config.max_entries, 128);

    config.max_entries = std::min<std::size_t>(config.max_entries, 262144);

    config.max_age_milliseconds = get_env_uint64_or_default("WEBRTC_RTX_RETRANSMISSION_INDEX_MAX_AGE_MS", config.max_age_milliseconds);

    if (config.max_age_milliseconds != 0 && config.max_age_milliseconds < 1000)
    {
        WEBRTC_LOG_WARN("rtx retransmission index max age too small max_age_ms={} clamped=1000", config.max_age_milliseconds);

        config.max_age_milliseconds = 1000;
    }

    if (config.max_age_milliseconds > 600000)
    {
        WEBRTC_LOG_WARN("rtx retransmission index max age too large max_age_ms={} clamped=600000", config.max_age_milliseconds);

        config.max_age_milliseconds = 600000;
    }

    WEBRTC_LOG_INFO("rtx retransmission index config max_entries={} max_age_ms={}", config.max_entries, config.max_age_milliseconds);

    return config;
}

nack_retransmit_throttle_config make_nack_retransmit_throttle_config_from_env()
{
    nack_retransmit_throttle_config config;

    config.min_interval_milliseconds = get_env_uint64_or_default("WEBRTC_NACK_RETRANSMIT_MIN_INTERVAL_MS", config.min_interval_milliseconds);

    config.max_age_milliseconds = get_env_uint64_or_default("WEBRTC_NACK_RETRANSMIT_MAX_AGE_MS", config.max_age_milliseconds);

    config.max_entries = get_env_size_or_default("WEBRTC_NACK_RETRANSMIT_MAX_ENTRIES", config.max_entries);

    if (config.min_interval_milliseconds > 1000)
    {
        WEBRTC_LOG_WARN("nack retransmit throttle min interval too large min_interval_ms={} clamped=1000", config.min_interval_milliseconds);

        config.min_interval_milliseconds = 1000;
    }

    if (config.max_age_milliseconds != 0 && config.max_age_milliseconds < 1000)
    {
        WEBRTC_LOG_WARN("nack retransmit throttle max age too small max_age_ms={} clamped=1000", config.max_age_milliseconds);

        config.max_age_milliseconds = 1000;
    }

    if (config.max_age_milliseconds > 600000)
    {
        WEBRTC_LOG_WARN("nack retransmit throttle max age too large max_age_ms={} clamped=600000", config.max_age_milliseconds);

        config.max_age_milliseconds = 600000;
    }

    config.max_entries = std::max<std::size_t>(config.max_entries, 128);

    config.max_entries = std::min<std::size_t>(config.max_entries, 262144);

    WEBRTC_LOG_INFO("nack retransmit throttle config min_interval_ms={} max_age_ms={} max_entries={}",
                    config.min_interval_milliseconds,
                    config.max_age_milliseconds,
                    config.max_entries);

    return config;
}

rtcp_transport_cc_feedback_config make_rtcp_transport_cc_feedback_config_from_env()
{
    rtcp_transport_cc_feedback_config config;

    config.feedback_interval_milliseconds = get_env_uint64_or_default("WEBRTC_TWCC_FEEDBACK_INTERVAL_MS", config.feedback_interval_milliseconds);

    config.stale_source_milliseconds = get_env_uint64_or_default("WEBRTC_TWCC_STALE_SOURCE_MS", config.stale_source_milliseconds);

    config.max_observed_packets_per_source =
        get_env_size_or_default("WEBRTC_TWCC_MAX_OBSERVED_PACKETS_PER_SOURCE", config.max_observed_packets_per_source);

    config.max_sources = get_env_size_or_default("WEBRTC_TWCC_MAX_SOURCES", config.max_sources);

    config.max_pending_packets_total = get_env_size_or_default("WEBRTC_TWCC_MAX_PENDING_PACKETS_TOTAL", config.max_pending_packets_total);

    const std::size_t max_packets_per_feedback = get_env_size_or_default("WEBRTC_TWCC_MAX_PACKETS_PER_FEEDBACK", config.max_packets_per_feedback);

    config.max_packets_per_feedback = static_cast<uint16_t>(std::min<std::size_t>(max_packets_per_feedback, 255));

    if (config.feedback_interval_milliseconds == 0)
    {
        WEBRTC_LOG_WARN("twcc feedback interval is zero use default=100");

        config.feedback_interval_milliseconds = 100;
    }

    if (config.stale_source_milliseconds != 0 && config.stale_source_milliseconds < 1000)
    {
        WEBRTC_LOG_WARN("twcc stale source timeout too small stale_ms={} clamped=1000", config.stale_source_milliseconds);

        config.stale_source_milliseconds = 1000;
    }

    config.max_observed_packets_per_source = std::max<std::size_t>(config.max_observed_packets_per_source, 16);

    config.max_observed_packets_per_source = std::min<std::size_t>(config.max_observed_packets_per_source, 4096);

    config.max_sources = std::max<std::size_t>(config.max_sources, 16);

    config.max_sources = std::min<std::size_t>(config.max_sources, 65536);

    config.max_pending_packets_total = std::max<std::size_t>(config.max_pending_packets_total, config.max_observed_packets_per_source);

    config.max_pending_packets_total = std::min<std::size_t>(config.max_pending_packets_total, 1048576);

    if (config.max_packets_per_feedback == 0)
    {
        WEBRTC_LOG_WARN("twcc max packets per feedback is zero use default=64");

        config.max_packets_per_feedback = 64;
    }

    WEBRTC_LOG_INFO(
        "twcc feedback config interval_ms={} stale_ms={} max_packets_per_source={} max_sources={} max_pending_packets_total={} "
        "max_packets_per_feedback={}",
        config.feedback_interval_milliseconds,
        config.stale_source_milliseconds,
        config.max_observed_packets_per_source,
        config.max_sources,
        config.max_pending_packets_total,
        config.max_packets_per_feedback);

    return config;
}

uint64_t make_endpoint_idle_timeout_milliseconds_from_env()
{
    uint64_t timeout_milliseconds = get_env_uint64_or_default("WEBRTC_ENDPOINT_IDLE_TIMEOUT_MS", k_default_endpoint_idle_timeout_milliseconds);

    if (timeout_milliseconds != 0 && timeout_milliseconds < 10000)
    {
        WEBRTC_LOG_WARN("endpoint idle timeout too small timeout_ms={} min_ms=10000 clamped=10000", timeout_milliseconds);

        timeout_milliseconds = 10000;
    }

    WEBRTC_LOG_INFO(
        "endpoint idle cleanup config timeout_ms={} interval_ms={}", timeout_milliseconds, k_endpoint_idle_cleanup_interval.count() * 1000);

    return timeout_milliseconds;
}
uint64_t make_pending_session_timeout_milliseconds_from_env()
{
    uint64_t timeout_milliseconds = get_env_uint64_or_default("WEBRTC_PENDING_SESSION_TIMEOUT_MS", k_default_pending_session_timeout_milliseconds);

    if (timeout_milliseconds != 0 && timeout_milliseconds < 10000)
    {
        WEBRTC_LOG_WARN("pending session timeout too small timeout_ms={} min_ms=10000 clamped=10000", timeout_milliseconds);

        timeout_milliseconds = 10000;
    }

    WEBRTC_LOG_INFO(
        "pending session cleanup config timeout_ms={} interval_ms={}", timeout_milliseconds, k_pending_session_cleanup_interval.count() * 1000);

    return timeout_milliseconds;
}
uint64_t make_orphan_subscriber_timeout_milliseconds_from_env()
{
    uint64_t timeout_milliseconds =
        get_env_uint64_or_default("WEBRTC_ORPHAN_SUBSCRIBER_TIMEOUT_MS", k_default_orphan_subscriber_timeout_milliseconds);

    if (timeout_milliseconds != 0 && timeout_milliseconds < 10000)
    {
        WEBRTC_LOG_WARN("orphan subscriber timeout too small timeout_ms={} min_ms=10000 clamped=10000", timeout_milliseconds);

        timeout_milliseconds = 10000;
    }

    WEBRTC_LOG_INFO(
        "orphan subscriber cleanup config timeout_ms={} interval_ms={}", timeout_milliseconds, k_pending_session_cleanup_interval.count() * 1000);

    return timeout_milliseconds;
}

struct ice_udp_server_runtime_config
{
    dtls_transport_config dtls_transport;

    rtp_packet_cache_config rtp_packet_cache;

    rtcp_report_service_config rtcp_report_service;

    rtcp_transport_cc_feedback_config rtcp_transport_cc_feedback;

    rtx_retransmission_index_config rtx_retransmission_index;

    nack_retransmit_throttle_config nack_retransmit_throttle;

    ice_udp_server::subscriber_downlink_control_config subscriber_downlink_control;

    std::chrono::milliseconds ice_consent_check_interval{std::chrono::seconds(5)};

    uint64_t ice_consent_timeout_milliseconds = k_ice_consent_timeout_milliseconds;

    uint64_t unselected_candidate_pair_retention_milliseconds = k_unselected_candidate_pair_retention_milliseconds;

    std::chrono::milliseconds rtcp_report_timer_interval{k_rtcp_report_interval};

    uint64_t endpoint_idle_timeout_milliseconds = k_default_endpoint_idle_timeout_milliseconds;

    uint64_t pending_session_timeout_milliseconds = k_default_pending_session_timeout_milliseconds;

    uint64_t orphan_subscriber_timeout_milliseconds = k_default_orphan_subscriber_timeout_milliseconds;
};

ice_udp_server_runtime_config make_ice_udp_server_runtime_config_from_env()
{
    ice_udp_server_runtime_config config;

    config.dtls_transport = make_dtls_transport_config_from_env();

    config.rtp_packet_cache = make_rtp_packet_cache_config_from_env();

    config.rtcp_report_service = make_rtcp_report_service_config_from_env();

    config.rtcp_transport_cc_feedback = make_rtcp_transport_cc_feedback_config_from_env();

    config.rtx_retransmission_index = make_rtx_retransmission_index_config_from_env();

    config.nack_retransmit_throttle = make_nack_retransmit_throttle_config_from_env();

    config.subscriber_downlink_control = make_subscriber_downlink_control_config_from_env();

    config.ice_consent_check_interval = make_ice_consent_check_interval_from_env();

    config.ice_consent_timeout_milliseconds = make_ice_consent_timeout_milliseconds_from_env();

    config.unselected_candidate_pair_retention_milliseconds = make_unselected_candidate_pair_retention_milliseconds_from_env();

    config.rtcp_report_timer_interval = make_rtcp_report_timer_interval_from_env();

    config.endpoint_idle_timeout_milliseconds = make_endpoint_idle_timeout_milliseconds_from_env();

    config.pending_session_timeout_milliseconds = make_pending_session_timeout_milliseconds_from_env();

    config.orphan_subscriber_timeout_milliseconds = make_orphan_subscriber_timeout_milliseconds_from_env();

    WEBRTC_LOG_INFO(
        "ice udp runtime config loaded dtls_handshake_timeout_ms={} rtp_cache_max_packets={} ice_consent_interval_ms={} "
        "ice_consent_timeout_ms={} unselected_pair_retention_ms={} rtcp_timer_interval_ms={} endpoint_idle_timeout_ms={} "
        "pending_session_timeout_ms={} orphan_subscriber_timeout_ms={}",
        config.dtls_transport.handshake_timeout.count(),
        config.rtp_packet_cache.max_packets,
        config.ice_consent_check_interval.count(),
        config.ice_consent_timeout_milliseconds,
        config.unselected_candidate_pair_retention_milliseconds,
        config.rtcp_report_timer_interval.count(),
        config.endpoint_idle_timeout_milliseconds,
        config.pending_session_timeout_milliseconds,
        config.orphan_subscriber_timeout_milliseconds);
    return config;
}

const ice_udp_server_runtime_config& ice_udp_server_runtime_config_instance()
{
    static const ice_udp_server_runtime_config config = make_ice_udp_server_runtime_config_from_env();

    return config;
}

bool is_pending_connection_state(session_state state) { return state == session_state::sdp_received || state == session_state::sdp_answered; }

uint64_t rtcp_empty_generation_log_interval_milliseconds()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(k_rtcp_report_empty_generation_log_interval).count());
}

bool has_elapsed_milliseconds(uint64_t now_milliseconds, uint64_t last_milliseconds, uint64_t interval_milliseconds)
{
    if (last_milliseconds == 0)
    {
        return true;
    }

    if (now_milliseconds < last_milliseconds)
    {
        return true;
    }

    return now_milliseconds - last_milliseconds >= interval_milliseconds;
}

bool should_log_empty_rtcp_generation(const rtcp_report_service_generation& generation, uint64_t now_milliseconds, uint64_t last_log_milliseconds)
{
    if (!generation.errors.empty() || generation.failed != 0 || generation.skipped != 0 || generation.due_sources != 0 ||
        generation.throttled_sources != 0)
    {
        return true;
    }

    return has_elapsed_milliseconds(now_milliseconds, last_log_milliseconds, rtcp_empty_generation_log_interval_milliseconds());
}
std::expected<std::string, std::string> get_required_env(const char* name)
{
    const char* value = std::getenv(name);

    if (value == nullptr || value[0] == '\0')
    {
        std::string message(name);

        message.append(" is empty");

        return std::unexpected(std::move(message));
    }

    return std::string(value);
}

bool is_valid_ice_username_character(char value)
{
    const auto byte = static_cast<unsigned char>(value);

    return std::isalnum(byte) != 0 || value == '+' || value == '/';
}

std::expected<void, std::string> validate_ice_username_fragment(std::string_view fragment, std::string_view field_name)
{
    if (fragment.empty())
    {
        return make_field_error(field_name, "is empty");
    }

    if (fragment.size() > k_max_ice_username_fragment_size)
    {
        return make_field_error(field_name, "is too large");
    }

    for (const char value : fragment)
    {
        if (!is_valid_ice_username_character(value))
        {
            return make_field_error(field_name, "contains invalid characters");
        }
    }

    return {};
}

std::expected<ice_username_parts, std::string> parse_ice_username(std::string_view username)
{
    if (username.empty())
    {
        return make_error("ice username is empty");
    }

    if (username.size() > k_max_ice_username_size)
    {
        return make_error("ice username is too large");
    }

    const std::size_t separator = username.find(':');

    if (separator == std::string_view::npos)
    {
        return make_error("ice username separator is missing");
    }

    if (username.find(':', separator + 1) != std::string_view::npos)
    {
        return make_error("ice username contains multiple separators");
    }

    ice_username_parts parts;

    parts.recipient_ufrag = username.substr(0, separator);

    parts.sender_ufrag = username.substr(separator + 1);

    auto recipient_result = validate_ice_username_fragment(parts.recipient_ufrag, "ice username recipient ufrag");

    if (!recipient_result)
    {
        return std::unexpected(recipient_result.error());
    }

    auto sender_result = validate_ice_username_fragment(parts.sender_ufrag, "ice username sender ufrag");

    if (!sender_result)
    {
        return std::unexpected(sender_result.error());
    }

    return parts;
}

std::expected<void, std::string> validate_ice_connectivity_check(const stun_message& message)
{
    if (!message.priority.has_value())
    {
        return make_error("ice connectivity check missing priority");
    }

    if (*message.priority == 0)
    {
        return make_error("ice connectivity check priority is zero");
    }

    if (!message.ice_controlling.has_value())
    {
        return make_error("ice-lite connectivity check missing ice-controlling");
    }

    if (message.ice_controlled.has_value())
    {
        return make_error("ice-lite connectivity check contains ice-controlled");
    }

    return {};
}

std::string endpoint_to_string(const boost::asio::ip::udp::endpoint& endpoint)
{
    std::string value = get_endpoint_address(endpoint);

    if (value.empty())
    {
        return "<unknown>";
    }

    return value;
}

template <typename transport_type>
void forget_transport_peer_if_supported(const std::shared_ptr<transport_type>& transport, std::string_view remote_address)
{
    if (transport == nullptr || remote_address.empty())
    {
        return;
    }

    const std::string remote_address_text(remote_address);

    if constexpr (requires(transport_type& item, const std::string& value) { item.forget_peer(value); })
    {
        transport->forget_peer(remote_address_text);
    }
}

std::string make_dtls_session_generation_id(std::string_view session_id, std::string_view local_ice_ufrag, std::string_view remote_ice_ufrag)
{
    std::string generation;
    generation.reserve(session_id.size() + local_ice_ufrag.size() + remote_ice_ufrag.size() + 3);
    generation.append(session_id);
    generation.push_back('|');
    generation.append(local_ice_ufrag);
    generation.push_back('|');
    generation.append(remote_ice_ufrag);
    return generation;
}

dtls_peer_identity make_publisher_dtls_identity(const std::shared_ptr<publisher_session>& session)
{
    dtls_peer_identity identity;

    identity.role = dtls_peer_role::publisher;

    identity.session_id = session->session_id();

    identity.stream_id = session->stream_id();

    identity.local_ice_ufrag = session->local_ice().ufrag;

    identity.remote_ice_ufrag = session->remote_offer_summary().ice_ufrag;

    identity.generation = make_dtls_session_generation_id(identity.session_id, identity.local_ice_ufrag, identity.remote_ice_ufrag);

    identity.local_setup = sdp::dtls_connection_role::passive;

    identity.remote_setup = session->remote_offer_summary().setup;

    identity.remote_fingerprint = session->remote_offer_summary().fingerprint;

    return identity;
}

dtls_peer_identity make_subscriber_dtls_identity(const std::shared_ptr<subscriber_session>& session)
{
    dtls_peer_identity identity;

    identity.role = dtls_peer_role::subscriber;

    identity.session_id = session->session_id();

    identity.stream_id = session->stream_id();

    identity.local_ice_ufrag = session->local_ice().ufrag;

    identity.remote_ice_ufrag = session->remote_offer_summary().ice_ufrag;

    identity.generation = make_dtls_session_generation_id(identity.session_id, identity.local_ice_ufrag, identity.remote_ice_ufrag);

    identity.local_setup = sdp::dtls_connection_role::passive;

    identity.remote_setup = session->remote_offer_summary().setup;

    identity.remote_fingerprint = session->remote_offer_summary().fingerprint;

    return identity;
}

const sdp::media_summary* find_media_summary_by_mid(const sdp::webrtc_offer_summary& offer, std::string_view mid)
{
    if (mid.empty())
    {
        return nullptr;
    }

    for (const auto& media : offer.media)
    {
        if (media.mid == mid)
        {
            return &media;
        }
    }

    return nullptr;
}

std::optional<uint32_t> find_codec_clock_rate(const sdp::webrtc_offer_summary& offer, std::string_view mid, uint16_t payload_type)
{
    if (!mid.empty())
    {
        const sdp::media_summary* media = find_media_summary_by_mid(offer, mid);

        if (media != nullptr)
        {
            for (const auto& codec : media->codecs)
            {
                if (codec.payload_type == payload_type)
                {
                    return codec.clock_rate;
                }
            }
        }
    }

    for (const auto& media : offer.media)
    {
        for (const auto& codec : media.codecs)
        {
            if (codec.payload_type == payload_type)
            {
                return codec.clock_rate;
            }
        }
    }

    return std::nullopt;
}

std::vector<uint8_t> string_to_bytes(std::string_view value)
{
    std::vector<uint8_t> result;

    result.reserve(value.size());

    for (char item : value)
    {
        result.push_back(static_cast<uint8_t>(item));
    }

    return result;
}
bool rtp_one_byte_header_extension_id_can_be_ensured(uint8_t extension_id) { return extension_id > 0 && extension_id < 15; }
using optional_mid_ensure_result = std::expected<std::optional<rtp_header_extension_ensure>, std::string>;

optional_mid_ensure_result make_outbound_mid_header_extension_ensure(const media_payload_type_mapping& mapping,
                                                                     const sdp::webrtc_offer_summary& subscriber_offer)
{
    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        return make_error("rtp outbound mid ensure subscriber media not found");
    }

    const std::optional<uint8_t> subscriber_mid_extension_id = find_rtp_header_extension_id(*subscriber_media, k_mid_extension_uri);

    if (!subscriber_mid_extension_id.has_value())
    {
        return std::optional<rtp_header_extension_ensure>{};
    }

    if (!rtp_one_byte_header_extension_id_can_be_ensured(*subscriber_mid_extension_id))
    {
        WEBRTC_LOG_WARN("rtp outbound mid ensure skipped unsupported extmap id stream={} publisher_mid={} subscriber_mid={} kind={} extension_id={}",
                        mapping.stream_id,
                        mapping.publisher_mid,
                        mapping.subscriber_mid,
                        mapping.kind,
                        *subscriber_mid_extension_id);

        return std::optional<rtp_header_extension_ensure>{};
    }

    if (mapping.subscriber_mid.empty())
    {
        return make_error("rtp outbound mid ensure subscriber mid is empty");
    }

    rtp_header_extension_ensure ensure;

    ensure.id = *subscriber_mid_extension_id;
    ensure.payload = string_to_bytes(mapping.subscriber_mid);

    return std::optional<rtp_header_extension_ensure>(std::move(ensure));
}
bool ensured_header_extension_id_exists(const std::vector<rtp_header_extension_ensure>& ensured_header_extensions, uint8_t extension_id)
{
    if (extension_id == 0)
    {
        return false;
    }

    for (const auto& extension : ensured_header_extensions)
    {
        if (extension.id == extension_id)
        {
            return true;
        }
    }

    return false;
}

bool rtp_packet_header_extension_id_exists(std::span<const uint8_t> plain_packet, uint8_t extension_id)
{
    if (extension_id == 0)
    {
        return false;
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        return false;
    }

    for (const auto& extension : header->header_extensions)
    {
        if (extension.id == extension_id)
        {
            return true;
        }
    }

    return false;
}

bool media_header_extension_id_has_uri(const sdp::media_summary& media, uint8_t extension_id, std::string_view uri)
{
    if (extension_id == 0 || uri.empty())
    {
        return false;
    }

    for (const auto& extension : media.header_extensions)
    {
        if (extension.id != extension_id)
        {
            continue;
        }

        return extension.uri == uri;
    }

    return false;
}

bool outbound_header_extension_ensure_would_overwrite_different_uri(const media_payload_type_mapping& mapping,
                                                                    const sdp::webrtc_offer_summary& publisher_offer,
                                                                    std::span<const uint8_t> plain_packet,
                                                                    const rtp_header_extension_ensure& ensure,
                                                                    std::string_view expected_uri)
{
    if (!rtp_packet_header_extension_id_exists(plain_packet, ensure.id))
    {
        return false;
    }

    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return true;
    }

    return !media_header_extension_id_has_uri(*publisher_media, ensure.id, expected_uri);
}

using optional_header_extension_id_rewrite_result = std::expected<std::optional<rtp_header_extension_id_rewrite>, std::string>;
using optional_header_extension_rewrite_result = std::expected<std::optional<rtp_header_extension_rewrite>, std::string>;

std::optional<uint8_t> find_transport_wide_cc_header_extension_id(const sdp::media_summary& media)
{
    for (const auto& extension : media.header_extensions)
    {
        if (extension.id == 0)
        {
            continue;
        }

        if (is_transport_wide_cc_rtp_header_extension_uri(extension.uri))
        {
            return extension.id;
        }
    }

    return std::nullopt;
}
std::vector<uint8_t> make_transport_wide_cc_sequence_payload(uint16_t sequence_number)
{
    std::vector<uint8_t> payload;

    payload.reserve(2);

    payload.push_back(static_cast<uint8_t>((sequence_number >> 8U) & 0xffU));

    payload.push_back(static_cast<uint8_t>(sequence_number & 0xffU));

    return payload;
}
std::optional<uint16_t> read_publisher_transport_cc_sequence_number(const media_payload_type_mapping& mapping,
                                                                    const sdp::webrtc_offer_summary& publisher_offer,
                                                                    std::span<const uint8_t> plain_packet)
{
    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return std::nullopt;
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        return std::nullopt;
    }

    auto values = parse_rtp_header_extension_values(plain_packet, *header, *publisher_media);

    if (!values)
    {
        return std::nullopt;
    }

    return values->transport_wide_sequence_number;
}
bool accepted_mline_indexes_contains(const std::vector<int>& accepted_mline_indexes, std::size_t media_index)
{
    if (media_index > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }

    const int expected_index = static_cast<int>(media_index);

    return std::find(accepted_mline_indexes.begin(), accepted_mline_indexes.end(), expected_index) != accepted_mline_indexes.end();
}

std::optional<std::size_t> find_media_index_by_mid(const sdp::webrtc_offer_summary& offer, std::string_view mid)
{
    if (mid.empty())
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < offer.media.size(); ++index)
    {
        if (offer.media[index].mid == mid)
        {
            return index;
        }
    }

    return std::nullopt;
}
bool accepted_offer_media_matches_mid_and_kind(const sdp::webrtc_offer_summary& offer,
                                               const std::vector<int>& accepted_mline_indexes,
                                               std::string_view mid,
                                               std::string_view kind)
{
    if (mid.empty() || kind.empty())
    {
        return false;
    }

    const std::optional<std::size_t> media_index = find_media_index_by_mid(offer, mid);

    if (!media_index.has_value())
    {
        return false;
    }

    if (!accepted_mline_indexes_contains(accepted_mline_indexes, *media_index))
    {
        return false;
    }

    const sdp::media_summary& media = offer.media[*media_index];

    return media.kind == kind;
}

bool payload_type_mapping_matches_accepted_media(const publisher_session& publisher,
                                                 const subscriber_session& subscriber,
                                                 const media_payload_type_mapping& mapping)
{
    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (!accepted_offer_media_matches_mid_and_kind(
            publisher.remote_offer_summary(), publisher.accepted_remote_media_mline_indexes(), mapping.publisher_mid, mapping.kind))
    {
        return false;
    }

    if (!accepted_offer_media_matches_mid_and_kind(
            subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind))
    {
        return false;
    }

    return true;
}
bool rtcp_report_source_matches_current_accepted_media(const stream_registry& registry,
                                                       const ice_udp_server::current_session_endpoint_state& current_session,
                                                       const rtcp_report_source_config& source)
{
    if (source.mid.empty() || source.kind.empty())
    {
        return false;
    }

    if (current_session.kind == stream_session_kind::publisher)
    {
        const auto publisher = registry.find_publisher_by_session_id(source.session_id);

        if (publisher == nullptr)
        {
            return false;
        }

        return accepted_offer_media_matches_mid_and_kind(
            publisher->remote_offer_summary(), publisher->accepted_remote_media_mline_indexes(), source.mid, source.kind);
    }

    if (current_session.kind == stream_session_kind::subscriber)
    {
        const auto subscriber = registry.find_subscriber_by_session_id(source.session_id);

        if (subscriber == nullptr)
        {
            return false;
        }

        return accepted_offer_media_matches_mid_and_kind(
            subscriber->remote_offer_summary(), subscriber->accepted_remote_media_mline_indexes(), source.mid, source.kind);
    }

    return false;
}

std::size_t erase_unaccepted_payload_type_mappings(media_payload_type_mapping_table& table,
                                                   const publisher_session& publisher,
                                                   const subscriber_session& subscriber)
{
    const std::size_t before_size = table.mappings.size();

    table.mappings.erase(std::remove_if(table.mappings.begin(),
                                        table.mappings.end(),
                                        [&](const media_payload_type_mapping& mapping)
                                        { return !payload_type_mapping_matches_accepted_media(publisher, subscriber, mapping); }),
                         table.mappings.end());

    return before_size - table.mappings.size();
}
bool payload_type_mapping_matches_track_resolution_kind_fallback(const media_payload_type_mapping& mapping,
                                                                 const media_track_resolution& track_resolution)
{
    if (!track_resolution.resolved)
    {
        return false;
    }

    if (track_resolution.kind.empty())
    {
        return false;
    }

    if (mapping.kind != track_resolution.kind)
    {
        return false;
    }

    if (mapping.publisher_payload_type != track_resolution.payload_type)
    {
        return false;
    }

    if (mapping.rtx != track_resolution.rtx)
    {
        return false;
    }

    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty())
    {
        return false;
    }

    return true;
}
bool payload_type_mapping_matches_track_resolution_exact_identity(const media_payload_type_mapping& mapping,
                                                                  const media_track_resolution& track_resolution)
{
    if (!track_resolution.resolved)
    {
        return false;
    }

    if (track_resolution.mid.empty())
    {
        return false;
    }

    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (mapping.publisher_mid != track_resolution.mid)
    {
        return false;
    }

    if (!track_resolution.kind.empty() && mapping.kind != track_resolution.kind)
    {
        return false;
    }

    if (mapping.publisher_payload_type != track_resolution.payload_type)
    {
        return false;
    }

    if (mapping.rtx != track_resolution.rtx)
    {
        return false;
    }

    return true;
}

std::optional<media_payload_type_mapping> find_unique_payload_type_mapping_by_track_resolution_kind(const media_payload_type_mapping_table& table,
                                                                                                    const media_track_resolution& track_resolution)
{
    std::optional<media_payload_type_mapping> selected_mapping;

    for (const auto& mapping : table.mappings)
    {
        if (!payload_type_mapping_matches_track_resolution_kind_fallback(mapping, track_resolution))
        {
            continue;
        }

        if (selected_mapping.has_value())
        {
            return std::nullopt;
        }

        selected_mapping = mapping;
    }

    return selected_mapping;
}

std::size_t count_payload_type_mapping_candidates_by_track_resolution_kind(const media_payload_type_mapping_table& table,
                                                                           const media_track_resolution& track_resolution)
{
    std::size_t count = 0;

    for (const auto& mapping : table.mappings)
    {
        if (payload_type_mapping_matches_track_resolution_kind_fallback(mapping, track_resolution))
        {
            count += 1;
        }
    }

    return count;
}
bool payload_type_mapping_kind_fallback_has_single_media_pair(const media_payload_type_mapping_table& table,
                                                              const media_track_resolution& track_resolution)
{
    if (!track_resolution.resolved)
    {
        return false;
    }

    if (track_resolution.kind.empty())
    {
        return false;
    }

    std::optional<std::size_t> publisher_media_ordinal;
    std::optional<std::size_t> subscriber_media_ordinal;

    bool has_matching_kind = false;

    for (const auto& mapping : table.mappings)
    {
        if (mapping.kind != track_resolution.kind)
        {
            continue;
        }

        if (mapping.rtx != track_resolution.rtx)
        {
            continue;
        }

        if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty())
        {
            return false;
        }

        has_matching_kind = true;

        if (!publisher_media_ordinal.has_value())
        {
            publisher_media_ordinal = mapping.publisher_media_ordinal;
        }
        else if (*publisher_media_ordinal != mapping.publisher_media_ordinal)
        {
            return false;
        }

        if (!subscriber_media_ordinal.has_value())
        {
            subscriber_media_ordinal = mapping.subscriber_media_ordinal;
        }
        else if (*subscriber_media_ordinal != mapping.subscriber_media_ordinal)
        {
            return false;
        }
    }

    return has_matching_kind && publisher_media_ordinal.has_value() && subscriber_media_ordinal.has_value();
}
bool accepted_offer_media_has_transport_cc(const sdp::webrtc_offer_summary& offer,
                                           const std::vector<int>& accepted_mline_indexes,
                                           std::string_view mid,
                                           std::string_view kind)
{
    if (mid.empty() || kind.empty())
    {
        return false;
    }

    const std::optional<std::size_t> media_index = find_media_index_by_mid(offer, mid);

    if (!media_index.has_value())
    {
        return false;
    }

    if (!accepted_mline_indexes_contains(accepted_mline_indexes, *media_index))
    {
        return false;
    }

    const sdp::media_summary& media = offer.media[*media_index];

    if (media.kind != kind)
    {
        return false;
    }

    return find_transport_wide_cc_header_extension_id(media).has_value();
}

bool publisher_subscriber_media_has_negotiated_transport_cc(const publisher_session& publisher,
                                                            const subscriber_session& subscriber,
                                                            const media_payload_type_mapping& mapping)
{
    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (!accepted_offer_media_has_transport_cc(
            publisher.remote_offer_summary(), publisher.accepted_remote_media_mline_indexes(), mapping.publisher_mid, mapping.kind))
    {
        return false;
    }

    if (!accepted_offer_media_has_transport_cc(
            subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind))
    {
        return false;
    }

    return true;
}

bool publisher_media_has_negotiated_transport_cc(const publisher_session& publisher, const std::optional<media_track_resolution>& track_resolution)
{
    if (!track_resolution.has_value())
    {
        return false;
    }

    if (!track_resolution->resolved)
    {
        return false;
    }

    if (track_resolution->mid.empty() || track_resolution->kind.empty())
    {
        return false;
    }

    const sdp::webrtc_offer_summary& offer = publisher.remote_offer_summary();

    const std::optional<std::size_t> media_index = find_media_index_by_mid(offer, track_resolution->mid);

    if (!media_index.has_value())
    {
        return false;
    }

    if (!accepted_mline_indexes_contains(publisher.accepted_remote_media_mline_indexes(), *media_index))
    {
        return false;
    }

    const sdp::media_summary& media = offer.media[*media_index];

    if (media.kind != track_resolution->kind)
    {
        return false;
    }

    return find_transport_wide_cc_header_extension_id(media).has_value();
}

optional_header_extension_rewrite_result make_transport_wide_cc_header_extension_rewrite(const media_payload_type_mapping& mapping,
                                                                                         const sdp::webrtc_offer_summary& publisher_offer,
                                                                                         const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                         std::span<const uint8_t> plain_packet,
                                                                                         uint16_t outbound_sequence_number)
{
    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return make_error("transport-cc sequence rewrite publisher media not found");
    }

    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        return make_error("transport-cc sequence rewrite subscriber media not found");
    }

    const std::optional<uint8_t> publisher_transport_cc_id = find_transport_wide_cc_header_extension_id(*publisher_media);

    if (!publisher_transport_cc_id.has_value())
    {
        return std::optional<rtp_header_extension_rewrite>{};
    }

    const std::optional<uint8_t> subscriber_transport_cc_id = find_transport_wide_cc_header_extension_id(*subscriber_media);

    if (!subscriber_transport_cc_id.has_value())
    {
        return std::optional<rtp_header_extension_rewrite>{};
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "transport-cc sequence rewrite parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    auto publisher_payload = find_rtp_header_extension(plain_packet, *header, *publisher_transport_cc_id);

    if (!publisher_payload.has_value())
    {
        return std::optional<rtp_header_extension_rewrite>{};
    }

    if (publisher_payload->size() != 2)
    {
        return make_error("transport-cc sequence rewrite payload size is invalid");
    }

    rtp_header_extension_rewrite rewrite;

    /*
     * header_extensions are applied before header_extension_id_rewrites.
     * Therefore payload rewrite must target the current publisher extmap id.
     * The existing id rewrite then moves the extension to subscriber extmap id.
     */
    rewrite.id = *publisher_transport_cc_id;

    rewrite.payload = make_transport_wide_cc_sequence_payload(outbound_sequence_number);

    return std::optional<rtp_header_extension_rewrite>(std::move(rewrite));
}

optional_header_extension_id_rewrite_result make_transport_wide_cc_header_extension_id_rewrite(const media_payload_type_mapping& mapping,
                                                                                               const sdp::webrtc_offer_summary& publisher_offer,
                                                                                               const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                               std::span<const uint8_t> plain_packet)
{
    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return make_error("transport-cc rewrite publisher media not found");
    }

    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        return make_error("transport-cc rewrite subscriber media not found");
    }

    const std::optional<uint8_t> publisher_transport_cc_id = find_transport_wide_cc_header_extension_id(*publisher_media);

    if (!publisher_transport_cc_id.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "transport-cc rewrite parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    auto publisher_payload = find_rtp_header_extension(plain_packet, *header, *publisher_transport_cc_id);

    if (!publisher_payload.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    const std::optional<uint8_t> subscriber_transport_cc_id = find_transport_wide_cc_header_extension_id(*subscriber_media);

    if (!subscriber_transport_cc_id.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    if (*publisher_transport_cc_id == *subscriber_transport_cc_id)
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    if (publisher_payload->size() != 2)
    {
        return make_error("transport-cc extension payload size is invalid");
    }

    rtp_header_extension_id_rewrite rewrite;

    rewrite.source_id = *publisher_transport_cc_id;

    rewrite.target_id = *subscriber_transport_cc_id;

    return std::optional<rtp_header_extension_id_rewrite>(rewrite);
}
std::optional<uint8_t> find_absolute_send_time_header_extension_id(const sdp::media_summary& media)
{
    for (const auto& extension : media.header_extensions)
    {
        if (extension.id == 0)
        {
            continue;
        }

        if (is_absolute_send_time_rtp_header_extension_uri(extension.uri))
        {
            return extension.id;
        }
    }

    return std::nullopt;
}
bool accepted_offer_media_has_absolute_send_time(const sdp::webrtc_offer_summary& offer,
                                                 const std::vector<int>& accepted_mline_indexes,
                                                 std::string_view mid,
                                                 std::string_view kind)
{
    if (mid.empty() || kind.empty())
    {
        return false;
    }

    const std::optional<std::size_t> media_index = find_media_index_by_mid(offer, mid);

    if (!media_index.has_value())
    {
        return false;
    }

    if (!accepted_mline_indexes_contains(accepted_mline_indexes, *media_index))
    {
        return false;
    }

    const sdp::media_summary& media = offer.media[*media_index];

    if (media.kind != kind)
    {
        return false;
    }

    return find_absolute_send_time_header_extension_id(media).has_value();
}

bool publisher_subscriber_media_has_negotiated_absolute_send_time(const publisher_session& publisher,
                                                                  const subscriber_session& subscriber,
                                                                  const media_payload_type_mapping& mapping)
{
    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (!accepted_offer_media_has_absolute_send_time(
            publisher.remote_offer_summary(), publisher.accepted_remote_media_mline_indexes(), mapping.publisher_mid, mapping.kind))
    {
        return false;
    }

    if (!accepted_offer_media_has_absolute_send_time(
            subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind))
    {
        return false;
    }

    return true;
}
bool accepted_offer_media_has_audio_level(const sdp::webrtc_offer_summary& offer,
                                          const std::vector<int>& accepted_mline_indexes,
                                          std::string_view mid,
                                          std::string_view kind)
{
    if (mid.empty() || kind.empty())
    {
        return false;
    }

    if (kind != "audio")
    {
        return false;
    }

    const std::optional<std::size_t> media_index = find_media_index_by_mid(offer, mid);

    if (!media_index.has_value())
    {
        return false;
    }

    if (!accepted_mline_indexes_contains(accepted_mline_indexes, *media_index))
    {
        return false;
    }

    const sdp::media_summary& media = offer.media[*media_index];

    if (media.kind != "audio")
    {
        return false;
    }

    return find_rtp_header_extension_id(media, k_audio_level_extension_uri).has_value();
}

bool publisher_subscriber_media_has_negotiated_audio_level(const publisher_session& publisher,
                                                           const subscriber_session& subscriber,
                                                           const media_payload_type_mapping& mapping)
{
    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (mapping.kind != "audio")
    {
        return false;
    }

    if (!accepted_offer_media_has_audio_level(
            publisher.remote_offer_summary(), publisher.accepted_remote_media_mline_indexes(), mapping.publisher_mid, mapping.kind))
    {
        return false;
    }

    if (!accepted_offer_media_has_audio_level(
            subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind))
    {
        return false;
    }

    return true;
}
bool accepted_offer_media_has_mid(const sdp::webrtc_offer_summary& offer,
                                  const std::vector<int>& accepted_mline_indexes,
                                  std::string_view mid,
                                  std::string_view kind)
{
    if (mid.empty() || kind.empty())
    {
        return false;
    }

    const std::optional<std::size_t> media_index = find_media_index_by_mid(offer, mid);

    if (!media_index.has_value())
    {
        return false;
    }

    if (!accepted_mline_indexes_contains(accepted_mline_indexes, *media_index))
    {
        return false;
    }

    const sdp::media_summary& media = offer.media[*media_index];

    if (media.kind != kind)
    {
        return false;
    }

    return find_rtp_header_extension_id(media, k_mid_extension_uri).has_value();
}

bool publisher_subscriber_media_has_negotiated_mid(const publisher_session& publisher,
                                                   const subscriber_session& subscriber,
                                                   const media_payload_type_mapping& mapping)
{
    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (!accepted_offer_media_has_mid(
            publisher.remote_offer_summary(), publisher.accepted_remote_media_mline_indexes(), mapping.publisher_mid, mapping.kind))
    {
        return false;
    }

    if (!accepted_offer_media_has_mid(
            subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind))
    {
        return false;
    }

    return true;
}
bool accepted_offer_media_has_rtp_header_extension_uri(const sdp::webrtc_offer_summary& offer,
                                                       const std::vector<int>& accepted_mline_indexes,
                                                       std::string_view mid,
                                                       std::string_view kind,
                                                       std::string_view uri)
{
    if (mid.empty() || kind.empty() || uri.empty())
    {
        return false;
    }

    const std::optional<std::size_t> media_index = find_media_index_by_mid(offer, mid);

    if (!media_index.has_value())
    {
        return false;
    }

    if (!accepted_mline_indexes_contains(accepted_mline_indexes, *media_index))
    {
        return false;
    }

    const sdp::media_summary& media = offer.media[*media_index];

    if (media.kind != kind)
    {
        return false;
    }

    return find_rtp_header_extension_id(media, uri).has_value();
}

bool accepted_offer_video_media_has_rid(const sdp::webrtc_offer_summary& offer,
                                        const std::vector<int>& accepted_mline_indexes,
                                        std::string_view mid,
                                        std::string_view kind)
{
    if (kind != "video")
    {
        return false;
    }

    return accepted_offer_media_has_rtp_header_extension_uri(
        offer, accepted_mline_indexes, mid, kind, sdp::k_rtp_header_extension_sdes_rtp_stream_id_uri);
}

bool accepted_offer_video_media_has_repaired_rid(const sdp::webrtc_offer_summary& offer,
                                                 const std::vector<int>& accepted_mline_indexes,
                                                 std::string_view mid,
                                                 std::string_view kind)
{
    if (kind != "video")
    {
        return false;
    }

    return accepted_offer_media_has_rtp_header_extension_uri(
        offer, accepted_mline_indexes, mid, kind, sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri);
}

bool publisher_subscriber_media_has_negotiated_rid_header_extension(const publisher_session& publisher,
                                                                    const subscriber_session& subscriber,
                                                                    const media_payload_type_mapping& mapping)
{
    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (mapping.kind != "video")
    {
        return false;
    }

    if (!accepted_offer_video_media_has_rid(
            publisher.remote_offer_summary(), publisher.accepted_remote_media_mline_indexes(), mapping.publisher_mid, mapping.kind))
    {
        return false;
    }

    if (mapping.rtx)
    {
        return accepted_offer_video_media_has_repaired_rid(
            subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind);
    }

    return accepted_offer_video_media_has_rid(
        subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind);
}

bool publisher_subscriber_media_has_negotiated_rtx_repaired_rid(const publisher_session& publisher,
                                                                const subscriber_session& subscriber,
                                                                const media_payload_type_mapping& mapping)
{
    if (mapping.publisher_mid.empty() || mapping.subscriber_mid.empty() || mapping.kind.empty())
    {
        return false;
    }

    if (mapping.kind != "video")
    {
        return false;
    }

    if (!accepted_offer_video_media_has_rid(
            publisher.remote_offer_summary(), publisher.accepted_remote_media_mline_indexes(), mapping.publisher_mid, mapping.kind))
    {
        return false;
    }

    return accepted_offer_video_media_has_repaired_rid(
        subscriber.remote_offer_summary(), subscriber.accepted_remote_media_mline_indexes(), mapping.subscriber_mid, mapping.kind);
}

optional_header_extension_id_rewrite_result make_absolute_send_time_header_extension_id_rewrite(const media_payload_type_mapping& mapping,
                                                                                                const sdp::webrtc_offer_summary& publisher_offer,
                                                                                                const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                                std::span<const uint8_t> plain_packet)
{
    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return make_error("abs-send-time rewrite publisher media not found");
    }

    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        return make_error("abs-send-time rewrite subscriber media not found");
    }

    const std::optional<uint8_t> publisher_absolute_send_time_id = find_absolute_send_time_header_extension_id(*publisher_media);

    if (!publisher_absolute_send_time_id.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "abs-send-time rewrite parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    auto publisher_payload = find_rtp_header_extension(plain_packet, *header, *publisher_absolute_send_time_id);

    if (!publisher_payload.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    if (publisher_payload->size() != 3)
    {
        return make_error("abs-send-time extension payload size is invalid");
    }

    const std::optional<uint8_t> subscriber_absolute_send_time_id = find_absolute_send_time_header_extension_id(*subscriber_media);

    if (!subscriber_absolute_send_time_id.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    if (*publisher_absolute_send_time_id == *subscriber_absolute_send_time_id)
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    rtp_header_extension_id_rewrite rewrite;

    rewrite.source_id = *publisher_absolute_send_time_id;

    rewrite.target_id = *subscriber_absolute_send_time_id;

    return std::optional<rtp_header_extension_id_rewrite>(rewrite);
}

optional_header_extension_id_rewrite_result make_forwarded_rtp_header_extension_id_rewrite(const media_payload_type_mapping& mapping,
                                                                                           const sdp::webrtc_offer_summary& publisher_offer,
                                                                                           const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                           std::span<const uint8_t> plain_packet,
                                                                                           std::string_view extension_uri,
                                                                                           std::string_view error_prefix)
{
    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        std::string message(error_prefix);

        message.append(" publisher media not found");

        return make_error(message);
    }

    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        std::string message(error_prefix);

        message.append(" subscriber media not found");

        return make_error(message);
    }

    const std::optional<uint8_t> publisher_extension_id = find_rtp_header_extension_id(*publisher_media, extension_uri);

    if (!publisher_extension_id.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message(error_prefix);

        message.append(" parse failed: ");
        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    auto publisher_payload = find_rtp_header_extension(plain_packet, *header, *publisher_extension_id);

    if (!publisher_payload.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    const std::optional<uint8_t> subscriber_extension_id = find_rtp_header_extension_id(*subscriber_media, extension_uri);

    if (!subscriber_extension_id.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    if (*publisher_extension_id == *subscriber_extension_id)
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    rtp_header_extension_id_rewrite rewrite;

    rewrite.source_id = *publisher_extension_id;

    rewrite.target_id = *subscriber_extension_id;

    return std::optional<rtp_header_extension_id_rewrite>(rewrite);
}

optional_header_extension_id_rewrite_result make_rid_header_extension_id_rewrite(const media_payload_type_mapping& mapping,
                                                                                 const sdp::webrtc_offer_summary& publisher_offer,
                                                                                 const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                 std::span<const uint8_t> plain_packet)
{
    return make_forwarded_rtp_header_extension_id_rewrite(
        mapping, publisher_offer, subscriber_offer, plain_packet, sdp::k_rtp_header_extension_sdes_rtp_stream_id_uri, "rid rewrite");
}

optional_header_extension_id_rewrite_result make_repaired_rid_header_extension_id_rewrite(const media_payload_type_mapping& mapping,
                                                                                          const sdp::webrtc_offer_summary& publisher_offer,
                                                                                          const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                          std::span<const uint8_t> plain_packet)
{
    return make_forwarded_rtp_header_extension_id_rewrite(mapping,
                                                          publisher_offer,
                                                          subscriber_offer,
                                                          plain_packet,
                                                          sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri,
                                                          "repaired-rid rewrite");
}

optional_rtx_header_extension_id_rewrite_result make_rtx_repaired_rid_header_extension_id_rewrite(const media_payload_type_mapping& mapping,
                                                                                                  const sdp::webrtc_offer_summary& publisher_offer,
                                                                                                  const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                                  std::span<const uint8_t> plain_packet)
{
    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return make_error("rtx repaired-rid rewrite publisher media not found");
    }

    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        return make_error("rtx repaired-rid rewrite subscriber media not found");
    }

    const std::optional<uint8_t> publisher_rid_extension_id =
        find_rtp_header_extension_id(*publisher_media, sdp::k_rtp_header_extension_sdes_rtp_stream_id_uri);

    if (!publisher_rid_extension_id.has_value())
    {
        return std::optional<rtp_rtx_header_extension_id_rewrite>{};
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "rtx repaired-rid rewrite parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    const auto existing_rid_payload = find_rtp_header_extension(plain_packet, *header, *publisher_rid_extension_id);

    if (!existing_rid_payload.has_value())
    {
        return std::optional<rtp_rtx_header_extension_id_rewrite>{};
    }

    const std::optional<uint8_t> subscriber_repaired_rid_extension_id =
        find_rtp_header_extension_id(*subscriber_media, sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri);

    if (!subscriber_repaired_rid_extension_id.has_value())
    {
        return make_error("rtx repaired-rid extension is missing in subscriber media");
    }

    if (*publisher_rid_extension_id == *subscriber_repaired_rid_extension_id)
    {
        return std::optional<rtp_rtx_header_extension_id_rewrite>{};
    }

    rtp_rtx_header_extension_id_rewrite rewrite;

    rewrite.source_id = *publisher_rid_extension_id;

    rewrite.target_id = *subscriber_repaired_rid_extension_id;

    return std::optional<rtp_rtx_header_extension_id_rewrite>(rewrite);
}

void log_rtcp_feedback_route_event(const rtcp_feedback_route_event& event)
{
    const bool has_hard_event = event.action == media_route_action::none || event.source.role == media_peer_role::unknown ||
                                event.event_type == rtcp_feedback_event_type::none || event.target_endpoints.empty();

    if (has_hard_event)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback route event={} action={} role={} stream={} session={} remote={} targets={} packet_type={} format={} feedback={} ssrc={} "
            "sender_ssrc={} media_ssrc={} nack_count={} fir_count={} keyframe_request={} generic_nack={} transport_cc={} remb={} remb_bitrate={}",
            rtcp_feedback_event_type_to_string(event.event_type),
            media_route_action_to_string(event.action),
            media_peer_role_to_string(event.source.role),
            event.source.stream_id,
            event.source.session_id,
            event.source.remote_endpoint,
            event.target_endpoints.size(),
            static_cast<unsigned int>(event.packet_type),
            static_cast<unsigned int>(event.feedback_format),
            event.feedback_name,
            event.ssrc,
            event.sender_ssrc,
            event.media_ssrc,
            event.nack_count,
            event.fir_count,
            event.has_keyframe_request ? 1 : 0,
            event.has_generic_nack ? 1 : 0,
            event.has_transport_cc ? 1 : 0,
            event.has_remb ? 1 : 0,
            event.remb_bitrate_bps);

        return;
    }

    WEBRTC_LOG_DEBUG(
        "rtcp feedback route event={} action={} role={} stream={} session={} remote={} targets={} packet_type={} format={} feedback={} ssrc={} "
        "sender_ssrc={} media_ssrc={} nack_count={} fir_count={} keyframe_request={} generic_nack={} transport_cc={} remb={} remb_bitrate={}",
        rtcp_feedback_event_type_to_string(event.event_type),
        media_route_action_to_string(event.action),
        media_peer_role_to_string(event.source.role),
        event.source.stream_id,
        event.source.session_id,
        event.source.remote_endpoint,
        event.target_endpoints.size(),
        static_cast<unsigned int>(event.packet_type),
        static_cast<unsigned int>(event.feedback_format),
        event.feedback_name,
        event.ssrc,
        event.sender_ssrc,
        event.media_ssrc,
        event.nack_count,
        event.fir_count,
        event.has_keyframe_request ? 1 : 0,
        event.has_generic_nack ? 1 : 0,
        event.has_transport_cc ? 1 : 0,
        event.has_remb ? 1 : 0,
        event.remb_bitrate_bps);
}

struct nack_sequence_expansion
{
    std::vector<uint16_t> sequence_numbers;

    std::size_t raw_sequence_count = 0;

    std::size_t duplicate_count = 0;

    bool truncated = false;
};

bool contains_nack_sequence(const std::vector<uint16_t>& sequence_numbers, uint16_t sequence_number)
{
    return std::find(sequence_numbers.begin(), sequence_numbers.end(), sequence_number) != sequence_numbers.end();
}

void append_nack_sequence(nack_sequence_expansion& expansion, uint16_t sequence_number, std::size_t max_sequences)
{
    expansion.raw_sequence_count += 1;

    if (contains_nack_sequence(expansion.sequence_numbers, sequence_number))
    {
        expansion.duplicate_count += 1;

        return;
    }

    if (expansion.sequence_numbers.size() >= max_sequences)
    {
        expansion.truncated = true;

        return;
    }

    expansion.sequence_numbers.push_back(sequence_number);
}

nack_sequence_expansion expand_nack_sequences(const std::vector<rtcp_nack_item>& nack_items, std::size_t max_sequences)
{
    nack_sequence_expansion expansion;

    const std::size_t reserve_size = std::min(nack_items.size() * k_nack_sequences_per_item, max_sequences);

    expansion.sequence_numbers.reserve(reserve_size);

    for (const auto& item : nack_items)
    {
        append_nack_sequence(expansion, item.packet_id, max_sequences);

        for (uint16_t bit_index = 0; bit_index < 16; ++bit_index)
        {
            const uint16_t mask = static_cast<uint16_t>(static_cast<uint32_t>(1U) << static_cast<uint32_t>(bit_index));

            if ((item.lost_packet_bitmask & mask) == 0)
            {
                continue;
            }

            const uint16_t sequence_number = static_cast<uint16_t>(item.packet_id + static_cast<uint16_t>(bit_index + 1));

            append_nack_sequence(expansion, sequence_number, max_sequences);
        }
    }

    return expansion;
}
struct rtcp_bye_target
{
    std::string subscriber_session_id;

    std::string remote_address;

    std::vector<uint32_t> ssrcs;
};

void append_unique_rtcp_bye_ssrc(std::vector<uint32_t>& ssrcs, uint32_t ssrc)
{
    if (ssrc == 0)
    {
        return;
    }

    if (std::find(ssrcs.begin(), ssrcs.end(), ssrc) != ssrcs.end())
    {
        return;
    }

    ssrcs.push_back(ssrc);
}

void append_unique_keyframe_media_target(std::vector<ice_udp_server::keyframe_request_media_target>& targets,
                                         ice_udp_server::keyframe_request_media_target target)
{
    if (target.media_ssrc == 0 || target.sender_ssrc == 0)
    {
        return;
    }

    for (const auto& current : targets)
    {
        if (current.media_ssrc == target.media_ssrc)
        {
            return;
        }
    }

    targets.push_back(std::move(target));
}
bool is_video_media_kind(std::string_view kind) { return kind == "video"; }
const sdp::media_summary* find_offer_media_by_mid(const sdp::webrtc_offer_summary& offer, std::string_view mid)
{
    if (mid.empty())
    {
        return nullptr;
    }

    for (const auto& media : offer.media)
    {
        if (media.mid == mid)
        {
            return &media;
        }
    }

    return nullptr;
}
enum class simulcast_rid_preference_policy : uint8_t
{
    offer_order,
    reverse_order,
    first,
    last,
};

std::vector<std::string> make_default_simulcast_rid_preference(const sdp::media_summary& publisher_media)
{
    std::vector<std::string> preferred_rids;

    if (publisher_media.simulcast.has_value())
    {
        for (const auto& rid : publisher_media.simulcast->send_rids)
        {
            if (rid.empty())
            {
                continue;
            }

            preferred_rids.push_back(rid);
        }
    }

    if (!preferred_rids.empty())
    {
        return preferred_rids;
    }

    for (const auto& rid : publisher_media.rids)
    {
        if (rid.id.empty())
        {
            continue;
        }

        preferred_rids.push_back(rid.id);
    }

    return preferred_rids;
}
std::string lower_ascii_copy(std::string_view value)
{
    std::string result;

    result.reserve(value.size());

    for (auto ch : value)
    {
        result.push_back(static_cast<char>(std::tolower(ch)));
    }

    return result;
}
enum class publisher_video_keyframe_codec : uint8_t
{
    unknown,
    vp8,
    h264,
};

publisher_video_keyframe_codec publisher_video_keyframe_codec_from_name(std::string_view codec_name)
{
    const std::string normalized = lower_ascii_copy(codec_name);

    if (normalized == "vp8")
    {
        return publisher_video_keyframe_codec::vp8;
    }

    if (normalized == "h264")
    {
        return publisher_video_keyframe_codec::h264;
    }

    return publisher_video_keyframe_codec::unknown;
}

std::string_view publisher_video_keyframe_codec_to_string(publisher_video_keyframe_codec codec)
{
    switch (codec)
    {
        case publisher_video_keyframe_codec::vp8:
            return "vp8";

        case publisher_video_keyframe_codec::h264:
            return "h264";

        case publisher_video_keyframe_codec::unknown:
            return "unknown";
    }

    return "unknown";
}

std::optional<std::string> find_offer_codec_name_by_payload_type(const sdp::webrtc_offer_summary& offer, std::string_view mid, uint16_t payload_type)
{
    if (!mid.empty())
    {
        const sdp::media_summary* media = find_media_summary_by_mid(offer, mid);

        if (media != nullptr)
        {
            for (const auto& codec : media->codecs)
            {
                if (codec.payload_type == payload_type)
                {
                    return codec.name;
                }
            }
        }
    }

    std::optional<std::string> matched_codec_name;

    for (const auto& media : offer.media)
    {
        for (const auto& codec : media.codecs)
        {
            if (codec.payload_type != payload_type)
            {
                continue;
            }

            if (matched_codec_name.has_value())
            {
                return std::nullopt;
            }

            matched_codec_name = codec.name;
        }
    }

    return matched_codec_name;
}

std::optional<std::span<const uint8_t>> rtp_payload_span(std::span<const uint8_t> packet, const rtp_packet_header& header)
{
    if (header.payload_size == 0)
    {
        return std::nullopt;
    }

    if (header.payload_offset > packet.size())
    {
        return std::nullopt;
    }

    if (header.payload_offset + header.payload_size > packet.size())
    {
        return std::nullopt;
    }

    return packet.subspan(header.payload_offset, header.payload_size);
}

bool is_vp8_keyframe_payload(std::span<const uint8_t> payload)
{
    if (payload.empty())
    {
        return false;
    }

    const uint8_t descriptor = payload[0];

    const bool extension_present = (descriptor & 0x80U) != 0;
    const bool start_of_partition = (descriptor & 0x10U) != 0;
    const auto partition_id = static_cast<uint8_t>(descriptor & 0x0FU);

    if (!start_of_partition || partition_id != 0)
    {
        return false;
    }

    std::size_t offset = 1;

    if (extension_present)
    {
        if (offset >= payload.size())
        {
            return false;
        }

        const uint8_t extension = payload[offset];

        offset += 1;

        const bool picture_id_present = (extension & 0x80U) != 0;
        const bool tl0picidx_present = (extension & 0x40U) != 0;
        const bool tid_present = (extension & 0x20U) != 0;
        const bool keyidx_present = (extension & 0x10U) != 0;

        if (picture_id_present)
        {
            if (offset >= payload.size())
            {
                return false;
            }

            const bool long_picture_id = (payload[offset] & 0x80U) != 0;

            offset += long_picture_id ? 2 : 1;
        }

        if (tl0picidx_present)
        {
            offset += 1;
        }

        if (tid_present || keyidx_present)
        {
            offset += 1;
        }
    }

    if (offset >= payload.size())
    {
        return false;
    }

    /*
     * RFC 7741 VP8 payload:
     * the first byte of the VP8 uncompressed data has bit 0 == 0 for key frames.
     */
    return (payload[offset] & 0x01U) == 0;
}

bool h264_nal_unit_type_is_idr(uint8_t nal_unit_type) { return nal_unit_type == 5; }

bool is_h264_single_nal_keyframe(std::span<const uint8_t> payload)
{
    if (payload.empty())
    {
        return false;
    }

    const auto nal_unit_type = static_cast<uint8_t>(payload[0] & 0x1FU);

    return h264_nal_unit_type_is_idr(nal_unit_type);
}

bool is_h264_stap_a_keyframe(std::span<const uint8_t> payload)
{
    if (payload.size() < 3)
    {
        return false;
    }

    std::size_t offset = 1;

    while (offset + 2 <= payload.size())
    {
        const auto nal_unit_size = static_cast<uint16_t>((static_cast<uint16_t>(payload[offset]) << 8U) | static_cast<uint16_t>(payload[offset + 1]));

        offset += 2;

        if (nal_unit_size == 0)
        {
            return false;
        }

        if (offset + static_cast<std::size_t>(nal_unit_size) > payload.size())
        {
            return false;
        }

        const auto nal_unit_type = static_cast<uint8_t>(payload[offset] & 0x1FU);

        if (h264_nal_unit_type_is_idr(nal_unit_type))
        {
            return true;
        }

        offset += static_cast<std::size_t>(nal_unit_size);
    }

    return false;
}

bool is_h264_fu_a_keyframe(std::span<const uint8_t> payload)
{
    if (payload.size() < 2)
    {
        return false;
    }

    const uint8_t fu_header = payload[1];

    const bool start = (fu_header & 0x80U) != 0;
    const auto reconstructed_nal_unit_type = static_cast<uint8_t>(fu_header & 0x1FU);

    return start && h264_nal_unit_type_is_idr(reconstructed_nal_unit_type);
}

bool is_h264_keyframe_payload(std::span<const uint8_t> payload)
{
    if (payload.empty())
    {
        return false;
    }

    const auto nal_unit_type = static_cast<uint8_t>(payload[0] & 0x1FU);

    if (nal_unit_type >= 1 && nal_unit_type <= 23)
    {
        return is_h264_single_nal_keyframe(payload);
    }

    if (nal_unit_type == 24)
    {
        return is_h264_stap_a_keyframe(payload);
    }

    if (nal_unit_type == 28)
    {
        return is_h264_fu_a_keyframe(payload);
    }

    return false;
}

bool is_publisher_video_keyframe_payload(publisher_video_keyframe_codec codec, std::span<const uint8_t> payload)
{
    switch (codec)
    {
        case publisher_video_keyframe_codec::vp8:
            return is_vp8_keyframe_payload(payload);

        case publisher_video_keyframe_codec::h264:
            return is_h264_keyframe_payload(payload);

        case publisher_video_keyframe_codec::unknown:
            return false;
    }

    return false;
}
simulcast_rid_preference_policy parse_simulcast_rid_preference_policy(std::string_view value)
{
    const std::string normalized = lower_ascii_copy(value);

    if (normalized == "reverse" || normalized == "reverse_order")
    {
        return simulcast_rid_preference_policy::reverse_order;
    }

    if (normalized == "first")
    {
        return simulcast_rid_preference_policy::first;
    }

    if (normalized == "last")
    {
        return simulcast_rid_preference_policy::last;
    }

    return simulcast_rid_preference_policy::offer_order;
}

simulcast_rid_preference_policy simulcast_rid_preference_policy_from_env()
{
    const char* value = std::getenv("WEBRTC_SIMULCAST_RID_PREFERENCE");

    if (value == nullptr)
    {
        return simulcast_rid_preference_policy::offer_order;
    }

    return parse_simulcast_rid_preference_policy(value);
}

std::string_view simulcast_rid_preference_policy_to_string(simulcast_rid_preference_policy policy)
{
    switch (policy)
    {
        case simulcast_rid_preference_policy::offer_order:
            return "offer";

        case simulcast_rid_preference_policy::reverse_order:
            return "reverse";

        case simulcast_rid_preference_policy::first:
            return "first";

        case simulcast_rid_preference_policy::last:
            return "last";
    }

    return "offer";
}

std::vector<std::string> apply_simulcast_rid_preference_policy(std::vector<std::string> preferred_rids, simulcast_rid_preference_policy policy)
{
    if (preferred_rids.empty())
    {
        return preferred_rids;
    }

    switch (policy)
    {
        case simulcast_rid_preference_policy::offer_order:
            return preferred_rids;

        case simulcast_rid_preference_policy::reverse_order:
            std::reverse(preferred_rids.begin(), preferred_rids.end());

            return preferred_rids;

        case simulcast_rid_preference_policy::first:
        {
            std::vector<std::string> result;

            result.push_back(preferred_rids.front());

            return result;
        }

        case simulcast_rid_preference_policy::last:
        {
            std::vector<std::string> result;

            result.push_back(preferred_rids.back());

            return result;
        }
    }

    return preferred_rids;
}

std::vector<std::string> make_simulcast_rid_preference(const sdp::media_summary& publisher_media, simulcast_rid_preference_policy policy)
{
    return apply_simulcast_rid_preference_policy(make_default_simulcast_rid_preference(publisher_media), policy);
}

struct simulcast_rid_preference_result
{
    std::string policy;
    std::vector<std::string> preferred_rids;
};

std::string_view trim_simulcast_env_token(std::string_view value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0)
    {
        value.remove_prefix(1);
    }

    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0)
    {
        value.remove_suffix(1);
    }

    return value;
}

std::optional<std::string> simulcast_rid_target_from_env()
{
    const char* value = std::getenv("WEBRTC_SIMULCAST_RID_TARGET");

    if (value == nullptr)
    {
        return std::nullopt;
    }

    const std::string_view target = trim_simulcast_env_token(value);

    if (target.empty())
    {
        return std::nullopt;
    }

    return std::string(target);
}

std::optional<std::string> simulcast_rid_target_for_subscriber_from_env(std::string_view subscriber_session_id)
{
    if (subscriber_session_id.empty())
    {
        return std::nullopt;
    }

    const char* value = std::getenv("WEBRTC_SIMULCAST_RID_TARGET_BY_SUBSCRIBER");

    if (value == nullptr)
    {
        return std::nullopt;
    }

    std::string_view config(value);

    while (!config.empty())
    {
        const std::size_t comma_position = config.find(',');

        std::string_view item = comma_position == std::string_view::npos ? config : config.substr(0, comma_position);

        item = trim_simulcast_env_token(item);

        if (!item.empty())
        {
            const std::size_t colon_position = item.find(':');

            if (colon_position != std::string_view::npos)
            {
                const std::string_view session_id = trim_simulcast_env_token(item.substr(0, colon_position));
                const std::string_view target_rid = trim_simulcast_env_token(item.substr(colon_position + 1));

                if (session_id == subscriber_session_id && !target_rid.empty())
                {
                    return std::string(target_rid);
                }
            }
        }

        if (comma_position == std::string_view::npos)
        {
            break;
        }

        config.remove_prefix(comma_position + 1);
    }

    return std::nullopt;
}
bool simulcast_adaptive_enabled_from_env()
{
    const char* value = std::getenv("WEBRTC_SIMULCAST_ADAPTIVE_ENABLED");

    if (value == nullptr)
    {
        return false;
    }

    const std::string normalized = lower_ascii_copy(trim_simulcast_env_token(value));

    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

uint64_t simulcast_uint64_from_env(std::string_view name, uint64_t default_value)
{
    const std::string env_name(name);

    const char* value = std::getenv(env_name.c_str());

    if (value == nullptr)
    {
        return default_value;
    }

    const std::string_view trimmed = trim_simulcast_env_token(value);

    if (trimmed.empty())
    {
        return default_value;
    }

    uint64_t result = 0;

    const auto parse_result = std::from_chars(trimmed.data(), trimmed.data() + trimmed.size(), result);

    if (parse_result.ec != std::errc{} || parse_result.ptr != trimmed.data() + trimmed.size())
    {
        return default_value;
    }

    return result;
}

uint64_t simulcast_adaptive_check_interval_milliseconds_from_env()
{
    return simulcast_uint64_from_env("WEBRTC_SIMULCAST_ADAPTIVE_CHECK_INTERVAL_MS", 5000);
}

uint64_t simulcast_adaptive_switch_cooldown_milliseconds_from_env()
{
    return simulcast_uint64_from_env("WEBRTC_SIMULCAST_SWITCH_COOLDOWN_MS", 10000);
}

uint64_t simulcast_adaptive_downgrade_nack_ratio_per_mille_from_env()
{
    return simulcast_uint64_from_env("WEBRTC_SIMULCAST_DOWNGRADE_NACK_RATIO_PERMILLE", 80);
}

uint64_t simulcast_adaptive_min_packets_per_window_from_env() { return simulcast_uint64_from_env("WEBRTC_SIMULCAST_ADAPTIVE_MIN_PACKETS", 50); }

uint64_t simulcast_adaptive_upgrade_stable_window_milliseconds_from_env()
{
    return simulcast_uint64_from_env("WEBRTC_SIMULCAST_UPGRADE_STABLE_WINDOW_MS", 15000);
}

std::optional<std::size_t> find_simulcast_rid_preference_index(const std::vector<std::string>& preferred_rids, std::string_view rid)
{
    for (std::size_t index = 0; index < preferred_rids.size(); ++index)
    {
        if (preferred_rids[index] == rid)
        {
            return index;
        }
    }

    return std::nullopt;
}

bool simulcast_rid_preference_contains(const std::vector<std::string>& preferred_rids, std::string_view rid)
{
    for (const auto& current : preferred_rids)
    {
        if (current == rid)
        {
            return true;
        }
    }

    return false;
}

std::vector<std::string> make_simulcast_target_first_preference(std::vector<std::string> preferred_rids, std::string_view target_rid)
{
    if (target_rid.empty() || preferred_rids.empty())
    {
        return preferred_rids;
    }

    if (!simulcast_rid_preference_contains(preferred_rids, target_rid))
    {
        return preferred_rids;
    }

    std::vector<std::string> result;

    result.reserve(preferred_rids.size());

    result.emplace_back(target_rid);

    for (const auto& rid : preferred_rids)
    {
        if (rid == target_rid)
        {
            continue;
        }

        result.push_back(rid);
    }

    return result;
}

simulcast_rid_preference_result make_simulcast_rid_preference_for_subscriber(const sdp::media_summary& publisher_media,
                                                                             const media_peer_info& target_peer)
{
    const simulcast_rid_preference_policy policy = simulcast_rid_preference_policy_from_env();

    simulcast_rid_preference_result result;

    result.policy = std::string(simulcast_rid_preference_policy_to_string(policy));
    result.preferred_rids = make_simulcast_rid_preference(publisher_media, policy);

    const std::optional<std::string> subscriber_target = simulcast_rid_target_for_subscriber_from_env(target_peer.session_id);

    if (subscriber_target.has_value())
    {
        const bool target_available = simulcast_rid_preference_contains(result.preferred_rids, *subscriber_target);

        if (target_available)
        {
            result.preferred_rids = make_simulcast_target_first_preference(std::move(result.preferred_rids), *subscriber_target);
            result.policy = "subscriber_target:" + *subscriber_target;
        }
        else
        {
            result.policy.append("+subscriber_target_missing:");
            result.policy.append(*subscriber_target);
        }

        return result;
    }

    const std::optional<std::string> global_target = simulcast_rid_target_from_env();

    if (global_target.has_value())
    {
        const bool target_available = simulcast_rid_preference_contains(result.preferred_rids, *global_target);

        if (target_available)
        {
            result.preferred_rids = make_simulcast_target_first_preference(std::move(result.preferred_rids), *global_target);
            result.policy = "target:" + *global_target;
        }
        else
        {
            result.policy.append("+target_missing:");
            result.policy.append(*global_target);
        }
    }

    return result;
}

bool rtcp_feedback_value_matches(std::string_view feedback, std::string_view expected) { return lower_ascii_copy(feedback) == expected; }
bool codec_supports_rtcp_feedback(const sdp::codec_info& codec, std::string_view feedback)
{
    for (const auto& value : codec.rtcp_feedback)
    {
        if (rtcp_feedback_value_matches(value, feedback))
        {
            return true;
        }
    }

    return false;
}

bool media_supports_rtcp_feedback(const sdp::media_summary& media, std::string_view feedback)
{
    if (!is_video_media_kind(media.kind))
    {
        return false;
    }

    for (const auto& codec : media.codecs)
    {
        if (codec_supports_rtcp_feedback(codec, feedback))
        {
            return true;
        }
    }

    return false;
}

std::string keyframe_request_feedback_type_to_string(ice_udp_server::keyframe_request_feedback_type feedback_type)
{
    switch (feedback_type)
    {
        case ice_udp_server::keyframe_request_feedback_type::pli:
            return "pli";

        case ice_udp_server::keyframe_request_feedback_type::fir:
            return "fir";

        case ice_udp_server::keyframe_request_feedback_type::none:
        default:
            return "none";
    }
}
bool is_resolved_video_track(const std::optional<media_track_resolution>& track_resolution)
{
    if (!track_resolution.has_value())
    {
        return false;
    }

    if (!track_resolution->resolved)
    {
        return false;
    }

    return is_video_media_kind(track_resolution->kind);
}
bool media_payload_type_mapping_allows_rid_header_extension_rewrite(const media_payload_type_mapping& mapping) { return mapping.kind == "video"; }

bool rtcp_feedback_event_needs_block_rewrite(const rtcp_feedback_route_event& event)
{
    return event.has_generic_nack || event.has_keyframe_request || event.has_remb;
}

bool rtcp_feedback_event_has_valid_block_range(const rtcp_feedback_route_event& event, std::size_t packet_size)
{
    if (event.block_size < 12)
    {
        return false;
    }

    if (event.block_offset > packet_size)
    {
        return false;
    }

    return event.block_size <= packet_size - event.block_offset;
}

bool is_publisher_rtp_fanout_to_subscriber(const srtp_packet_process_result& packet,
                                           const media_route_result& route,
                                           const media_peer_info& target_peer)
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return false;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return false;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return false;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return false;
    }

    return true;
}
uint16_t advance_transport_cc_sequence(uint16_t base_sequence_number, uint16_t offset)
{
    return static_cast<uint16_t>(base_sequence_number + offset);
}
}    // namespace

ice_udp_server::ice_udp_server(boost::asio::io_context& io_context,
                               std::string bind_host,
                               uint16_t bind_port,
                               std::shared_ptr<stream_registry> registry,
                               std::shared_ptr<media_router> media_router)
    : io_context_(io_context),
      socket_(io_context),
      dtls_timeout_timer_(io_context),
      ice_consent_timer_(io_context),
      rtcp_report_timer_(io_context),
      rtcp_transport_cc_feedback_timer_(io_context),
      endpoint_idle_cleanup_timer_(io_context),
      pending_session_cleanup_timer_(io_context),
      subscriber_downlink_pacing_timer_(io_context),
      bind_host_(std::move(bind_host)),
      bind_port_(bind_port),
      registry_(std::move(registry)),
      media_router_(std::move(media_router)),
      track_resolver_(std::make_shared<media_track_resolver>()),
      ssrc_mapper_(std::make_shared<media_ssrc_mapper>()),
      identity_authority_(std::make_shared<media_identity_authority>()),
      rtcp_report_service_(std::make_shared<rtcp_report_service>(ice_udp_server_runtime_config_instance().rtcp_report_service)),
      rtcp_transport_cc_feedback_service_(
          std::make_shared<rtcp_transport_cc_feedback_service>(ice_udp_server_runtime_config_instance().rtcp_transport_cc_feedback)),
      endpoint_idle_timeout_milliseconds_(ice_udp_server_runtime_config_instance().endpoint_idle_timeout_milliseconds),
      pending_session_timeout_milliseconds_(ice_udp_server_runtime_config_instance().pending_session_timeout_milliseconds),
      orphan_subscriber_timeout_milliseconds_(ice_udp_server_runtime_config_instance().orphan_subscriber_timeout_milliseconds)
{
}

ice_udp_server_result ice_udp_server::start()
{
    if (started_)
    {
        return {};
    }

    if (registry_ == nullptr)
    {
        return make_error("ice udp server registry is null");
    }

    if (media_router_ == nullptr)
    {
        return make_error("ice udp server media router is null");
    }

    if (track_resolver_ == nullptr)
    {
        track_resolver_ = std::make_shared<media_track_resolver>();
    }

    const ice_udp_server_runtime_config& runtime_config = ice_udp_server_runtime_config_instance();
    if (ssrc_mapper_ == nullptr)
    {
        ssrc_mapper_ = std::make_shared<media_ssrc_mapper>();
    }
    if (identity_authority_ == nullptr)
    {
        identity_authority_ = std::make_shared<media_identity_authority>();
    }

    if (rtcp_report_service_ == nullptr)
    {
        rtcp_report_service_ = std::make_shared<rtcp_report_service>(runtime_config.rtcp_report_service);
    }

    if (rtcp_transport_cc_feedback_service_ == nullptr)
    {
        rtcp_transport_cc_feedback_service_ = std::make_shared<rtcp_transport_cc_feedback_service>(runtime_config.rtcp_transport_cc_feedback);
    }

    register_session_removed_callback();

    auto dtls_result = init_dtls_transport();

    if (!dtls_result)
    {
        return std::unexpected(dtls_result.error());
    }

    boost::system::error_code ec;

    const auto address = boost::asio::ip::make_address(bind_host_, ec);

    if (ec)
    {
        std::string message = "ice udp bind address is invalid: ";

        message.append(ec.message());

        return std::unexpected(std::move(message));
    }

    boost::asio::ip::udp::endpoint endpoint(address, bind_port_);

    ec = socket_.open(endpoint.protocol(), ec);

    if (ec)
    {
        std::string message = "ice udp socket open failed: ";

        message.append(ec.message());

        return std::unexpected(std::move(message));
    }

    boost::asio::socket_base::reuse_address reuse_address(true);

    ec = socket_.set_option(reuse_address, ec);

    if (ec)
    {
        WEBRTC_LOG_WARN("ice udp socket set reuse_address failed: {}", ec.message());
    }

    ec = socket_.bind(endpoint, ec);

    if (ec)
    {
        std::string message = "ice udp socket bind failed: ";

        message.append(ec.message());

        return std::unexpected(std::move(message));
    }

    const auto local_endpoint = socket_.local_endpoint(ec);

    if (!ec)
    {
        bind_port_ = local_endpoint.port();
    }

    started_ = true;

    WEBRTC_LOG_INFO("ice udp server listen {}:{}", bind_host_, bind_port_);

    do_receive();

    schedule_ice_consent_check();

    schedule_rtcp_report();

    schedule_rtcp_transport_cc_feedback();

    schedule_endpoint_idle_cleanup();

    schedule_pending_session_cleanup();

    return {};
}

void ice_udp_server::stop()
{
    if (!started_)
    {
        return;
    }

    started_ = false;

    if (registry_ != nullptr && registry_callback_registered_)
    {
        registry_->set_session_removed_callback(stream_session_removed_callback{});
        registry_->set_session_ice_restart_callback(stream_session_ice_restart_callback{});
        registry_->set_subscriber_reconnect_callback(stream_subscriber_reconnect_callback{});
        registry_->set_publisher_republish_callback(stream_publisher_republish_callback{});

        registry_callback_registered_ = false;
    }
    lifecycle_convergence_check_generation_.fetch_add(1, std::memory_order_relaxed);

    dtls_timeout_timer_.cancel();

    ice_consent_timer_.cancel();

    rtcp_report_timer_.cancel();

    rtcp_transport_cc_feedback_timer_.cancel();

    endpoint_idle_cleanup_timer_.cancel();

    pending_session_cleanup_timer_.cancel();

    subscriber_downlink_pacing_timer_.cancel();

    {
        std::lock_guard lock(endpoint_mutex_);

        publisher_absent_since_milliseconds_by_stream_id_.clear();
    }

    boost::system::error_code socket_ec;

    socket_ec = socket_.close(socket_ec);

    if (socket_ec)
    {
        WEBRTC_LOG_WARN("ice udp server close failed: {}", socket_ec.message());
    }

    {
        std::lock_guard lock(endpoint_mutex_);

        endpoints_by_address_.clear();

        endpoint_address_by_session_id_.clear();

        session_id_by_endpoint_address_.clear();

        candidate_pairs_by_key_.clear();

        payload_type_mappings_by_key_.clear();

        keyframe_request_last_time_milliseconds_by_key_.clear();

        fir_sequence_number_by_key_.clear();

        publisher_video_ssrc_by_stream_.clear();

        pending_republish_keyframe_state_by_stream_.clear();

        selected_rid_layer_state_by_key_.clear();
        subscriber_downlink_republish_grace_until_by_key_.clear();

        runtime_selected_rid_targets_by_key_.clear();

        pending_selected_rid_keyframe_request_keys_.clear();

        pending_selected_rid_keyframe_request_state_by_key_.clear();

        extmap_rewrite_state_by_key_.clear();
        outbound_rtp_sequence_by_key_.clear();
        outbound_rtp_packets_by_key_.clear();
        outbound_rtp_packet_insertion_order_.clear();
        outbound_transport_cc_sequence_by_key_.clear();
        outbound_transport_cc_packets_by_key_.clear();
        outbound_transport_cc_packet_insertion_order_.clear();
        outbound_transport_cc_feedback_windows_by_key_.clear();

        subscriber_downlink_pacing_by_key_.clear();
        subscriber_downlink_bandwidth_by_key_.clear();
        subscriber_downlink_pacing_round_robin_after_key.clear();
        subscriber_downlink_pacing_timer_scheduled_ = false;

        endpoint_last_seen_milliseconds_by_address_.clear();

        retired_endpoints_by_address_.clear();

        retired_ice_credentials_by_local_ufrag_.clear();
    }

    track_resolver_ = std::make_shared<media_track_resolver>();

    ssrc_mapper_ = std::make_shared<media_ssrc_mapper>();

    if (identity_authority_ != nullptr)
    {
        identity_authority_->clear();
    }

    rtcp_report_service_ = make_rtcp_report_service_from_env();

    rtcp_transport_cc_feedback_service_ = std::make_shared<rtcp_transport_cc_feedback_service>();

    last_empty_rtcp_report_log_milliseconds_ = 0;

    reset_rtcp_report_runtime_counters();

    if (rtp_packet_cache_ != nullptr)
    {
        rtp_packet_cache_->clear();
    }
    if (rtx_sequence_allocator_ != nullptr)
    {
        rtx_sequence_allocator_->clear();
    }

    if (rtx_retransmission_index_ != nullptr)
    {
        rtx_retransmission_index_->clear();
    }
    if (nack_retransmit_throttle_ != nullptr)
    {
        nack_retransmit_throttle_->clear();
    }
    if (media_router_ != nullptr)
    {
        media_router_->clear();
    }
}
lifecycle_debug_subscriber_runtime_residual_entry ice_udp_server::make_subscriber_runtime_residual_entry(std::string_view stream_id,
                                                                                                         std::string_view subscriber_session_id) const
{
    lifecycle_debug_subscriber_runtime_residual_entry entry;

    entry.stream_id = std::string(stream_id);
    entry.subscriber_session_id = std::string(subscriber_session_id);

    if (track_resolver_ != nullptr)
    {
        const std::vector<media_track_resolver::media_track_binding> bindings = track_resolver_->binding_snapshot();

        for (const auto& binding : bindings)
        {
            if (binding.session_id == subscriber_session_id)
            {
                entry.track_binding_count += 1;
            }
        }
    }
    if (ssrc_mapper_ != nullptr)
    {
        const std::vector<media_ssrc_mapping> mappings = ssrc_mapper_->find_by_subscriber_session(subscriber_session_id);

        entry.ssrc_mapping_count = to_debug_count(mappings.size());
    }

    if (rtcp_report_service_ != nullptr)
    {
        const std::vector<rtcp_report_source_snapshot> sources = rtcp_report_service_->source_snapshot();

        for (const auto& source : sources)
        {
            if (source.session_id == subscriber_session_id)
            {
                entry.rtcp_report_source_count += 1;
            }
        }
    }

    if (rtcp_transport_cc_feedback_service_ != nullptr)
    {
        const std::vector<rtcp_transport_cc_feedback_source_snapshot> sources = rtcp_transport_cc_feedback_service_->source_snapshot();

        for (const auto& source : sources)
        {
            if (source.session_id == subscriber_session_id)
            {
                entry.twcc_feedback_source_count += 1;
            }
        }
    }
    if (identity_authority_ != nullptr)
    {
        const std::vector<media_identity_track_binding> track_bindings = identity_authority_->track_binding_snapshot();

        for (const auto& binding : track_bindings)
        {
            if (binding.session_id == subscriber_session_id)
            {
                entry.identity_track_binding_count += 1;
            }
        }

        const std::vector<media_identity_rid_layer_binding> rid_layers = identity_authority_->rid_layer_binding_snapshot();

        for (const auto& binding : rid_layers)
        {
            if (binding.session_id == subscriber_session_id)
            {
                entry.identity_rid_layer_binding_count += 1;
            }
        }

        const std::vector<media_identity_forward_binding> forward_bindings = identity_authority_->forward_binding_snapshot();

        for (const auto& binding : forward_bindings)
        {
            if (binding.subscriber_session_id == subscriber_session_id)
            {
                entry.identity_forward_binding_count += 1;
            }
        }
    }

    entry.residual_count = entry.media_router_peer_count + entry.track_binding_count + entry.ssrc_mapping_count + entry.identity_track_binding_count +
                           entry.identity_rid_layer_binding_count + entry.identity_forward_binding_count + entry.rtcp_report_source_count +
                           entry.twcc_feedback_source_count + entry.rtx_retransmission_index_count + entry.nack_retransmit_throttle_count;

    return entry;
}

void ice_udp_server::schedule_subscriber_runtime_residual_check(std::string_view stream_id, std::string_view subscriber_session_id)
{
    if (stream_id.empty() || subscriber_session_id.empty())
    {
        return;
    }

    const lifecycle_debug_subscriber_runtime_residual_entry residual = make_subscriber_runtime_residual_entry(stream_id, subscriber_session_id);

    if (residual.residual_count == 0)
    {
        return;
    }

    pending_subscriber_runtime_residual_check check;

    check.stream_id = std::string(stream_id);
    check.subscriber_session_id = std::string(subscriber_session_id);
    check.scheduled_at_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    for (const auto& pending : pending_subscriber_runtime_residual_checks_)
    {
        if (pending.subscriber_session_id == check.subscriber_session_id)
        {
            return;
        }
    }

    pending_subscriber_runtime_residual_checks_.push_back(std::move(check));
}

void ice_udp_server::forget_session_runtime_state(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    forget_extmap_rewrite_states_for_session(session_id);
    forget_selected_rid_layer_states_for_session(session_id);
    forget_outbound_rtp_sequences_for_session(session_id);
    forget_outbound_transport_cc_sequences_for_session(session_id);
    forget_subscriber_downlink_republish_grace_for_session(session_id);
    forget_outbound_transport_cc_packets_for_session(session_id);
    forget_outbound_transport_cc_feedback_windows_for_session(session_id);
    forget_subscriber_downlink_bandwidth_states_for_session(session_id);
    forget_subscriber_downlink_pacing_states_for_session(session_id);
    if (track_resolver_ != nullptr)
    {
        track_resolver_->forget_session(session_id);
    }

    if (ssrc_mapper_ != nullptr)
    {
        ssrc_mapper_->forget_session(session_id);
    }

    if (identity_authority_ != nullptr)
    {
        identity_authority_->forget_session(session_id);
    }

    if (media_router_ != nullptr)
    {
        media_router_->forget_session(session_id);
    }

    if (rtcp_report_service_ != nullptr)
    {
        rtcp_report_service_->forget_session(session_id);
    }

    if (rtcp_transport_cc_feedback_service_ != nullptr)
    {
        rtcp_transport_cc_feedback_service_->forget_session(session_id);
    }

    if (rtx_sequence_allocator_ != nullptr)
    {
        rtx_sequence_allocator_->forget_session(session_id);
    }

    if (rtx_retransmission_index_ != nullptr)
    {
        rtx_retransmission_index_->forget_session(session_id);
    }

    if (nack_retransmit_throttle_ != nullptr)
    {
        nack_retransmit_throttle_->forget_session(session_id);
    }
}
void ice_udp_server::mark_subscriber_downlink_republish_grace_for_stream(std::string_view stream_id, std::string_view publisher_session_id)
{
    if (stream_id.empty())
    {
        return;
    }

    const uint64_t grace_until_milliseconds = now_milliseconds() + k_subscriber_downlink_republish_grace_milliseconds;

    std::size_t state_count = 0;
    std::size_t pacing_state_count = 0;
    std::lock_guard lock(endpoint_mutex_);

    for (auto& [key, state] : subscriber_downlink_bandwidth_by_key_)
    {
        if (state.stream_id != stream_id)
        {
            continue;
        }

        const std::string grace_key = make_subscriber_downlink_republish_grace_key(state.stream_id, state.subscriber_session_id);

        subscriber_downlink_republish_grace_until_by_key_[grace_key] = grace_until_milliseconds;

        state.updated_at_milliseconds = now_milliseconds();
        state.last_feedback_at_milliseconds = now_milliseconds();
        state.last_transition_at_milliseconds = now_milliseconds();
        state.transition_count += 1;
        state.last_transition_reason = "publisher republish grace";

        state.control_state = subscriber_downlink_control_state::probing;
        state.state_entered_at_milliseconds = now_milliseconds();
        state.hold_down_until_milliseconds = 0;
        state.healthy_window_count = 0;
        state.bad_window_count = 0;
        state.unreliable_window_count = 0;
        state.last_keyframe_request_at_milliseconds = 0;
        state.target_bitrate_bps = clamp_subscriber_downlink_republish_grace_bitrate(
            k_subscriber_downlink_republish_grace_target_bitrate_bps, state.min_bitrate_bps, state.max_bitrate_bps);

        state.feedback_count = 0;
        state.window_observation_count = 0;
        state.window_packet_status_count = 0;
        state.lookup_hit_rate_ppm = 1000000;
        state.loss_rate_ppm = 0;
        state.received_count = 0;
        state.lost_count = 0;
        state.avg_delta_microseconds = 0;
        state.min_delta_microseconds = 0;
        state.max_delta_microseconds = 0;

        state_count += 1;
    }

    erase_orphan_subscriber_keyframe_requests_for_stream_locked(stream_id);
    pacing_state_count = erase_subscriber_downlink_pacing_states_for_stream_locked(stream_id);

    WEBRTC_LOG_INFO(
        "subscriber downlink republish grace marked stream={} publisher_session={} subscribers={} pacing_states_erased={} grace_ms={} "
        "grace_until_ms={}",
        stream_id,
        publisher_session_id,
        state_count,
        pacing_state_count,
        k_subscriber_downlink_republish_grace_milliseconds,
        grace_until_milliseconds);
}
void ice_udp_server::erase_orphan_subscriber_keyframe_requests_for_session_locked(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    for (auto iterator = orphan_subscriber_keyframe_requests_by_key_.begin(); iterator != orphan_subscriber_keyframe_requests_by_key_.end();)
    {
        if (iterator->second.subscriber_session_id == session_id)
        {
            iterator = orphan_subscriber_keyframe_requests_by_key_.erase(iterator);
            continue;
        }

        ++iterator;
    }
}

void ice_udp_server::erase_orphan_subscriber_keyframe_requests_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    for (auto iterator = orphan_subscriber_keyframe_requests_by_key_.begin(); iterator != orphan_subscriber_keyframe_requests_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = orphan_subscriber_keyframe_requests_by_key_.erase(iterator);
            continue;
        }

        ++iterator;
    }
}

void ice_udp_server::mark_subscriber_downlink_ice_restart_grace_for_session(std::string_view stream_id, std::string_view subscriber_session_id)
{
    if (stream_id.empty() || subscriber_session_id.empty())
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();
    const uint64_t grace_until_milliseconds = current_time_milliseconds + k_subscriber_downlink_republish_grace_milliseconds;

    std::size_t state_count = 0;
    std::size_t erased_feedback_windows = 0;
    std::size_t erased_pacing_states = 0;

    std::lock_guard lock(endpoint_mutex_);

    const std::string state_key = make_subscriber_downlink_bandwidth_state_key(stream_id, subscriber_session_id);

    auto state_iterator = subscriber_downlink_bandwidth_by_key_.find(state_key);

    if (state_iterator != subscriber_downlink_bandwidth_by_key_.end())
    {
        auto& state = state_iterator->second;

        const std::string grace_key = make_subscriber_downlink_republish_grace_key(state.stream_id, state.subscriber_session_id);

        subscriber_downlink_republish_grace_until_by_key_[grace_key] = grace_until_milliseconds;

        state.updated_at_milliseconds = current_time_milliseconds;
        state.last_feedback_at_milliseconds = current_time_milliseconds;
        state.last_transition_at_milliseconds = current_time_milliseconds;
        state.transition_count += 1;
        state.last_transition_reason = "subscriber ice restart grace";

        state.control_state = subscriber_downlink_control_state::probing;
        state.target_bitrate_bps = clamp_subscriber_downlink_republish_grace_bitrate(
            k_subscriber_downlink_republish_grace_target_bitrate_bps, state.min_bitrate_bps, state.max_bitrate_bps);

        state.feedback_count = 0;
        state.window_observation_count = 0;
        state.window_packet_status_count = 0;
        state.lookup_hit_rate_ppm = 1000000;
        state.loss_rate_ppm = 0;
        state.received_count = 0;
        state.lost_count = 0;
        state.avg_delta_microseconds = 0;
        state.min_delta_microseconds = 0;
        state.max_delta_microseconds = 0;

        state_count = 1;
    }
    else
    {
        subscriber_downlink_republish_grace_until_by_key_[make_subscriber_downlink_republish_grace_key(stream_id, subscriber_session_id)] =
            grace_until_milliseconds;
    }

    for (auto iterator = outbound_transport_cc_feedback_windows_by_key_.begin(); iterator != outbound_transport_cc_feedback_windows_by_key_.end();)
    {
        if (outbound_transport_cc_feedback_window_key_matches_session(iterator->first, subscriber_session_id))
        {
            iterator = outbound_transport_cc_feedback_windows_by_key_.erase(iterator);

            erased_feedback_windows += 1;

            continue;
        }

        ++iterator;
    }

    erased_pacing_states = erase_subscriber_downlink_pacing_states_for_session_locked(subscriber_session_id);
    erase_orphan_subscriber_keyframe_requests_for_session_locked(subscriber_session_id);

    WEBRTC_LOG_INFO(
        "subscriber downlink ice restart grace marked stream={} subscriber_session={} states={} feedback_windows_erased={} "
        "pacing_states_erased={} grace_ms={} grace_until_ms={}",
        stream_id,
        subscriber_session_id,
        state_count,
        erased_feedback_windows,
        erased_pacing_states,
        k_subscriber_downlink_republish_grace_milliseconds,
        grace_until_milliseconds);
}

void ice_udp_server::forget_subscriber_downlink_republish_grace_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = subscriber_downlink_republish_grace_until_by_key_.begin();
         iterator != subscriber_downlink_republish_grace_until_by_key_.end();)
    {
        if (subscriber_downlink_republish_grace_key_matches_session(iterator->first, session_id))
        {
            iterator = subscriber_downlink_republish_grace_until_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

std::size_t ice_udp_server::erase_subscriber_downlink_republish_grace_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = subscriber_downlink_republish_grace_until_by_key_.begin();
         iterator != subscriber_downlink_republish_grace_until_by_key_.end();)
    {
        if (subscriber_downlink_republish_grace_key_matches_stream(iterator->first, stream_id))
        {
            iterator = subscriber_downlink_republish_grace_until_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}
void ice_udp_server::forget_publisher_runtime_state_preserving_subscribers(std::string_view stream_id,
                                                                           std::string_view publisher_session_id,
                                                                           std::string_view reason)
{
    if (stream_id.empty() || publisher_session_id.empty())
    {
        return;
    }

    /*
     * Clear publisher transport/runtime by session id first.
     * This removes the publisher endpoint, DTLS, SRTP, publisher media_router peer,
     * track binding, publisher-side SSRC mapping, identity authority, RTCP/TWCC and
     * session-scoped RTX/NACK state.
     *
     * Do not call cleanup_stream_runtime_state(stream_id) here because it would
     * remove existing WHEP subscribers from media_router.
     *
     * Do not erase outbound transport-cc sequence state for this stream.
     * WHEP subscriber transports may stay alive across publisher republish or
     * publisher delete/recreate, so subscriber transport-wide sequence numbers
     * must remain monotonic.
     */
    forget_session(publisher_session_id);
    bool cache_erased = false;
    std::size_t cache_packets_before = 0;
    std::size_t cache_packets_after = 0;
    std::size_t cache_packets_erased = 0;
    std::size_t remaining_packets = 0;

    if (rtp_packet_cache_ != nullptr)
    {
        cache_packets_before = rtp_packet_cache_->size();

        rtp_packet_cache_->erase_stream(stream_id);

        cache_packets_after = rtp_packet_cache_->size();
        cache_packets_erased = cache_packets_before >= cache_packets_after ? cache_packets_before - cache_packets_after : 0;
        remaining_packets = cache_packets_after;

        cache_erased = true;
    }

    if (rtx_sequence_allocator_ != nullptr)
    {
        rtx_sequence_allocator_->forget_stream(stream_id);
    }

    if (rtx_retransmission_index_ != nullptr)
    {
        rtx_retransmission_index_->forget_stream(stream_id);
    }

    if (nack_retransmit_throttle_ != nullptr)
    {
        nack_retransmit_throttle_->forget_stream(stream_id);
    }

    std::size_t erased_payload_type_mappings = 0;
    std::size_t erased_keyframe_request_states = 0;
    std::size_t erased_extmap_rewrite_states = 0;
    std::size_t erased_selected_rid_states = 0;
    std::size_t erased_outbound_transport_cc_packets = 0;
    std::size_t erased_outbound_transport_cc_feedback_windows = 0;
    std::size_t erased_fir_sequence_states = 0;
    std::size_t erased_publisher_video_ssrc_states = 0;

    {
        std::lock_guard lock(endpoint_mutex_);

        erased_payload_type_mappings = erase_payload_type_mappings_for_stream_locked(stream_id);

        erased_keyframe_request_states = erase_keyframe_request_states_for_stream_locked(stream_id);

        erased_extmap_rewrite_states = erase_extmap_rewrite_states_for_stream_locked(stream_id);

        erased_selected_rid_states = erase_selected_rid_layer_states_for_stream_locked(stream_id);

        /*
         * Clear old publisher-derived packet identity/window data, but keep
         * outbound_transport_cc_sequence_by_key_ untouched. Existing WHEP
         * subscribers continue on the same transport and must not see TWCC
         * sequence rollback after publisher republish.
         */
        erased_outbound_transport_cc_packets = erase_outbound_transport_cc_packets_for_stream_locked(stream_id);

        erased_outbound_transport_cc_feedback_windows = erase_outbound_transport_cc_feedback_windows_for_stream_locked(stream_id);

        const std::string stream_prefix = std::string(stream_id) + "|";

        for (auto iterator = fir_sequence_number_by_key_.begin(); iterator != fir_sequence_number_by_key_.end();)
        {
            if (iterator->first.starts_with(stream_prefix))
            {
                iterator = fir_sequence_number_by_key_.erase(iterator);

                erased_fir_sequence_states += 1;

                continue;
            }

            ++iterator;
        }

        const std::string publisher_video_ssrc_exact_key = std::string(stream_id);
        const std::string publisher_video_ssrc_prefix = publisher_video_ssrc_exact_key + "|";

        for (auto iterator = publisher_video_ssrc_by_stream_.begin(); iterator != publisher_video_ssrc_by_stream_.end();)
        {
            if (iterator->first == publisher_video_ssrc_exact_key || iterator->first.starts_with(publisher_video_ssrc_prefix))
            {
                iterator = publisher_video_ssrc_by_stream_.erase(iterator);

                erased_publisher_video_ssrc_states += 1;

                continue;
            }

            ++iterator;
        }

        pending_republish_keyframe_state_by_stream_.erase(std::string(stream_id));
    }

    WEBRTC_LOG_INFO(
        "publisher runtime state forgotten preserving subscribers stream={} publisher_session={} reason={} cache_erased={} cache_packets_before={} "
        "cache_packets_erased={} remaining_cache_packets={} payload_type_mappings_erased={} keyframe_states_erased={} "
        "extmap_rewrite_states_erased={} selected_rid_states_erased={} outbound_twcc_packets_erased={} outbound_twcc_windows_erased={} "
        "fir_sequence_states_erased={} publisher_video_ssrc_states_erased={}",
        stream_id,
        publisher_session_id,
        reason,
        cache_erased ? 1 : 0,
        cache_packets_before,
        cache_packets_erased,
        remaining_packets,
        erased_payload_type_mappings,
        erased_keyframe_request_states,
        erased_extmap_rewrite_states,
        erased_selected_rid_states,
        erased_outbound_transport_cc_packets,
        erased_outbound_transport_cc_feedback_windows,
        erased_fir_sequence_states,
        erased_publisher_video_ssrc_states);
}
void ice_udp_server::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::vector<std::string> remote_addresses;
    std::vector<std::pair<std::string, boost::asio::ip::udp::endpoint>> close_notify_targets;
    bool endpoint_removed = false;

    {
        std::lock_guard lock(endpoint_mutex_);

        close_notify_targets = collect_session_endpoint_snapshots_locked(session_id);

        const std::vector<std::string> erased_remote_addresses = erase_endpoint_indexes_for_session_locked(session_id);
        const uint64_t current_time_milliseconds = now_milliseconds();

        for (const auto& erased_remote_address : erased_remote_addresses)
        {
            retire_endpoint_locked(erased_remote_address, session_id, current_time_milliseconds, "session cleanup");
        }

        if (erased_remote_addresses.empty())
        {
            WEBRTC_LOG_DEBUG("ice udp session endpoint not found session={}", session_id);
        }
        else
        {
            remote_addresses = erased_remote_addresses;
            endpoint_removed = true;
        }
        erase_candidate_pairs_for_session_locked(session_id);

        const std::size_t orphan_endpoint_indexes_erased = erase_orphan_endpoint_indexes_locked();

        if (orphan_endpoint_indexes_erased != 0)
        {
            WEBRTC_LOG_INFO(
                "ice udp orphan endpoint indexes erased during session cleanup session={} count={}", session_id, orphan_endpoint_indexes_erased);
        }

        erase_payload_type_mappings_for_session_locked(session_id);

        const std::size_t erased_keyframe_request_state_count = erase_keyframe_request_states_for_session_locked(session_id);

        WEBRTC_LOG_DEBUG("ice udp session keyframe request states erased session={} count={}", session_id, erased_keyframe_request_state_count);
    }

    forget_session_runtime_state(session_id);

    if (endpoint_removed)
    {
        for (const auto& [remote_address, remote_endpoint] : close_notify_targets)
        {
            send_dtls_close_notify_to_endpoint(remote_address, remote_endpoint);
        }

        for (const auto& remote_address : remote_addresses)
        {
            forget_peer_transport_state(remote_address);
        }
    }
    WEBRTC_LOG_INFO(
        "ice udp session cleanup completed session={} endpoint_removed={} remote_count={}", session_id, endpoint_removed, remote_addresses.size());
}
void ice_udp_server::touch_endpoint_activity(const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    endpoint_last_seen_milliseconds_by_address_[remote_address] = current_time_milliseconds;
}

void ice_udp_server::schedule_endpoint_idle_cleanup()
{
    if (!started_ || endpoint_idle_timeout_milliseconds_ == 0)
    {
        return;
    }

    endpoint_idle_cleanup_timer_.cancel();

    endpoint_idle_cleanup_timer_.expires_after(k_endpoint_idle_cleanup_interval);

    auto self = shared_from_this();

    endpoint_idle_cleanup_timer_.async_wait([this, self](boost::system::error_code ec) { on_endpoint_idle_cleanup(ec); });
}

void ice_udp_server::on_endpoint_idle_cleanup(boost::system::error_code ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("endpoint idle cleanup timer failed error={}", ec.message());

        schedule_endpoint_idle_cleanup();

        return;
    }

    if (!started_)
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::vector<std::string> expired_session_ids = collect_idle_session_ids(current_time_milliseconds);

    for (const auto& session_id : expired_session_ids)
    {
        WEBRTC_LOG_WARN("endpoint idle session expired session={} timeout_ms={}", session_id, endpoint_idle_timeout_milliseconds_);

        remove_expired_session(session_id, "endpoint idle");
    }

    schedule_endpoint_idle_cleanup();
}

std::vector<std::string> ice_udp_server::collect_idle_session_ids(uint64_t current_time_milliseconds)
{
    std::vector<std::string> expired_session_ids;

    if (endpoint_idle_timeout_milliseconds_ == 0)
    {
        return expired_session_ids;
    }

    std::lock_guard lock(endpoint_mutex_);
    expire_retired_endpoints_locked(current_time_milliseconds);
    const std::size_t expired_ice_credential_count = expire_retired_ice_credentials_locked(current_time_milliseconds);

    if (expired_ice_credential_count != 0)
    {
        WEBRTC_LOG_INFO("ice retired credentials expired during idle cleanup count={}", expired_ice_credential_count);
    }
    for (auto iterator = endpoint_last_seen_milliseconds_by_address_.begin(); iterator != endpoint_last_seen_milliseconds_by_address_.end();)
    {
        const std::string& remote_address = iterator->first;

        uint64_t& last_seen_milliseconds = iterator->second;

        if (last_seen_milliseconds == 0)
        {
            last_seen_milliseconds = current_time_milliseconds;

            ++iterator;

            continue;
        }

        if (current_time_milliseconds < last_seen_milliseconds)
        {
            last_seen_milliseconds = current_time_milliseconds;

            ++iterator;

            continue;
        }

        const uint64_t idle_milliseconds = current_time_milliseconds - last_seen_milliseconds;

        if (idle_milliseconds < endpoint_idle_timeout_milliseconds_)
        {
            ++iterator;

            continue;
        }

        const auto session_iterator = session_id_by_endpoint_address_.find(remote_address);
        if (session_iterator == session_id_by_endpoint_address_.end())
        {
            const std::string orphan_remote_address = remote_address;

            iterator = endpoint_last_seen_milliseconds_by_address_.erase(iterator);

            endpoints_by_address_.erase(orphan_remote_address);

            erase_candidate_pairs_for_endpoint_locked(orphan_remote_address);

            if (rtcp_transport_cc_feedback_service_ != nullptr)
            {
                rtcp_transport_cc_feedback_service_->forget_peer(orphan_remote_address);
            }

            WEBRTC_LOG_DEBUG("ice endpoint idle removed orphan last seen remote={}", orphan_remote_address);

            continue;
        }
        expired_session_ids.push_back(session_iterator->second);

        ++iterator;
    }

    return expired_session_ids;
}

void ice_udp_server::schedule_pending_session_cleanup()
{
    if (!started_ || pending_session_timeout_milliseconds_ == 0)
    {
        return;
    }

    pending_session_cleanup_timer_.cancel();

    pending_session_cleanup_timer_.expires_after(k_pending_session_cleanup_interval);

    auto self = shared_from_this();

    pending_session_cleanup_timer_.async_wait([this, self](boost::system::error_code ec) { on_pending_session_cleanup(ec); });
}

void ice_udp_server::on_pending_session_cleanup(boost::system::error_code ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("pending session cleanup timer failed error={}", ec.message());

        schedule_pending_session_cleanup();

        return;
    }

    if (!started_)
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::vector<std::string> expired_session_ids = collect_pending_session_ids(current_time_milliseconds);

    for (const auto& session_id : expired_session_ids)
    {
        WEBRTC_LOG_WARN("pending session expired session={} timeout_ms={}", session_id, pending_session_timeout_milliseconds_);

        remove_expired_session(session_id, "pending session");
    }

    std::vector<std::string> orphan_subscriber_session_ids = collect_orphan_subscriber_session_ids(current_time_milliseconds);

    for (const auto& session_id : orphan_subscriber_session_ids)
    {
        WEBRTC_LOG_WARN("orphan subscriber expired session={} timeout_ms={}", session_id, orphan_subscriber_timeout_milliseconds_);

        remove_expired_session(session_id, "orphan subscriber");
    }

    schedule_pending_session_cleanup();
}

std::expected<void, std::string> validate_simulcast_rid_target_request(const simulcast_rid_target_request& request)
{
    if (request.stream_id.empty())
    {
        return std::unexpected(std::string("stream id is empty"));
    }

    if (request.publisher_session_id.empty())
    {
        return std::unexpected(std::string("publisher session id is empty"));
    }

    if (request.subscriber_session_id.empty())
    {
        return std::unexpected(std::string("subscriber session id is empty"));
    }

    if (request.mid.empty())
    {
        return std::unexpected(std::string("mid is empty"));
    }

    if (request.kind.empty())
    {
        return std::unexpected(std::string("kind is empty"));
    }

    if (!is_video_media_kind(request.kind))
    {
        return std::unexpected(std::string("only video simulcast rid target is supported"));
    }

    if (!request.clear && request.target_rid.empty())
    {
        return std::unexpected(std::string("target rid is empty"));
    }

    return {};
}

std::vector<std::string> ice_udp_server::collect_pending_session_ids(uint64_t current_time_milliseconds) const
{
    std::vector<std::string> expired_session_ids;
    std::vector<std::string> expired_publisher_stream_ids;

    if (pending_session_timeout_milliseconds_ == 0 || registry_ == nullptr)
    {
        return expired_session_ids;
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    std::vector<pending_session_cleanup_candidate> pending_publishers;
    std::vector<pending_session_cleanup_candidate> pending_subscribers;

    for (const auto& snapshot : snapshots)
    {
        if (!is_pending_connection_state(snapshot.state))
        {
            continue;
        }

        if (snapshot.kind == stream_session_kind::publisher)
        {
            append_pending_session_cleanup_candidate(pending_publishers, snapshot, current_time_milliseconds);

            continue;
        }

        if (snapshot.kind == stream_session_kind::subscriber)
        {
            append_pending_session_cleanup_candidate(pending_subscribers, snapshot, current_time_milliseconds);
        }
    }

    for (const auto& candidate : pending_publishers)
    {
        if (candidate.age_milliseconds < pending_session_timeout_milliseconds_)
        {
            continue;
        }

        if (!contains_string(expired_session_ids, candidate.session_id))
        {
            expired_session_ids.push_back(candidate.session_id);
        }

        if (!contains_string(expired_publisher_stream_ids, candidate.stream_id))
        {
            expired_publisher_stream_ids.push_back(candidate.stream_id);
        }
    }

    for (const auto& candidate : pending_subscribers)
    {
        if (contains_string(expired_publisher_stream_ids, candidate.stream_id))
        {
            continue;
        }

        if (candidate.age_milliseconds < pending_session_timeout_milliseconds_)
        {
            continue;
        }

        if (!contains_string(expired_session_ids, candidate.session_id))
        {
            expired_session_ids.push_back(candidate.session_id);
        }
    }

    const std::size_t pending_session_count = pending_publishers.size() + pending_subscribers.size();

    if (pending_session_count <= k_max_pending_sessions)
    {
        return expired_session_ids;
    }

    std::vector<pending_session_cleanup_candidate> pending_candidates;

    pending_candidates.reserve(pending_session_count);

    pending_candidates.insert(pending_candidates.end(), pending_publishers.begin(), pending_publishers.end());
    pending_candidates.insert(pending_candidates.end(), pending_subscribers.begin(), pending_subscribers.end());

    std::sort(pending_candidates.begin(), pending_candidates.end(), pending_session_cleanup_candidate_is_older);

    std::size_t overflow_count = pending_session_count - k_max_pending_sessions;

    for (const auto& candidate : pending_candidates)
    {
        if (overflow_count == 0)
        {
            break;
        }

        if (contains_string(expired_session_ids, candidate.session_id))
        {
            continue;
        }

        if (candidate.kind == stream_session_kind::subscriber && contains_string(expired_publisher_stream_ids, candidate.stream_id))
        {
            continue;
        }

        WEBRTC_LOG_WARN("pending session pruned by limit session={} stream={} kind={} age_ms={} count={} limit={}",
                        candidate.session_id,
                        candidate.stream_id,
                        stream_session_kind_to_string(candidate.kind),
                        candidate.age_milliseconds,
                        pending_session_count,
                        k_max_pending_sessions);

        expired_session_ids.push_back(candidate.session_id);

        if (candidate.kind == stream_session_kind::publisher && !contains_string(expired_publisher_stream_ids, candidate.stream_id))
        {
            expired_publisher_stream_ids.push_back(candidate.stream_id);
        }

        overflow_count -= 1;
    }

    return expired_session_ids;
}

void ice_udp_server::mark_publisher_absent_for_stream(std::string_view stream_id, std::string_view reason)
{
    if (stream_id.empty() || orphan_subscriber_timeout_milliseconds_ == 0)
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    auto [iterator, inserted] = publisher_absent_since_milliseconds_by_stream_id_.try_emplace(std::string(stream_id), current_time_milliseconds);

    WEBRTC_LOG_INFO("publisher absent stream marked stream={} reason={} inserted={} absent_since_ms={} timeout_ms={}",
                    stream_id,
                    reason,
                    inserted ? 1 : 0,
                    iterator->second,
                    orphan_subscriber_timeout_milliseconds_);
}

void ice_udp_server::forget_publisher_absent_for_stream(std::string_view stream_id, std::string_view reason)
{
    if (stream_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    const std::size_t erased = publisher_absent_since_milliseconds_by_stream_id_.erase(std::string(stream_id));

    if (erased != 0)
    {
        WEBRTC_LOG_INFO("publisher absent stream cleared stream={} reason={}", stream_id, reason);
    }
}

std::vector<std::string> ice_udp_server::collect_orphan_subscriber_session_ids(uint64_t current_time_milliseconds)
{
    std::vector<std::string> expired_session_ids;

    if (orphan_subscriber_timeout_milliseconds_ == 0 || registry_ == nullptr)
    {
        return expired_session_ids;
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    std::unordered_map<std::string, std::vector<std::string>> subscriber_session_ids_by_stream;
    std::unordered_set<std::string> streams_with_publisher;

    for (const auto& snapshot : snapshots)
    {
        if (snapshot.stream_id.empty())
        {
            continue;
        }

        if (snapshot.kind == stream_session_kind::publisher)
        {
            streams_with_publisher.insert(snapshot.stream_id);

            continue;
        }

        if (snapshot.kind == stream_session_kind::subscriber)
        {
            subscriber_session_ids_by_stream[snapshot.stream_id].push_back(snapshot.session_id);
        }
    }

    {
        std::vector<std::string> stale_absent_stream_ids;

        {
            std::lock_guard lock(endpoint_mutex_);

            for (const auto& [stream_id, absent_since_milliseconds] : publisher_absent_since_milliseconds_by_stream_id_)
            {
                (void)absent_since_milliseconds;

                if (contains_unordered_string(streams_with_publisher, stream_id))
                {
                    stale_absent_stream_ids.push_back(stream_id);

                    continue;
                }

                if (!subscriber_session_ids_by_stream.contains(stream_id))
                {
                    stale_absent_stream_ids.push_back(stream_id);
                }
            }

            for (const auto& stream_id : stale_absent_stream_ids)
            {
                publisher_absent_since_milliseconds_by_stream_id_.erase(stream_id);
            }
        }

        for (const auto& stream_id : stale_absent_stream_ids)
        {
            WEBRTC_LOG_INFO("publisher absent stream cleared stream={} reason=orphan cleanup stale stream", stream_id);
        }
    }

    std::vector<pending_session_cleanup_candidate> orphan_candidates;

    for (const auto& [stream_id, subscriber_session_ids] : subscriber_session_ids_by_stream)
    {
        if (subscriber_session_ids.empty())
        {
            continue;
        }

        if (streams_with_publisher.contains(stream_id) || registry_->find_publisher_by_stream_id(stream_id) != nullptr)
        {
            forget_publisher_absent_for_stream(stream_id, "publisher present during orphan cleanup");

            continue;
        }

        uint64_t absent_since_milliseconds = current_time_milliseconds;
        bool inserted = false;

        {
            std::lock_guard lock(endpoint_mutex_);

            auto [iterator, emplaced] = publisher_absent_since_milliseconds_by_stream_id_.try_emplace(stream_id, current_time_milliseconds);

            absent_since_milliseconds = iterator->second;
            inserted = emplaced;
        }

        if (inserted)
        {
            WEBRTC_LOG_INFO("publisher absent stream observed by orphan cleanup stream={} subscriber_count={} timeout_ms={}",
                            stream_id,
                            subscriber_session_ids.size(),
                            orphan_subscriber_timeout_milliseconds_);
        }

        const uint64_t absent_age_milliseconds =
            current_time_milliseconds >= absent_since_milliseconds ? current_time_milliseconds - absent_since_milliseconds : 0;

        for (const auto& subscriber_session_id : subscriber_session_ids)
        {
            pending_session_cleanup_candidate candidate;

            candidate.session_id = subscriber_session_id;
            candidate.stream_id = stream_id;
            candidate.kind = stream_session_kind::subscriber;
            candidate.reference_time_milliseconds = absent_since_milliseconds;
            candidate.age_milliseconds = absent_age_milliseconds;

            orphan_candidates.push_back(std::move(candidate));
        }

        if (absent_age_milliseconds < orphan_subscriber_timeout_milliseconds_)
        {
            WEBRTC_LOG_DEBUG("orphan subscriber grace active stream={} subscriber_count={} absent_age_ms={} timeout_ms={}",
                             stream_id,
                             subscriber_session_ids.size(),
                             absent_age_milliseconds,
                             orphan_subscriber_timeout_milliseconds_);

            continue;
        }

        WEBRTC_LOG_WARN("orphan subscriber grace expired stream={} subscriber_count={} absent_age_ms={} timeout_ms={}",
                        stream_id,
                        subscriber_session_ids.size(),
                        absent_age_milliseconds,
                        orphan_subscriber_timeout_milliseconds_);

        for (const auto& subscriber_session_id : subscriber_session_ids)
        {
            if (!contains_string(expired_session_ids, subscriber_session_id))
            {
                expired_session_ids.push_back(subscriber_session_id);
            }
        }

        forget_publisher_absent_for_stream(stream_id, "orphan subscriber expired");
    }

    if (orphan_candidates.size() > k_max_orphan_subscriber_sessions)
    {
        std::sort(orphan_candidates.begin(), orphan_candidates.end(), pending_session_cleanup_candidate_is_older);

        std::size_t overflow_count = orphan_candidates.size() - k_max_orphan_subscriber_sessions;

        for (const auto& candidate : orphan_candidates)
        {
            if (overflow_count == 0)
            {
                break;
            }

            if (contains_string(expired_session_ids, candidate.session_id))
            {
                continue;
            }

            WEBRTC_LOG_WARN("orphan subscriber pruned by limit session={} stream={} absent_age_ms={} count={} limit={}",
                            candidate.session_id,
                            candidate.stream_id,
                            candidate.age_milliseconds,
                            orphan_candidates.size(),
                            k_max_orphan_subscriber_sessions);

            expired_session_ids.push_back(candidate.session_id);

            overflow_count -= 1;
        }
    }

    return expired_session_ids;
}

void ice_udp_server::remove_expired_session(std::string_view session_id, std::string_view reason)
{
    if (session_id.empty())
    {
        return;
    }

    if (registry_ == nullptr)
    {
        WEBRTC_LOG_WARN("{} session removal fallback registry missing session={}", reason, session_id);

        forget_session(session_id);

        schedule_lifecycle_snapshot_log(std::string(reason) + " registry missing", "", std::string(session_id));

        return;
    }

    auto publisher = registry_->find_publisher_by_session_id(session_id);

    if (publisher != nullptr)
    {
        const std::string stream_id = publisher->stream_id();

        auto result = registry_->remove_publisher_session(session_id);

        if (!result)
        {
            WEBRTC_LOG_WARN("{} publisher removal failed session={} error={}", reason, session_id, stream_registry_error_to_string(result.error()));

            forget_session(session_id);

            cleanup_stream_runtime_state(stream_id);

            schedule_lifecycle_snapshot_log(std::string(reason) + " publisher removal failed", stream_id, std::string(session_id));

            return;
        }

        if (!registry_callback_registered_)
        {
            forget_session(session_id);

            cleanup_stream_runtime_state(stream_id);

            erase_rtp_cache(stream_id);
        }

        WEBRTC_LOG_WARN("{} publisher session removed stream={} session={}", reason, stream_id, session_id);

        schedule_lifecycle_snapshot_log(std::string(reason) + " publisher session removed", stream_id, std::string(session_id));

        return;
    }

    auto subscriber = registry_->find_subscriber_by_session_id(session_id);

    if (subscriber != nullptr)
    {
        const std::string stream_id = subscriber->stream_id();

        auto result = registry_->remove_subscriber_session(session_id);

        if (!result)
        {
            WEBRTC_LOG_WARN("{} subscriber removal failed session={} error={}", reason, session_id, stream_registry_error_to_string(result.error()));

            forget_session(session_id);

            schedule_lifecycle_snapshot_log(std::string(reason) + " subscriber removal failed", stream_id, std::string(session_id));

            return;
        }

        if (!registry_callback_registered_)
        {
            forget_session(session_id);
        }

        WEBRTC_LOG_WARN("{} subscriber session removed stream={} session={}", reason, stream_id, session_id);

        schedule_lifecycle_snapshot_log(std::string(reason) + " subscriber session removed", stream_id, std::string(session_id));

        return;
    }

    WEBRTC_LOG_WARN("{} session not found in registry session={}", reason, session_id);

    forget_session(session_id);

    schedule_lifecycle_snapshot_log(std::string(reason) + " session missing", "", std::string(session_id));
}

uint16_t ice_udp_server::local_port() const { return bind_port_; }

simulcast_rid_target_expected ice_udp_server::set_runtime_selected_rid_target(const simulcast_rid_target_request& request)
{
    auto validation_result = validate_simulcast_rid_target_request(request);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    const std::string key =
        make_selected_rid_layer_key(request.stream_id, request.publisher_session_id, request.subscriber_session_id, request.mid, request.kind);

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    runtime_selected_rid_target_state& target_state = runtime_selected_rid_targets_by_key_[key];

    const bool changed = target_state.target_rid != request.target_rid || target_state.policy != "manual_api";

    target_state.stream_id = request.stream_id;
    target_state.publisher_session_id = request.publisher_session_id;
    target_state.subscriber_session_id = request.subscriber_session_id;
    target_state.mid = request.mid;
    target_state.kind = request.kind;
    target_state.target_rid = request.target_rid;
    target_state.policy = "manual_api";
    target_state.reason = request.reason.empty() ? "manual simulcast rid target" : request.reason;
    target_state.updated_at_milliseconds = current_time_milliseconds;

    auto selected_state_iterator = selected_rid_layer_state_by_key_.find(key);

    const bool selected_state_found = selected_state_iterator != selected_rid_layer_state_by_key_.end();

    if (selected_state_found)
    {
        selected_rid_layer_runtime_state& selected_state = selected_state_iterator->second;

        remember_runtime_selected_rid_target_locked(
            key, selected_state, request.target_rid, "manual_api", target_state.reason, current_time_milliseconds);

        if (selected_state.rid != request.target_rid)
        {
            selected_state.last_switch_reason = "manual target pending:" + request.target_rid;
        }
    }
    WEBRTC_LOG_INFO(
        "simulcast manual rid target set stream={} publisher_session={} subscriber_session={} mid={} kind={} target_rid={} changed={} "
        "selected_state_found={} reason={}",
        request.stream_id,
        request.publisher_session_id,
        request.subscriber_session_id,
        request.mid,
        request.kind,
        request.target_rid,
        changed ? 1 : 0,
        selected_state_found ? 1 : 0,
        target_state.reason);

    simulcast_rid_target_result result;

    result.stream_id = target_state.stream_id;
    result.publisher_session_id = target_state.publisher_session_id;
    result.subscriber_session_id = target_state.subscriber_session_id;
    result.mid = target_state.mid;
    result.kind = target_state.kind;
    result.target_rid = target_state.target_rid;
    result.policy = target_state.policy;
    result.reason = target_state.reason;
    result.changed = changed;
    result.cleared = false;
    result.selected_state_found = selected_state_found;
    result.updated_at_milliseconds = target_state.updated_at_milliseconds;
    result.applied_count = target_state.applied_count;

    return result;
}

simulcast_rid_target_expected ice_udp_server::clear_runtime_selected_rid_target(const simulcast_rid_target_request& request)
{
    simulcast_rid_target_request clear_request = request;

    clear_request.clear = true;

    auto validation_result = validate_simulcast_rid_target_request(clear_request);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    const std::string key = make_selected_rid_layer_key(
        clear_request.stream_id, clear_request.publisher_session_id, clear_request.subscriber_session_id, clear_request.mid, clear_request.kind);

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    const auto target_iterator = runtime_selected_rid_targets_by_key_.find(key);

    simulcast_rid_target_result result;

    result.stream_id = clear_request.stream_id;
    result.publisher_session_id = clear_request.publisher_session_id;
    result.subscriber_session_id = clear_request.subscriber_session_id;
    result.mid = clear_request.mid;
    result.kind = clear_request.kind;
    result.policy = "manual_api";
    result.reason = clear_request.reason.empty() ? "manual simulcast rid target cleared" : clear_request.reason;
    result.cleared = target_iterator != runtime_selected_rid_targets_by_key_.end();
    result.changed = result.cleared;
    result.updated_at_milliseconds = current_time_milliseconds;

    if (target_iterator != runtime_selected_rid_targets_by_key_.end())
    {
        result.target_rid = target_iterator->second.target_rid;
        result.applied_count = target_iterator->second.applied_count;

        runtime_selected_rid_targets_by_key_.erase(target_iterator);
    }

    auto selected_state_iterator = selected_rid_layer_state_by_key_.find(key);

    result.selected_state_found = selected_state_iterator != selected_rid_layer_state_by_key_.end();

    if (selected_state_iterator != selected_rid_layer_state_by_key_.end())
    {
        selected_rid_layer_runtime_state& selected_state = selected_state_iterator->second;

        selected_state.target_rid.clear();
        selected_state.target_policy.clear();
        selected_state.manual_target_active = false;
        selected_state.last_adaptive_decision = "manual_clear";
        selected_state.last_adaptive_decision_reason = result.reason;
        selected_state.last_adaptive_decision_milliseconds = current_time_milliseconds;
    }

    WEBRTC_LOG_INFO(
        "simulcast manual rid target cleared stream={} publisher_session={} subscriber_session={} mid={} kind={} cleared={} selected_state_found={} "
        "reason={}",
        clear_request.stream_id,
        clear_request.publisher_session_id,
        clear_request.subscriber_session_id,
        clear_request.mid,
        clear_request.kind,
        result.cleared ? 1 : 0,
        result.selected_state_found ? 1 : 0,
        result.reason);

    return result;
}
lifecycle_debug_snapshot ice_udp_server::debug_state_snapshot() const
{
    lifecycle_debug_snapshot snapshot;

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::vector<std::string> stream_ids;

    if (registry_ != nullptr)
    {
        const std::vector<stream_session_lifecycle_snapshot> sessions = registry_->session_lifecycle_snapshots();

        for (const auto& session : sessions)
        {
            snapshot.registry_session_count += 1;

            if (!contains_string(stream_ids, session.stream_id))
            {
                stream_ids.push_back(session.stream_id);
            }

            if (session.kind == stream_session_kind::publisher)
            {
                snapshot.registry_publisher_count += 1;
            }
            else if (session.kind == stream_session_kind::subscriber)
            {
                snapshot.registry_subscriber_count += 1;
            }

            if (is_pending_connection_state(session.state))
            {
                snapshot.registry_pending_session_count += 1;
            }

            lifecycle_debug_session_entry entry;

            entry.kind = std::string(stream_session_kind_to_string(session.kind));

            entry.stream_id = session.stream_id;
            entry.session_id = session.session_id;

            entry.state = std::string(session_state_to_string(session.state));

            entry.created_at_milliseconds = session.created_at_milliseconds;
            entry.updated_at_milliseconds = session.updated_at_milliseconds;

            snapshot.sessions.push_back(std::move(entry));
        }

        const std::vector<stream_removed_session_tombstone> tombstones = registry_->removed_session_tombstone_snapshot();

        snapshot.registry_removed_session_tombstone_count = to_debug_count(tombstones.size());

        snapshot.removed_session_tombstones.reserve(tombstones.size());

        for (const auto& tombstone : tombstones)
        {
            if (tombstone.kind == stream_session_kind::publisher)
            {
                snapshot.registry_removed_publisher_tombstone_count += 1;
            }
            else if (tombstone.kind == stream_session_kind::subscriber)
            {
                snapshot.registry_removed_subscriber_tombstone_count += 1;
            }

            lifecycle_debug_removed_session_tombstone_entry entry;

            entry.kind = std::string(stream_session_kind_to_string(tombstone.kind));
            entry.stream_id = tombstone.stream_id;
            entry.session_id = tombstone.session_id;
            entry.removed_at_milliseconds = tombstone.removed_at_milliseconds;

            snapshot.removed_session_tombstones.push_back(std::move(entry));
        }

        snapshot.registry_stream_count = to_debug_count(stream_ids.size());
    }
    {
        std::lock_guard lock(endpoint_mutex_);

        snapshot.endpoint_count = to_debug_count(endpoints_by_address_.size());

        snapshot.endpoint_session_index_count = to_debug_count(endpoint_address_by_session_id_.size());

        snapshot.endpoint_reverse_index_count = to_debug_count(session_id_by_endpoint_address_.size());

        snapshot.endpoint_last_seen_count = to_debug_count(endpoint_last_seen_milliseconds_by_address_.size());
        snapshot.publisher_absent_stream_count = to_debug_count(publisher_absent_since_milliseconds_by_stream_id_.size());
        snapshot.candidate_pair_count = to_debug_count(candidate_pairs_by_key_.size());

        for (const auto& [key, pair] : candidate_pairs_by_key_)
        {
            (void)key;
            lifecycle_debug_candidate_pair_entry entry;
            entry.session_id = pair.session_id;
            entry.stream_id = pair.stream_id;
            entry.remote_address = pair.remote_address;
            entry.selected = pair.selected;
            entry.nominated = pair.nominated;
            entry.consent_request_in_flight = pair.consent_request_in_flight;
            entry.last_binding_at_milliseconds = pair.last_binding_at_milliseconds;
            entry.last_consent_request_at_milliseconds = pair.last_consent_request_at_milliseconds;
            entry.last_consent_response_at_milliseconds = pair.last_consent_response_at_milliseconds;
            entry.consent_request_failures = static_cast<uint64_t>(pair.consent_request_failures);

            if (pair.selected)
            {
                snapshot.selected_candidate_pair_count += 1;
            }

            if (pair.consent_request_in_flight)
            {
                snapshot.candidate_pair_consent_in_flight_count += 1;
            }

            snapshot.candidate_pair_consent_failure_count += static_cast<uint64_t>(pair.consent_request_failures);

            const uint64_t consent_freshness_at_milliseconds =
                pair.last_consent_response_at_milliseconds != 0 ? pair.last_consent_response_at_milliseconds : pair.last_binding_at_milliseconds;

            uint64_t consent_age_milliseconds = 0;
            bool consent_stale = false;

            if (pair.selected && consent_freshness_at_milliseconds != 0)
            {
                consent_age_milliseconds =
                    current_time_milliseconds > consent_freshness_at_milliseconds ? current_time_milliseconds - consent_freshness_at_milliseconds : 0;

                if (consent_age_milliseconds >= k_ice_consent_timeout_milliseconds)
                {
                    consent_stale = true;

                    snapshot.candidate_pair_consent_stale_count += 1;
                }
            }

            if (pair.selected)
            {
                lifecycle_debug_session_entry* session_entry = find_lifecycle_debug_session_entry(snapshot.sessions, pair.session_id);

                if (session_entry != nullptr)
                {
                    session_entry->has_selected_candidate_pair = true;
                    session_entry->selected_candidate_pair_nominated = pair.nominated;
                    session_entry->selected_candidate_pair_consent_in_flight = pair.consent_request_in_flight;
                    session_entry->selected_candidate_pair_consent_stale = consent_stale;
                    session_entry->selected_candidate_pair_last_binding_at_milliseconds = pair.last_binding_at_milliseconds;
                    session_entry->selected_candidate_pair_last_consent_response_at_milliseconds = pair.last_consent_response_at_milliseconds;
                    session_entry->selected_candidate_pair_consent_age_milliseconds = consent_age_milliseconds;
                    session_entry->selected_candidate_pair_consent_failures = static_cast<uint64_t>(pair.consent_request_failures);
                }
            }

            snapshot.candidate_pairs.push_back(std::move(entry));
        }
        snapshot.retired_endpoint_count = to_debug_count(retired_endpoints_by_address_.size());

        for (const auto& [remote_address, state] : retired_endpoints_by_address_)
        {
            lifecycle_debug_retired_endpoint_entry entry;

            entry.remote_address = remote_address;

            entry.session_id = state.session_id;

            entry.reason = state.reason;

            entry.expires_at_milliseconds = state.expires_at_milliseconds;

            entry.remaining_ttl_milliseconds =
                state.expires_at_milliseconds > current_time_milliseconds ? state.expires_at_milliseconds - current_time_milliseconds : 0;

            entry.suppressed_packets = state.suppressed_packets;

            snapshot.retired_endpoint_suppressed_packet_count += state.suppressed_packets;

            snapshot.retired_endpoints.push_back(std::move(entry));
        }

        snapshot.retired_ice_credential_count = to_debug_count(retired_ice_credentials_by_local_ufrag_.size());

        for (const auto& [local_ufrag, state] : retired_ice_credentials_by_local_ufrag_)
        {
            (void)local_ufrag;
            lifecycle_debug_retired_ice_credential_entry entry;
            entry.stream_id = state.stream_id;
            entry.session_id = state.session_id;
            entry.local_ice_ufrag = state.local_ice_ufrag;
            entry.remote_ice_ufrag = state.remote_ice_ufrag;
            entry.reason = state.reason;
            entry.expires_at_milliseconds = state.expires_at_milliseconds;
            entry.remaining_ttl_milliseconds =
                state.expires_at_milliseconds > current_time_milliseconds ? state.expires_at_milliseconds - current_time_milliseconds : 0;
            entry.suppressed_stun_packets = state.suppressed_stun_packets;
            snapshot.retired_ice_credential_suppressed_stun_packet_count += state.suppressed_stun_packets;
            snapshot.retired_ice_credentials.push_back(std::move(entry));
        }
        snapshot.payload_type_mapping_count = to_debug_count(payload_type_mappings_by_key_.size());
        snapshot.keyframe_request_state_count = to_debug_count(keyframe_request_last_time_milliseconds_by_key_.size());
        snapshot.fir_sequence_number_state_count = to_debug_count(fir_sequence_number_by_key_.size());
        snapshot.publisher_video_ssrc_state_count = to_debug_count(publisher_video_ssrc_by_stream_.size());
        snapshot.pending_republish_keyframe_request_count = to_debug_count(pending_republish_keyframe_state_by_stream_.size());
        snapshot.selected_rid_layer_state_count = to_debug_count(selected_rid_layer_state_by_key_.size());
        snapshot.pending_selected_rid_keyframe_request_count = to_debug_count(pending_selected_rid_keyframe_request_keys_.size());
        snapshot.selected_rid_keyframe_pending_metadata_count = to_debug_count(pending_selected_rid_keyframe_request_state_by_key_.size());
        snapshot.simulcast_rid_preference_policy = std::string(simulcast_rid_preference_policy_to_string(simulcast_rid_preference_policy_from_env()));
        snapshot.extmap_rewrite_state_count = to_debug_count(extmap_rewrite_state_by_key_.size());
        snapshot.selected_rid_layers.reserve(selected_rid_layer_state_by_key_.size());
        snapshot.outbound_transport_cc_sequence_count = to_debug_count(outbound_transport_cc_sequence_by_key_.size());
        snapshot.outbound_transport_cc_packet_count = to_debug_count(outbound_transport_cc_packets_by_key_.size());
        snapshot.outbound_transport_cc_feedback_window_count = to_debug_count(outbound_transport_cc_feedback_windows_by_key_.size());

        snapshot.outbound_transport_cc_feedback_window_observation_count =
            to_debug_count(outbound_transport_cc_feedback_window_observation_count_locked());
        snapshot.subscriber_downlink_bandwidth_state_count = to_debug_count(subscriber_downlink_bandwidth_by_key_.size());
        snapshot.subscriber_downlink_pacing_state_count = to_debug_count(subscriber_downlink_pacing_by_key_.size());
        snapshot.subscriber_downlink_pacing_queue_packet_count = to_debug_count(subscriber_downlink_pacing_queue_packet_count_locked());
        snapshot.subscriber_downlink_pacing_queue_byte_count = to_debug_count(subscriber_downlink_pacing_queue_byte_count_locked());

        snapshot.outbound_transport_cc_feedback_windows.reserve(outbound_transport_cc_feedback_windows_by_key_.size());
        for (const auto& [key, window] : outbound_transport_cc_feedback_windows_by_key_)
        {
            (void)key;

            snapshot.outbound_transport_cc_feedback_windows.push_back(make_transport_cc_feedback_window_debug_entry(window));
        }

        snapshot.subscriber_downlink_bandwidth_states.reserve(subscriber_downlink_bandwidth_by_key_.size());

        const subscriber_downlink_control_mode downlink_control_mode = ice_udp_server_runtime_config_instance().subscriber_downlink_control.mode;

        for (const auto& [key, state] : subscriber_downlink_bandwidth_by_key_)
        {
            const auto pacing_iterator = subscriber_downlink_pacing_by_key_.find(key);

            const subscriber_downlink_pacing_state* pacing_state =
                pacing_iterator == subscriber_downlink_pacing_by_key_.end() ? nullptr : &pacing_iterator->second;

            snapshot.subscriber_downlink_bandwidth_states.push_back(
                make_subscriber_downlink_bandwidth_debug_entry(state, pacing_state, downlink_control_mode));
        }
        for (const auto& [key, state] : selected_rid_layer_state_by_key_)
        {
            lifecycle_debug_selected_rid_layer_entry entry;

            entry.stream_id = state.stream_id;

            entry.publisher_session_id = state.publisher_session_id;
            entry.subscriber_session_id = state.subscriber_session_id;

            entry.mid = state.mid;
            entry.kind = state.kind;

            entry.selected_rid = state.rid;
            entry.previous_rid = state.previous_rid;
            entry.target_rid = state.target_rid;
            entry.target_policy = state.target_policy;

            entry.effective_target_rid = state.target_rid;
            entry.effective_target_policy = state.target_policy;
            entry.manual_target_active = state.manual_target_active;

            entry.adaptive_suggested_rid = state.adaptive_suggested_rid;
            entry.adaptive_suggested_policy = state.adaptive_suggested_policy;
            entry.adaptive_suggested_reason = state.adaptive_suggested_reason;
            entry.adaptive_suggested_at_milliseconds = state.adaptive_suggested_at_milliseconds;

            entry.switch_count = state.switch_count;
            entry.last_switch_milliseconds = state.last_switch_milliseconds;
            entry.last_switch_reason = state.last_switch_reason;

            entry.adaptive_enabled = state.adaptive_enabled;
            entry.last_adaptive_decision = state.last_adaptive_decision;
            entry.last_adaptive_decision_reason = state.last_adaptive_decision_reason;
            entry.last_adaptive_decision_milliseconds = state.last_adaptive_decision_milliseconds;

            const uint64_t cooldown_milliseconds = simulcast_adaptive_switch_cooldown_milliseconds_from_env();

            entry.switch_cooldown_remaining_milliseconds =
                state.last_switch_milliseconds != 0 && current_time_milliseconds < state.last_switch_milliseconds + cooldown_milliseconds
                    ? state.last_switch_milliseconds + cooldown_milliseconds - current_time_milliseconds
                    : 0;

            entry.selection_policy = state.selection_policy;
            entry.rid_preference = state.rid_preference;

            entry.primary_ssrc = state.primary_ssrc;
            entry.repair_ssrc = state.repair_ssrc;

            const auto pending_iterator = pending_selected_rid_keyframe_request_keys_.find(key);

            entry.pending_keyframe_request = pending_iterator != pending_selected_rid_keyframe_request_keys_.end();

            if (entry.pending_keyframe_request)
            {
                const auto pending_state_iterator = pending_selected_rid_keyframe_request_state_by_key_.find(key);

                if (pending_state_iterator != pending_selected_rid_keyframe_request_state_by_key_.end())
                {
                    entry.pending_keyframe_request_since_milliseconds = pending_state_iterator->second.pending_since_milliseconds;
                    entry.pending_keyframe_request_expires_at_milliseconds = pending_state_iterator->second.expires_at_milliseconds;
                    entry.pending_keyframe_request_remaining_ttl_milliseconds =
                        pending_state_iterator->second.expires_at_milliseconds > current_time_milliseconds
                            ? pending_state_iterator->second.expires_at_milliseconds - current_time_milliseconds
                            : 0;
                }
            }

            entry.packet_count = state.packet_count;
            entry.byte_count = state.byte_count;

            entry.primary_packet_count = state.primary_packet_count;
            entry.primary_byte_count = state.primary_byte_count;

            entry.repair_packet_count = state.repair_packet_count;
            entry.repair_byte_count = state.repair_byte_count;

            entry.last_packet_milliseconds = state.last_packet_milliseconds;
            entry.bitrate_bps = state.bitrate_bps;

            entry.nack_feedback_count = state.nack_feedback_count;
            entry.nack_sequence_count = state.nack_sequence_count;
            entry.last_nack_milliseconds = state.last_nack_milliseconds;

            entry.keyframe_request_attempt_count = state.keyframe_request_attempt_count;
            entry.keyframe_request_success_count = state.keyframe_request_success_count;
            entry.keyframe_request_restore_count = state.keyframe_request_restore_count;
            entry.last_keyframe_request_milliseconds = state.last_keyframe_request_milliseconds;
            entry.last_keyframe_request_result = state.last_keyframe_request_result;
            entry.last_keyframe_request_reason = state.last_keyframe_request_reason;

            snapshot.selected_rid_layers.push_back(std::move(entry));
        }

        for (const auto& [endpoint, value] : endpoints_by_address_)
        {
            (void)value;

            lifecycle_debug_endpoint_entry entry;

            entry.endpoint = endpoint;
            entry.has_endpoint = true;

            const auto reverse_iterator = session_id_by_endpoint_address_.find(endpoint);

            if (reverse_iterator != session_id_by_endpoint_address_.end())
            {
                entry.session_id = reverse_iterator->second;
                entry.has_reverse_endpoint_index = true;
            }

            if (!entry.session_id.empty())
            {
                const auto forward_iterator = endpoint_address_by_session_id_.find(entry.session_id);

                entry.has_forward_session_index = forward_iterator != endpoint_address_by_session_id_.end() && forward_iterator->second == endpoint;
            }

            const auto last_seen_iterator = endpoint_last_seen_milliseconds_by_address_.find(endpoint);

            if (last_seen_iterator != endpoint_last_seen_milliseconds_by_address_.end())
            {
                entry.has_last_seen = true;
                entry.last_seen_milliseconds = last_seen_iterator->second;
            }

            if (!entry.session_id.empty())
            {
                lifecycle_debug_session_entry* session_entry = find_lifecycle_debug_session_entry(snapshot.sessions, entry.session_id);

                if (session_entry != nullptr)
                {
                    session_entry->endpoint = endpoint;
                    session_entry->has_endpoint = true;
                }
            }

            snapshot.endpoints.push_back(std::move(entry));
        }

        for (const auto& [session_id, endpoint] : endpoint_address_by_session_id_)
        {
            if (lifecycle_debug_endpoint_exists(snapshot.endpoints, endpoint))
            {
                continue;
            }

            lifecycle_debug_endpoint_entry entry;

            entry.endpoint = endpoint;
            entry.session_id = session_id;
            entry.has_endpoint = false;
            entry.has_forward_session_index = true;

            const auto reverse_iterator = session_id_by_endpoint_address_.find(endpoint);

            entry.has_reverse_endpoint_index = reverse_iterator != session_id_by_endpoint_address_.end() && reverse_iterator->second == session_id;

            const auto last_seen_iterator = endpoint_last_seen_milliseconds_by_address_.find(endpoint);

            if (last_seen_iterator != endpoint_last_seen_milliseconds_by_address_.end())
            {
                entry.has_last_seen = true;
                entry.last_seen_milliseconds = last_seen_iterator->second;
            }

            snapshot.endpoints.push_back(std::move(entry));
        }

        for (const auto& [endpoint, session_id] : session_id_by_endpoint_address_)
        {
            if (lifecycle_debug_endpoint_exists(snapshot.endpoints, endpoint))
            {
                continue;
            }

            lifecycle_debug_endpoint_entry entry;

            entry.endpoint = endpoint;
            entry.session_id = session_id;
            entry.has_endpoint = false;
            entry.has_reverse_endpoint_index = true;

            const auto forward_iterator = endpoint_address_by_session_id_.find(session_id);

            entry.has_forward_session_index = forward_iterator != endpoint_address_by_session_id_.end() && forward_iterator->second == endpoint;

            const auto last_seen_iterator = endpoint_last_seen_milliseconds_by_address_.find(endpoint);

            if (last_seen_iterator != endpoint_last_seen_milliseconds_by_address_.end())
            {
                entry.has_last_seen = true;
                entry.last_seen_milliseconds = last_seen_iterator->second;
            }

            snapshot.endpoints.push_back(std::move(entry));
        }
        for (auto& session_entry : snapshot.sessions)
        {
            session_entry.transport_blockers.clear();

            if (!session_entry.has_endpoint)
            {
                session_entry.transport_blockers.emplace_back("endpoint missing");
            }

            if (!session_entry.has_selected_candidate_pair)
            {
                session_entry.transport_blockers.emplace_back("selected candidate pair missing");
            }

            if (session_entry.has_selected_candidate_pair && !session_entry.selected_candidate_pair_nominated)
            {
                session_entry.transport_blockers.emplace_back("selected candidate pair not nominated");
            }

            if (session_entry.selected_candidate_pair_consent_stale)
            {
                session_entry.transport_blockers.emplace_back("selected candidate pair consent stale");
            }

            session_entry.transport_blocker_count = to_debug_count(session_entry.transport_blockers.size());

            session_entry.transport_ready = session_entry.transport_blocker_count == 0;
        }
    }

    if (dtls_transport_ != nullptr)
    {
        snapshot.dtls_peer_count = to_debug_count(dtls_transport_->peer_count());
    }

    if (srtp_transport_ != nullptr)
    {
        snapshot.srtp_peer_count = to_debug_count(srtp_transport_->peer_count());
    }

    if (media_router_ != nullptr)
    {
        const media_router_stats_snapshot media_snapshot = media_router_->get_stats_snapshot();

        snapshot.media_router_peer_count = to_debug_count(media_snapshot.peers.size());

        snapshot.media_router_stream_count = to_debug_count(media_snapshot.streams.size());

        snapshot.media_router_active_publisher_count = media_snapshot.active_publisher_count;

        snapshot.media_router_active_subscriber_count = media_snapshot.active_subscriber_count;
    }

    if (track_resolver_ != nullptr)
    {
        const std::vector<media_track_resolver::media_track_binding> bindings = track_resolver_->binding_snapshot();

        snapshot.track_binding_count = to_debug_count(bindings.size());

        snapshot.track_bindings.reserve(bindings.size());

        for (const auto& binding : bindings)
        {
            lifecycle_debug_track_binding_entry entry;

            entry.remote_endpoint = binding.remote_endpoint;
            entry.stream_id = binding.stream_id;
            entry.session_id = binding.session_id;

            entry.mid = binding.mid;
            entry.kind = binding.kind;
            entry.rid = optional_string_or_empty(binding.rid);
            entry.repaired_rid = optional_string_or_empty(binding.repaired_rid);

            entry.initial_resolution_state = media_track_resolution_state_to_string(binding.initial_resolution_state);
            entry.fallback_resolution = binding.fallback_resolution;

            entry.has_audio_level = binding.audio_level.has_value();
            entry.audio_level = binding.audio_level.has_value() ? static_cast<uint64_t>(*binding.audio_level) : 0;

            entry.has_voice_activity = binding.voice_activity.has_value();
            entry.voice_activity = binding.voice_activity.value_or(false);

            entry.ssrc = binding.ssrc;
            entry.payload_type = static_cast<uint64_t>(binding.payload_type);

            entry.rtx = binding.rtx;
            entry.rtx_primary_ssrc = binding.rtx_primary_ssrc;
            entry.rtx_repair_ssrc = binding.rtx_repair_ssrc;

            entry.packet_count = binding.packet_count;

            snapshot.track_bindings.push_back(std::move(entry));
        }
    }
    if (ssrc_mapper_ != nullptr)
    {
        snapshot.ssrc_mapping_count = to_debug_count(ssrc_mapper_->mapping_count());
    }
    if (identity_authority_ != nullptr)
    {
        const std::vector<media_identity_track_binding> track_bindings = identity_authority_->track_binding_snapshot();
        const std::vector<media_identity_rid_layer_binding> rid_layers = identity_authority_->rid_layer_binding_snapshot();
        const std::vector<media_identity_forward_binding> forward_bindings = identity_authority_->forward_binding_snapshot();

        snapshot.identity_authority_track_binding_count = to_debug_count(track_bindings.size());
        snapshot.identity_authority_rid_layer_binding_count = to_debug_count(rid_layers.size());
        snapshot.identity_authority_forward_binding_count = to_debug_count(forward_bindings.size());

        snapshot.identity_track_bindings.reserve(track_bindings.size());

        for (const auto& binding : track_bindings)
        {
            lifecycle_debug_identity_track_binding_entry entry;

            entry.remote_endpoint = binding.remote_endpoint;
            entry.stream_id = binding.stream_id;
            entry.session_id = binding.session_id;

            entry.track_key = binding.track_key;

            entry.mid = binding.mid;
            entry.kind = binding.kind;
            entry.rid = optional_string_or_empty(binding.rid);
            entry.repaired_rid = optional_string_or_empty(binding.repaired_rid);

            entry.ssrc = binding.ssrc;
            entry.payload_type = static_cast<uint64_t>(binding.payload_type);

            entry.rtx = binding.rtx;

            entry.packet_count = binding.packet_count;

            snapshot.identity_track_bindings.push_back(std::move(entry));
        }

        snapshot.identity_rid_layers.reserve(rid_layers.size());

        for (const auto& binding : rid_layers)
        {
            lifecycle_debug_identity_rid_layer_entry entry;

            entry.remote_endpoint = binding.remote_endpoint;
            entry.stream_id = binding.stream_id;
            entry.session_id = binding.session_id;

            entry.mid = binding.mid;
            entry.kind = binding.kind;
            entry.rid = binding.rid;

            entry.primary_ssrc = binding.primary_ssrc;
            entry.repair_ssrc = binding.repair_ssrc;

            entry.primary_payload_type = static_cast<uint64_t>(binding.primary_payload_type);
            entry.repair_payload_type = static_cast<uint64_t>(binding.repair_payload_type);

            entry.packet_count = binding.packet_count;

            snapshot.identity_rid_layers.push_back(std::move(entry));
        }

        snapshot.identity_forward_bindings.reserve(forward_bindings.size());

        for (const auto& binding : forward_bindings)
        {
            lifecycle_debug_identity_forward_binding_entry entry;

            entry.stream_id = binding.stream_id;

            entry.publisher_session_id = binding.publisher_session_id;
            entry.subscriber_session_id = binding.subscriber_session_id;

            entry.publisher_track_key = binding.publisher_track_key;
            entry.subscriber_track_key = binding.subscriber_track_key;

            entry.publisher_mid = binding.publisher_mid;
            entry.subscriber_mid = binding.subscriber_mid;
            entry.kind = binding.kind;

            entry.publisher_media_ordinal = static_cast<uint64_t>(binding.publisher_media_ordinal);
            entry.subscriber_media_ordinal = static_cast<uint64_t>(binding.subscriber_media_ordinal);
            entry.audio_ordinal_mismatch = media_identity_forward_binding_has_audio_ordinal_mismatch(binding);

            entry.publisher_ssrc = binding.publisher_ssrc;
            entry.subscriber_ssrc = binding.subscriber_ssrc;

            entry.publisher_payload_type = static_cast<uint64_t>(binding.publisher_payload_type);
            entry.subscriber_payload_type = static_cast<uint64_t>(binding.subscriber_payload_type);

            entry.rtx = binding.rtx;
            entry.publisher_apt_payload_type = static_cast<uint64_t>(binding.publisher_apt_payload_type);
            entry.subscriber_apt_payload_type = static_cast<uint64_t>(binding.subscriber_apt_payload_type);

            entry.publisher_rtx_primary_ssrc = binding.publisher_rtx_primary_ssrc;
            entry.publisher_rtx_repair_ssrc = binding.publisher_rtx_repair_ssrc;

            entry.payload_type_rewrite_required = binding.payload_type_rewrite_required;
            entry.mid_rewrite_required = binding.mid_rewrite_required;
            entry.ssrc_rewrite_required = binding.ssrc_rewrite_required;

            entry.packet_count = binding.packet_count;

            snapshot.identity_forward_bindings.push_back(std::move(entry));
        }
        snapshot.subscriber_forward_groups = make_subscriber_forward_groups(forward_bindings);

        snapshot.subscriber_forward_group_count = to_debug_count(snapshot.subscriber_forward_groups.size());
        std::vector<lifecycle_debug_subscriber_rtcp_group_entry> subscriber_rtcp_groups;
        std::vector<std::string> subscriber_rtcp_group_keys;

        if (rtcp_report_service_ != nullptr)
        {
            const std::vector<rtcp_report_source_snapshot> report_sources = rtcp_report_service_->source_snapshot();

            snapshot.rtcp_report_source_count = to_debug_count(report_sources.size());

            snapshot.rtcp_report_sources.reserve(report_sources.size());

            for (const auto& source : report_sources)
            {
                lifecycle_debug_rtcp_report_source_entry entry;

                entry.stream_id = source.stream_id;
                entry.session_id = source.session_id;
                entry.remote_endpoint = source.remote_endpoint;

                entry.mid = source.mid;
                entry.kind = source.kind;
                entry.rid = optional_string_or_empty(source.rid);
                entry.repaired_rid = optional_string_or_empty(source.repaired_rid);

                entry.local_ssrc = source.local_ssrc;

                entry.sender_report_enabled = source.sender_report_enabled;
                entry.receiver_report_enabled = source.receiver_report_enabled;

                entry.max_report_blocks = to_debug_count(source.max_report_blocks);

                entry.next_due_milliseconds = source.next_due_milliseconds;
                entry.last_active_milliseconds = source.last_active_milliseconds;

                snapshot.rtcp_report_sources.push_back(std::move(entry));

                const auto subscriber = registry_ != nullptr ? registry_->find_subscriber_by_session_id(source.session_id) : nullptr;

                if (subscriber != nullptr)
                {
                    auto& group =
                        get_or_create_subscriber_rtcp_group(subscriber_rtcp_groups, subscriber_rtcp_group_keys, source.stream_id, source.session_id);

                    update_subscriber_rtcp_group_from_report_source(group, source);
                }
            }
        }

        if (rtcp_transport_cc_feedback_service_ != nullptr)
        {
            const std::vector<rtcp_transport_cc_feedback_source_snapshot> twcc_sources = rtcp_transport_cc_feedback_service_->source_snapshot();

            snapshot.twcc_feedback_source_count = to_debug_count(twcc_sources.size());

            snapshot.twcc_feedback_sources.reserve(twcc_sources.size());

            snapshot.transport_cc_feedback_total = transport_cc_feedback_total_.load(std::memory_order_relaxed);
            snapshot.transport_cc_feedback_packet_status_total = transport_cc_feedback_packet_status_total_.load(std::memory_order_relaxed);
            snapshot.transport_cc_feedback_lookup_hit_total = transport_cc_feedback_lookup_hit_total_.load(std::memory_order_relaxed);
            snapshot.transport_cc_feedback_lookup_miss_total = transport_cc_feedback_lookup_miss_total_.load(std::memory_order_relaxed);
            snapshot.transport_cc_feedback_received_packet_total = transport_cc_feedback_received_packet_total_.load(std::memory_order_relaxed);
            snapshot.transport_cc_feedback_not_received_packet_total =
                transport_cc_feedback_not_received_packet_total_.load(std::memory_order_relaxed);
            snapshot.transport_cc_feedback_small_delta_total = transport_cc_feedback_small_delta_total_.load(std::memory_order_relaxed);
            snapshot.transport_cc_feedback_large_delta_total = transport_cc_feedback_large_delta_total_.load(std::memory_order_relaxed);

            for (const auto& source : twcc_sources)
            {
                lifecycle_debug_twcc_feedback_source_entry entry;

                entry.stream_id = source.stream_id;
                entry.session_id = source.session_id;
                entry.remote_endpoint = source.remote_endpoint;

                entry.mid = source.mid;
                entry.kind = source.kind;

                entry.sender_ssrc = source.sender_ssrc;
                entry.media_ssrc = source.media_ssrc;

                entry.feedback_packet_count = source.feedback_packet_count;
                entry.pending_packet_count = source.pending_packet_count;

                entry.next_due_milliseconds = source.next_due_milliseconds;
                entry.last_active_milliseconds = source.last_active_milliseconds;

                entry.total_feedback_packet_count = source.total_feedback_packet_count;
                entry.feedback_interval_milliseconds = source.feedback_interval_milliseconds;
                entry.stale_source_milliseconds = source.stale_source_milliseconds;
                entry.next_due_milliseconds = source.next_due_milliseconds;
                entry.last_feedback_milliseconds = source.last_feedback_milliseconds;
                entry.oldest_pending_packet_milliseconds = source.oldest_pending_packet_milliseconds;
                entry.newest_pending_packet_milliseconds = source.newest_pending_packet_milliseconds;

                snapshot.twcc_feedback_sources.push_back(std::move(entry));

                const auto subscriber = registry_ != nullptr ? registry_->find_subscriber_by_session_id(source.session_id) : nullptr;

                if (subscriber != nullptr)
                {
                    auto& group =
                        get_or_create_subscriber_rtcp_group(subscriber_rtcp_groups, subscriber_rtcp_group_keys, source.stream_id, source.session_id);

                    update_subscriber_rtcp_group_from_twcc_source(group, source);
                }
            }
        }

        snapshot.subscriber_rtcp_groups = std::move(subscriber_rtcp_groups);

        snapshot.subscriber_rtcp_group_count = to_debug_count(snapshot.subscriber_rtcp_groups.size());
    }
    if (rtcp_report_service_ != nullptr)
    {
        snapshot.rtcp_report_source_count = to_debug_count(rtcp_report_service_->source_count());

        snapshot.rtcp_report_stats_source_count = to_debug_count(rtcp_report_service_->stats_source_count());
    }

    if (rtcp_transport_cc_feedback_service_ != nullptr)
    {
        snapshot.rtcp_transport_cc_source_count = to_debug_count(rtcp_transport_cc_feedback_service_->source_count());

        snapshot.rtcp_transport_cc_pending_packet_count = to_debug_count(rtcp_transport_cc_feedback_service_->pending_packet_count());
    }
    {
        std::vector<pending_subscriber_runtime_residual_check> pending_checks;

        {
            std::lock_guard lock(endpoint_mutex_);

            pending_checks = pending_subscriber_runtime_residual_checks_;
        }

        snapshot.subscriber_runtime_residuals.reserve(pending_checks.size());

        for (const auto& check : pending_checks)
        {
            lifecycle_debug_subscriber_runtime_residual_entry entry =
                make_subscriber_runtime_residual_entry(check.stream_id, check.subscriber_session_id);

            if (entry.residual_count == 0)
            {
                continue;
            }

            snapshot.subscriber_runtime_residual_count += 1;

            snapshot.subscriber_runtime_residuals.push_back(std::move(entry));
        }
    }

    if (rtp_packet_cache_ != nullptr)
    {
        snapshot.rtp_cache_packet_count = to_debug_count(rtp_packet_cache_->size());

        for (const auto& cache_stream : rtp_packet_cache_->stream_snapshot())
        {
            lifecycle_debug_rtp_cache_stream_entry entry;

            entry.stream_id = cache_stream.stream_id;
            entry.packet_count = cache_stream.packet_count;
            entry.byte_count = cache_stream.byte_count;
            entry.min_ssrc = cache_stream.min_ssrc;
            entry.max_ssrc = cache_stream.max_ssrc;

            snapshot.rtp_cache_streams.push_back(std::move(entry));
        }
    }

    if (rtx_sequence_allocator_ != nullptr)
    {
        snapshot.rtx_sequence_allocator_count = to_debug_count(rtx_sequence_allocator_->size());
    }

    if (rtx_retransmission_index_ != nullptr)
    {
        snapshot.rtx_retransmission_index_count = to_debug_count(rtx_retransmission_index_->size());
    }
    if (nack_retransmit_throttle_ != nullptr)
    {
        snapshot.nack_retransmit_throttle_count = to_debug_count(nack_retransmit_throttle_->size());
    }

    append_subscriber_recovery_runtime_debug_entries(snapshot);

    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "current session gate", rtp_rtcp_drop_inbound_session_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "media runtime gate", rtp_rtcp_drop_inbound_runtime_gate_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "srtp transport missing", rtp_rtcp_drop_inbound_transport_missing_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "srtp unprotect failed", rtp_rtcp_drop_inbound_srtp_failed_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "srtp ignored non rtp rtcp", rtp_rtcp_drop_inbound_srtp_non_rtp_rtcp_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(snapshot,
                                       "rtp_inbound",
                                       "srtp ignored dtls identity missing",
                                       rtp_rtcp_drop_inbound_srtp_dtls_identity_missing_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "srtp ignored dtls not ready", rtp_rtcp_drop_inbound_srtp_dtls_not_ready_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "srtp replay ignored", rtp_rtcp_drop_inbound_srtp_replay_ignored_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "srtp unprotect ignored", rtp_rtcp_drop_inbound_srtp_unprotect_ignored_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "srtp ignored other", rtp_rtcp_drop_inbound_srtp_ignored_other_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "media router unknown peer", rtp_rtcp_drop_inbound_unknown_peer_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "rtp_inbound", "publisher identity gate", rtp_rtcp_drop_inbound_identity_gate_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "no target", rtp_rtcp_drop_media_forward_no_target_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "srtp transport missing", rtp_rtcp_drop_media_forward_transport_missing_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(snapshot,
                                       "media_forward",
                                       "target endpoint missing",
                                       rtp_rtcp_drop_media_forward_target_endpoint_missing_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "target peer missing", rtp_rtcp_drop_media_forward_target_peer_missing_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "rewrite failed", rtp_rtcp_drop_media_forward_rewrite_failed_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "rewrite empty", rtp_rtcp_drop_media_forward_rewrite_empty_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "outbound runtime gate", rtp_rtcp_drop_media_forward_runtime_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "subscriber bitrate gate", rtp_rtcp_drop_media_forward_bitrate_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "subscriber pacing queue", rtp_rtcp_drop_media_forward_pacing_queue_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "srtp protect failed", rtp_rtcp_drop_media_forward_protect_failed_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "media_forward", "srtp protect ignored", rtp_rtcp_drop_media_forward_protect_ignored_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_report", "current session gate", rtp_rtcp_drop_rtcp_report_session_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_report", "outbound runtime gate", rtp_rtcp_drop_rtcp_report_runtime_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_report", "endpoint missing", rtcp_report_endpoint_not_found_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_report", "srtp protect failed", rtcp_report_protect_failed_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_report", "srtp protect ignored", rtcp_report_protect_ignored_total_.load(std::memory_order_relaxed));

    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_twcc", "current session gate", rtp_rtcp_drop_twcc_session_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_twcc", "identity gate", rtp_rtcp_drop_twcc_identity_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_twcc", "send runtime gate", rtp_rtcp_drop_twcc_send_runtime_gate_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_twcc", "endpoint missing", rtp_rtcp_drop_twcc_endpoint_missing_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_twcc", "srtp protect failed", rtp_rtcp_drop_twcc_protect_failed_total_.load(std::memory_order_relaxed));
    append_lifecycle_debug_drop_reason(
        snapshot, "rtcp_twcc", "srtp protect ignored", rtp_rtcp_drop_twcc_protect_ignored_total_.load(std::memory_order_relaxed));

    snapshot.rtp_rtcp_drop_reason_count = to_debug_count(snapshot.rtp_rtcp_drop_reasons.size());
    if (snapshot.endpoint_session_index_count != snapshot.endpoint_reverse_index_count)
    {
        add_lifecycle_inconsistency(snapshot, "endpoint session index count does not match reverse index count");
    }

    if (snapshot.endpoint_count < snapshot.endpoint_session_index_count)
    {
        add_lifecycle_inconsistency(snapshot, "endpoint count is smaller than session endpoint index count");
    }

    if (snapshot.endpoint_count < snapshot.endpoint_reverse_index_count)
    {
        add_lifecycle_inconsistency(snapshot, "endpoint count is smaller than endpoint session reverse index count");
    }

    if (snapshot.registry_session_count == 0 && !lifecycle_active_runtime_state_is_empty(snapshot))
    {
        add_lifecycle_inconsistency(snapshot, "registry is empty but active runtime state remains");
    }

    for (const auto& endpoint : snapshot.endpoints)
    {
        if (!endpoint.session_id.empty() && !lifecycle_debug_session_exists(snapshot.sessions, endpoint.session_id))
        {
            add_lifecycle_inconsistency(
                snapshot, "endpoint references missing registry session endpoint=" + endpoint.endpoint + " session=" + endpoint.session_id);
        }

        if (endpoint.has_forward_session_index != endpoint.has_reverse_endpoint_index)
        {
            add_lifecycle_inconsistency(snapshot,
                                        "endpoint forward reverse index mismatch endpoint=" + endpoint.endpoint + " session=" + endpoint.session_id);
        }

        if (!endpoint.has_endpoint)
        {
            add_lifecycle_inconsistency(
                snapshot, "endpoint index remains without endpoint object endpoint=" + endpoint.endpoint + " session=" + endpoint.session_id);
        }
    }

    for (const auto& session : snapshot.sessions)
    {
        const bool pending = session.state == "created" || session.state == "sdp_received" || session.state == "sdp_answered";

        if (!pending && !session.has_endpoint)
        {
            add_lifecycle_inconsistency(snapshot,
                                        "active registry session has no endpoint session=" + session.session_id + " stream=" + session.stream_id);
        }
    }

    if (snapshot.registry_session_count == 0)
    {
        if (snapshot.endpoint_count != 0)
        {
            add_lifecycle_residual(snapshot, "endpoint remains count=" + std::to_string(snapshot.endpoint_count));
        }

        if (snapshot.endpoint_session_index_count != 0)
        {
            add_lifecycle_residual(snapshot, "endpoint session index remains count=" + std::to_string(snapshot.endpoint_session_index_count));
        }

        if (snapshot.endpoint_reverse_index_count != 0)
        {
            add_lifecycle_residual(snapshot, "endpoint reverse index remains count=" + std::to_string(snapshot.endpoint_reverse_index_count));
        }

        if (snapshot.endpoint_last_seen_count != 0)
        {
            add_lifecycle_residual(snapshot, "endpoint last seen remains count=" + std::to_string(snapshot.endpoint_last_seen_count));
        }

        if (snapshot.candidate_pair_count != 0)
        {
            add_lifecycle_residual(snapshot, "candidate pair remains count=" + std::to_string(snapshot.candidate_pair_count));
        }
        if (snapshot.publisher_absent_stream_count != 0)
        {
            add_lifecycle_residual(snapshot, "publisher absent stream remains count=" + std::to_string(snapshot.publisher_absent_stream_count));
        }

        if (snapshot.selected_candidate_pair_count != 0)
        {
            add_lifecycle_residual(snapshot, "selected candidate pair remains count=" + std::to_string(snapshot.selected_candidate_pair_count));
        }

        if (snapshot.candidate_pair_consent_in_flight_count != 0)
        {
            add_lifecycle_residual(
                snapshot, "candidate pair consent in flight remains count=" + std::to_string(snapshot.candidate_pair_consent_in_flight_count));
        }

        if (snapshot.candidate_pair_consent_failure_count != 0)
        {
            add_lifecycle_residual(snapshot,
                                   "candidate pair consent failure remains count=" + std::to_string(snapshot.candidate_pair_consent_failure_count));
        }

        if (snapshot.candidate_pair_consent_stale_count != 0)
        {
            add_lifecycle_residual(snapshot,
                                   "candidate pair consent stale remains count=" + std::to_string(snapshot.candidate_pair_consent_stale_count));
        }

        if (snapshot.dtls_peer_count != 0)
        {
            add_lifecycle_residual(snapshot, "dtls peer remains count=" + std::to_string(snapshot.dtls_peer_count));
        }

        if (snapshot.srtp_peer_count != 0)
        {
            add_lifecycle_residual(snapshot, "srtp peer remains count=" + std::to_string(snapshot.srtp_peer_count));
        }

        if (snapshot.media_router_peer_count != 0)
        {
            add_lifecycle_residual(snapshot, "media router peer remains count=" + std::to_string(snapshot.media_router_peer_count));
        }

        if (snapshot.media_router_stream_count != 0)
        {
            add_lifecycle_residual(snapshot, "media router stream remains count=" + std::to_string(snapshot.media_router_stream_count));
        }

        if (snapshot.media_router_active_publisher_count != 0)
        {
            add_lifecycle_residual(snapshot,
                                   "media router active publisher remains count=" + std::to_string(snapshot.media_router_active_publisher_count));
        }

        if (snapshot.media_router_active_subscriber_count != 0)
        {
            add_lifecycle_residual(snapshot,
                                   "media router active subscriber remains count=" + std::to_string(snapshot.media_router_active_subscriber_count));
        }

        if (snapshot.track_binding_count != 0)
        {
            add_lifecycle_residual(snapshot, "track binding remains count=" + std::to_string(snapshot.track_binding_count));
        }

        if (snapshot.ssrc_mapping_count != 0)
        {
            add_lifecycle_residual(snapshot, "ssrc mapping remains count=" + std::to_string(snapshot.ssrc_mapping_count));
        }

        if (snapshot.identity_authority_track_binding_count != 0)
        {
            add_lifecycle_residual(
                snapshot, "identity authority track binding remains count=" + std::to_string(snapshot.identity_authority_track_binding_count));
        }

        if (snapshot.identity_authority_rid_layer_binding_count != 0)
        {
            add_lifecycle_residual(
                snapshot,
                "identity authority rid layer binding remains count=" + std::to_string(snapshot.identity_authority_rid_layer_binding_count));
        }

        if (snapshot.identity_authority_forward_binding_count != 0)
        {
            add_lifecycle_residual(
                snapshot, "identity authority forward binding remains count=" + std::to_string(snapshot.identity_authority_forward_binding_count));
        }

        if (snapshot.payload_type_mapping_count != 0)
        {
            add_lifecycle_residual(snapshot, "payload type mapping remains count=" + std::to_string(snapshot.payload_type_mapping_count));
        }

        if (snapshot.keyframe_request_state_count != 0)
        {
            add_lifecycle_residual(snapshot, "keyframe request state remains count=" + std::to_string(snapshot.keyframe_request_state_count));
        }

        if (snapshot.fir_sequence_number_state_count != 0)
        {
            add_lifecycle_residual(snapshot, "fir sequence number state remains count=" + std::to_string(snapshot.fir_sequence_number_state_count));
        }

        if (snapshot.publisher_video_ssrc_state_count != 0)
        {
            add_lifecycle_residual(snapshot, "publisher video ssrc state remains count=" + std::to_string(snapshot.publisher_video_ssrc_state_count));
        }

        if (snapshot.pending_republish_keyframe_request_count != 0)
        {
            add_lifecycle_residual(
                snapshot, "pending republish keyframe request remains count=" + std::to_string(snapshot.pending_republish_keyframe_request_count));
        }

        if (snapshot.selected_rid_layer_state_count != 0)
        {
            add_lifecycle_residual(snapshot, "selected rid layer state remains count=" + std::to_string(snapshot.selected_rid_layer_state_count));
        }

        if (snapshot.pending_selected_rid_keyframe_request_count != 0)
        {
            add_lifecycle_residual(
                snapshot,
                "pending selected rid keyframe request remains count=" + std::to_string(snapshot.pending_selected_rid_keyframe_request_count));
        }

        if (snapshot.selected_rid_keyframe_pending_metadata_count != 0)
        {
            add_lifecycle_residual(
                snapshot,
                "selected rid keyframe pending metadata remains count=" + std::to_string(snapshot.selected_rid_keyframe_pending_metadata_count));
        }

        if (snapshot.extmap_rewrite_state_count != 0)
        {
            add_lifecycle_residual(snapshot, "extmap rewrite state remains count=" + std::to_string(snapshot.extmap_rewrite_state_count));
        }

        if (snapshot.outbound_transport_cc_sequence_count != 0)
        {
            add_lifecycle_residual(snapshot,
                                   "outbound transport cc sequence remains count=" + std::to_string(snapshot.outbound_transport_cc_sequence_count));
        }
        if (snapshot.outbound_transport_cc_packet_count != 0)
        {
            add_lifecycle_residual(snapshot,
                                   "outbound transport cc packet remains count=" + std::to_string(snapshot.outbound_transport_cc_packet_count));
        }
        if (snapshot.outbound_transport_cc_feedback_window_count != 0)
        {
            add_lifecycle_residual(
                snapshot,
                "outbound transport cc feedback window remains count=" + std::to_string(snapshot.outbound_transport_cc_feedback_window_count));
        }

        if (snapshot.outbound_transport_cc_feedback_window_observation_count != 0)
        {
            add_lifecycle_residual(snapshot,
                                   "outbound transport cc feedback window observation remains count=" +
                                       std::to_string(snapshot.outbound_transport_cc_feedback_window_observation_count));
        }

        if (snapshot.subscriber_downlink_bandwidth_state_count != 0)
        {
            add_lifecycle_residual(
                snapshot, "subscriber downlink bandwidth state remains count=" + std::to_string(snapshot.subscriber_downlink_bandwidth_state_count));
        }

        if (snapshot.subscriber_downlink_pacing_state_count != 0)
        {
            add_lifecycle_residual(
                snapshot, "subscriber downlink pacing state remains count=" + std::to_string(snapshot.subscriber_downlink_pacing_state_count));
        }

        if (snapshot.subscriber_downlink_pacing_queue_packet_count != 0)
        {
            add_lifecycle_residual(
                snapshot,
                "subscriber downlink pacing queue packet remains count=" + std::to_string(snapshot.subscriber_downlink_pacing_queue_packet_count));
        }

        if (snapshot.subscriber_downlink_pacing_queue_byte_count != 0)
        {
            add_lifecycle_residual(
                snapshot,
                "subscriber downlink pacing queue byte remains count=" + std::to_string(snapshot.subscriber_downlink_pacing_queue_byte_count));
        }

        if (snapshot.rtcp_report_source_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtcp report source remains count=" + std::to_string(snapshot.rtcp_report_source_count));
        }

        if (snapshot.rtcp_report_stats_source_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtcp report stats source remains count=" + std::to_string(snapshot.rtcp_report_stats_source_count));
        }

        if (snapshot.rtcp_transport_cc_source_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtcp transport cc source remains count=" + std::to_string(snapshot.rtcp_transport_cc_source_count));
        }

        if (snapshot.rtcp_transport_cc_pending_packet_count != 0)
        {
            add_lifecycle_residual(
                snapshot, "rtcp transport cc pending packet remains count=" + std::to_string(snapshot.rtcp_transport_cc_pending_packet_count));
        }

        if (snapshot.rtp_cache_packet_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtp cache packet remains count=" + std::to_string(snapshot.rtp_cache_packet_count));
        }

        if (snapshot.rtx_sequence_allocator_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtx sequence allocator remains count=" + std::to_string(snapshot.rtx_sequence_allocator_count));
        }

        if (snapshot.rtx_retransmission_index_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtx retransmission index remains count=" + std::to_string(snapshot.rtx_retransmission_index_count));
        }

        if (snapshot.nack_retransmit_throttle_count != 0)
        {
            add_lifecycle_residual(snapshot, "nack retransmit throttle remains count=" + std::to_string(snapshot.nack_retransmit_throttle_count));
        }

        if (snapshot.retired_endpoint_count != 0)
        {
            add_lifecycle_delayed_residual(snapshot, "retired endpoint pending count=" + std::to_string(snapshot.retired_endpoint_count));
        }

        if (snapshot.retired_endpoint_suppressed_packet_count != 0)
        {
            add_lifecycle_delayed_residual(
                snapshot, "retired endpoint suppressed packet count=" + std::to_string(snapshot.retired_endpoint_suppressed_packet_count));
        }

        if (snapshot.retired_ice_credential_count != 0)
        {
            add_lifecycle_delayed_residual(snapshot, "retired ice credential pending count=" + std::to_string(snapshot.retired_ice_credential_count));
        }

        if (snapshot.retired_ice_credential_suppressed_stun_packet_count != 0)
        {
            add_lifecycle_delayed_residual(snapshot,
                                           "retired ice credential suppressed stun packet count=" +
                                               std::to_string(snapshot.retired_ice_credential_suppressed_stun_packet_count));
        }
    }

    const auto& runtime_config = ice_udp_server_runtime_config_instance();

    append_runtime_resource_limit(snapshot, "registry_pending_sessions", snapshot.registry_pending_session_count, k_max_pending_sessions);
    append_runtime_resource_limit(snapshot, "retired_endpoints", snapshot.retired_endpoint_count, k_max_retired_endpoints);
    append_runtime_resource_limit(snapshot, "retired_ice_credentials", snapshot.retired_ice_credential_count, k_max_retired_ice_credentials);
    append_runtime_resource_limit(snapshot, "rtp_cache_packets", snapshot.rtp_cache_packet_count, runtime_config.rtp_packet_cache.max_packets);
    append_runtime_resource_limit(
        snapshot, "rtx_retransmission_index", snapshot.rtx_retransmission_index_count, runtime_config.rtx_retransmission_index.max_entries);
    append_runtime_resource_limit(
        snapshot, "nack_retransmit_throttle", snapshot.nack_retransmit_throttle_count, runtime_config.nack_retransmit_throttle.max_entries);
    append_runtime_resource_limit(
        snapshot, "rtcp_transport_cc_sources", snapshot.rtcp_transport_cc_source_count, runtime_config.rtcp_transport_cc_feedback.max_sources);
    append_runtime_resource_limit(snapshot,
                                  "rtcp_transport_cc_pending_packets",
                                  snapshot.rtcp_transport_cc_pending_packet_count,
                                  runtime_config.rtcp_transport_cc_feedback.max_pending_packets_total);
    append_runtime_resource_limit(
        snapshot, "outbound_transport_cc_packets", snapshot.outbound_transport_cc_packet_count, k_max_outbound_transport_cc_packet_identities);
    append_runtime_resource_limit(
        snapshot,
        "outbound_transport_cc_feedback_window_observations",
        snapshot.outbound_transport_cc_feedback_window_observation_count,
        snapshot.outbound_transport_cc_feedback_window_count * static_cast<uint64_t>(k_max_outbound_transport_cc_feedback_observations_per_window));

    if (snapshot.runtime_resource_limit_over_count != 0)
    {
        add_lifecycle_inconsistency(snapshot, "runtime resource limit exceeded count=" + std::to_string(snapshot.runtime_resource_limit_over_count));
    }

    snapshot.active_runtime_clean = snapshot.registry_session_count == 0 && lifecycle_active_runtime_state_is_empty(snapshot);
    snapshot.delayed_runtime_clean = lifecycle_delayed_runtime_state_is_empty(snapshot);
    snapshot.full_idle_clean = snapshot.active_runtime_clean && snapshot.delayed_runtime_clean;
    snapshot.idle_clean = snapshot.active_runtime_clean;
    snapshot.inconsistency_count = to_debug_count(snapshot.inconsistencies.size());
    snapshot.delayed_residual_count = to_debug_count(snapshot.delayed_residuals.size());
    snapshot.consistent = snapshot.inconsistency_count == 0;

    update_runtime_acceptance_summary(snapshot);

    return snapshot;
}

void ice_udp_server::schedule_lifecycle_snapshot_log(std::string reason, std::string stream_id, std::string session_id)
{
    std::string convergence_reason = reason;
    std::string convergence_stream_id = stream_id;
    std::string convergence_session_id = session_id;

    auto self = shared_from_this();

    boost::asio::post(io_context_,
                      [self, reason = std::move(reason), stream_id = std::move(stream_id), session_id = std::move(session_id)]()
                      { self->log_lifecycle_snapshot(reason, stream_id, session_id); });

    schedule_lifecycle_convergence_checks(std::move(convergence_reason), std::move(convergence_stream_id), std::move(convergence_session_id));
}

void ice_udp_server::log_lifecycle_snapshot(std::string_view reason, std::string_view stream_id, std::string_view session_id) const
{
    const lifecycle_debug_snapshot snapshot = debug_state_snapshot();

    const bool active_runtime_residual_after_idle = snapshot.registry_session_count == 0 && !snapshot.active_runtime_clean;

    log_lifecycle_acceptance_summary("snapshot", reason, stream_id, session_id, snapshot);
    log_lifecycle_resource_limit_over_details("snapshot", reason, stream_id, session_id, snapshot);
    log_lifecycle_downlink_summary("snapshot", reason, stream_id, session_id, snapshot);

    if (!snapshot.consistent || active_runtime_residual_after_idle)
    {
        WEBRTC_LOG_WARN(
            "lifecycle snapshot residual reason={} stream={} session={} "
            "registry_streams={} registry_sessions={} registry_publishers={} registry_subscribers={} registry_pending_sessions={} "
            "endpoints={} endpoint_session_index={} endpoint_reverse_index={} endpoint_last_seen={} "
            "retired_endpoints={} retired_endpoint_suppressed_packets={} retired_ice_credentials={} "
            "retired_ice_credential_suppressed_stun_packets={} "
            "candidate_pairs={} selected_candidate_pairs={} candidate_pair_consent_in_flight={} candidate_pair_consent_failures={} "
            "candidate_pair_consent_stale={} "
            "payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} pending_republish_keyframes={} "
            "selected_rid_layer_states={} pending_selected_rid_keyframes={} selected_rid_pending_metadata={} extmap_rewrite_states={} "
            "dtls_peers={} srtp_peers={} "
            "media_router_peers={} media_router_streams={} media_router_active_publishers={} media_router_active_subscribers={} "
            "track_bindings={} ssrc_mappings={} "
            "identity_track_bindings={} identity_rid_layer_bindings={} identity_forward_bindings={} "
            "rtcp_report_sources={} rtcp_report_stats_sources={} "
            "rtcp_transport_cc_sources={} rtcp_transport_cc_pending_packets={} "
            "rtp_cache_packets={} rtx_retransmission_index={} nack_retransmit_throttle={} "
            "active_runtime_clean={} delayed_runtime_clean={} full_idle_clean={} idle_clean={} consistent={} inconsistencies={} residuals={} "
            "delayed_residuals={}",
            reason,
            stream_id,
            session_id,
            snapshot.registry_stream_count,
            snapshot.registry_session_count,
            snapshot.registry_publisher_count,
            snapshot.registry_subscriber_count,
            snapshot.registry_pending_session_count,
            snapshot.endpoint_count,
            snapshot.endpoint_session_index_count,
            snapshot.endpoint_reverse_index_count,
            snapshot.endpoint_last_seen_count,
            snapshot.retired_endpoint_count,
            snapshot.retired_endpoint_suppressed_packet_count,
            snapshot.retired_ice_credential_count,
            snapshot.retired_ice_credential_suppressed_stun_packet_count,
            snapshot.candidate_pair_count,
            snapshot.selected_candidate_pair_count,
            snapshot.candidate_pair_consent_in_flight_count,
            snapshot.candidate_pair_consent_failure_count,
            snapshot.candidate_pair_consent_stale_count,
            snapshot.payload_type_mapping_count,
            snapshot.keyframe_request_state_count,
            snapshot.fir_sequence_number_state_count,
            snapshot.publisher_video_ssrc_state_count,
            snapshot.pending_republish_keyframe_request_count,
            snapshot.selected_rid_layer_state_count,
            snapshot.pending_selected_rid_keyframe_request_count,
            snapshot.selected_rid_keyframe_pending_metadata_count,
            snapshot.extmap_rewrite_state_count,
            snapshot.dtls_peer_count,
            snapshot.srtp_peer_count,
            snapshot.media_router_peer_count,
            snapshot.media_router_stream_count,
            snapshot.media_router_active_publisher_count,
            snapshot.media_router_active_subscriber_count,
            snapshot.track_binding_count,
            snapshot.ssrc_mapping_count,
            snapshot.identity_authority_track_binding_count,
            snapshot.identity_authority_rid_layer_binding_count,
            snapshot.identity_authority_forward_binding_count,
            snapshot.rtcp_report_source_count,
            snapshot.rtcp_report_stats_source_count,
            snapshot.rtcp_transport_cc_source_count,
            snapshot.rtcp_transport_cc_pending_packet_count,
            snapshot.rtp_cache_packet_count,
            snapshot.rtx_retransmission_index_count,
            snapshot.nack_retransmit_throttle_count,
            snapshot.active_runtime_clean ? 1 : 0,
            snapshot.delayed_runtime_clean ? 1 : 0,
            snapshot.full_idle_clean ? 1 : 0,
            snapshot.idle_clean ? 1 : 0,
            snapshot.consistent ? 1 : 0,
            snapshot.inconsistency_count,
            snapshot.residuals.size(),
            snapshot.delayed_residual_count);

        return;
    }

    WEBRTC_LOG_INFO(
        "lifecycle snapshot clean reason={} stream={} session={} "
        "registry_streams={} registry_sessions={} registry_publishers={} registry_subscribers={} registry_pending_sessions={} "
        "endpoints={} endpoint_session_index={} endpoint_reverse_index={} endpoint_last_seen={} "
        "retired_endpoints={} retired_endpoint_suppressed_packets={} retired_ice_credentials={} retired_ice_credential_suppressed_stun_packets={} "
        "candidate_pairs={} selected_candidate_pairs={} candidate_pair_consent_in_flight={} candidate_pair_consent_failures={} "
        "candidate_pair_consent_stale={} "
        "payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} pending_republish_keyframes={} "
        "selected_rid_layer_states={} pending_selected_rid_keyframes={} selected_rid_pending_metadata={} extmap_rewrite_states={} "
        "dtls_peers={} srtp_peers={} "
        "media_router_peers={} media_router_streams={} media_router_active_publishers={} media_router_active_subscribers={} "
        "track_bindings={} ssrc_mappings={} "
        "identity_track_bindings={} identity_rid_layer_bindings={} identity_forward_bindings={} "
        "rtcp_report_sources={} rtcp_report_stats_sources={} "
        "rtcp_transport_cc_sources={} rtcp_transport_cc_pending_packets={} "
        "rtp_cache_packets={} rtx_retransmission_index={} nack_retransmit_throttle={} "
        "active_runtime_clean={} delayed_runtime_clean={} full_idle_clean={} idle_clean={} consistent={} inconsistencies={} residuals={} "
        "delayed_residuals={}",
        reason,
        stream_id,
        session_id,
        snapshot.registry_stream_count,
        snapshot.registry_session_count,
        snapshot.registry_publisher_count,
        snapshot.registry_subscriber_count,
        snapshot.registry_pending_session_count,
        snapshot.endpoint_count,
        snapshot.endpoint_session_index_count,
        snapshot.endpoint_reverse_index_count,
        snapshot.endpoint_last_seen_count,
        snapshot.retired_endpoint_count,
        snapshot.retired_endpoint_suppressed_packet_count,
        snapshot.retired_ice_credential_count,
        snapshot.retired_ice_credential_suppressed_stun_packet_count,
        snapshot.candidate_pair_count,
        snapshot.selected_candidate_pair_count,
        snapshot.candidate_pair_consent_in_flight_count,
        snapshot.candidate_pair_consent_failure_count,
        snapshot.candidate_pair_consent_stale_count,
        snapshot.payload_type_mapping_count,
        snapshot.keyframe_request_state_count,
        snapshot.fir_sequence_number_state_count,
        snapshot.publisher_video_ssrc_state_count,
        snapshot.pending_republish_keyframe_request_count,
        snapshot.selected_rid_layer_state_count,
        snapshot.pending_selected_rid_keyframe_request_count,
        snapshot.selected_rid_keyframe_pending_metadata_count,
        snapshot.extmap_rewrite_state_count,
        snapshot.dtls_peer_count,
        snapshot.srtp_peer_count,
        snapshot.media_router_peer_count,
        snapshot.media_router_stream_count,
        snapshot.media_router_active_publisher_count,
        snapshot.media_router_active_subscriber_count,
        snapshot.track_binding_count,
        snapshot.ssrc_mapping_count,
        snapshot.identity_authority_track_binding_count,
        snapshot.identity_authority_rid_layer_binding_count,
        snapshot.identity_authority_forward_binding_count,
        snapshot.rtcp_report_source_count,
        snapshot.rtcp_report_stats_source_count,
        snapshot.rtcp_transport_cc_source_count,
        snapshot.rtcp_transport_cc_pending_packet_count,
        snapshot.rtp_cache_packet_count,
        snapshot.rtx_retransmission_index_count,
        snapshot.nack_retransmit_throttle_count,
        snapshot.active_runtime_clean ? 1 : 0,
        snapshot.delayed_runtime_clean ? 1 : 0,
        snapshot.full_idle_clean ? 1 : 0,
        snapshot.idle_clean ? 1 : 0,
        snapshot.consistent ? 1 : 0,
        snapshot.inconsistency_count,
        snapshot.residuals.size(),
        snapshot.delayed_residual_count);
}

void ice_udp_server::schedule_lifecycle_convergence_checks(std::string reason, std::string stream_id, std::string session_id)
{
    const uint64_t generation = lifecycle_convergence_check_generation_.fetch_add(1, std::memory_order_relaxed) + 1;

    schedule_lifecycle_convergence_check(reason, stream_id, session_id, k_lifecycle_fast_convergence_check_delay_milliseconds, false, generation);

    schedule_lifecycle_convergence_check(
        std::move(reason), std::move(stream_id), std::move(session_id), k_lifecycle_final_convergence_check_delay_milliseconds, true, generation);
}

void ice_udp_server::schedule_lifecycle_convergence_check(std::string reason,
                                                          std::string stream_id,
                                                          std::string session_id,
                                                          uint64_t delay_milliseconds,
                                                          bool require_retired_endpoints_empty,
                                                          uint64_t generation)
{
    auto timer = std::make_shared<boost::asio::steady_timer>(io_context_);

    timer->expires_after(std::chrono::milliseconds(delay_milliseconds));

    auto self = shared_from_this();

    timer->async_wait(
        [self,
         timer,
         reason = std::move(reason),
         stream_id = std::move(stream_id),
         session_id = std::move(session_id),
         delay_milliseconds,
         require_retired_endpoints_empty,
         generation](const boost::system::error_code& error)
        {
            (void)timer;

            if (error)
            {
                return;
            }

            const uint64_t current_generation = self->lifecycle_convergence_check_generation_.load(std::memory_order_relaxed);

            if (current_generation != generation)
            {
                return;
            }

            self->log_lifecycle_convergence_check(reason, stream_id, session_id, delay_milliseconds, require_retired_endpoints_empty, generation);
        });
}

void ice_udp_server::log_lifecycle_convergence_check(std::string_view reason,
                                                     std::string_view stream_id,
                                                     std::string_view session_id,
                                                     uint64_t delay_milliseconds,
                                                     bool require_retired_endpoints_empty,
                                                     uint64_t generation)
{
    {
        std::lock_guard lock(endpoint_mutex_);

        const uint64_t current_time_milliseconds = now_milliseconds();

        const std::size_t expired_selected_rid_keyframe_pending_count =
            expire_selected_rid_keyframe_request_pending_locked(current_time_milliseconds);

        if (expired_selected_rid_keyframe_pending_count != 0)
        {
            WEBRTC_LOG_INFO("simulcast selected rid keyframe pending expired during lifecycle convergence check count={}",
                            expired_selected_rid_keyframe_pending_count);
        }

        const std::size_t expired_retired_endpoint_count = expire_retired_endpoints_locked(current_time_milliseconds);

        if (expired_retired_endpoint_count != 0)
        {
            WEBRTC_LOG_INFO("ice udp retired endpoints expired during lifecycle convergence check count={}", expired_retired_endpoint_count);
        }

        const std::size_t expired_ice_credential_count = expire_retired_ice_credentials_locked(current_time_milliseconds);

        if (expired_ice_credential_count != 0)
        {
            WEBRTC_LOG_INFO("ice retired credentials expired during lifecycle convergence check count={}", expired_ice_credential_count);
        }
    }
    const lifecycle_debug_snapshot snapshot = debug_state_snapshot();

    const bool retired_state_clean = !require_retired_endpoints_empty || snapshot.delayed_runtime_clean;

    log_lifecycle_acceptance_summary("convergence_check", reason, stream_id, session_id, snapshot);
    log_lifecycle_resource_limit_over_details("convergence_check", reason, stream_id, session_id, snapshot);
    log_lifecycle_downlink_summary("convergence_check", reason, stream_id, session_id, snapshot);

    if (snapshot.registry_session_count != 0)
    {
        WEBRTC_LOG_DEBUG(
            "lifecycle convergence waiting generation={} delay_ms={} require_retired_empty={} reason={} stream={} session={} "
            "registry_streams={} registry_sessions={} registry_publishers={} registry_subscribers={} registry_pending_sessions={} "
            "endpoints={} endpoint_session_index={} endpoint_reverse_index={} endpoint_last_seen={} "
            "retired_endpoints={} retired_endpoint_suppressed_packets={} retired_ice_credentials={} "
            "retired_ice_credential_suppressed_stun_packets={} "
            "candidate_pairs={} selected_candidate_pairs={} candidate_pair_consent_in_flight={} candidate_pair_consent_failures={} "
            "candidate_pair_consent_stale={} "
            "payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} pending_republish_keyframes={} "
            "selected_rid_layer_states={} pending_selected_rid_keyframes={} selected_rid_pending_metadata={} extmap_rewrite_states={} "
            "dtls_peers={} srtp_peers={} "
            "media_router_peers={} media_router_streams={} media_router_active_publishers={} media_router_active_subscribers={} "
            "track_bindings={} ssrc_mappings={} "
            "identity_track_bindings={} identity_rid_layer_bindings={} identity_forward_bindings={} "
            "rtcp_report_sources={} rtcp_report_stats_sources={} "
            "rtcp_transport_cc_sources={} rtcp_transport_cc_pending_packets={} "
            "rtp_cache_packets={} rtx_retransmission_index={} nack_retransmit_throttle={} "
            "active_runtime_clean={} delayed_runtime_clean={} full_idle_clean={} idle_clean={} retired_state_clean={} consistent={} "
            "inconsistencies={} residuals={} delayed_residuals={}",
            generation,
            delay_milliseconds,
            require_retired_endpoints_empty ? 1 : 0,
            reason,
            stream_id,
            session_id,
            snapshot.registry_stream_count,
            snapshot.registry_session_count,
            snapshot.registry_publisher_count,
            snapshot.registry_subscriber_count,
            snapshot.registry_pending_session_count,
            snapshot.endpoint_count,
            snapshot.endpoint_session_index_count,
            snapshot.endpoint_reverse_index_count,
            snapshot.endpoint_last_seen_count,
            snapshot.retired_endpoint_count,
            snapshot.retired_endpoint_suppressed_packet_count,
            snapshot.retired_ice_credential_count,
            snapshot.retired_ice_credential_suppressed_stun_packet_count,
            snapshot.candidate_pair_count,
            snapshot.selected_candidate_pair_count,
            snapshot.candidate_pair_consent_in_flight_count,
            snapshot.candidate_pair_consent_failure_count,
            snapshot.candidate_pair_consent_stale_count,
            snapshot.payload_type_mapping_count,
            snapshot.keyframe_request_state_count,
            snapshot.fir_sequence_number_state_count,
            snapshot.publisher_video_ssrc_state_count,
            snapshot.pending_republish_keyframe_request_count,
            snapshot.selected_rid_layer_state_count,
            snapshot.pending_selected_rid_keyframe_request_count,
            snapshot.selected_rid_keyframe_pending_metadata_count,
            snapshot.extmap_rewrite_state_count,
            snapshot.dtls_peer_count,
            snapshot.srtp_peer_count,
            snapshot.media_router_peer_count,
            snapshot.media_router_stream_count,
            snapshot.media_router_active_publisher_count,
            snapshot.media_router_active_subscriber_count,
            snapshot.track_binding_count,
            snapshot.ssrc_mapping_count,
            snapshot.identity_authority_track_binding_count,
            snapshot.identity_authority_rid_layer_binding_count,
            snapshot.identity_authority_forward_binding_count,
            snapshot.rtcp_report_source_count,
            snapshot.rtcp_report_stats_source_count,
            snapshot.rtcp_transport_cc_source_count,
            snapshot.rtcp_transport_cc_pending_packet_count,
            snapshot.rtp_cache_packet_count,
            snapshot.rtx_retransmission_index_count,
            snapshot.nack_retransmit_throttle_count,
            snapshot.active_runtime_clean ? 1 : 0,
            snapshot.delayed_runtime_clean ? 1 : 0,
            snapshot.full_idle_clean ? 1 : 0,
            snapshot.idle_clean ? 1 : 0,
            retired_state_clean ? 1 : 0,
            snapshot.consistent ? 1 : 0,
            snapshot.inconsistency_count,
            snapshot.residuals.size(),
            snapshot.delayed_residual_count);

        return;
    }

    if (snapshot.active_runtime_clean && snapshot.consistent && retired_state_clean)
    {
        WEBRTC_LOG_INFO(
            "lifecycle convergence clean generation={} delay_ms={} require_retired_empty={} reason={} stream={} session={} "
            "registry_streams={} registry_sessions={} registry_publishers={} registry_subscribers={} registry_pending_sessions={} "
            "endpoints={} endpoint_session_index={} endpoint_reverse_index={} endpoint_last_seen={} "
            "retired_endpoints={} retired_endpoint_suppressed_packets={} retired_ice_credentials={} "
            "retired_ice_credential_suppressed_stun_packets={} "
            "candidate_pairs={} selected_candidate_pairs={} candidate_pair_consent_in_flight={} candidate_pair_consent_failures={} "
            "candidate_pair_consent_stale={} "
            "payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} pending_republish_keyframes={} "
            "selected_rid_layer_states={} pending_selected_rid_keyframes={} selected_rid_pending_metadata={} extmap_rewrite_states={} "
            "dtls_peers={} srtp_peers={} "
            "media_router_peers={} media_router_streams={} media_router_active_publishers={} media_router_active_subscribers={} "
            "track_bindings={} ssrc_mappings={} "
            "identity_track_bindings={} identity_rid_layer_bindings={} identity_forward_bindings={} "
            "rtcp_report_sources={} rtcp_report_stats_sources={} "
            "rtcp_transport_cc_sources={} rtcp_transport_cc_pending_packets={} "
            "rtp_cache_packets={} rtx_retransmission_index={} nack_retransmit_throttle={} "
            "active_runtime_clean={} delayed_runtime_clean={} full_idle_clean={} idle_clean={} retired_state_clean={} consistent={} "
            "inconsistencies={} residuals={} delayed_residuals={}",
            generation,
            delay_milliseconds,
            require_retired_endpoints_empty ? 1 : 0,
            reason,
            stream_id,
            session_id,
            snapshot.registry_stream_count,
            snapshot.registry_session_count,
            snapshot.registry_publisher_count,
            snapshot.registry_subscriber_count,
            snapshot.registry_pending_session_count,
            snapshot.endpoint_count,
            snapshot.endpoint_session_index_count,
            snapshot.endpoint_reverse_index_count,
            snapshot.endpoint_last_seen_count,
            snapshot.retired_endpoint_count,
            snapshot.retired_endpoint_suppressed_packet_count,
            snapshot.retired_ice_credential_count,
            snapshot.retired_ice_credential_suppressed_stun_packet_count,
            snapshot.candidate_pair_count,
            snapshot.selected_candidate_pair_count,
            snapshot.candidate_pair_consent_in_flight_count,
            snapshot.candidate_pair_consent_failure_count,
            snapshot.candidate_pair_consent_stale_count,
            snapshot.payload_type_mapping_count,
            snapshot.keyframe_request_state_count,
            snapshot.fir_sequence_number_state_count,
            snapshot.publisher_video_ssrc_state_count,
            snapshot.pending_republish_keyframe_request_count,
            snapshot.selected_rid_layer_state_count,
            snapshot.pending_selected_rid_keyframe_request_count,
            snapshot.selected_rid_keyframe_pending_metadata_count,
            snapshot.extmap_rewrite_state_count,
            snapshot.dtls_peer_count,
            snapshot.srtp_peer_count,
            snapshot.media_router_peer_count,
            snapshot.media_router_stream_count,
            snapshot.media_router_active_publisher_count,
            snapshot.media_router_active_subscriber_count,
            snapshot.track_binding_count,
            snapshot.ssrc_mapping_count,
            snapshot.identity_authority_track_binding_count,
            snapshot.identity_authority_rid_layer_binding_count,
            snapshot.identity_authority_forward_binding_count,
            snapshot.rtcp_report_source_count,
            snapshot.rtcp_report_stats_source_count,
            snapshot.rtcp_transport_cc_source_count,
            snapshot.rtcp_transport_cc_pending_packet_count,
            snapshot.rtp_cache_packet_count,
            snapshot.rtx_retransmission_index_count,
            snapshot.nack_retransmit_throttle_count,
            snapshot.active_runtime_clean ? 1 : 0,
            snapshot.delayed_runtime_clean ? 1 : 0,
            snapshot.full_idle_clean ? 1 : 0,
            snapshot.idle_clean ? 1 : 0,
            retired_state_clean ? 1 : 0,
            snapshot.consistent ? 1 : 0,
            snapshot.inconsistency_count,
            snapshot.residuals.size(),
            snapshot.delayed_residual_count);

        return;
    }

    WEBRTC_LOG_WARN(
        "lifecycle convergence residual generation={} delay_ms={} require_retired_empty={} reason={} stream={} session={} "
        "registry_streams={} registry_sessions={} registry_publishers={} registry_subscribers={} registry_pending_sessions={} "
        "endpoints={} endpoint_session_index={} endpoint_reverse_index={} endpoint_last_seen={} "
        "retired_endpoints={} retired_endpoint_suppressed_packets={} retired_ice_credentials={} retired_ice_credential_suppressed_stun_packets={} "
        "candidate_pairs={} selected_candidate_pairs={} candidate_pair_consent_in_flight={} candidate_pair_consent_failures={} "
        "candidate_pair_consent_stale={} "
        "payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} pending_republish_keyframes={} "
        "selected_rid_layer_states={} pending_selected_rid_keyframes={} selected_rid_pending_metadata={} extmap_rewrite_states={} "
        "dtls_peers={} srtp_peers={} "
        "media_router_peers={} media_router_streams={} media_router_active_publishers={} media_router_active_subscribers={} "
        "track_bindings={} ssrc_mappings={} "
        "identity_track_bindings={} identity_rid_layer_bindings={} identity_forward_bindings={} "
        "rtcp_report_sources={} rtcp_report_stats_sources={} "
        "rtcp_transport_cc_sources={} rtcp_transport_cc_pending_packets={} "
        "rtp_cache_packets={} rtx_retransmission_index={} nack_retransmit_throttle={} "
        "active_runtime_clean={} delayed_runtime_clean={} full_idle_clean={} idle_clean={} retired_state_clean={} consistent={} "
        "inconsistencies={} residuals={} delayed_residuals={}",
        generation,
        delay_milliseconds,
        require_retired_endpoints_empty ? 1 : 0,
        reason,
        stream_id,
        session_id,
        snapshot.registry_stream_count,
        snapshot.registry_session_count,
        snapshot.registry_publisher_count,
        snapshot.registry_subscriber_count,
        snapshot.registry_pending_session_count,
        snapshot.endpoint_count,
        snapshot.endpoint_session_index_count,
        snapshot.endpoint_reverse_index_count,
        snapshot.endpoint_last_seen_count,
        snapshot.retired_endpoint_count,
        snapshot.retired_endpoint_suppressed_packet_count,
        snapshot.retired_ice_credential_count,
        snapshot.retired_ice_credential_suppressed_stun_packet_count,
        snapshot.candidate_pair_count,
        snapshot.selected_candidate_pair_count,
        snapshot.candidate_pair_consent_in_flight_count,
        snapshot.candidate_pair_consent_failure_count,
        snapshot.candidate_pair_consent_stale_count,
        snapshot.payload_type_mapping_count,
        snapshot.keyframe_request_state_count,
        snapshot.fir_sequence_number_state_count,
        snapshot.publisher_video_ssrc_state_count,
        snapshot.pending_republish_keyframe_request_count,
        snapshot.selected_rid_layer_state_count,
        snapshot.pending_selected_rid_keyframe_request_count,
        snapshot.selected_rid_keyframe_pending_metadata_count,
        snapshot.extmap_rewrite_state_count,
        snapshot.dtls_peer_count,
        snapshot.srtp_peer_count,
        snapshot.media_router_peer_count,
        snapshot.media_router_stream_count,
        snapshot.media_router_active_publisher_count,
        snapshot.media_router_active_subscriber_count,
        snapshot.track_binding_count,
        snapshot.ssrc_mapping_count,
        snapshot.identity_authority_track_binding_count,
        snapshot.identity_authority_rid_layer_binding_count,
        snapshot.identity_authority_forward_binding_count,
        snapshot.rtcp_report_source_count,
        snapshot.rtcp_report_stats_source_count,
        snapshot.rtcp_transport_cc_source_count,
        snapshot.rtcp_transport_cc_pending_packet_count,
        snapshot.rtp_cache_packet_count,
        snapshot.rtx_retransmission_index_count,
        snapshot.nack_retransmit_throttle_count,
        snapshot.active_runtime_clean ? 1 : 0,
        snapshot.delayed_runtime_clean ? 1 : 0,
        snapshot.full_idle_clean ? 1 : 0,
        snapshot.idle_clean ? 1 : 0,
        retired_state_clean ? 1 : 0,
        snapshot.consistent ? 1 : 0,
        snapshot.inconsistency_count,
        snapshot.residuals.size(),
        snapshot.delayed_residual_count);
}

ice_udp_server_result ice_udp_server::init_dtls_transport()
{
    if (dtls_transport_ != nullptr && srtp_transport_ != nullptr && rtp_packet_cache_ != nullptr && rtx_sequence_allocator_ != nullptr &&
        rtx_retransmission_index_ != nullptr && nack_retransmit_throttle_ != nullptr)
    {
        return {};
    }
    auto certificate_file = get_required_env("WEBRTC_CERT_FILE");

    if (!certificate_file)
    {
        return std::unexpected(certificate_file.error());
    }

    auto private_key_file = get_required_env("WEBRTC_KEY_FILE");

    if (!private_key_file)
    {
        return std::unexpected(private_key_file.error());
    }

    dtls_context_config context_config;

    context_config.certificate_file = *certificate_file;

    context_config.private_key_file = *private_key_file;

    auto context = make_dtls_context(context_config);

    if (!context)
    {
        return std::unexpected(context.error());
    }

    const ice_udp_server_runtime_config& runtime_config = ice_udp_server_runtime_config_instance();

    dtls_transport_ = std::make_shared<dtls_transport>(*context, runtime_config.dtls_transport);

    srtp_transport_ = std::make_shared<srtp_transport>(dtls_transport_);

    rtp_packet_cache_ = std::make_shared<rtp_packet_cache>(runtime_config.rtp_packet_cache);

    rtx_sequence_allocator_ = std::make_shared<rtx_sequence_number_allocator>();

    rtx_retransmission_index_ = std::make_shared<rtx_retransmission_index>(runtime_config.rtx_retransmission_index);

    nack_retransmit_throttle_ = std::make_shared<nack_retransmit_throttle>(runtime_config.nack_retransmit_throttle);

    WEBRTC_LOG_INFO("dtls transport initialized handshake_timeout_ms={}", runtime_config.dtls_transport.handshake_timeout.count());

    WEBRTC_LOG_INFO("rtp packet cache initialized max_packets={}", runtime_config.rtp_packet_cache.max_packets);
    WEBRTC_LOG_INFO("srtp transport initialized");

    WEBRTC_LOG_INFO("rtx sequence allocator initialized");
    WEBRTC_LOG_INFO("nack retransmit throttle initialized");
    return {};
}

std::optional<std::string> ice_udp_server::remote_address_for_session(std::string_view session_id) const
{
    if (session_id.empty())
    {
        return std::nullopt;
    }

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = endpoint_address_by_session_id_.find(std::string(session_id));

    if (iterator == endpoint_address_by_session_id_.end())
    {
        return std::nullopt;
    }

    if (iterator->second.empty())
    {
        return std::nullopt;
    }

    return iterator->second;
}

void ice_udp_server::send_rtcp_bye_for_removed_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    if (ssrc_mapper_ == nullptr)
    {
        return;
    }

    const std::vector<media_ssrc_mapping> mappings = ssrc_mapper_->find_by_stream_id(stream_id);

    send_rtcp_bye_for_mappings(stream_id, mappings);
}

void ice_udp_server::send_rtcp_bye_for_removed_session(const stream_removed_session& removed_session)
{
    if (removed_session.kind != stream_session_kind::subscriber)
    {
        return;
    }

    if (removed_session.session_id.empty())
    {
        return;
    }

    if (ssrc_mapper_ == nullptr)
    {
        return;
    }

    const std::vector<media_ssrc_mapping> mappings = ssrc_mapper_->find_by_subscriber_session(removed_session.session_id);

    send_rtcp_bye_for_mappings(removed_session.stream_id, mappings);
}

void ice_udp_server::send_rtcp_bye_for_mappings(std::string_view stream_id, const std::vector<media_ssrc_mapping>& mappings)
{
    if (mappings.empty())
    {
        return;
    }

    std::unordered_map<std::string, rtcp_bye_target> targets_by_session_id;

    for (const auto& mapping : mappings)
    {
        if (mapping.subscriber_session_id.empty())
        {
            continue;
        }

        auto& target = targets_by_session_id[mapping.subscriber_session_id];

        if (target.subscriber_session_id.empty())
        {
            target.subscriber_session_id = mapping.subscriber_session_id;

            auto remote_address = remote_address_for_session(mapping.subscriber_session_id);

            if (remote_address.has_value())
            {
                target.remote_address = std::move(*remote_address);
            }
        }

        append_unique_rtcp_bye_ssrc(target.ssrcs, mapping.subscriber_ssrc);
    }

    for (const auto& [subscriber_session_id, target] : targets_by_session_id)
    {
        (void)subscriber_session_id;

        if (target.remote_address.empty())
        {
            continue;
        }

        if (target.ssrcs.empty())
        {
            continue;
        }

        send_rtcp_bye_to_subscriber(stream_id, target.subscriber_session_id, target.remote_address, target.ssrcs);
    }
}

void ice_udp_server::send_rtcp_bye_to_subscriber(std::string_view stream_id,
                                                 std::string_view subscriber_session_id,
                                                 std::string_view remote_address,
                                                 const std::vector<uint32_t>& ssrcs)
{
    if (stream_id.empty())
    {
        return;
    }

    if (subscriber_session_id.empty())
    {
        return;
    }

    if (remote_address.empty())
    {
        return;
    }

    if (ssrcs.empty())
    {
        return;
    }

    if (srtp_transport_ == nullptr)
    {
        return;
    }

    auto remote_endpoint = find_remote_endpoint(remote_address);

    if (!remote_endpoint.has_value())
    {
        WEBRTC_LOG_DEBUG("rtcp bye skipped endpoint not found stream={} subscriber={} remote={}", stream_id, subscriber_session_id, remote_address);

        return;
    }

    std::size_t offset = 0;

    while (offset < ssrcs.size())
    {
        const std::size_t chunk_end = std::min(offset + k_rtcp_bye_max_ssrcs_per_packet, ssrcs.size());

        rtcp_bye_write_options bye_options;

        bye_options.ssrcs.reserve(chunk_end - offset);

        for (std::size_t index = offset; index < chunk_end; ++index)
        {
            bye_options.ssrcs.push_back(ssrcs[index]);
        }

        auto bye_packet = write_rtcp_bye_packet(bye_options);

        if (!bye_packet)
        {
            WEBRTC_LOG_WARN("rtcp bye write failed stream={} subscriber={} remote={} ssrc_count={} error={}",
                            stream_id,
                            subscriber_session_id,
                            remote_address,
                            bye_options.ssrcs.size(),
                            bye_packet.error());

            offset = chunk_end;

            continue;
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(bye_packet->data(), bye_packet->size()), remote_address, srtp_packet_kind::rtcp);

        if (!protected_packet)
        {
            WEBRTC_LOG_WARN("rtcp bye protect failed stream={} subscriber={} remote={} ssrc_count={} error={}",
                            stream_id,
                            subscriber_session_id,
                            remote_address,
                            bye_options.ssrcs.size(),
                            protected_packet.error());

            offset = chunk_end;

            continue;
        }

        if (protected_packet->state == srtp_packet_process_state::ignored)
        {
            WEBRTC_LOG_DEBUG("rtcp bye ignored stream={} subscriber={} remote={} ssrc_count={} reason={}",
                             stream_id,
                             subscriber_session_id,
                             remote_address,
                             bye_options.ssrcs.size(),
                             protected_packet->reason);

            offset = chunk_end;

            continue;
        }

        send_response(std::move(protected_packet->protected_packet), *remote_endpoint);

        WEBRTC_LOG_INFO("rtcp bye sent stream={} subscriber={} remote={} ssrc_count={}",
                        stream_id,
                        subscriber_session_id,
                        remote_address,
                        bye_options.ssrcs.size());

        offset = chunk_end;
    }
}

void ice_udp_server::remember_publisher_video_ssrc(const media_peer_info& peer,
                                                   const srtp_packet_process_result& packet,
                                                   const std::optional<media_track_resolution>& track_resolution)
{
    if (peer.role != media_peer_role::publisher)
    {
        return;
    }

    if (packet.kind != srtp_packet_kind::rtp)
    {
        return;
    }

    if (packet.ssrc == 0)
    {
        return;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved)
    {
        return;
    }

    if (track_resolution->rtx)
    {
        return;
    }

    if (!is_video_media_kind(track_resolution->kind))
    {
        return;
    }

    const std::string state_key = make_publisher_video_ssrc_state_key(peer.stream_id, peer.session_id, *track_resolution, packet.ssrc);

    std::lock_guard lock(endpoint_mutex_);

    publisher_video_ssrc_by_stream_[state_key] = packet.ssrc;
}

ice_udp_server::keyframe_request_feedback_type ice_udp_server::select_keyframe_request_feedback_type(std::string_view stream_id,
                                                                                                     std::string_view publisher_session_id,
                                                                                                     std::string_view mid,
                                                                                                     std::string_view kind) const
{
    if (stream_id.empty() || registry_ == nullptr)
    {
        return keyframe_request_feedback_type::none;
    }

    std::shared_ptr<publisher_session> publisher;

    if (!publisher_session_id.empty())
    {
        publisher = registry_->find_publisher_by_session_id(publisher_session_id);

        if (publisher != nullptr && publisher->stream_id() != stream_id)
        {
            WEBRTC_LOG_WARN(
                "keyframe request feedback selection rejected publisher stream mismatch stream={} publisher_session={} publisher_stream={}",
                stream_id,
                publisher_session_id,
                publisher->stream_id());

            return keyframe_request_feedback_type::none;
        }
    }
    else
    {
        publisher = registry_->find_publisher_by_stream_id(stream_id);
    }

    if (publisher == nullptr)
    {
        return keyframe_request_feedback_type::none;
    }

    const sdp::webrtc_offer_summary& offer_summary = publisher->remote_offer_summary();

    bool supports_pli = false;
    bool supports_fir = false;
    bool matched_media = false;

    for (const auto& media : offer_summary.media)
    {
        if (!kind.empty() && media.kind != kind)
        {
            continue;
        }

        if (!mid.empty() && media.mid != mid)
        {
            continue;
        }

        if (!is_video_media_kind(media.kind))
        {
            continue;
        }

        matched_media = true;

        supports_pli = supports_pli || media_supports_rtcp_feedback(media, "nack pli");

        supports_fir = supports_fir || media_supports_rtcp_feedback(media, "ccm fir");
    }

    if ((!mid.empty() || !kind.empty()) && !matched_media)
    {
        WEBRTC_LOG_WARN("keyframe request feedback selection media not found stream={} publisher_session={} mid={} kind={}",
                        stream_id,
                        publisher_session_id,
                        mid,
                        kind);

        return keyframe_request_feedback_type::none;
    }

    if (supports_pli)
    {
        return keyframe_request_feedback_type::pli;
    }

    if (supports_fir)
    {
        return keyframe_request_feedback_type::fir;
    }

    return keyframe_request_feedback_type::none;
}

std::vector<ice_udp_server::keyframe_request_media_target> ice_udp_server::collect_keyframe_request_media_targets(std::string_view stream_id) const
{
    std::vector<keyframe_request_media_target> targets;

    if (stream_id.empty())
    {
        return targets;
    }

    if (ssrc_mapper_ != nullptr)
    {
        const std::vector<media_ssrc_mapping> mappings = ssrc_mapper_->find_by_stream_id(stream_id);

        for (const auto& mapping : mappings)
        {
            if (!media_ssrc_mapping_is_primary_video(mapping))
            {
                WEBRTC_LOG_DEBUG(
                    "keyframe request skip non primary video mapping stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                    "subscriber_mid={} publisher_ssrc={} subscriber_ssrc={} kind={} rid={} repaired_rid={} rtx={}",
                    mapping.stream_id,
                    mapping.publisher_session_id,
                    mapping.subscriber_session_id,
                    mapping.publisher_mid,
                    mapping.subscriber_mid,
                    mapping.publisher_ssrc,
                    mapping.subscriber_ssrc,
                    mapping.kind,
                    mapping.rid.value_or(""),
                    mapping.repaired_rid.value_or(""),
                    media_ssrc_mapping_is_rtx(mapping) ? 1 : 0);

                continue;
            }

            media_peer_info publisher_peer;

            publisher_peer.role = media_peer_role::publisher;

            publisher_peer.stream_id = mapping.stream_id;

            publisher_peer.session_id = mapping.publisher_session_id;

            if (!mapping.publisher_session_id.empty())
            {
                auto remote_address = remote_address_for_session(mapping.publisher_session_id);

                if (remote_address.has_value())
                {
                    publisher_peer.remote_endpoint = *remote_address;
                }
            }

            keyframe_request_media_target target;

            target.media_ssrc = mapping.publisher_ssrc;

            target.sender_ssrc = make_rtcp_report_local_ssrc(publisher_peer, mapping.publisher_ssrc);

            target.mid = mapping.publisher_mid;

            target.kind = mapping.kind;

            target.rid = mapping.rid;

            target.repaired_rid = mapping.repaired_rid;

            append_unique_keyframe_media_target(targets, std::move(target));
        }
    }

    std::vector<uint32_t> legacy_video_ssrcs;

    {
        std::lock_guard lock(endpoint_mutex_);

        const std::string exact_legacy_key = std::string(stream_id);

        const std::string stream_prefix = exact_legacy_key + "|";

        for (const auto& [key, ssrc] : publisher_video_ssrc_by_stream_)
        {
            if (key != exact_legacy_key && !key.starts_with(stream_prefix))
            {
                continue;
            }

            if (ssrc == 0)
            {
                continue;
            }

            const auto existing = std::find(legacy_video_ssrcs.begin(), legacy_video_ssrcs.end(), ssrc);

            if (existing == legacy_video_ssrcs.end())
            {
                legacy_video_ssrcs.push_back(ssrc);
            }
        }
    }

    if (!legacy_video_ssrcs.empty())
    {
        media_peer_info publisher_peer;

        publisher_peer.role = media_peer_role::publisher;

        publisher_peer.stream_id = std::string(stream_id);

        auto publisher = registry_ != nullptr ? registry_->find_publisher_by_stream_id(stream_id) : nullptr;

        if (publisher != nullptr)
        {
            publisher_peer.session_id = publisher->session_id();

            auto remote_address = remote_address_for_session(publisher_peer.session_id);

            if (remote_address.has_value())
            {
                publisher_peer.remote_endpoint = *remote_address;
            }
        }

        for (uint32_t ssrc : legacy_video_ssrcs)
        {
            keyframe_request_media_target target;

            target.media_ssrc = ssrc;

            target.sender_ssrc = make_rtcp_report_local_ssrc(publisher_peer, ssrc);

            target.kind = "video";

            append_unique_keyframe_media_target(targets, std::move(target));
        }
    }

    return targets;
}

uint8_t ice_udp_server::next_fir_sequence_number(std::string_view stream_id, uint32_t media_ssrc)
{
    std::string key;

    key.reserve(stream_id.size() + 16);

    key.append(stream_id);

    key.push_back('|');

    key.append(std::to_string(media_ssrc));

    std::lock_guard lock(endpoint_mutex_);

    uint8_t& sequence_number = fir_sequence_number_by_key_[key];

    sequence_number = static_cast<uint8_t>(sequence_number + 1U);

    if (sequence_number == 0)
    {
        sequence_number = 1;
    }

    return sequence_number;
}
std::optional<std::vector<uint8_t>> ice_udp_server::make_keyframe_request_packet(keyframe_request_feedback_type feedback_type,
                                                                                 std::string_view stream_id,
                                                                                 uint32_t sender_ssrc,
                                                                                 uint32_t media_ssrc)
{
    if (sender_ssrc == 0 || media_ssrc == 0)
    {
        return std::nullopt;
    }

    if (feedback_type == keyframe_request_feedback_type::pli)
    {
        rtcp_pli_write_options options;

        options.sender_ssrc = sender_ssrc;

        options.media_ssrc = media_ssrc;

        auto packet = write_rtcp_pli_packet(options);

        if (!packet)
        {
            WEBRTC_LOG_WARN("keyframe request pli build failed stream={} sender_ssrc={} media_ssrc={} error={}",
                            stream_id,
                            sender_ssrc,
                            media_ssrc,
                            packet.error());

            return std::nullopt;
        }

        return std::move(*packet);
    }

    if (feedback_type == keyframe_request_feedback_type::fir)
    {
        rtcp_fir_write_options options;

        options.sender_ssrc = sender_ssrc;

        options.media_ssrc = media_ssrc;

        options.sequence_number = next_fir_sequence_number(stream_id, media_ssrc);

        auto packet = write_rtcp_fir_packet(options);

        if (!packet)
        {
            WEBRTC_LOG_WARN("keyframe request fir build failed stream={} sender_ssrc={} media_ssrc={} sequence={} error={}",
                            stream_id,
                            sender_ssrc,
                            media_ssrc,
                            options.sequence_number,
                            packet.error());

            return std::nullopt;
        }

        return std::move(*packet);
    }

    return std::nullopt;
}
keyframe_request_expected ice_udp_server::request_keyframe(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return make_error("stream id is empty");
    }

    if (registry_ == nullptr)
    {
        return make_error("session registry unavailable");
    }

    if (srtp_transport_ == nullptr)
    {
        return make_error("srtp transport unavailable");
    }

    auto publisher = registry_->find_publisher_by_stream_id(stream_id);

    if (publisher == nullptr)
    {
        return make_error("stream publisher not found");
    }

    keyframe_request_result result;

    result.stream_id = publisher->stream_id();

    result.publisher_session_id = publisher->session_id();

    std::optional<std::string> remote_address = remote_address_for_session(result.publisher_session_id);

    if (!remote_address.has_value() || remote_address->empty())
    {
        return make_error("publisher endpoint not found");
    }

    result.publisher_remote_address = *remote_address;

    auto remote_endpoint = find_remote_endpoint(*remote_address);

    if (!remote_endpoint.has_value())
    {
        return make_error("publisher endpoint not found");
    }

    if (!outbound_media_runtime_ready(
            *remote_address, result.publisher_session_id, result.stream_id, media_peer_role::publisher, "keyframe request protect"))
    {
        return make_error("publisher media runtime not ready");
    }

    const std::vector<keyframe_request_media_target> media_targets = collect_keyframe_request_media_targets(stream_id);
    if (media_targets.empty())
    {
        return make_error("publisher media ssrc not found");
    }

    result.media_ssrc_count = static_cast<uint64_t>(media_targets.size());

    for (const auto& media_target : media_targets)
    {
        if (media_target.media_ssrc == 0 || media_target.sender_ssrc == 0)
        {
            result.failed_count += 1;

            continue;
        }

        const keyframe_request_feedback_type feedback_type =
            select_keyframe_request_feedback_type(stream_id, result.publisher_session_id, media_target.mid, media_target.kind);

        if (feedback_type == keyframe_request_feedback_type::none)
        {
            WEBRTC_LOG_DEBUG(
                "keyframe request skipped publisher unsupported stream={} publisher_session={} remote={} mid={} kind={} rid={} repaired_rid={} "
                "sender_ssrc={} media_ssrc={}",
                result.stream_id,
                result.publisher_session_id,
                result.publisher_remote_address,
                media_target.mid,
                media_target.kind,
                media_target.rid.value_or(""),
                media_target.repaired_rid.value_or(""),
                media_target.sender_ssrc,
                media_target.media_ssrc);

            result.failed_count += 1;

            continue;
        }

        auto plain_packet = make_keyframe_request_packet(feedback_type, stream_id, media_target.sender_ssrc, media_target.media_ssrc);

        if (!plain_packet.has_value())
        {
            result.failed_count += 1;

            continue;
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(plain_packet->data(), plain_packet->size()), *remote_address, srtp_packet_kind::rtcp);

        if (!protected_packet)
        {
            result.failed_count += 1;

            WEBRTC_LOG_WARN(
                "keyframe request protect failed stream={} publisher_session={} remote={} feedback={} mid={} kind={} rid={} repaired_rid={} "
                "sender_ssrc={} media_ssrc={} error={}",
                result.stream_id,
                result.publisher_session_id,
                result.publisher_remote_address,
                keyframe_request_feedback_type_to_string(feedback_type),
                media_target.mid,
                media_target.kind,
                media_target.rid.value_or(""),
                media_target.repaired_rid.value_or(""),
                media_target.sender_ssrc,
                media_target.media_ssrc,
                protected_packet.error());

            continue;
        }

        if (protected_packet->state == srtp_packet_process_state::ignored)
        {
            result.failed_count += 1;

            WEBRTC_LOG_DEBUG(
                "keyframe request ignored stream={} publisher_session={} remote={} feedback={} mid={} kind={} rid={} repaired_rid={} "
                "sender_ssrc={} media_ssrc={} reason={}",
                result.stream_id,
                result.publisher_session_id,
                result.publisher_remote_address,
                keyframe_request_feedback_type_to_string(feedback_type),
                media_target.mid,
                media_target.kind,
                media_target.rid.value_or(""),
                media_target.repaired_rid.value_or(""),
                media_target.sender_ssrc,
                media_target.media_ssrc,
                protected_packet->reason);

            continue;
        }

        send_response(std::move(protected_packet->protected_packet), *remote_endpoint);

        WEBRTC_LOG_INFO(
            "keyframe request sent stream={} publisher_session={} remote={} feedback={} mid={} kind={} rid={} repaired_rid={} sender_ssrc={} "
            "media_ssrc={}",
            result.stream_id,
            result.publisher_session_id,
            result.publisher_remote_address,
            keyframe_request_feedback_type_to_string(feedback_type),
            media_target.mid,
            media_target.kind,
            media_target.rid.value_or(""),
            media_target.repaired_rid.value_or(""),
            media_target.sender_ssrc,
            media_target.media_ssrc);

        result.sent_count += 1;
    }

    if (result.sent_count == 0)
    {
        return make_error("keyframe request send failed");
    }

    return result;
}

void ice_udp_server::register_session_removed_callback()
{
    if (registry_ == nullptr || registry_callback_registered_)
    {
        return;
    }

    std::weak_ptr<ice_udp_server> weak_self = weak_from_this();

    registry_->set_session_removed_callback(
        [weak_self](const stream_removed_session& removed_session)
        {
            auto self = weak_self.lock();

            if (self == nullptr)
            {
                return;
            }

            WEBRTC_LOG_INFO("ice udp registry removal callback kind={} stream={} session={} local_ufrag={} remote_ufrag={}",
                            stream_session_kind_to_string(removed_session.kind),
                            removed_session.stream_id,
                            removed_session.session_id,
                            removed_session.local_ice_ufrag,
                            removed_session.remote_ice_ufrag);

            self->retire_removed_session_ice_credentials(removed_session, "registry removal callback");

            if (removed_session.kind == stream_session_kind::publisher)
            {
                self->forget_publisher_runtime_state_preserving_subscribers(
                    removed_session.stream_id, removed_session.session_id, "publisher removal callback");
                self->mark_publisher_absent_for_stream(removed_session.stream_id, "publisher removal callback");
            }
            else if (removed_session.kind == stream_session_kind::subscriber)
            {
                self->send_rtcp_bye_for_removed_session(removed_session);

                self->forget_republish_keyframe_request_pending_for_subscriber(removed_session.stream_id, removed_session.session_id);

                self->forget_session(removed_session.session_id);

                self->schedule_subscriber_runtime_residual_check(removed_session.stream_id, removed_session.session_id);
            }

            self->schedule_lifecycle_snapshot_log("registry removal callback", removed_session.stream_id, removed_session.session_id);
        });

    registry_->set_session_ice_restart_callback(
        [weak_self](const stream_restarted_session& restarted_session)
        {
            auto self = weak_self.lock();

            if (self == nullptr)
            {
                return;
            }

            WEBRTC_LOG_INFO(
                "ice udp registry ice restart callback kind={} stream={} session={} old_local_ufrag={} old_remote_ufrag={} new_local_ufrag={} "
                "new_remote_ufrag={}",
                stream_session_kind_to_string(restarted_session.kind),
                restarted_session.stream_id,
                restarted_session.session_id,
                restarted_session.old_local_ice_ufrag,
                restarted_session.old_remote_ice_ufrag,
                restarted_session.new_local_ice_ufrag,
                restarted_session.new_remote_ice_ufrag);

            self->retire_restarted_session_ice_credentials(restarted_session, "ice restart callback");

            self->retire_session_endpoint_for_ice_restart(restarted_session, "ice restart callback");

            if (restarted_session.kind == stream_session_kind::subscriber)
            {
                self->mark_subscriber_downlink_ice_restart_grace_for_session(restarted_session.stream_id, restarted_session.session_id);

                self->forget_keyframe_request_states_for_session(restarted_session.session_id);
            }

            self->schedule_lifecycle_snapshot_log("ice restart callback", restarted_session.stream_id, restarted_session.session_id);
        });
    registry_->set_publisher_republish_callback(
        [weak_self](const stream_republished_session& republished_session)
        {
            auto self = weak_self.lock();

            if (self == nullptr)
            {
                return;
            }

            WEBRTC_LOG_INFO(
                "ice udp registry publisher republish callback stream={} old_session={} new_session={} "
                "old_local_ufrag={} old_remote_ufrag={} new_local_ufrag={} new_remote_ufrag={}",
                republished_session.stream_id,
                republished_session.old_session_id,
                republished_session.new_session_id,
                republished_session.old_local_ice_ufrag,
                republished_session.old_remote_ice_ufrag,
                republished_session.new_local_ice_ufrag,
                republished_session.new_remote_ice_ufrag);

            self->retire_republished_publisher_ice_credentials(republished_session, "publisher republish callback");

            self->retire_old_publisher_endpoint_for_republish(republished_session, "publisher republish callback");

            self->forget_publisher_absent_for_stream(republished_session.stream_id, "publisher republish callback");

            self->forget_publisher_runtime_state_preserving_subscribers(
                republished_session.stream_id, republished_session.old_session_id, "publisher republish callback");

            self->mark_subscriber_downlink_republish_grace_for_stream(republished_session.stream_id, republished_session.new_session_id);

            self->mark_republish_keyframe_request_pending(republished_session.stream_id, republished_session.new_session_id);

            self->schedule_lifecycle_snapshot_log("publisher republish callback", republished_session.stream_id, republished_session.old_session_id);
        });
    registry_->set_subscriber_reconnect_callback(
        [weak_self](const stream_reconnected_session& reconnected_session)
        {
            auto self = weak_self.lock();

            if (self == nullptr)
            {
                return;
            }

            WEBRTC_LOG_INFO(
                "ice udp registry subscriber reconnect callback stream={} old_session={} new_session={} "
                "old_local_ufrag={} old_remote_ufrag={} new_local_ufrag={} new_remote_ufrag={}",
                reconnected_session.stream_id,
                reconnected_session.old_session_id,
                reconnected_session.new_session_id,
                reconnected_session.old_local_ice_ufrag,
                reconnected_session.old_remote_ice_ufrag,
                reconnected_session.new_local_ice_ufrag,
                reconnected_session.new_remote_ice_ufrag);

            stream_removed_session removed_subscriber;
            removed_subscriber.kind = stream_session_kind::subscriber;
            removed_subscriber.stream_id = reconnected_session.stream_id;
            removed_subscriber.session_id = reconnected_session.old_session_id;
            removed_subscriber.local_ice_ufrag = reconnected_session.old_local_ice_ufrag;
            removed_subscriber.remote_ice_ufrag = reconnected_session.old_remote_ice_ufrag;

            self->retire_removed_session_ice_credentials(removed_subscriber, "subscriber reconnect callback");
            self->send_rtcp_bye_for_removed_session(removed_subscriber);

            self->forget_republish_keyframe_request_pending_for_subscriber(reconnected_session.stream_id, reconnected_session.old_session_id);

            self->forget_session(reconnected_session.old_session_id);

            self->schedule_subscriber_runtime_residual_check(reconnected_session.stream_id, reconnected_session.old_session_id);

            self->schedule_lifecycle_snapshot_log("subscriber reconnect callback", reconnected_session.stream_id, reconnected_session.old_session_id);
        });
    registry_callback_registered_ = true;
}

void ice_udp_server::do_receive()
{
    if (!started_)
    {
        return;
    }

    auto self = shared_from_this();

    socket_.async_receive_from(boost::asio::buffer(receive_buffer_),
                               remote_endpoint_,
                               [this, self](boost::system::error_code ec, std::size_t bytes_transferred) { on_receive(ec, bytes_transferred); });
}

void ice_udp_server::on_receive(boost::system::error_code ec, std::size_t bytes_transferred)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("ice udp receive failed: {}", ec.message());

        do_receive();

        return;
    }

    std::span<const uint8_t> packet(receive_buffer_.data(), bytes_transferred);

    const std::string remote_address = endpoint_to_string(remote_endpoint_);

    const bool packet_is_stun = is_stun_packet(packet);

    if (!packet_is_stun)
    {
        const bool packet_is_dtls = is_dtls_packet(packet);

        const bool packet_is_rtp_or_rtcp = !packet_is_dtls && is_rtp_or_rtcp_packet(packet);

        std::string_view packet_kind = "unknown";

        if (packet_is_dtls)
        {
            packet_kind = "dtls";
        }
        else if (packet_is_rtp_or_rtcp)
        {
            packet_kind = "srtp";
        }

        if (suppress_retired_endpoint_packet(remote_address, packet_kind))
        {
            do_receive();

            return;
        }

        if (packet_is_dtls)
        {
            handle_dtls_packet(packet, remote_endpoint_);
        }
        else if (packet_is_rtp_or_rtcp)
        {
            handle_rtp_or_rtcp_packet(packet, remote_endpoint_);
        }
        else
        {
            WEBRTC_LOG_DEBUG("ice udp unknown packet remote={} size={} first_byte={}",
                             remote_address,
                             bytes_transferred,
                             bytes_transferred == 0 ? 0U : static_cast<unsigned int>(receive_buffer_[0]));
        }

        do_receive();

        return;
    }

    handle_stun_packet(packet, remote_endpoint_);

    do_receive();
}

void ice_udp_server::schedule_dtls_timeout()
{
    if (!started_ || dtls_transport_ == nullptr)
    {
        return;
    }

    dtls_timeout_timer_.cancel();

    auto timeout = dtls_transport_->next_timeout();

    if (!timeout.has_value())
    {
        return;
    }

    const auto delay = std::max(*timeout, k_minimum_dtls_timer_delay);

    dtls_timeout_timer_.expires_after(delay);

    auto self = shared_from_this();

    dtls_timeout_timer_.async_wait([this, self](boost::system::error_code ec) { on_dtls_timeout(ec); });

    WEBRTC_LOG_DEBUG("dtls timeout timer scheduled delay_ms={}", delay.count());
}

void ice_udp_server::on_dtls_timeout(boost::system::error_code ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("dtls timeout timer failed: {}", ec.message());

        schedule_dtls_timeout();

        return;
    }

    if (!started_ || dtls_transport_ == nullptr)
    {
        return;
    }

    auto events = dtls_transport_->handle_timeouts();

    for (auto& event : events)
    {
        if (event.peer_failed)
        {
            WEBRTC_LOG_WARN("dtls timeout peer failed remote={} error={}", event.remote_endpoint, event.error);

            forget_peer_endpoint(event.remote_endpoint);

            continue;
        }

        const current_session_endpoint_state current_session = find_current_session_endpoint(event.remote_endpoint, "dtls retransmit");

        if (!current_session.allowed)
        {
            WEBRTC_LOG_DEBUG("dtls retransmit ignored by current session gate remote={} session={} packets={} reason={}",
                             event.remote_endpoint,
                             current_session.session_id,
                             event.packets.size(),
                             current_session.reject_reason);

            forget_peer_transport_state(event.remote_endpoint);

            continue;
        }

        auto remote_endpoint = find_remote_endpoint(event.remote_endpoint);

        if (!remote_endpoint.has_value())
        {
            WEBRTC_LOG_WARN("dtls retransmit endpoint not found remote={} session={} packets={}",
                            event.remote_endpoint,
                            current_session.session_id,
                            event.packets.size());

            forget_peer_transport_state(event.remote_endpoint);

            continue;
        }

        for (auto& packet : event.packets)
        {
            const current_session_endpoint_state send_session = validate_current_session_endpoint(
                event.remote_endpoint, current_session.session_id, current_session.stream_id, "dtls retransmit send");

            if (!send_session.allowed)
            {
                WEBRTC_LOG_DEBUG("dtls retransmit send skipped by current session gate remote={} session={} size={} reason={}",
                                 event.remote_endpoint,
                                 current_session.session_id,
                                 packet.size(),
                                 send_session.reject_reason);

                forget_peer_transport_state(event.remote_endpoint);

                break;
            }

            WEBRTC_LOG_DEBUG("dtls retransmit packet remote={} session={} size={}", event.remote_endpoint, current_session.session_id, packet.size());

            send_response(std::move(packet), *remote_endpoint);
        }
    }

    schedule_dtls_timeout();
}

void ice_udp_server::schedule_ice_consent_check()
{
    if (!started_)
    {
        return;
    }

    ice_consent_timer_.cancel();

    ice_consent_timer_.expires_after(ice_udp_server_runtime_config_instance().ice_consent_check_interval);
    auto self = shared_from_this();

    ice_consent_timer_.async_wait([this, self](boost::system::error_code ec) { on_ice_consent_check(ec); });
}

void ice_udp_server::on_ice_consent_check(boost::system::error_code ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("ice consent timer failed error={}", ec.message());

        schedule_ice_consent_check();

        return;
    }

    if (!started_)
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    {
        std::lock_guard lock(endpoint_mutex_);

        const std::size_t expired_selected_rid_keyframe_pending_count =
            expire_selected_rid_keyframe_request_pending_locked(current_time_milliseconds);

        if (expired_selected_rid_keyframe_pending_count != 0)
        {
            WEBRTC_LOG_WARN("simulcast selected rid keyframe pending expired count={}", expired_selected_rid_keyframe_pending_count);
        }
    }

    send_ice_consent_requests(current_time_milliseconds);

    std::vector<ice_consent_timeout_event> timeout_events = collect_expired_ice_consent_timeout_events(current_time_milliseconds);

    for (const auto& event : timeout_events)
    {
        expire_ice_consent_session(event);
    }

    cleanup_unselected_candidate_pairs(current_time_milliseconds);

    schedule_ice_consent_check();
}

void ice_udp_server::schedule_rtcp_report()
{
    if (!started_)
    {
        return;
    }

    rtcp_report_timer_.cancel();

    rtcp_report_timer_.expires_after(ice_udp_server_runtime_config_instance().rtcp_report_timer_interval);
    auto self = shared_from_this();

    rtcp_report_timer_.async_wait([this, self](boost::system::error_code ec) { on_rtcp_report_timer(ec); });
}

void ice_udp_server::on_rtcp_report_timer(boost::system::error_code ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("rtcp report timer failed: {}", ec.message());

        schedule_rtcp_report();

        return;
    }

    if (!started_)
    {
        return;
    }

    send_rtcp_reports(now_milliseconds());

    schedule_rtcp_report();
}

void ice_udp_server::send_rtcp_reports(uint64_t current_time_milliseconds)
{
    if (rtcp_report_service_ == nullptr || srtp_transport_ == nullptr)
    {
        return;
    }

    rtcp_report_service_generation generation = rtcp_report_service_->generate_reports(current_time_milliseconds);

    if (!generation.errors.empty())
    {
        for (const auto& error : generation.errors)
        {
            WEBRTC_LOG_WARN("rtcp active report generation error={}", error);
        }
    }

    if (generation.packets.empty())
    {
        const rtcp_report_service_runtime_snapshot snapshot = rtcp_report_runtime_snapshot();
        if (generation.stale_sources_expired != 0)
        {
            last_empty_rtcp_report_log_milliseconds_ = current_time_milliseconds;

            WEBRTC_LOG_INFO("rtcp active report stale cleanup {} runtime={}",
                            rtcp_report_service_generation_to_string(generation),
                            rtcp_report_service_runtime_snapshot_to_string(snapshot));

            return;
        }

        if (should_log_empty_rtcp_generation(generation, current_time_milliseconds, last_empty_rtcp_report_log_milliseconds_))
        {
            last_empty_rtcp_report_log_milliseconds_ = current_time_milliseconds;

            WEBRTC_LOG_DEBUG("rtcp active report generation empty {} runtime={}",
                             rtcp_report_service_generation_to_string(generation),
                             rtcp_report_service_runtime_snapshot_to_string(snapshot));
        }

        return;
    }

    last_empty_rtcp_report_log_milliseconds_ = current_time_milliseconds;

    std::size_t sent_count = 0;
    std::size_t endpoint_not_found_count = 0;
    std::size_t protect_failed_count = 0;
    std::size_t protect_ignored_count = 0;
    std::size_t current_session_gate_skipped_count = 0;

    for (const auto& report_packet : generation.packets)
    {
        rtcp_report_send_attempts_total_.fetch_add(1, std::memory_order_relaxed);

        const current_session_endpoint_state current_session = validate_current_session_endpoint(
            report_packet.source.remote_endpoint, report_packet.source.session_id, report_packet.source.stream_id, "rtcp active report");

        if (!current_session.allowed)
        {
            current_session_gate_skipped_count += 1;
            rtp_rtcp_drop_rtcp_report_session_gate_total_.fetch_add(1, std::memory_order_relaxed);

            rtcp_report_service_->forget_source(
                report_packet.source.session_id, report_packet.source.remote_endpoint, report_packet.source.local_ssrc);

            WEBRTC_LOG_DEBUG("rtcp active report source forgotten by current session gate stream={} session={} remote={} local_ssrc={} reason={}",
                             report_packet.source.stream_id,
                             report_packet.source.session_id,
                             report_packet.source.remote_endpoint,
                             report_packet.source.local_ssrc,
                             current_session.reject_reason);

            continue;
        }

        auto remote_endpoint = find_remote_endpoint(report_packet.source.remote_endpoint);
        if (!remote_endpoint.has_value())
        {
            endpoint_not_found_count += 1;

            rtcp_report_endpoint_not_found_total_.fetch_add(1, std::memory_order_relaxed);

            rtcp_report_service_->forget_source(
                report_packet.source.session_id, report_packet.source.remote_endpoint, report_packet.source.local_ssrc);

            WEBRTC_LOG_WARN("rtcp active report endpoint not found stream={} session={} remote={} local_ssrc={} source_forgot=1",
                            report_packet.source.stream_id,
                            report_packet.source.session_id,
                            report_packet.source.remote_endpoint,
                            report_packet.source.local_ssrc);

            continue;
        }

        media_peer_role report_peer_role = media_peer_role::subscriber;

        if (current_session.kind == stream_session_kind::publisher)
        {
            report_peer_role = media_peer_role::publisher;
        }
        else if (current_session.kind == stream_session_kind::subscriber)
        {
            report_peer_role = media_peer_role::subscriber;
        }
        else
        {
            current_session_gate_skipped_count += 1;
            rtp_rtcp_drop_rtcp_report_session_gate_total_.fetch_add(1, std::memory_order_relaxed);

            rtcp_report_service_->forget_source(
                report_packet.source.session_id, report_packet.source.remote_endpoint, report_packet.source.local_ssrc);

            WEBRTC_LOG_DEBUG("rtcp active report protect skipped unknown session kind stream={} session={} remote={} local_ssrc={} source_forgot=1",
                             report_packet.source.stream_id,
                             report_packet.source.session_id,
                             report_packet.source.remote_endpoint,
                             report_packet.source.local_ssrc);

            continue;
        }

        if (!outbound_media_runtime_ready(report_packet.source.remote_endpoint,
                                          report_packet.source.session_id,
                                          report_packet.source.stream_id,
                                          report_peer_role,
                                          "rtcp active report protect"))
        {
            current_session_gate_skipped_count += 1;
            rtp_rtcp_drop_rtcp_report_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);

            rtcp_report_service_->forget_source(
                report_packet.source.session_id, report_packet.source.remote_endpoint, report_packet.source.local_ssrc);

            WEBRTC_LOG_DEBUG(
                "rtcp active report protect skipped outbound runtime not ready stream={} session={} remote={} role={} local_ssrc={} source_forgot=1",
                report_packet.source.stream_id,
                report_packet.source.session_id,
                report_packet.source.remote_endpoint,
                media_peer_role_to_string(report_peer_role),
                report_packet.source.local_ssrc);

            continue;
        }
        if (registry_ == nullptr || !rtcp_report_source_matches_current_accepted_media(*registry_, current_session, report_packet.source))
        {
            current_session_gate_skipped_count += 1;

            rtp_rtcp_drop_rtcp_report_session_gate_total_.fetch_add(1, std::memory_order_relaxed);

            rtcp_report_service_->forget_source(
                report_packet.source.session_id, report_packet.source.remote_endpoint, report_packet.source.local_ssrc);

            WEBRTC_LOG_DEBUG(
                "rtcp active report source forgotten by accepted media gate stream={} session={} remote={} mid={} kind={} local_ssrc={} "
                "source_forgot=1",
                report_packet.source.stream_id,
                report_packet.source.session_id,
                report_packet.source.remote_endpoint,
                report_packet.source.mid,
                report_packet.source.kind,
                report_packet.source.local_ssrc);

            continue;
        }
        auto protected_packet =
            srtp_transport_->protect_outbound_packet(std::span<const uint8_t>(report_packet.report.packet.data(), report_packet.report.packet.size()),
                                                     report_packet.source.remote_endpoint,
                                                     srtp_packet_kind::rtcp);
        if (!protected_packet)
        {
            protect_failed_count += 1;

            rtcp_report_protect_failed_total_.fetch_add(1, std::memory_order_relaxed);

            WEBRTC_LOG_WARN("rtcp active report protect failed stream={} session={} remote={} local_ssrc={} error={}",
                            report_packet.source.stream_id,
                            report_packet.source.session_id,
                            report_packet.source.remote_endpoint,
                            report_packet.source.local_ssrc,
                            protected_packet.error());

            continue;
        }

        if (protected_packet->state == srtp_packet_process_state::ignored)
        {
            protect_ignored_count += 1;

            rtcp_report_protect_ignored_total_.fetch_add(1, std::memory_order_relaxed);

            WEBRTC_LOG_DEBUG("rtcp active report protect ignored stream={} session={} remote={} local_ssrc={} reason={}",
                             report_packet.source.stream_id,
                             report_packet.source.session_id,
                             report_packet.source.remote_endpoint,
                             report_packet.source.local_ssrc,
                             protected_packet->reason);

            continue;
        }

        const current_session_endpoint_state send_session = validate_current_session_endpoint(
            report_packet.source.remote_endpoint, report_packet.source.session_id, report_packet.source.stream_id, "rtcp active report send");

        if (!send_session.allowed)
        {
            current_session_gate_skipped_count += 1;
            rtp_rtcp_drop_rtcp_report_session_gate_total_.fetch_add(1, std::memory_order_relaxed);

            rtcp_report_service_->forget_source(
                report_packet.source.session_id, report_packet.source.remote_endpoint, report_packet.source.local_ssrc);

            WEBRTC_LOG_DEBUG("rtcp active report send skipped by current session gate stream={} session={} remote={} local_ssrc={} reason={}",
                             report_packet.source.stream_id,
                             report_packet.source.session_id,
                             report_packet.source.remote_endpoint,
                             report_packet.source.local_ssrc,
                             send_session.reject_reason);

            continue;
        }

        WEBRTC_LOG_DEBUG("rtcp active report send stream={} session={} remote={} local_ssrc={} report={} protected_size={}",
                         report_packet.source.stream_id,
                         report_packet.source.session_id,
                         report_packet.source.remote_endpoint,
                         report_packet.source.local_ssrc,
                         rtcp_report_generation_result_to_string(report_packet.report),
                         protected_packet->protected_packet.size());

        send_response(std::move(protected_packet->protected_packet), *remote_endpoint);
        sent_count += 1;

        rtcp_report_send_success_total_.fetch_add(1, std::memory_order_relaxed);
    }

    const rtcp_report_service_runtime_snapshot snapshot = rtcp_report_runtime_snapshot();

    const bool has_hard_error = generation.failed != 0 || !generation.errors.empty() || endpoint_not_found_count != 0 || protect_failed_count != 0;

    const bool has_soft_event = generation.skipped != 0 || generation.throttled_sources != 0 || generation.stale_sources_expired != 0 ||
                                protect_ignored_count != 0 || current_session_gate_skipped_count != 0;

    if (has_hard_error)
    {
        WEBRTC_LOG_WARN(
            "rtcp active report generation summary {} sent={} endpoint_not_found={} protect_failed={} protect_ignored={} "
            "current_session_gate_skipped={} runtime={} ",
            rtcp_report_service_generation_to_string(generation),
            sent_count,
            endpoint_not_found_count,
            protect_failed_count,
            protect_ignored_count,
            current_session_gate_skipped_count,
            rtcp_report_service_runtime_snapshot_to_string(snapshot));

        return;
    }

    if (has_soft_event)
    {
        WEBRTC_LOG_INFO(
            "rtcp active report generation summary {} sent={} endpoint_not_found={} protect_failed={} protect_ignored={} "
            "current_session_gate_skipped={} runtime={}",
            rtcp_report_service_generation_to_string(generation),
            sent_count,
            endpoint_not_found_count,
            protect_failed_count,
            protect_ignored_count,
            current_session_gate_skipped_count,
            rtcp_report_service_runtime_snapshot_to_string(snapshot));

        return;
    }

    WEBRTC_LOG_DEBUG(
        "rtcp active report generation summary {} sent={} endpoint_not_found={} protect_failed={} protect_ignored={}  "
        "current_session_gate_skipped={} runtime={}",
        rtcp_report_service_generation_to_string(generation),
        sent_count,
        endpoint_not_found_count,
        protect_failed_count,
        protect_ignored_count,
        current_session_gate_skipped_count,
        rtcp_report_service_runtime_snapshot_to_string(snapshot));
}

void ice_udp_server::schedule_rtcp_transport_cc_feedback()
{
    if (!started_)
    {
        return;
    }

    rtcp_transport_cc_feedback_timer_.cancel();

    rtcp_transport_cc_feedback_timer_.expires_after(std::chrono::milliseconds(100));

    auto self = shared_from_this();

    rtcp_transport_cc_feedback_timer_.async_wait([this, self](boost::system::error_code ec) { on_rtcp_transport_cc_feedback_timer(ec); });
}

void ice_udp_server::on_rtcp_transport_cc_feedback_timer(boost::system::error_code ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("rtcp transport cc timer failed: {}", ec.message());

        schedule_rtcp_transport_cc_feedback();

        return;
    }

    if (!started_)
    {
        return;
    }

    send_rtcp_transport_cc_feedback(now_milliseconds());

    schedule_rtcp_transport_cc_feedback();
}

void ice_udp_server::send_rtcp_transport_cc_feedback(uint64_t current_time_milliseconds)
{
    if (rtcp_transport_cc_feedback_service_ == nullptr || srtp_transport_ == nullptr)
    {
        return;
    }

    rtcp_transport_cc_feedback_generation generation = rtcp_transport_cc_feedback_service_->generate_due_feedback(current_time_milliseconds);

    if (!generation.errors.empty())
    {
        for (const auto& error : generation.errors)
        {
            WEBRTC_LOG_DEBUG("rtcp transport cc generation error={}", error);
        }
    }

    if (generation.packets.empty())
    {
        return;
    }

    std::size_t sent_count = 0;
    std::size_t endpoint_not_found_count = 0;
    std::size_t protect_failed_count = 0;
    std::size_t protect_ignored_count = 0;
    std::size_t current_session_gate_skipped_count = 0;
    std::size_t identity_gate_skipped_count = 0;
    std::size_t send_session_gate_skipped_count = 0;

    for (const auto& feedback_packet : generation.packets)
    {
        const current_session_endpoint_state current_session = validate_current_session_endpoint(
            feedback_packet.remote_endpoint, feedback_packet.session_id, feedback_packet.stream_id, "rtcp transport cc feedback");

        if (!current_session.allowed)
        {
            current_session_gate_skipped_count += 1;
            rtp_rtcp_drop_rtcp_report_session_gate_total_.fetch_add(1, std::memory_order_relaxed);
            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG("rtcp transport cc source forgotten by current session gate stream={} session={} remote={} media_ssrc={} reason={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.media_ssrc,
                             current_session.reject_reason);

            continue;
        }

        if (identity_authority_ == nullptr)
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG("rtcp transport cc source forgotten identity authority unavailable stream={} session={} remote={} media_ssrc={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.media_ssrc);

            continue;
        }

        const std::optional<media_identity_track_binding> track_binding =
            identity_authority_->find_track_by_peer_ssrc(feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

        if (!track_binding.has_value())
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG("rtcp transport cc source forgotten missing media identity stream={} session={} remote={} sender_ssrc={} media_ssrc={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.sender_ssrc,
                             feedback_packet.media_ssrc);

            continue;
        }
        if (feedback_packet.mid.empty() || feedback_packet.kind.empty())
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG(
                "rtcp transport cc source forgotten incomplete feedback identity stream={} session={} remote={} media_ssrc={} mid={} kind={}",
                feedback_packet.stream_id,
                feedback_packet.session_id,
                feedback_packet.remote_endpoint,
                feedback_packet.media_ssrc,
                feedback_packet.mid,
                feedback_packet.kind);

            continue;
        }
        if (track_binding->stream_id != feedback_packet.stream_id || track_binding->session_id != feedback_packet.session_id ||
            track_binding->remote_endpoint != feedback_packet.remote_endpoint || track_binding->ssrc != feedback_packet.media_ssrc ||
            track_binding->mid != feedback_packet.mid || track_binding->kind != feedback_packet.kind)
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_WARN(
                "rtcp transport cc source forgotten identity mismatch stream={} session={} remote={} sender_ssrc={} media_ssrc={} mid={} kind={} "
                "binding_stream={} binding_session={} binding_remote={} binding_ssrc={} binding_mid={} binding_kind={}",
                feedback_packet.stream_id,
                feedback_packet.session_id,
                feedback_packet.remote_endpoint,
                feedback_packet.sender_ssrc,
                feedback_packet.media_ssrc,
                feedback_packet.mid,
                feedback_packet.kind,
                track_binding->stream_id,
                track_binding->session_id,
                track_binding->remote_endpoint,
                track_binding->ssrc,
                track_binding->mid,
                track_binding->kind);
            continue;
        }

        if (track_binding->rtx)
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG("rtcp transport cc source forgotten rtx identity stream={} session={} remote={} media_ssrc={} mid={} kind={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.media_ssrc,
                             track_binding->mid,
                             track_binding->kind);

            continue;
        }

        if (track_binding->mid.empty() || track_binding->kind.empty())
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG("rtcp transport cc source forgotten incomplete identity stream={} session={} remote={} media_ssrc={} mid={} kind={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.media_ssrc,
                             track_binding->mid,
                             track_binding->kind);

            continue;
        }

        if (current_session.kind != stream_session_kind::publisher)
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_WARN("rtcp transport cc source forgotten non publisher session stream={} session={} remote={} media_ssrc={}",
                            feedback_packet.stream_id,
                            feedback_packet.session_id,
                            feedback_packet.remote_endpoint,
                            feedback_packet.media_ssrc);

            continue;
        }
        media_peer_info feedback_peer;

        feedback_peer.role = media_peer_role::publisher;

        feedback_peer.stream_id = current_session.stream_id;

        feedback_peer.session_id = current_session.session_id;

        feedback_peer.remote_endpoint = current_session.remote_address;

        const uint32_t expected_sender_ssrc = make_rtcp_report_local_ssrc(feedback_peer, feedback_packet.media_ssrc);
        if (expected_sender_ssrc != 0 && feedback_packet.sender_ssrc != expected_sender_ssrc)
        {
            identity_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_WARN(
                "rtcp transport cc source forgotten sender ssrc mismatch stream={} session={} remote={} media_ssrc={} sender_ssrc={} "
                "expected_sender_ssrc={} mid={} kind={}",
                feedback_packet.stream_id,
                feedback_packet.session_id,
                feedback_packet.remote_endpoint,
                feedback_packet.media_ssrc,
                feedback_packet.sender_ssrc,
                expected_sender_ssrc,
                track_binding->mid,
                track_binding->kind);

            continue;
        }

        auto remote_endpoint = find_remote_endpoint(feedback_packet.remote_endpoint);

        if (!remote_endpoint.has_value())
        {
            endpoint_not_found_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_WARN("rtcp transport cc endpoint not found stream={} session={} remote={} media_ssrc={} source_forgot=1",
                            feedback_packet.stream_id,
                            feedback_packet.session_id,
                            feedback_packet.remote_endpoint,
                            feedback_packet.media_ssrc);

            continue;
        }

        if (!outbound_media_runtime_ready(feedback_packet.remote_endpoint,
                                          feedback_packet.session_id,
                                          feedback_packet.stream_id,
                                          media_peer_role::publisher,
                                          "rtcp transport cc feedback protect"))
        {
            send_session_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG(
                "rtcp transport cc protect skipped outbound runtime not ready stream={} session={} remote={} media_ssrc={} mid={} kind={}",
                feedback_packet.stream_id,
                feedback_packet.session_id,
                feedback_packet.remote_endpoint,
                feedback_packet.media_ssrc,
                track_binding->mid,
                track_binding->kind);

            continue;
        }

        auto protected_packet =
            srtp_transport_->protect_outbound_packet(std::span<const uint8_t>(feedback_packet.packet.data(), feedback_packet.packet.size()),
                                                     feedback_packet.remote_endpoint,
                                                     srtp_packet_kind::rtcp);
        if (!protected_packet)
        {
            protect_failed_count += 1;

            WEBRTC_LOG_DEBUG(
                "rtcp transport cc protect failed stream={} session={} remote={} media_ssrc={} mid={} kind={} base_seq={} count={} error={}",
                feedback_packet.stream_id,
                feedback_packet.session_id,
                feedback_packet.remote_endpoint,
                feedback_packet.media_ssrc,
                track_binding->mid,
                track_binding->kind,
                feedback_packet.base_sequence_number,
                feedback_packet.packet_status_count,
                protected_packet.error());

            continue;
        }

        if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
        {
            protect_ignored_count += 1;

            WEBRTC_LOG_DEBUG("rtcp transport cc protect ignored stream={} session={} remote={} media_ssrc={} mid={} kind={} reason={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.media_ssrc,
                             track_binding->mid,
                             track_binding->kind,
                             protected_packet->reason);

            continue;
        }

        const current_session_endpoint_state send_session = validate_current_session_endpoint(
            feedback_packet.remote_endpoint, feedback_packet.session_id, feedback_packet.stream_id, "rtcp transport cc feedback send");

        if (!send_session.allowed)
        {
            send_session_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_source(
                feedback_packet.session_id, feedback_packet.remote_endpoint, feedback_packet.media_ssrc);

            WEBRTC_LOG_DEBUG("rtcp transport cc send skipped by current session gate stream={} session={} remote={} media_ssrc={} reason={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.media_ssrc,
                             send_session.reject_reason);

            continue;
        }

        WEBRTC_LOG_DEBUG(
            "rtcp transport cc send stream={} session={} remote={} sender_ssrc={} media_ssrc={} mid={} kind={} base_seq={} count={} "
            "feedback_count={} protected_size={}",
            feedback_packet.stream_id,
            feedback_packet.session_id,
            feedback_packet.remote_endpoint,
            feedback_packet.sender_ssrc,
            feedback_packet.media_ssrc,
            track_binding->mid,
            track_binding->kind,
            feedback_packet.base_sequence_number,
            feedback_packet.packet_status_count,
            static_cast<unsigned int>(feedback_packet.feedback_packet_count),
            protected_packet->protected_packet.size());

        send_response(std::move(protected_packet->protected_packet), *remote_endpoint);

        sent_count += 1;
    }

    rtp_rtcp_drop_twcc_session_gate_total_.fetch_add(static_cast<uint64_t>(current_session_gate_skipped_count), std::memory_order_relaxed);
    rtp_rtcp_drop_twcc_identity_gate_total_.fetch_add(static_cast<uint64_t>(identity_gate_skipped_count), std::memory_order_relaxed);
    rtp_rtcp_drop_twcc_send_runtime_gate_total_.fetch_add(static_cast<uint64_t>(send_session_gate_skipped_count), std::memory_order_relaxed);
    rtp_rtcp_drop_twcc_endpoint_missing_total_.fetch_add(static_cast<uint64_t>(endpoint_not_found_count), std::memory_order_relaxed);
    rtp_rtcp_drop_twcc_protect_failed_total_.fetch_add(static_cast<uint64_t>(protect_failed_count), std::memory_order_relaxed);
    rtp_rtcp_drop_twcc_protect_ignored_total_.fetch_add(static_cast<uint64_t>(protect_ignored_count), std::memory_order_relaxed);
    const bool has_hard_error = !generation.errors.empty() || endpoint_not_found_count != 0 || protect_failed_count != 0;

    const bool has_soft_event = generation.stale_sources_expired != 0 || generation.skipped_sources != 0 || protect_ignored_count != 0 ||
                                current_session_gate_skipped_count != 0 || identity_gate_skipped_count != 0 || send_session_gate_skipped_count != 0;

    if (has_hard_error)
    {
        WEBRTC_LOG_WARN(
            "rtcp transport cc generation summary sources={} pending={} packets={} sent={} stale_expired={} skipped_sources={} "
            "current_session_gate_skipped={} identity_gate_skipped={} send_session_gate_skipped={} endpoint_not_found={} protect_failed={} "
            "protect_ignored={} errors={}",
            generation.source_count,
            generation.pending_packet_count,
            generation.packets.size(),
            sent_count,
            generation.stale_sources_expired,
            generation.skipped_sources,
            current_session_gate_skipped_count,
            identity_gate_skipped_count,
            send_session_gate_skipped_count,
            endpoint_not_found_count,
            protect_failed_count,
            protect_ignored_count,
            generation.errors.size());

        return;
    }

    if (has_soft_event)
    {
        WEBRTC_LOG_INFO(
            "rtcp transport cc generation summary sources={} pending={} packets={} sent={} stale_expired={} skipped_sources={} "
            "current_session_gate_skipped={} identity_gate_skipped={} send_session_gate_skipped={} endpoint_not_found={} protect_failed={} "
            "protect_ignored={} errors={}",
            generation.source_count,
            generation.pending_packet_count,
            generation.packets.size(),
            sent_count,
            generation.stale_sources_expired,
            generation.skipped_sources,
            current_session_gate_skipped_count,
            identity_gate_skipped_count,
            send_session_gate_skipped_count,
            endpoint_not_found_count,
            protect_failed_count,
            protect_ignored_count,
            generation.errors.size());

        return;
    }

    WEBRTC_LOG_DEBUG(
        "rtcp transport cc generation summary sources={} pending={} packets={} sent={} stale_expired={} skipped_sources={} "
        "current_session_gate_skipped={} identity_gate_skipped={} send_session_gate_skipped={} endpoint_not_found={} protect_failed={} "
        "protect_ignored={} errors={}",
        generation.source_count,
        generation.pending_packet_count,
        generation.packets.size(),
        sent_count,
        generation.stale_sources_expired,
        generation.skipped_sources,
        current_session_gate_skipped_count,
        identity_gate_skipped_count,
        send_session_gate_skipped_count,
        endpoint_not_found_count,
        protect_failed_count,
        protect_ignored_count,
        generation.errors.size());
}

void ice_udp_server::reset_rtcp_report_runtime_counters()
{
    rtcp_report_inbound_rtcp_observe_attempts_total_.store(0, std::memory_order_relaxed);

    rtcp_report_inbound_rtcp_observe_failed_total_.store(0, std::memory_order_relaxed);

    rtcp_report_inbound_sender_report_sources_total_.store(0, std::memory_order_relaxed);

    rtcp_report_remember_source_attempts_total_.store(0, std::memory_order_relaxed);

    rtcp_report_remember_source_success_total_.store(0, std::memory_order_relaxed);

    rtcp_report_remember_source_failed_total_.store(0, std::memory_order_relaxed);

    rtcp_report_send_attempts_total_.store(0, std::memory_order_relaxed);

    rtcp_report_send_success_total_.store(0, std::memory_order_relaxed);

    rtcp_report_endpoint_not_found_total_.store(0, std::memory_order_relaxed);

    rtcp_report_protect_failed_total_.store(0, std::memory_order_relaxed);

    rtcp_report_protect_ignored_total_.store(0, std::memory_order_relaxed);
}
std::optional<std::string> ice_udp_server::remote_ice_password_for_session(std::string_view session_id) const
{
    if (registry_ == nullptr || session_id.empty())
    {
        return std::nullopt;
    }

    auto publisher = registry_->find_publisher_by_session_id(session_id);

    if (publisher != nullptr)
    {
        const auto& password = publisher->remote_offer_summary().ice_pwd;

        if (password.empty())
        {
            return std::nullopt;
        }

        return password;
    }

    auto subscriber = registry_->find_subscriber_by_session_id(session_id);

    if (subscriber != nullptr)
    {
        const auto& password = subscriber->remote_offer_summary().ice_pwd;

        if (password.empty())
        {
            return std::nullopt;
        }

        return password;
    }

    return std::nullopt;
}

bool ice_udp_server::remember_ice_consent_success_locked(std::string_view remote_address,
                                                         const std::array<uint8_t, 12>& transaction_id,
                                                         uint64_t current_time_milliseconds)
{
    if (remote_address.empty())
    {
        return false;
    }

    for (auto& [key, pair] : candidate_pairs_by_key_)
    {
        (void)key;

        if (!pair.selected)
        {
            continue;
        }

        if (pair.remote_address != remote_address)
        {
            continue;
        }

        if (!pair.consent_request_in_flight)
        {
            continue;
        }

        if (pair.pending_consent_transaction_id != transaction_id)
        {
            continue;
        }

        pair.last_consent_response_at_milliseconds = current_time_milliseconds;

        pair.last_binding_at_milliseconds = current_time_milliseconds;

        pair.consent_request_failures = 0;

        pair.consent_request_in_flight = false;

        pair.pending_consent_transaction_id = {};

        return true;
    }

    return false;
}

void ice_udp_server::handle_stun_binding_success_response(std::span<const uint8_t> data,
                                                          const stun_message& message,
                                                          const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    std::string session_id;

    {
        std::lock_guard lock(endpoint_mutex_);

        const auto iterator = session_id_by_endpoint_address_.find(remote_address);

        if (iterator == session_id_by_endpoint_address_.end())
        {
            WEBRTC_LOG_DEBUG("ice consent response ignored remote={} reason=session endpoint not found", remote_address);

            return;
        }

        session_id = iterator->second;
    }

    auto integrity_key = remote_ice_password_for_session(session_id);

    if (!integrity_key.has_value() || integrity_key->empty())
    {
        WEBRTC_LOG_WARN("ice consent response remote ice pwd not found session={} remote={}", session_id, remote_address);

        return;
    }

    if (!message.has_message_integrity)
    {
        WEBRTC_LOG_WARN("ice consent response missing message-integrity session={} remote={}", session_id, remote_address);

        return;
    }

    auto integrity_result = verify_stun_message_integrity(data, *integrity_key);

    if (!integrity_result)
    {
        WEBRTC_LOG_WARN("ice consent response message-integrity verify failed session={} remote={} error={}",
                        session_id,
                        remote_address,
                        integrity_result.error());

        return;
    }

    if (message.has_fingerprint)
    {
        auto fingerprint_result = verify_stun_fingerprint(data);

        if (!fingerprint_result)
        {
            WEBRTC_LOG_WARN("ice consent response fingerprint verify failed session={} remote={} error={}",
                            session_id,
                            remote_address,
                            fingerprint_result.error());

            return;
        }
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    bool accepted = false;

    {
        std::lock_guard lock(endpoint_mutex_);

        accepted = remember_ice_consent_success_locked(remote_address, message.transaction_id, current_time_milliseconds);
    }

    if (!accepted)
    {
        WEBRTC_LOG_DEBUG("ice consent response ignored session={} remote={} reason=transaction not found", session_id, remote_address);

        return;
    }

    touch_endpoint_activity(remote_endpoint);

    WEBRTC_LOG_DEBUG("ice consent response accepted session={} remote={}", session_id, remote_address);
}
void ice_udp_server::handle_stun_packet(std::span<const uint8_t> data, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    auto message = parse_stun_message(data);

    if (!message)
    {
        WEBRTC_LOG_WARN("ice stun parse failed remote={} error={}", remote_address, message.error());

        return;
    }

    if (message->method == stun_method::binding && message->message_class == stun_message_class::success_response)
    {
        handle_stun_binding_success_response(data, *message, remote_endpoint);

        return;
    }

    if (message->method != stun_method::binding || message->message_class != stun_message_class::request)
    {
        WEBRTC_LOG_DEBUG("ice stun ignored method={} class={} remote={}",
                         stun_method_to_string(message->method),
                         stun_class_to_string(message->message_class),
                         remote_address);

        return;
    }

    if (!message->username.has_value())
    {
        WEBRTC_LOG_WARN("ice stun binding request missing username remote={}", remote_address);

        return;
    }

    auto connectivity_check_result = validate_ice_connectivity_check(*message);

    if (!connectivity_check_result)
    {
        WEBRTC_LOG_WARN(
            "ice connectivity check rejected username={} remote={} error={}", *message->username, remote_address, connectivity_check_result.error());

        return;
    }

    auto username_parts = parse_ice_username(*message->username);

    if (!username_parts)
    {
        WEBRTC_LOG_WARN(
            "ice stun binding request invalid username username={} remote={} error={}", *message->username, remote_address, username_parts.error());

        return;
    }

    auto publisher = find_publisher_for_username(*message->username);

    auto subscriber = find_subscriber_for_username(*message->username);

    if (publisher != nullptr && subscriber != nullptr)
    {
        WEBRTC_LOG_ERROR("ice stun binding request ambiguous session username={} recipient_ufrag={} sender_ufrag={} remote={}",
                         *message->username,
                         username_parts->recipient_ufrag,
                         username_parts->sender_ufrag,
                         remote_address);

        return;
    }

    std::string integrity_key;
    std::string session_id;
    std::string stream_id;

    if (publisher != nullptr)
    {
        integrity_key = publisher->local_ice().pwd;

        session_id = publisher->session_id();

        stream_id = publisher->stream_id();
    }
    else if (subscriber != nullptr)
    {
        integrity_key = subscriber->local_ice().pwd;

        session_id = subscriber->session_id();

        stream_id = subscriber->stream_id();
    }
    else
    {
        if (suppress_retired_ice_credential_stun(username_parts->recipient_ufrag, username_parts->sender_ufrag, remote_address))
        {
            return;
        }

        if (suppress_retired_endpoint_packet(remote_address, "stun"))
        {
            return;
        }

        WEBRTC_LOG_WARN("ice stun binding request session not found username={} recipient_ufrag={} sender_ufrag={} remote={}",
                        *message->username,
                        username_parts->recipient_ufrag,
                        username_parts->sender_ufrag,
                        remote_address);

        return;
    }
    if (retired_endpoint_matches_session(remote_address, session_id))
    {
        const bool suppressed = suppress_retired_endpoint_packet(remote_address, "stun");
        (void)suppressed;

        return;
    }
    if (integrity_key.empty())
    {
        WEBRTC_LOG_WARN("ice stun binding request local ice pwd is empty username={} remote={}", *message->username, remote_address);

        return;
    }

    if (!message->has_message_integrity)
    {
        WEBRTC_LOG_WARN("ice stun binding request missing message-integrity username={} remote={}", *message->username, remote_address);

        return;
    }

    auto integrity_result = verify_stun_message_integrity(data, integrity_key);

    if (!integrity_result)
    {
        WEBRTC_LOG_WARN(
            "ice stun message-integrity verify failed username={} remote={} error={}", *message->username, remote_address, integrity_result.error());

        return;
    }

    accept_retired_endpoint_reuse_after_valid_stun(
        remote_address, stream_id, session_id, username_parts->recipient_ufrag, username_parts->sender_ufrag);

    if (message->has_fingerprint)
    {
        auto fingerprint_result = verify_stun_fingerprint(data);

        if (!fingerprint_result)
        {
            WEBRTC_LOG_WARN(
                "ice stun fingerprint verify failed username={} remote={} error={}", *message->username, remote_address, fingerprint_result.error());

            return;
        }
    }

    const uint32_t remote_priority = *message->priority;

    const uint64_t remote_tie_breaker = *message->ice_controlling;

    remember_candidate_pair(session_id, stream_id, remote_address, remote_priority, remote_tie_breaker, message->use_candidate);

    bool selected = false;
    bool selection_changed = false;

    if (message->use_candidate)
    {
        auto selection_result = select_candidate_pair(session_id, stream_id, remote_endpoint, remote_priority, remote_tie_breaker);

        if (!selection_result)
        {
            WEBRTC_LOG_WARN("ice candidate pair selection failed stream={} session={} remote={} error={}",
                            stream_id,
                            session_id,
                            remote_address,
                            selection_result.error());

            return;
        }

        selected = true;

        selection_changed = selection_result->changed;

        if (!selection_result->previous_remote_address.empty())
        {
            bool transport_migrated = false;

            auto expected_identity = current_dtls_identity_for_session(session_id);

            if (expected_identity.has_value())
            {
                transport_migrated =
                    migrate_peer_transport_state_for_ice_restart(selection_result->previous_remote_address, remote_address, *expected_identity);
            }

            if (!transport_migrated)
            {
                forget_peer_transport_state(selection_result->previous_remote_address);
            }

            WEBRTC_LOG_INFO("ice selected candidate pair replaced stream={} session={} old_remote={} new_remote={} transport_migrated={}",
                            stream_id,
                            session_id,
                            selection_result->previous_remote_address,
                            remote_address,
                            transport_migrated ? 1 : 0);
        }
        if (selection_result->remote_address_reused_by_different_session && !selection_result->replaced_session_id.empty())
        {
            forget_session_runtime_state(selection_result->replaced_session_id);

            /*
             * The same remote address is now owned by the new valid STUN session.
             * Do not send DTLS close_notify here because it would be delivered to
             * the new transport five-tuple. Just drop old local DTLS/SRTP/router
             * runtime and let the selected peer be remembered again below.
             */
            forget_peer_transport_state(remote_address);

            WEBRTC_LOG_INFO("ice selected candidate pair remote ownership replaced stream={} old_session={} new_session={} remote={}",
                            stream_id,
                            selection_result->replaced_session_id,
                            session_id,
                            remote_address);
        }

        const bool media_peer_refresh_required = selected_media_peer_needs_refresh(remote_address, session_id);

        const bool transport_peer_refresh_required =
            selected_transport_peer_needs_refresh(remote_address, session_id, username_parts->recipient_ufrag, username_parts->sender_ufrag);

        if (selection_changed || media_peer_refresh_required || transport_peer_refresh_required)
        {
            if (transport_peer_refresh_required && !selection_changed && !selection_result->remote_address_reused_by_different_session)
            {
                bool transport_migrated = false;

                auto expected_identity = current_dtls_identity_for_session(session_id);

                if (expected_identity.has_value())
                {
                    transport_migrated = migrate_peer_transport_state_for_ice_restart(remote_address, remote_address, *expected_identity);
                }

                if (!transport_migrated)
                {
                    forget_peer_transport_state(remote_address);
                }

                WEBRTC_LOG_INFO("ice selected candidate pair transport refreshed stream={} session={} remote={} transport_migrated={}",
                                stream_id,
                                session_id,
                                remote_address,
                                transport_migrated ? 1 : 0);
            }
            if (publisher != nullptr)
            {
                publisher->set_state(session_state::ice_connected);
                if (dtls_transport_ != nullptr)
                {
                    dtls_transport_->remember_peer(remote_address, make_publisher_dtls_identity(publisher));
                }

                media_router_->remember_publisher(remote_address, publisher->stream_id(), publisher->session_id());
            }

            if (subscriber != nullptr)
            {
                subscriber->set_state(session_state::ice_connected);

                if (dtls_transport_ != nullptr)
                {
                    dtls_transport_->remember_peer(remote_address, make_subscriber_dtls_identity(subscriber));
                }

                media_router_->remember_subscriber(remote_address, subscriber->stream_id(), subscriber->session_id());
            }

            WEBRTC_LOG_INFO(
                "ice candidate pair selected stream={} session={} remote={} priority={} tie_breaker={} selection_changed={} media_refresh={} "
                "transport_refresh={}",
                stream_id,
                session_id,
                remote_address,
                remote_priority,
                remote_tie_breaker,
                selection_changed ? 1 : 0,
                media_peer_refresh_required ? 1 : 0,
                transport_peer_refresh_required ? 1 : 0);
        }
    }

    if (selected || is_selected_endpoint(remote_address))
    {
        touch_endpoint_activity(remote_endpoint);
    }

    const std::string remote_ip = endpoint_ip(remote_endpoint);

    if (remote_ip.empty())
    {
        WEBRTC_LOG_WARN("ice stun remote endpoint ip is empty remote={}", remote_address);

        return;
    }

    stun_binding_success_response_options options;

    options.mapped_address.ip = remote_ip;

    options.mapped_address.port = remote_endpoint.port();

    options.mapped_address.is_ipv6 = remote_endpoint.address().is_v6();

    options.message_integrity_key = integrity_key;

    options.include_message_integrity = true;

    options.include_fingerprint = true;

    auto response = write_stun_binding_success_response(*message, options);

    if (!response)
    {
        WEBRTC_LOG_WARN(
            "ice stun build binding response failed username={} remote={} error={}", *message->username, remote_address, response.error());

        return;
    }
    if (selection_changed)
    {
        WEBRTC_LOG_INFO(
            "ice stun binding success username={} recipient_ufrag={} sender_ufrag={} stream={} session={} remote={} nominated={} selected={} "
            "selection_changed={} priority={} response_size={}",
            *message->username,
            username_parts->recipient_ufrag,
            username_parts->sender_ufrag,
            stream_id,
            session_id,
            remote_address,
            message->use_candidate ? 1 : 0,
            selected ? 1 : 0,
            selection_changed ? 1 : 0,
            remote_priority,
            response->size());
    }
    else
    {
        WEBRTC_LOG_DEBUG(
            "ice stun binding success username={} recipient_ufrag={} sender_ufrag={} stream={} session={} remote={} nominated={} selected={} "
            "selection_changed={} priority={} response_size={}",
            *message->username,
            username_parts->recipient_ufrag,
            username_parts->sender_ufrag,
            stream_id,
            session_id,
            remote_address,
            message->use_candidate ? 1 : 0,
            selected ? 1 : 0,
            selection_changed ? 1 : 0,
            remote_priority,
            response->size());
    }

    send_response(std::move(*response), remote_endpoint);
}

void ice_udp_server::handle_dtls_packet(std::span<const uint8_t> data, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    const current_session_endpoint_state current_session = find_current_session_endpoint(remote_address, "dtls");

    if (!current_session.allowed)
    {
        WEBRTC_LOG_WARN("dtls packet ignored by current session gate remote={} session={} size={} reason={}",
                        remote_address,
                        current_session.session_id,
                        data.size(),
                        current_session.reject_reason);

        forget_peer_transport_state(remote_address);

        return;
    }

    touch_endpoint_activity(remote_endpoint);

    if (dtls_transport_ == nullptr)
    {
        WEBRTC_LOG_WARN("dtls transport is null remote={} session={} size={}", remote_address, current_session.session_id, data.size());

        return;
    }

    std::optional<dtls_peer_identity> expected_identity = current_dtls_identity_for_session(current_session.session_id);

    if (!expected_identity.has_value())
    {
        WEBRTC_LOG_WARN("dtls packet ignored because current identity is missing remote={} session={} stream={} size={}",
                        remote_address,
                        current_session.session_id,
                        current_session.stream_id,
                        data.size());

        forget_peer_transport_state(remote_address);

        return;
    }

    dtls_transport_->remember_peer(remote_address, std::move(*expected_identity));

    auto packets = dtls_transport_->handle_udp_packet(data, remote_address);

    if (!packets)
    {
        WEBRTC_LOG_WARN("dtls packet handle failed remote={} session={} stream={} error={}",
                        remote_address,
                        current_session.session_id,
                        current_session.stream_id,
                        packets.error());

        forget_peer_endpoint(remote_address);

        schedule_dtls_timeout();

        return;
    }

    for (auto& packet : *packets)
    {
        const current_session_endpoint_state send_session =
            validate_current_session_endpoint(remote_address, current_session.session_id, current_session.stream_id, "dtls send");

        if (!send_session.allowed)
        {
            WEBRTC_LOG_DEBUG("dtls send skipped by current session gate remote={} session={} size={} reason={}",
                             remote_address,
                             current_session.session_id,
                             packet.size(),
                             send_session.reject_reason);

            forget_peer_transport_state(remote_address);

            break;
        }

        WEBRTC_LOG_DEBUG("dtls send packet remote={} session={} stream={} size={}",
                         remote_address,
                         current_session.session_id,
                         current_session.stream_id,
                         packet.size());

        send_response(std::move(packet), remote_endpoint);
    }

    schedule_dtls_timeout();
}

void ice_udp_server::handle_dtls_close_notify(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    std::optional<std::string> session_id = find_session_id_by_endpoint(remote_address);

    if (!session_id.has_value() || session_id->empty())
    {
        WEBRTC_LOG_WARN("dtls close notify session not found remote={}", remote_address);

        forget_peer_transport_state(remote_address);

        return;
    }

    WEBRTC_LOG_INFO("dtls close notify session cleanup remote={} session={}", remote_address, *session_id);

    remove_expired_session(*session_id, "dtls close notify");
}

void ice_udp_server::maybe_request_keyframe_from_publisher(const srtp_packet_process_result& packet,
                                                           const media_route_result& route,
                                                           const std::optional<media_track_resolution>& track_resolution,
                                                           const media_peer_info& target_peer)
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved || !is_video_media_kind(track_resolution->kind))
    {
        return;
    }

    if (track_resolution->rtx)
    {
        WEBRTC_LOG_DEBUG(
            "keyframe request skipped rtx packet stream={} publisher={} publisher_session={} subscriber={} subscriber_session={} mid={} kind={} "
            "rid={} repaired_rid={} media_ssrc={} primary_ssrc={}",
            route.source.stream_id,
            route.source.remote_endpoint,
            route.source.session_id,
            target_peer.remote_endpoint,
            target_peer.session_id,
            track_resolution->mid,
            track_resolution->kind,
            track_resolution->rid.value_or(""),
            track_resolution->repaired_rid.value_or(""),
            packet.ssrc,
            track_resolution->rtx_primary_ssrc);

        return;
    }

    if (packet.ssrc == 0)
    {
        return;
    }

    if (srtp_transport_ == nullptr)
    {
        return;
    }

    auto publisher_endpoint = find_remote_endpoint(route.source.remote_endpoint);

    if (!publisher_endpoint.has_value())
    {
        WEBRTC_LOG_WARN(
            "keyframe request skipped publisher endpoint not found stream={} publisher={} publisher_session={} subscriber={} "
            "subscriber_session={} mid={} kind={} rid={} repaired_rid={} media_ssrc={}",
            route.source.stream_id,
            route.source.remote_endpoint,
            route.source.session_id,
            target_peer.remote_endpoint,
            target_peer.session_id,
            track_resolution->mid,
            track_resolution->kind,
            track_resolution->rid.value_or(""),
            track_resolution->repaired_rid.value_or(""),
            packet.ssrc);

        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    const std::string key = make_keyframe_request_key(route, target_peer, *track_resolution, packet.ssrc);

    const bool republish_keyframe_request = consume_republish_keyframe_request_pending_for_subscriber(packet, route, track_resolution, target_peer);

    const bool selected_rid_keyframe_request =
        consume_selected_rid_keyframe_request_pending_for_subscriber(packet, route, track_resolution, target_peer);

    {
        std::lock_guard lock(endpoint_mutex_);

        auto iterator = keyframe_request_last_time_milliseconds_by_key_.find(key);

        if (republish_keyframe_request || selected_rid_keyframe_request)
        {
            if (iterator != keyframe_request_last_time_milliseconds_by_key_.end())
            {
                iterator->second = current_time_milliseconds;
            }
            else
            {
                keyframe_request_last_time_milliseconds_by_key_.emplace(key, current_time_milliseconds);
            }
        }
        else if (iterator == keyframe_request_last_time_milliseconds_by_key_.end())
        {
            /*
             * Send one proactive PLI for a newly observed publisher->subscriber
             * video forwarding binding. After that, normal browser RTCP feedback
             * is responsible for additional keyframe requests.
             *
             * Do not keep sending proactive PLI every interval for healthy video:
             * that creates a permanent keyframe request loop even when WHEP is
             * already decoding frames.
             */
            keyframe_request_last_time_milliseconds_by_key_.emplace(key, current_time_milliseconds);
        }
        else
        {
            return;
        }
    }
    const keyframe_request_feedback_type feedback_type =
        select_keyframe_request_feedback_type(route.source.stream_id, route.source.session_id, track_resolution->mid, track_resolution->kind);

    if (feedback_type == keyframe_request_feedback_type::none)
    {
        if (selected_rid_keyframe_request)
        {
            remember_selected_rid_keyframe_request_result(
                route, track_resolution, target_peer, "unsupported", "publisher keyframe feedback unsupported", false);
        }

        WEBRTC_LOG_DEBUG(
            "keyframe request skipped publisher unsupported stream={} publisher_session={} subscriber_session={} mid={} kind={} rid={} "
            "repaired_rid={} media_ssrc={} selected_rid_pending={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            track_resolution->mid,
            track_resolution->kind,
            track_resolution->rid.value_or(""),
            track_resolution->repaired_rid.value_or(""),
            packet.ssrc,
            selected_rid_keyframe_request ? 1 : 0);
        return;
    }
    const uint32_t sender_ssrc = make_rtcp_report_local_ssrc(route.source, packet.ssrc);

    auto plain_packet = make_keyframe_request_packet(feedback_type, route.source.stream_id, sender_ssrc, packet.ssrc);

    if (!plain_packet.has_value())
    {
        if (selected_rid_keyframe_request)
        {
            restore_selected_rid_keyframe_request_pending_for_subscriber(
                route, track_resolution, target_peer, "keyframe request packet build failed");
        }

        return;
    }

    auto protected_packet = srtp_transport_->protect_outbound_packet(
        std::span<const uint8_t>(plain_packet->data(), plain_packet->size()), route.source.remote_endpoint, srtp_packet_kind::rtcp);

    if (!protected_packet)
    {
        WEBRTC_LOG_WARN(
            "keyframe request protect failed stream={} publisher={} publisher_session={} subscriber={} subscriber_session={} feedback_type={} "
            "mid={} kind={} rid={} repaired_rid={} sender_ssrc={} media_ssrc={} selected_rid_pending={} error={}",
            route.source.stream_id,
            route.source.remote_endpoint,
            route.source.session_id,
            target_peer.remote_endpoint,
            target_peer.session_id,
            keyframe_request_feedback_type_to_string(feedback_type),
            track_resolution->mid,
            track_resolution->kind,
            track_resolution->rid.value_or(""),
            track_resolution->repaired_rid.value_or(""),
            sender_ssrc,
            packet.ssrc,
            selected_rid_keyframe_request ? 1 : 0,
            protected_packet.error());

        if (selected_rid_keyframe_request)
        {
            restore_selected_rid_keyframe_request_pending_for_subscriber(route, track_resolution, target_peer, "keyframe request protect failed");
        }

        return;
    }

    if (protected_packet->state == srtp_packet_process_state::ignored)
    {
        WEBRTC_LOG_DEBUG(
            "keyframe request ignored stream={} publisher={} publisher_session={} subscriber={} subscriber_session={} feedback_type={} "
            "mid={} kind={} rid={} repaired_rid={} sender_ssrc={} media_ssrc={} selected_rid_pending={} reason={}",
            route.source.stream_id,
            route.source.remote_endpoint,
            route.source.session_id,
            target_peer.remote_endpoint,
            target_peer.session_id,
            keyframe_request_feedback_type_to_string(feedback_type),
            track_resolution->mid,
            track_resolution->kind,
            track_resolution->rid.value_or(""),
            track_resolution->repaired_rid.value_or(""),
            sender_ssrc,
            packet.ssrc,
            selected_rid_keyframe_request ? 1 : 0,
            protected_packet->reason);

        if (selected_rid_keyframe_request)
        {
            restore_selected_rid_keyframe_request_pending_for_subscriber(route, track_resolution, target_peer, "keyframe request protect ignored");
        }

        return;
    }

    if (selected_rid_keyframe_request)
    {
        remember_selected_rid_keyframe_request_result(route, track_resolution, target_peer, "sent", "keyframe request sent", true);
    }

    WEBRTC_LOG_INFO(
        "keyframe request sent stream={} publisher={} publisher_session={} subscriber={} subscriber_session={} feedback_type={} mid={} kind={} "
        "rid={} repaired_rid={} sender_ssrc={} media_ssrc={} republish_pending={} selected_rid_pending={}",
        route.source.stream_id,
        route.source.remote_endpoint,
        route.source.session_id,
        target_peer.remote_endpoint,
        target_peer.session_id,
        keyframe_request_feedback_type_to_string(feedback_type),
        track_resolution->mid,
        track_resolution->kind,
        track_resolution->rid.value_or(""),
        track_resolution->repaired_rid.value_or(""),
        sender_ssrc,
        packet.ssrc,
        republish_keyframe_request ? 1 : 0,
        selected_rid_keyframe_request ? 1 : 0);

    send_response(std::move(protected_packet->protected_packet), *publisher_endpoint);
}
void ice_udp_server::handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    const current_session_endpoint_state current_session = find_current_session_endpoint(remote_address, "srtp");

    if (!current_session.allowed)
    {
        WEBRTC_LOG_DEBUG("srtp packet ignored by current session gate remote={} session={} size={} reason={}",
                         remote_address,
                         current_session.session_id,
                         data.size(),
                         current_session.reject_reason);

        rtp_rtcp_drop_inbound_session_gate_total_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    if (media_router_ == nullptr)
    {
        rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
        WEBRTC_LOG_WARN("srtp packet ignored media router unavailable remote={} session={} stream={} size={}",
                        remote_address,
                        current_session.session_id,
                        current_session.stream_id,
                        data.size());

        return;
    }

    if (registry_ == nullptr)
    {
        rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
        WEBRTC_LOG_WARN("srtp packet ignored session registry unavailable remote={} session={} stream={} size={}",
                        remote_address,
                        current_session.session_id,
                        current_session.stream_id,
                        data.size());

        return;
    }

    std::optional<media_peer_info> peer = media_router_->get_peer(remote_address);

    if (!peer.has_value())
    {
        WEBRTC_LOG_DEBUG("srtp packet ignored media peer not ready remote={} session={} stream={} size={}",
                         remote_address,
                         current_session.session_id,
                         current_session.stream_id,
                         data.size());

        rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    if (peer->session_id != current_session.session_id || peer->stream_id != current_session.stream_id)
    {
        rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
        WEBRTC_LOG_DEBUG(
            "srtp packet ignored stale media peer remote={} current_session={} current_stream={} peer_session={} peer_stream={} role={} size={}",
            remote_address,
            current_session.session_id,
            current_session.stream_id,
            peer->session_id,
            peer->stream_id,
            media_peer_role_to_string(peer->role),
            data.size());

        return;
    }

    std::size_t accepted_mline_count = 0;

    if (peer->role == media_peer_role::publisher)
    {
        auto publisher = registry_->find_publisher_by_session_id(peer->session_id);

        if (publisher == nullptr)
        {
            rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
            WEBRTC_LOG_DEBUG("srtp packet ignored publisher session not ready remote={} session={} stream={} size={}",
                             remote_address,
                             peer->session_id,
                             peer->stream_id,
                             data.size());

            return;
        }

        accepted_mline_count = publisher->accepted_remote_media_mline_indexes().size();
    }
    else if (peer->role == media_peer_role::subscriber)
    {
        auto subscriber = registry_->find_subscriber_by_session_id(peer->session_id);

        if (subscriber == nullptr)
        {
            rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
            WEBRTC_LOG_DEBUG("srtp packet ignored subscriber session not ready remote={} session={} stream={} size={}",
                             remote_address,
                             peer->session_id,
                             peer->stream_id,
                             data.size());

            return;
        }

        accepted_mline_count = subscriber->accepted_remote_media_mline_indexes().size();
    }
    else
    {
        rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
        WEBRTC_LOG_DEBUG("srtp packet ignored unknown media peer role remote={} session={} stream={} size={}",
                         remote_address,
                         peer->session_id,
                         peer->stream_id,
                         data.size());

        return;
    }

    if (accepted_mline_count == 0)
    {
        rtp_rtcp_drop_inbound_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
        WEBRTC_LOG_DEBUG("srtp packet ignored accepted media not ready remote={} role={} session={} stream={} size={}",
                         remote_address,
                         media_peer_role_to_string(peer->role),
                         peer->session_id,
                         peer->stream_id,
                         data.size());

        return;
    }

    touch_endpoint_activity(remote_endpoint);

    if (srtp_transport_ == nullptr)
    {
        rtp_rtcp_drop_inbound_transport_missing_total_.fetch_add(1, std::memory_order_relaxed);
        WEBRTC_LOG_WARN("srtp transport is null remote={} size={}", remote_address, data.size());

        return;
    }

    auto result = srtp_transport_->handle_inbound_packet(data, remote_address);
    if (!result)
    {
        WEBRTC_LOG_WARN("srtp inbound packet handle failed remote={} error={}", remote_address, result.error());
        rtp_rtcp_drop_inbound_srtp_failed_total_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    if (result->state == srtp_packet_process_state::ignored)
    {
        rtp_rtcp_drop_inbound_srtp_ignored_total_.fetch_add(1, std::memory_order_relaxed);

        switch (classify_inbound_srtp_ignored_drop_reason(result->reason))
        {
            case inbound_srtp_ignored_drop_reason::non_rtp_rtcp:
                rtp_rtcp_drop_inbound_srtp_non_rtp_rtcp_total_.fetch_add(1, std::memory_order_relaxed);
                break;

            case inbound_srtp_ignored_drop_reason::dtls_identity_missing:
                rtp_rtcp_drop_inbound_srtp_dtls_identity_missing_total_.fetch_add(1, std::memory_order_relaxed);
                break;

            case inbound_srtp_ignored_drop_reason::dtls_not_ready:
                rtp_rtcp_drop_inbound_srtp_dtls_not_ready_total_.fetch_add(1, std::memory_order_relaxed);
                break;

            case inbound_srtp_ignored_drop_reason::srtp_replay:
                rtp_rtcp_drop_inbound_srtp_replay_ignored_total_.fetch_add(1, std::memory_order_relaxed);
                break;

            case inbound_srtp_ignored_drop_reason::srtp_unprotect_failed:
                rtp_rtcp_drop_inbound_srtp_unprotect_ignored_total_.fetch_add(1, std::memory_order_relaxed);
                break;

            case inbound_srtp_ignored_drop_reason::other:
                rtp_rtcp_drop_inbound_srtp_ignored_other_total_.fetch_add(1, std::memory_order_relaxed);
                break;
        }

        WEBRTC_LOG_DEBUG("srtp inbound packet ignored remote={} kind={} size={} reason={}",
                         remote_address,
                         srtp_packet_kind_to_string(result->kind),
                         result->packet_size,
                         result->reason);

        return;
    }
    WEBRTC_LOG_DEBUG("srtp inbound packet accepted remote={} kind={} size={} plain_size={} ssrc={} payload_type={}",
                     remote_address,
                     srtp_packet_kind_to_string(result->kind),
                     result->packet_size,
                     result->unprotected_size,
                     result->ssrc,
                     static_cast<unsigned int>(result->payload_type));

    std::optional<media_track_resolution> track_resolution;

    track_resolution = resolve_media_track(*peer, *result);

    normalize_inbound_rtcp_report_stats(*peer, *result);

    const media_route_result route = media_router_->handle_inbound_packet(remote_address, *result);
    if (!route.known_peer)
    {
        rtp_rtcp_drop_inbound_unknown_peer_total_.fetch_add(1, std::memory_order_relaxed);
        WEBRTC_LOG_WARN(
            "media route ignored unknown peer remote={} kind={} ssrc={}", remote_address, srtp_packet_kind_to_string(result->kind), result->ssrc);

        return;
    }

    observe_inbound_rtp_stats(*peer, *result, track_resolution);

    if (track_resolution.has_value() && track_resolution->resolved)
    {
        if (track_resolution->rtx)
        {
            WEBRTC_LOG_DEBUG("media inbound track stats skipped rtx repair stream={} session={} remote={} ssrc={} primary_ssrc={} repair_ssrc={}",
                             track_resolution->stream_id,
                             track_resolution->session_id,
                             track_resolution->remote_endpoint,
                             track_resolution->ssrc,
                             track_resolution->rtx_primary_ssrc,
                             track_resolution->rtx_repair_ssrc);
        }
        else
        {
            media_router_->observe_inbound_track(*peer, *result, *track_resolution);

            remember_publisher_video_ssrc(*peer, *result, track_resolution);
        }
    }

    observe_inbound_rtcp_reports(*peer, *result);
    if (track_resolution.has_value() && track_resolution->resolved)
    {
        WEBRTC_LOG_DEBUG(
            "media track resolved remote={} action={} stream={} session={} state={} initial_state={} fallback={} mid={} kind={} ssrc={} "
            "sequence={} payload_type={} newly_bound={} has_twcc={} twcc={} rtx={} rtx_primary_ssrc={} rtx_repair_ssrc={}",
            remote_address,
            media_route_action_to_string(route.action),
            track_resolution->stream_id,
            track_resolution->session_id,
            media_track_resolution_state_to_string(track_resolution->state),
            media_track_resolution_state_to_string(track_resolution->initial_resolution_state),
            track_resolution->fallback_resolution ? 1 : 0,
            track_resolution->mid,
            track_resolution->kind,
            track_resolution->ssrc,
            track_resolution->sequence_number,
            static_cast<unsigned int>(track_resolution->payload_type),
            track_resolution->newly_bound ? 1 : 0,
            track_resolution->transport_wide_sequence_number.has_value() ? 1 : 0,
            track_resolution->transport_wide_sequence_number.has_value()
                ? static_cast<unsigned int>(*track_resolution->transport_wide_sequence_number)
                : 0U,
            track_resolution->rtx ? 1 : 0,
            track_resolution->rtx_primary_ssrc,
            track_resolution->rtx_repair_ssrc);
    }

    WEBRTC_LOG_DEBUG("media route resolved remote={} action={} stream={} session={} targets={}",
                     remote_address,
                     media_route_action_to_string(route.action),
                     route.source.stream_id,
                     route.source.session_id,
                     route.target_endpoints.size());

    if (!publisher_rtp_identity_is_allowed(route, *result, track_resolution))
    {
        rtp_rtcp_drop_inbound_identity_gate_total_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    complete_republish_keyframe_request_pending_for_publisher_keyframe(*result, route, track_resolution);

    cache_inbound_rtp_packet(*result, route, track_resolution);

    if (result->kind == srtp_packet_kind::rtcp && result->rtcp_has_bye)
    {
        handle_rtcp_bye_packet(*result, route);
        return;
    }

    const std::vector<rtcp_feedback_route_event> feedback_events = make_rtcp_feedback_route_events(*result, route);

    for (const auto& feedback_event : feedback_events)
    {
        log_rtcp_feedback_route_event(feedback_event);

        handle_rtcp_feedback_event(feedback_event);
    }

    forward_media_packet(*result, route, track_resolution, feedback_events);
}

std::optional<media_track_resolution> ice_udp_server::resolve_media_track(const media_peer_info& peer, const srtp_packet_process_result& packet)
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return std::nullopt;
    }

    if (packet.plain_packet.empty())
    {
        return std::nullopt;
    }

    if (registry_ == nullptr || track_resolver_ == nullptr)
    {
        return std::nullopt;
    }

    if (peer.role != media_peer_role::publisher)
    {
        return std::nullopt;
    }

    auto publisher = registry_->find_publisher_by_session_id(peer.session_id);

    if (publisher == nullptr)
    {
        WEBRTC_LOG_WARN("media track resolve skipped publisher session not found remote={} stream={} session={}",
                        peer.remote_endpoint,
                        peer.stream_id,
                        peer.session_id);

        return std::nullopt;
    }

    auto resolution = track_resolver_->resolve_inbound_rtp(peer.remote_endpoint,
                                                           peer.stream_id,
                                                           peer.session_id,
                                                           publisher->remote_offer_summary(),
                                                           publisher->accepted_remote_media_mline_indexes(),
                                                           std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));
    if (!resolution)
    {
        WEBRTC_LOG_WARN("media track resolve failed remote={} stream={} session={} ssrc={} sequence={} error={}",
                        peer.remote_endpoint,
                        peer.stream_id,
                        peer.session_id,
                        packet.ssrc,
                        packet.sequence_number,
                        resolution.error());

        return std::nullopt;
    }

    if (!resolution->resolved)
    {
        WEBRTC_LOG_DEBUG("media track unresolved remote={} stream={} session={} ssrc={} sequence={} error={}",
                         peer.remote_endpoint,
                         peer.stream_id,
                         peer.session_id,
                         packet.ssrc,
                         packet.sequence_number,
                         resolution->error);

        return *resolution;
    }

    if (media_offer_payload_type_is_unsupported_repair_codec(publisher->remote_offer_summary(), resolution->mid, resolution->payload_type))
    {
        WEBRTC_LOG_DEBUG(
            "media track resolve skipped unsupported repair codec remote={} stream={} session={} ssrc={} sequence={} payload_type={} mid={} kind={} "
            "rid={} repaired_rid={} rtx={}",
            peer.remote_endpoint,
            peer.stream_id,
            peer.session_id,
            packet.ssrc,
            packet.sequence_number,
            static_cast<unsigned int>(resolution->payload_type),
            resolution->mid,
            resolution->kind,
            resolution->rid.has_value() ? *resolution->rid : "",
            resolution->repaired_rid.has_value() ? *resolution->repaired_rid : "",
            resolution->rtx ? 1 : 0);

        return std::nullopt;
    }

    if (resolution->newly_bound)
    {
        const std::string audio_level =
            resolution->audio_level.has_value() ? std::to_string(static_cast<unsigned int>(*resolution->audio_level)) : std::string();

        const std::string voice_activity =
            resolution->voice_activity.has_value() ? std::string(*resolution->voice_activity ? "1" : "0") : std::string();

        WEBRTC_LOG_INFO(
            "media track binding created remote={} stream={} session={} state={} mid={} kind={} ssrc={} payload_type={} rid={} repaired_rid={} "
            "audio_level={} voice_activity={} rtx={} rtx_primary_ssrc={} rtx_repair_ssrc={}",
            peer.remote_endpoint,
            peer.stream_id,
            peer.session_id,
            media_track_resolution_state_to_string(resolution->state),
            resolution->mid,
            resolution->kind,
            resolution->ssrc,
            static_cast<unsigned int>(resolution->payload_type),
            resolution->rid.has_value() ? *resolution->rid : "",
            resolution->repaired_rid.has_value() ? *resolution->repaired_rid : "",
            audio_level,
            voice_activity,
            resolution->rtx ? 1 : 0,
            resolution->rtx_primary_ssrc,
            resolution->rtx_repair_ssrc);
    }

    return *resolution;
}

bool ice_udp_server::publisher_rtp_identity_is_allowed(const media_route_result& route,
                                                       const srtp_packet_process_result& packet,
                                                       const std::optional<media_track_resolution>& track_resolution) const
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return true;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return true;
    }

    if (track_resolution.has_value() && track_resolution->resolved)
    {
        return true;
    }

    WEBRTC_LOG_DEBUG("publisher rtp dropped unresolved identity stream={} session={} remote={} ssrc={} sequence={} payload_type={}",
                     route.source.stream_id,
                     route.source.session_id,
                     route.source.remote_endpoint,
                     packet.ssrc,
                     packet.sequence_number,
                     static_cast<unsigned int>(packet.payload_type));

    return false;
}

bool ice_udp_server::remember_media_identity_forward_mapping(const media_ssrc_mapping& ssrc_mapping,
                                                             const media_payload_type_mapping& payload_type_mapping)
{
    if (identity_authority_ == nullptr)
    {
        return true;
    }

    auto identity_result = identity_authority_->remember_forward_mapping(ssrc_mapping, payload_type_mapping);

    if (!identity_result)
    {
        WEBRTC_LOG_WARN(
            "media identity forward mapping rejected stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} "
            "publisher_ssrc={} subscriber_ssrc={} publisher_pt={} subscriber_pt={} rtx={} error={}",
            ssrc_mapping.stream_id,
            ssrc_mapping.publisher_session_id,
            ssrc_mapping.subscriber_session_id,
            ssrc_mapping.publisher_mid,
            ssrc_mapping.subscriber_mid,
            ssrc_mapping.publisher_ssrc,
            ssrc_mapping.subscriber_ssrc,
            payload_type_mapping.publisher_payload_type,
            payload_type_mapping.subscriber_payload_type,
            ssrc_mapping.rtx ? 1 : 0,
            identity_result.error());

        return false;
    }

    return true;
}
std::optional<media_ssrc_mapping> ice_udp_server::find_identity_ssrc_mapping_by_subscriber_ssrc(std::string_view subscriber_session_id,
                                                                                                uint32_t subscriber_ssrc) const
{
    if (identity_authority_ != nullptr)
    {
        auto mapping = identity_authority_->find_ssrc_mapping_by_subscriber_ssrc(subscriber_session_id, subscriber_ssrc);

        if (mapping.has_value())
        {
            return mapping;
        }
    }

    if (ssrc_mapper_ == nullptr)
    {
        return std::nullopt;
    }

    return ssrc_mapper_->find_by_subscriber_ssrc(subscriber_session_id, subscriber_ssrc);
}

std::optional<media_ssrc_mapping> ice_udp_server::find_identity_ssrc_mapping_by_publisher_ssrc(std::string_view stream_id,
                                                                                               std::string_view publisher_session_id,
                                                                                               std::string_view subscriber_session_id,
                                                                                               std::string_view publisher_mid,
                                                                                               uint32_t publisher_ssrc) const
{
    if (identity_authority_ != nullptr)
    {
        auto mapping = identity_authority_->find_ssrc_mapping_by_publisher_ssrc(
            stream_id, publisher_session_id, subscriber_session_id, publisher_mid, publisher_ssrc);

        if (mapping.has_value())
        {
            return mapping;
        }
    }

    if (ssrc_mapper_ == nullptr)
    {
        return std::nullopt;
    }

    return ssrc_mapper_->find_by_publisher_ssrc(stream_id, publisher_session_id, subscriber_session_id, publisher_mid, publisher_ssrc);
}

bool ice_udp_server::selected_media_peer_needs_refresh(std::string_view remote_address, std::string_view session_id) const
{
    if (remote_address.empty() || session_id.empty())
    {
        return false;
    }

    if (media_router_ == nullptr)
    {
        return true;
    }

    const std::optional<media_peer_info> peer = media_router_->get_peer(remote_address);

    if (!peer.has_value())
    {
        return true;
    }

    return peer->session_id != session_id;
}
bool ice_udp_server::selected_transport_peer_needs_refresh(std::string_view remote_address,
                                                           std::string_view session_id,
                                                           std::string_view local_ice_ufrag,
                                                           std::string_view remote_ice_ufrag) const
{
    if (remote_address.empty() || session_id.empty() || local_ice_ufrag.empty())
    {
        return false;
    }

    if (dtls_transport_ == nullptr)
    {
        return false;
    }

    const std::optional<dtls_peer_identity> identity = dtls_transport_->get_peer_identity(remote_address);

    if (!identity.has_value())
    {
        return true;
    }

    if (identity->session_id != session_id)
    {
        return true;
    }

    if (identity->local_ice_ufrag != local_ice_ufrag)
    {
        return true;
    }

    if (!remote_ice_ufrag.empty() && identity->remote_ice_ufrag != remote_ice_ufrag)
    {
        return true;
    }

    return false;
}

void ice_udp_server::observe_inbound_rtp_stats(const media_peer_info& peer,
                                               const srtp_packet_process_result& packet,
                                               const std::optional<media_track_resolution>& track_resolution)
{
    if (rtcp_report_service_ == nullptr || registry_ == nullptr)
    {
        return;
    }

    if (peer.role != media_peer_role::publisher)
    {
        return;
    }

    if (packet.kind != srtp_packet_kind::rtp || packet.plain_packet.empty())
    {
        return;
    }
    if (track_resolution.has_value() && track_resolution->resolved && track_resolution->rtx)
    {
        WEBRTC_LOG_DEBUG(
            "rtcp stats inbound rtp skipped rtx repair stream={} session={} remote={} ssrc={} primary_ssrc={} repair_ssrc={} payload_type={}",
            peer.stream_id,
            peer.session_id,
            peer.remote_endpoint,
            track_resolution->ssrc,
            track_resolution->rtx_primary_ssrc,
            track_resolution->rtx_repair_ssrc,
            static_cast<unsigned int>(track_resolution->payload_type));

        return;
    }

    auto header = parse_rtp_packet_header(std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));
    if (!header)
    {
        WEBRTC_LOG_DEBUG("rtcp stats inbound rtp parse skipped remote={} error={}", peer.remote_endpoint, header.error());
        return;
    }

    if (peer.role == media_peer_role::publisher && rtcp_transport_cc_feedback_service_ != nullptr && track_resolution.has_value() &&
        track_resolution->resolved && track_resolution->transport_wide_sequence_number.has_value())
    {
        auto publisher = registry_ != nullptr ? registry_->find_publisher_by_session_id(peer.session_id) : nullptr;

        if (publisher == nullptr)
        {
            WEBRTC_LOG_DEBUG(
                "rtcp transport cc observe skipped publisher session not found stream={} session={} remote={} ssrc={} mid={} kind={} twcc={}",
                peer.stream_id,
                peer.session_id,
                peer.remote_endpoint,
                header->ssrc,
                track_resolution->mid,
                track_resolution->kind,
                *track_resolution->transport_wide_sequence_number);
        }
        else if (!publisher_media_has_negotiated_transport_cc(*publisher, track_resolution))
        {
            WEBRTC_LOG_DEBUG(
                "rtcp transport cc observe skipped not negotiated stream={} session={} remote={} ssrc={} mid={} kind={} twcc={} accepted_mlines={}",
                peer.stream_id,
                peer.session_id,
                peer.remote_endpoint,
                header->ssrc,
                track_resolution->mid,
                track_resolution->kind,
                *track_resolution->transport_wide_sequence_number,
                publisher->accepted_remote_media_mline_indexes().size());
        }
        else if (identity_authority_ == nullptr)
        {
            WEBRTC_LOG_DEBUG("rtcp transport cc observe skipped identity authority unavailable stream={} session={} remote={} ssrc={} twcc={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             header->ssrc,
                             *track_resolution->transport_wide_sequence_number);
        }
        else if (track_resolution->mid.empty() || track_resolution->kind.empty())
        {
            WEBRTC_LOG_DEBUG(
                "rtcp transport cc observe skipped incomplete track resolution stream={} session={} remote={} ssrc={} mid={} kind={} twcc={}",
                peer.stream_id,
                peer.session_id,
                peer.remote_endpoint,
                header->ssrc,
                track_resolution->mid,
                track_resolution->kind,
                *track_resolution->transport_wide_sequence_number);
        }
        else
        {
            const std::optional<media_identity_track_binding> track_binding =
                identity_authority_->find_track_by_peer_ssrc(peer.remote_endpoint, header->ssrc);

            if (!track_binding.has_value())
            {
                WEBRTC_LOG_DEBUG(
                    "rtcp transport cc observe skipped missing media identity stream={} session={} remote={} ssrc={} mid={} kind={} twcc={}",
                    peer.stream_id,
                    peer.session_id,
                    peer.remote_endpoint,
                    header->ssrc,
                    track_resolution->mid,
                    track_resolution->kind,
                    *track_resolution->transport_wide_sequence_number);
            }
            else if (track_binding->stream_id != peer.stream_id || track_binding->session_id != peer.session_id ||
                     track_binding->remote_endpoint != peer.remote_endpoint || track_binding->ssrc != header->ssrc ||
                     track_binding->mid != track_resolution->mid || track_binding->kind != track_resolution->kind)
            {
                WEBRTC_LOG_WARN(
                    "rtcp transport cc observe skipped identity mismatch stream={} session={} remote={} ssrc={} mid={} kind={} "
                    "binding_stream={} binding_session={} binding_remote={} binding_ssrc={} binding_mid={} binding_kind={} twcc={}",
                    peer.stream_id,
                    peer.session_id,
                    peer.remote_endpoint,
                    header->ssrc,
                    track_resolution->mid,
                    track_resolution->kind,
                    track_binding->stream_id,
                    track_binding->session_id,
                    track_binding->remote_endpoint,
                    track_binding->ssrc,
                    track_binding->mid,
                    track_binding->kind,
                    *track_resolution->transport_wide_sequence_number);
            }
            else if (track_binding->rtx)
            {
                WEBRTC_LOG_DEBUG("rtcp transport cc observe skipped rtx identity stream={} session={} remote={} ssrc={} mid={} kind={} twcc={}",
                                 peer.stream_id,
                                 peer.session_id,
                                 peer.remote_endpoint,
                                 header->ssrc,
                                 track_binding->mid,
                                 track_binding->kind,
                                 *track_resolution->transport_wide_sequence_number);
            }
            else
            {
                rtcp_transport_cc_observed_packet transport_cc_packet;

                transport_cc_packet.stream_id = peer.stream_id;

                transport_cc_packet.session_id = peer.session_id;

                transport_cc_packet.remote_endpoint = peer.remote_endpoint;

                transport_cc_packet.mid = track_binding->mid;

                transport_cc_packet.kind = track_binding->kind;

                transport_cc_packet.sender_ssrc = make_rtcp_report_local_ssrc(peer, header->ssrc);
                transport_cc_packet.media_ssrc = header->ssrc;

                transport_cc_packet.transport_sequence_number = *track_resolution->transport_wide_sequence_number;

                transport_cc_packet.arrival_time_milliseconds = now_milliseconds();

                auto transport_cc_observe_result = rtcp_transport_cc_feedback_service_->observe_received_packet(transport_cc_packet);

                if (!transport_cc_observe_result)
                {
                    WEBRTC_LOG_DEBUG(
                        "rtcp transport cc observe skipped stream={} session={} remote={} ssrc={} mid={} kind={} rid={} repaired_rid={} twcc={} "
                        "error={}",
                        peer.stream_id,
                        peer.session_id,
                        peer.remote_endpoint,
                        header->ssrc,
                        track_binding->mid,
                        track_binding->kind,
                        track_binding->rid.value_or(""),
                        track_binding->repaired_rid.value_or(""),
                        *track_resolution->transport_wide_sequence_number,
                        transport_cc_observe_result.error());
                }
            }
        }
    }

    auto publisher = registry_->find_publisher_by_session_id(peer.session_id);

    if (publisher == nullptr)
    {
        return;
    }

    std::string mid;
    std::string kind;
    std::optional<std::string> rid;
    std::optional<std::string> repaired_rid;

    if (track_resolution.has_value() && track_resolution->resolved)
    {
        mid = track_resolution->mid;

        kind = track_resolution->kind;

        rid = track_resolution->rid;

        repaired_rid = track_resolution->repaired_rid;
    }
    if (media_offer_payload_type_is_rtx(publisher->remote_offer_summary(), mid, header->payload_type))
    {
        WEBRTC_LOG_DEBUG("rtcp stats inbound rtp skipped rtx payload type stream={} session={} remote={} ssrc={} payload_type={} mid={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         header->ssrc,
                         static_cast<unsigned int>(header->payload_type),
                         mid);

        return;
    }

    auto clock_rate = find_codec_clock_rate(publisher->remote_offer_summary(), mid, header->payload_type);
    if (!clock_rate.has_value() || *clock_rate == 0)
    {
        WEBRTC_LOG_DEBUG("rtcp stats inbound rtp clock rate not found stream={} session={} remote={} ssrc={} payload_type={} mid={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         header->ssrc,
                         static_cast<unsigned int>(header->payload_type),
                         mid);

        return;
    }

    auto payload_size = compute_rtp_payload_size(std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

    if (!payload_size)
    {
        WEBRTC_LOG_DEBUG("rtcp stats inbound rtp payload size skipped stream={} session={} remote={} ssrc={} error={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         header->ssrc,
                         payload_size.error());

        return;
    }

    rtcp_received_rtp_packet observed_packet;

    observed_packet.stream_id = peer.stream_id;

    observed_packet.session_id = peer.session_id;

    observed_packet.remote_endpoint = peer.remote_endpoint;

    observed_packet.mid = mid;

    observed_packet.rid = rid;

    observed_packet.repaired_rid = repaired_rid;

    observed_packet.ssrc = header->ssrc;

    observed_packet.sequence_number = header->sequence_number;

    observed_packet.rtp_timestamp = header->timestamp;

    observed_packet.clock_rate = *clock_rate;

    observed_packet.payload_size = *payload_size;

    observed_packet.arrival_time_milliseconds = now_milliseconds();

    auto observe_result = rtcp_report_service_->observe_received_rtp(observed_packet);

    if (!observe_result)
    {
        WEBRTC_LOG_DEBUG("rtcp stats inbound rtp observe failed stream={} session={} remote={} ssrc={} error={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         header->ssrc,
                         observe_result.error());

        return;
    }

    const uint32_t local_ssrc = make_rtcp_report_local_ssrc(peer, header->ssrc);

    rtcp_report_source_config source;

    source.stream_id = peer.stream_id;

    source.session_id = peer.session_id;

    source.remote_endpoint = peer.remote_endpoint;

    source.mid = mid;
    source.kind = kind;
    source.rid = rid;
    source.repaired_rid = repaired_rid;
    source.local_ssrc = local_ssrc;
    source.cname = make_rtcp_cname(peer.session_id, local_ssrc);
    source.sender_report_enabled = false;
    source.receiver_report_enabled = true;

    auto remember_result = rtcp_report_service_->remember_source(source);

    if (!remember_result)
    {
        WEBRTC_LOG_DEBUG("rtcp stats inbound rtp remember source failed stream={} session={} remote={} ssrc={} error={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         header->ssrc,
                         remember_result.error());
    }
}

void ice_udp_server::observe_inbound_rtcp_reports(const media_peer_info& peer, const srtp_packet_process_result& packet)
{
    if (rtcp_report_service_ == nullptr)
    {
        return;
    }

    if (packet.kind != srtp_packet_kind::rtcp || packet.plain_packet.empty())
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    rtcp_report_inbound_rtcp_observe_attempts_total_.fetch_add(1, std::memory_order_relaxed);

    if (peer.role == media_peer_role::subscriber)
    {
        std::size_t receiver_report_observed_count = 0;
        std::size_t remb_observed_count = 0;
        uint64_t max_remb_bitrate_bps = 0;

        if (packet.rtcp_has_receiver_report && !packet.rtcp_report_blocks.empty())
        {
            if (packet.rtcp_report_sender_ssrc == 0)
            {
                WEBRTC_LOG_DEBUG("rtcp stats subscriber receiver report skipped empty reporter stream={} session={} remote={}",
                                 peer.stream_id,
                                 peer.session_id,
                                 peer.remote_endpoint);
            }
            else
            {
                rtcp_received_receiver_report report;

                report.stream_id = peer.stream_id;

                report.session_id = peer.session_id;

                report.remote_endpoint = peer.remote_endpoint;

                report.reporter_ssrc = packet.rtcp_report_sender_ssrc;

                report.report_blocks = packet.rtcp_report_blocks;

                report.arrival_time_milliseconds = current_time_milliseconds;

                auto observe_result = rtcp_report_service_->observe_receiver_report(report);

                if (!observe_result)
                {
                    rtcp_report_inbound_rtcp_observe_failed_total_.fetch_add(1, std::memory_order_relaxed);

                    WEBRTC_LOG_DEBUG(
                        "rtcp stats subscriber receiver report observe failed stream={} session={} remote={} reporter_ssrc={} blocks={} error={}",
                        peer.stream_id,
                        peer.session_id,
                        peer.remote_endpoint,
                        packet.rtcp_report_sender_ssrc,
                        packet.rtcp_report_blocks.size(),
                        observe_result.error());
                }
                else
                {
                    receiver_report_observed_count = packet.rtcp_report_blocks.size();
                }
            }
        }

        if (!packet.rtcp_feedback_blocks.empty())
        {
            for (const auto& block : packet.rtcp_feedback_blocks)
            {
                if (!block.has_remb || block.feedback_sender_ssrc == 0 || block.remb_bitrate_bps == 0)
                {
                    continue;
                }

                std::vector<uint32_t> normalized_remb_ssrcs;

                auto append_normalized_remb_ssrc = [&](uint32_t subscriber_ssrc)
                {
                    if (subscriber_ssrc == 0)
                    {
                        return;
                    }

                    const std::optional<media_ssrc_mapping> mapping = find_identity_ssrc_mapping_by_subscriber_ssrc(peer.session_id, subscriber_ssrc);

                    if (!mapping.has_value())
                    {
                        WEBRTC_LOG_DEBUG(
                            "rtcp stats subscriber remb target skipped mapping not found stream={} session={} remote={} subscriber_ssrc={}",
                            peer.stream_id,
                            peer.session_id,
                            peer.remote_endpoint,
                            subscriber_ssrc);

                        return;
                    }

                    if (!peer.stream_id.empty() && mapping->stream_id != peer.stream_id)
                    {
                        WEBRTC_LOG_DEBUG(
                            "rtcp stats subscriber remb target skipped stream mismatch stream={} session={} remote={} subscriber_ssrc={} "
                            "mapping_stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={}",
                            peer.stream_id,
                            peer.session_id,
                            peer.remote_endpoint,
                            subscriber_ssrc,
                            mapping->stream_id,
                            mapping->publisher_session_id,
                            mapping->subscriber_session_id,
                            mapping->publisher_mid,
                            mapping->subscriber_mid);

                        return;
                    }

                    if (mapping->subscriber_session_id != peer.session_id)
                    {
                        WEBRTC_LOG_DEBUG(
                            "rtcp stats subscriber remb target skipped session mismatch stream={} session={} remote={} subscriber_ssrc={} "
                            "mapping_subscriber_session={} publisher_session={} publisher_mid={} subscriber_mid={}",
                            peer.stream_id,
                            peer.session_id,
                            peer.remote_endpoint,
                            subscriber_ssrc,
                            mapping->subscriber_session_id,
                            mapping->publisher_session_id,
                            mapping->publisher_mid,
                            mapping->subscriber_mid);

                        return;
                    }

                    if (media_ssrc_mapping_is_rtx(*mapping))
                    {
                        WEBRTC_LOG_DEBUG(
                            "rtcp stats subscriber remb target skipped rtx mapping stream={} session={} remote={} subscriber_ssrc={} "
                            "publisher_ssrc={} publisher_mid={} subscriber_mid={} kind={}",
                            peer.stream_id,
                            peer.session_id,
                            peer.remote_endpoint,
                            mapping->subscriber_ssrc,
                            mapping->publisher_ssrc,
                            mapping->publisher_mid,
                            mapping->subscriber_mid,
                            mapping->kind);

                        return;
                    }

                    const auto existing = std::find(normalized_remb_ssrcs.begin(), normalized_remb_ssrcs.end(), mapping->publisher_ssrc);

                    if (existing == normalized_remb_ssrcs.end())
                    {
                        normalized_remb_ssrcs.push_back(mapping->publisher_ssrc);
                    }
                };

                if (!block.remb_ssrcs.empty())
                {
                    for (uint32_t subscriber_ssrc : block.remb_ssrcs)
                    {
                        append_normalized_remb_ssrc(subscriber_ssrc);
                    }
                }
                else
                {
                    append_normalized_remb_ssrc(block.feedback_media_ssrc);
                }

                if (normalized_remb_ssrcs.empty())
                {
                    WEBRTC_LOG_DEBUG(
                        "rtcp stats subscriber remb skipped no normalized target stream={} session={} remote={} sender_ssrc={} bitrate_bps={}",
                        peer.stream_id,
                        peer.session_id,
                        peer.remote_endpoint,
                        block.feedback_sender_ssrc,
                        block.remb_bitrate_bps);

                    continue;
                }

                rtcp_received_remb report;

                report.stream_id = peer.stream_id;

                report.session_id = peer.session_id;

                report.remote_endpoint = peer.remote_endpoint;

                report.sender_ssrc = block.feedback_sender_ssrc;

                report.media_ssrc = normalized_remb_ssrcs.front();

                report.bitrate_bps = block.remb_bitrate_bps;

                report.ssrcs = std::move(normalized_remb_ssrcs);

                report.arrival_time_milliseconds = current_time_milliseconds;

                auto observe_result = rtcp_report_service_->observe_remb(report);

                if (!observe_result)
                {
                    rtcp_report_inbound_rtcp_observe_failed_total_.fetch_add(1, std::memory_order_relaxed);

                    WEBRTC_LOG_DEBUG(
                        "rtcp stats subscriber remb observe failed stream={} session={} remote={} sender_ssrc={} bitrate_bps={} error={}",
                        peer.stream_id,
                        peer.session_id,
                        peer.remote_endpoint,
                        block.feedback_sender_ssrc,
                        block.remb_bitrate_bps,
                        observe_result.error());

                    continue;
                }

                remb_observed_count += report.ssrcs.size();

                if (report.bitrate_bps > max_remb_bitrate_bps)
                {
                    max_remb_bitrate_bps = report.bitrate_bps;
                }
            }
        }

        if (receiver_report_observed_count != 0 || remb_observed_count != 0)
        {
            WEBRTC_LOG_DEBUG("rtcp stats subscriber feedback observed stream={} session={} remote={} rr={} remb={} max_remb_bps={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             receiver_report_observed_count,
                             remb_observed_count,
                             max_remb_bitrate_bps);
        }

        return;
    }

    auto observation =
        rtcp_report_service_->observe_received_rtcp_with_summary(peer.stream_id,
                                                                 peer.session_id,
                                                                 peer.remote_endpoint,
                                                                 std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()),
                                                                 current_time_milliseconds);

    if (!observation)
    {
        rtcp_report_inbound_rtcp_observe_failed_total_.fetch_add(1, std::memory_order_relaxed);

        WEBRTC_LOG_DEBUG("rtcp stats observe skipped stream={} session={} remote={} role={} error={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         media_peer_role_to_string(peer.role),
                         observation.error());

        return;
    }

    if (observation->receiver_report_count != 0 || observation->remb_count != 0)
    {
        WEBRTC_LOG_DEBUG("rtcp stats feedback observed stream={} session={} remote={} role={} rr={} remb={} max_remb_bps={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         media_peer_role_to_string(peer.role),
                         observation->receiver_report_count,
                         observation->remb_count,
                         observation->max_remb_bitrate_bps);
    }

    if (peer.role != media_peer_role::publisher)
    {
        return;
    }

    if (observation->sender_report_count == 0)
    {
        return;
    }

    auto publisher = registry_ != nullptr ? registry_->find_publisher_by_session_id(peer.session_id) : nullptr;

    std::size_t remembered_sender_report_source_count = 0;

    for (uint32_t sender_report_ssrc : observation->sender_report_ssrcs)
    {
        if (sender_report_ssrc == 0)
        {
            continue;
        }

        if (publisher != nullptr && offer_ssrc_is_rtx_repair(publisher->remote_offer_summary(), sender_report_ssrc))
        {
            WEBRTC_LOG_DEBUG("rtcp stats sender report skipped rtx repair stream={} session={} remote={} sender_ssrc={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             sender_report_ssrc);

            continue;
        }

        std::optional<media_identity_track_binding> track_binding;

        if (identity_authority_ != nullptr)
        {
            track_binding = identity_authority_->find_track_by_peer_ssrc(peer.remote_endpoint, sender_report_ssrc);
        }

        if (!track_binding.has_value())
        {
            WEBRTC_LOG_DEBUG("rtcp stats sender report skipped missing media identity stream={} session={} remote={} sender_ssrc={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             sender_report_ssrc);

            continue;
        }

        if (track_binding->stream_id != peer.stream_id || track_binding->session_id != peer.session_id ||
            track_binding->remote_endpoint != peer.remote_endpoint || track_binding->ssrc != sender_report_ssrc)
        {
            WEBRTC_LOG_WARN(
                "rtcp stats sender report skipped identity mismatch stream={} session={} remote={} sender_ssrc={} binding_stream={} "
                "binding_session={} binding_remote={} binding_mid={} binding_kind={} binding_ssrc={}",
                peer.stream_id,
                peer.session_id,
                peer.remote_endpoint,
                sender_report_ssrc,
                track_binding->stream_id,
                track_binding->session_id,
                track_binding->remote_endpoint,
                track_binding->mid,
                track_binding->kind,
                track_binding->ssrc);

            continue;
        }

        if (track_binding->rtx)
        {
            WEBRTC_LOG_DEBUG("rtcp stats sender report skipped rtx identity stream={} session={} remote={} sender_ssrc={} mid={} kind={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             sender_report_ssrc,
                             track_binding->mid,
                             track_binding->kind);

            continue;
        }

        if (track_binding->mid.empty() || track_binding->kind.empty())
        {
            WEBRTC_LOG_DEBUG("rtcp stats sender report skipped incomplete identity stream={} session={} remote={} sender_ssrc={} mid={} kind={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             sender_report_ssrc,
                             track_binding->mid,
                             track_binding->kind);

            continue;
        }

        const uint32_t local_ssrc = make_rtcp_report_local_ssrc(peer, sender_report_ssrc);

        rtcp_report_source_config source;

        source.stream_id = peer.stream_id;

        source.session_id = peer.session_id;

        source.remote_endpoint = peer.remote_endpoint;

        source.mid = track_binding->mid;
        source.kind = track_binding->kind;

        source.rid = track_binding->rid;

        source.repaired_rid = track_binding->repaired_rid;

        source.local_ssrc = local_ssrc;

        source.cname = make_rtcp_cname(peer.session_id, local_ssrc);

        source.sender_report_enabled = false;

        source.receiver_report_enabled = true;

        rtcp_report_remember_source_attempts_total_.fetch_add(1, std::memory_order_relaxed);

        auto remember_result = rtcp_report_service_->remember_source(source, current_time_milliseconds);

        if (!remember_result)
        {
            rtcp_report_remember_source_failed_total_.fetch_add(1, std::memory_order_relaxed);

            WEBRTC_LOG_DEBUG(
                "rtcp stats sender report remember source failed stream={} session={} remote={} sender_ssrc={} local_ssrc={} mid={} kind={} rid={} "
                "repaired_rid={} error={}",
                peer.stream_id,
                peer.session_id,
                peer.remote_endpoint,
                sender_report_ssrc,
                local_ssrc,
                track_binding->mid,
                track_binding->kind,
                track_binding->rid.value_or(""),
                track_binding->repaired_rid.value_or(""),
                remember_result.error());

            continue;
        }

        rtcp_report_remember_source_success_total_.fetch_add(1, std::memory_order_relaxed);

        remembered_sender_report_source_count += 1;

        WEBRTC_LOG_DEBUG(
            "rtcp stats sender report observed stream={} session={} remote={} sender_ssrc={} local_ssrc={} mid={} kind={} rid={} repaired_rid={}",
            peer.stream_id,
            peer.session_id,
            peer.remote_endpoint,
            sender_report_ssrc,
            local_ssrc,
            track_binding->mid,
            track_binding->kind,
            track_binding->rid.value_or(""),
            track_binding->repaired_rid.value_or(""));
    }

    if (remembered_sender_report_source_count != 0)
    {
        rtcp_report_inbound_sender_report_sources_total_.fetch_add(static_cast<uint64_t>(remembered_sender_report_source_count),
                                                                   std::memory_order_relaxed);
    }
}

void ice_udp_server::normalize_inbound_rtcp_report_stats(const media_peer_info& peer, srtp_packet_process_result& packet)
{
    if (packet.kind != srtp_packet_kind::rtcp)
    {
        return;
    }

    if (packet.rtcp_report_packet_count == 0)
    {
        return;
    }

    bool sender_report_skipped = false;

    if (peer.role == media_peer_role::publisher && packet.rtcp_has_sender_report && packet.rtcp_report_sender_ssrc != 0 && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(peer.session_id);

        if (publisher != nullptr && offer_ssrc_is_rtx_repair(publisher->remote_offer_summary(), packet.rtcp_report_sender_ssrc))
        {
            WEBRTC_LOG_DEBUG("rtcp report stats skipped rtx sender report stream={} session={} remote={} sender_ssrc={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             packet.rtcp_report_sender_ssrc);

            packet.rtcp_has_sender_report = false;

            packet.rtcp_has_sender_info = false;

            packet.rtcp_report_sender_ssrc = 0;

            packet.rtcp_sender_info_data = rtcp_sender_info{};

            sender_report_skipped = true;
        }
    }

    if (packet.rtcp_report_blocks.empty())
    {
        if (sender_report_skipped && !packet.rtcp_has_receiver_report && !packet.rtcp_has_sender_report)
        {
            packet.rtcp_report_packet_count = 0;

            packet.rtcp_report_block_count = 0;
        }

        return;
    }

    if (peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (ssrc_mapper_ == nullptr && identity_authority_ == nullptr)
    {
        return;
    }

    std::vector<rtcp_report_block> normalized_blocks;

    normalized_blocks.reserve(packet.rtcp_report_blocks.size());

    std::size_t rtx_skipped_count = 0;
    std::size_t mapping_missing_count = 0;
    std::size_t rewritten_count = 0;

    for (rtcp_report_block report_block : packet.rtcp_report_blocks)
    {
        if (report_block.ssrc == 0)
        {
            continue;
        }

        const uint32_t original_subscriber_ssrc = report_block.ssrc;

        const std::optional<media_ssrc_mapping> mapping = find_identity_ssrc_mapping_by_subscriber_ssrc(peer.session_id, original_subscriber_ssrc);

        if (!mapping.has_value())
        {
            mapping_missing_count += 1;

            WEBRTC_LOG_DEBUG("rtcp report block skipped mapping not found stream={} session={} remote={} subscriber_ssrc={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             original_subscriber_ssrc);

            continue;
        }

        if (media_ssrc_mapping_is_rtx(*mapping))
        {
            rtx_skipped_count += 1;

            WEBRTC_LOG_DEBUG("rtcp report block skipped rtx mapping stream={} session={} remote={} subscriber_ssrc={} publisher_ssrc={} kind={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             mapping->subscriber_ssrc,
                             mapping->publisher_ssrc,
                             mapping->kind);

            continue;
        }

        if (report_block.ssrc != mapping->publisher_ssrc)
        {
            rewritten_count += 1;
        }

        report_block.ssrc = mapping->publisher_ssrc;

        normalized_blocks.push_back(report_block);
    }

    packet.rtcp_report_blocks = std::move(normalized_blocks);

    packet.rtcp_report_block_count = packet.rtcp_report_blocks.size();

    if (packet.rtcp_report_blocks.empty())
    {
        packet.rtcp_last_fraction_lost = 0;

        packet.rtcp_last_cumulative_lost = 0;

        packet.rtcp_last_jitter = 0;
    }
    else
    {
        const rtcp_report_block& last_report_block = packet.rtcp_report_blocks.back();

        packet.rtcp_last_fraction_lost = last_report_block.fraction_lost;

        packet.rtcp_last_cumulative_lost = last_report_block.cumulative_lost;

        packet.rtcp_last_jitter = last_report_block.jitter;
    }

    if (rtx_skipped_count != 0 || mapping_missing_count != 0 || rewritten_count != 0)
    {
        WEBRTC_LOG_DEBUG("rtcp report blocks normalized stream={} session={} remote={} kept={} rtx_skipped={} mapping_missing={} rewritten={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         packet.rtcp_report_blocks.size(),
                         rtx_skipped_count,
                         mapping_missing_count,
                         rewritten_count);
    }
}
std::optional<media_ssrc_mapping> ice_udp_server::find_outbound_ssrc_mapping(const media_peer_info& target_peer,
                                                                             std::span<const uint8_t> outbound_plain_packet) const
{
    if (target_peer.role != media_peer_role::subscriber)
    {
        return std::nullopt;
    }

    if (target_peer.session_id.empty())
    {
        return std::nullopt;
    }

    if (outbound_plain_packet.empty())
    {
        return std::nullopt;
    }

    if (identity_authority_ == nullptr && ssrc_mapper_ == nullptr)
    {
        return std::nullopt;
    }

    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        WEBRTC_LOG_DEBUG("outbound ssrc mapping parse skipped subscriber_session={} remote={} error={}",
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         header.error());

        return std::nullopt;
    }

    if (header->ssrc == 0)
    {
        return std::nullopt;
    }

    auto mapping = find_identity_ssrc_mapping_by_subscriber_ssrc(target_peer.session_id, header->ssrc);

    if (!mapping.has_value())
    {
        WEBRTC_LOG_DEBUG("outbound ssrc mapping not found subscriber_session={} remote={} subscriber_ssrc={}",
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         header->ssrc);

        return std::nullopt;
    }

    if (mapping->subscriber_session_id != target_peer.session_id)
    {
        WEBRTC_LOG_WARN(
            "outbound ssrc mapping subscriber session mismatch target_session={} remote={} subscriber_ssrc={} mapping_stream={} "
            "mapping_publisher_session={} mapping_subscriber_session={} publisher_mid={} subscriber_mid={}",
            target_peer.session_id,
            target_peer.remote_endpoint,
            header->ssrc,
            mapping->stream_id,
            mapping->publisher_session_id,
            mapping->subscriber_session_id,
            mapping->publisher_mid,
            mapping->subscriber_mid);

        return std::nullopt;
    }

    if (!target_peer.stream_id.empty() && mapping->stream_id != target_peer.stream_id)
    {
        WEBRTC_LOG_WARN(
            "outbound ssrc mapping stream mismatch target_stream={} subscriber_session={} remote={} subscriber_ssrc={} mapping_stream={} "
            "mapping_publisher_session={} publisher_mid={} subscriber_mid={}",
            target_peer.stream_id,
            target_peer.session_id,
            target_peer.remote_endpoint,
            header->ssrc,
            mapping->stream_id,
            mapping->publisher_session_id,
            mapping->publisher_mid,
            mapping->subscriber_mid);

        return std::nullopt;
    }

    if (mapping->subscriber_ssrc != header->ssrc)
    {
        WEBRTC_LOG_WARN(
            "outbound ssrc mapping subscriber ssrc mismatch stream={} subscriber_session={} remote={} packet_ssrc={} mapping_subscriber_ssrc={} "
            "publisher_ssrc={} publisher_mid={} subscriber_mid={} kind={} rtx={}",
            mapping->stream_id,
            target_peer.session_id,
            target_peer.remote_endpoint,
            header->ssrc,
            mapping->subscriber_ssrc,
            mapping->publisher_ssrc,
            mapping->publisher_mid,
            mapping->subscriber_mid,
            mapping->kind,
            media_ssrc_mapping_is_rtx(*mapping) ? 1 : 0);

        return std::nullopt;
    }

    return mapping;
}
void ice_udp_server::observe_outbound_rtp_stats(const media_peer_info& target_peer,
                                                std::span<const uint8_t> outbound_plain_packet,
                                                const std::optional<media_ssrc_mapping>& mapping)
{
    if (rtcp_report_service_ == nullptr)
    {
        return;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (target_peer.session_id.empty() || target_peer.remote_endpoint.empty())
    {
        return;
    }

    if (outbound_plain_packet.empty())
    {
        return;
    }

    if (!mapping.has_value())
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp skipped missing mapping stream={} session={} remote={}",
                         target_peer.stream_id,
                         target_peer.session_id,
                         target_peer.remote_endpoint);

        return;
    }

    if (mapping->subscriber_session_id != target_peer.session_id)
    {
        WEBRTC_LOG_WARN(
            "rtcp stats outbound rtp skipped mapping session mismatch target_stream={} target_session={} remote={} mapping_stream={} "
            "mapping_publisher_session={} mapping_subscriber_session={} publisher_mid={} subscriber_mid={} publisher_ssrc={} subscriber_ssrc={}",
            target_peer.stream_id,
            target_peer.session_id,
            target_peer.remote_endpoint,
            mapping->stream_id,
            mapping->publisher_session_id,
            mapping->subscriber_session_id,
            mapping->publisher_mid,
            mapping->subscriber_mid,
            mapping->publisher_ssrc,
            mapping->subscriber_ssrc);

        return;
    }

    if (!target_peer.stream_id.empty() && mapping->stream_id != target_peer.stream_id)
    {
        WEBRTC_LOG_WARN(
            "rtcp stats outbound rtp skipped mapping stream mismatch target_stream={} target_session={} remote={} mapping_stream={} "
            "mapping_publisher_session={} publisher_mid={} subscriber_mid={} publisher_ssrc={} subscriber_ssrc={}",
            target_peer.stream_id,
            target_peer.session_id,
            target_peer.remote_endpoint,
            mapping->stream_id,
            mapping->publisher_session_id,
            mapping->publisher_mid,
            mapping->subscriber_mid,
            mapping->publisher_ssrc,
            mapping->subscriber_ssrc);

        return;
    }

    if (mapping->subscriber_mid.empty() || mapping->kind.empty())
    {
        WEBRTC_LOG_WARN(
            "rtcp stats outbound rtp skipped incomplete mapping stream={} session={} remote={} publisher_mid={} subscriber_mid={} kind={} "
            "publisher_ssrc={} subscriber_ssrc={}",
            target_peer.stream_id,
            target_peer.session_id,
            target_peer.remote_endpoint,
            mapping->publisher_mid,
            mapping->subscriber_mid,
            mapping->kind,
            mapping->publisher_ssrc,
            mapping->subscriber_ssrc);

        return;
    }

    if (media_ssrc_mapping_is_rtx(*mapping))
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp skipped rtx mapping stream={} session={} remote={} subscriber_ssrc={} publisher_ssrc={}",
                         target_peer.stream_id,
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         mapping->subscriber_ssrc,
                         mapping->publisher_ssrc);

        return;
    }

    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp parse skipped remote={} error={}", target_peer.remote_endpoint, header.error());

        return;
    }

    if (header->ssrc == 0)
    {
        return;
    }

    if (header->ssrc != mapping->subscriber_ssrc)
    {
        WEBRTC_LOG_WARN(
            "rtcp stats outbound rtp skipped ssrc mismatch stream={} session={} remote={} packet_ssrc={} mapping_subscriber_ssrc={} "
            "publisher_ssrc={} publisher_mid={} subscriber_mid={} kind={}",
            target_peer.stream_id,
            target_peer.session_id,
            target_peer.remote_endpoint,
            header->ssrc,
            mapping->subscriber_ssrc,
            mapping->publisher_ssrc,
            mapping->publisher_mid,
            mapping->subscriber_mid,
            mapping->kind);

        return;
    }

    auto payload_size = compute_rtp_payload_size(outbound_plain_packet);

    if (!payload_size)
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp payload size skipped stream={} session={} remote={} ssrc={} error={}",
                         target_peer.stream_id,
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         header->ssrc,
                         payload_size.error());

        return;
    }

    rtcp_sent_rtp_packet observed_packet;

    observed_packet.stream_id = mapping->stream_id;

    observed_packet.session_id = target_peer.session_id;

    observed_packet.remote_endpoint = target_peer.remote_endpoint;

    observed_packet.mid = mapping->subscriber_mid;

    observed_packet.rid = mapping->rid;

    observed_packet.repaired_rid = mapping->repaired_rid;

    observed_packet.ssrc = header->ssrc;

    observed_packet.rtp_timestamp = header->timestamp;

    observed_packet.payload_size = *payload_size;

    observed_packet.send_time_milliseconds = now_milliseconds();

    auto observe_result = rtcp_report_service_->observe_sent_rtp(observed_packet);

    if (!observe_result)
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp observe failed stream={} session={} remote={} ssrc={} mid={} rid={} repaired_rid={} error={}",
                         observed_packet.stream_id,
                         observed_packet.session_id,
                         observed_packet.remote_endpoint,
                         observed_packet.ssrc,
                         observed_packet.mid,
                         observed_packet.rid.value_or(""),
                         observed_packet.repaired_rid.value_or(""),
                         observe_result.error());

        return;
    }

    rtcp_report_source_config source;

    source.stream_id = mapping->stream_id;

    source.session_id = target_peer.session_id;

    source.remote_endpoint = target_peer.remote_endpoint;

    source.mid = mapping->subscriber_mid;
    source.kind = mapping->kind;
    source.rid = mapping->rid;
    source.repaired_rid = mapping->repaired_rid;

    source.local_ssrc = header->ssrc;

    source.cname = make_rtcp_cname(target_peer.session_id, header->ssrc);

    source.sender_report_enabled = true;

    source.receiver_report_enabled = true;

    auto remember_result = rtcp_report_service_->remember_source(source, observed_packet.send_time_milliseconds);

    if (!remember_result)
    {
        WEBRTC_LOG_DEBUG(
            "rtcp stats outbound rtp remember source failed stream={} session={} remote={} ssrc={} mid={} rid={} repaired_rid={} error={}",
            source.stream_id,
            source.session_id,
            source.remote_endpoint,
            source.local_ssrc,
            source.mid,
            source.rid.value_or(""),
            source.repaired_rid.value_or(""),
            remember_result.error());

        return;
    }

    WEBRTC_LOG_DEBUG(
        "rtcp stats outbound rtp source remembered stream={} session={} remote={} publisher_session={} publisher_mid={} subscriber_mid={} "
        "kind={} publisher_ssrc={} subscriber_ssrc={} rid={} repaired_rid={} payload_size={}",
        mapping->stream_id,
        target_peer.session_id,
        target_peer.remote_endpoint,
        mapping->publisher_session_id,
        mapping->publisher_mid,
        mapping->subscriber_mid,
        mapping->kind,
        mapping->publisher_ssrc,
        mapping->subscriber_ssrc,
        mapping->rid.value_or(""),
        mapping->repaired_rid.value_or(""),
        *payload_size);
}

void ice_udp_server::observe_outbound_track_stats(const media_peer_info& target_peer,
                                                  std::span<const uint8_t> outbound_plain_packet,
                                                  const std::optional<media_ssrc_mapping>& mapping)
{
    if (target_peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (outbound_plain_packet.empty())
    {
        return;
    }

    if (media_router_ == nullptr)
    {
        return;
    }

    if (!mapping.has_value())
    {
        return;
    }

    if (media_ssrc_mapping_is_rtx(*mapping))
    {
        WEBRTC_LOG_DEBUG("media outbound track stats skipped rtx mapping stream={} session={} remote={} subscriber_ssrc={} publisher_ssrc={}",
                         target_peer.stream_id,
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         mapping->subscriber_ssrc,
                         mapping->publisher_ssrc);

        return;
    }

    media_router_->observe_outbound_track(target_peer, *mapping, outbound_plain_packet);
}

std::optional<media_payload_type_mapping_table> ice_udp_server::get_or_create_payload_type_mapping_table(const media_route_result& route,
                                                                                                         const media_peer_info& target_peer)
{
    if (route.source.role != media_peer_role::publisher)
    {
        return std::nullopt;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return std::nullopt;
    }

    if (route.source.stream_id != target_peer.stream_id)
    {
        WEBRTC_LOG_WARN(
            "payload type mapping skipped stream mismatch publisher_stream={} subscriber_stream={} publisher_session={} subscriber_session={}",
            route.source.stream_id,
            target_peer.stream_id,
            route.source.session_id,
            target_peer.session_id);

        return std::nullopt;
    }

    return get_or_create_payload_type_mapping_table_for_sessions(route.source.stream_id, route.source.session_id, target_peer.session_id);
}

std::optional<media_payload_type_mapping_table> ice_udp_server::get_or_create_payload_type_mapping_table_for_sessions(
    std::string_view stream_id, std::string_view publisher_session_id, std::string_view subscriber_session_id)
{
    if (registry_ == nullptr)
    {
        return std::nullopt;
    }

    if (stream_id.empty() || publisher_session_id.empty() || subscriber_session_id.empty())
    {
        return std::nullopt;
    }

    const std::string cache_key = make_payload_type_mapping_key(publisher_session_id, subscriber_session_id);

    {
        std::lock_guard lock(endpoint_mutex_);

        const auto iterator = payload_type_mappings_by_key_.find(cache_key);

        if (iterator != payload_type_mappings_by_key_.end())
        {
            return iterator->second.table;
        }
    }

    auto publisher = registry_->find_publisher_by_session_id(publisher_session_id);

    if (publisher == nullptr)
    {
        WEBRTC_LOG_WARN("payload type mapping publisher session not found stream={} session={}", stream_id, publisher_session_id);

        return std::nullopt;
    }

    auto subscriber = registry_->find_subscriber_by_session_id(subscriber_session_id);

    if (subscriber == nullptr)
    {
        WEBRTC_LOG_WARN("payload type mapping subscriber session not found stream={} session={}", stream_id, subscriber_session_id);

        return std::nullopt;
    }

    auto table_result = build_media_payload_type_mapping_table(stream_id, publisher->remote_offer_summary(), subscriber->remote_offer_summary());

    if (!table_result)
    {
        WEBRTC_LOG_WARN("payload type mapping build failed stream={} publisher_session={} subscriber_session={} error={}",
                        stream_id,
                        publisher_session_id,
                        subscriber_session_id,
                        table_result.error());

        return std::nullopt;
    }

    const std::size_t removed_mapping_count = erase_unaccepted_payload_type_mappings(*table_result, *publisher, *subscriber);

    if (table_result->mappings.empty())
    {
        WEBRTC_LOG_WARN(
            "payload type mapping build rejected by accepted media gate stream={} publisher_session={} subscriber_session={} "
            "publisher_accepted_mlines={} subscriber_accepted_mlines={} removed_mappings={}",
            stream_id,
            publisher_session_id,
            subscriber_session_id,
            publisher->accepted_remote_media_mline_indexes().size(),
            subscriber->accepted_remote_media_mline_indexes().size(),
            removed_mapping_count);

        return std::nullopt;
    }

    if (removed_mapping_count != 0)
    {
        WEBRTC_LOG_INFO(
            "payload type mapping filtered by accepted media gate stream={} publisher_session={} subscriber_session={} remaining_mappings={} "
            "removed_mappings={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
            stream_id,
            publisher_session_id,
            subscriber_session_id,
            table_result->mappings.size(),
            removed_mapping_count,
            publisher->accepted_remote_media_mline_indexes().size(),
            subscriber->accepted_remote_media_mline_indexes().size());
    }

    media_payload_type_mapping_cache_entry entry;

    entry.publisher_session_id = std::string(publisher_session_id);
    entry.subscriber_session_id = std::string(subscriber_session_id);

    entry.stream_id = std::string(stream_id);

    entry.table = std::move(*table_result);

    WEBRTC_LOG_INFO("payload type mapping table created stream={} publisher_session={} subscriber_session={} mappings={}",
                    entry.stream_id,
                    entry.publisher_session_id,
                    entry.subscriber_session_id,
                    entry.table.mappings.size());

    {
        std::lock_guard lock(endpoint_mutex_);

        auto [iterator, inserted] = payload_type_mappings_by_key_.try_emplace(cache_key, std::move(entry));

        (void)inserted;

        return iterator->second.table;
    }
}

std::optional<media_payload_type_mapping> ice_udp_server::find_payload_type_mapping(const media_route_result& route,
                                                                                    const media_peer_info& subscriber,
                                                                                    const std::optional<media_track_resolution>& track_resolution)
{
    if (!track_resolution.has_value() || !track_resolution->resolved)
    {
        return std::nullopt;
    }

    if (!track_resolution->mid.empty() && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        if (publisher != nullptr && media_offer_payload_type_is_unsupported_repair_codec(
                                        publisher->remote_offer_summary(), track_resolution->mid, track_resolution->payload_type))
        {
            WEBRTC_LOG_DEBUG(
                "payload type mapping skipped unsupported repair codec stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                "kind={} publisher_payload_type={} ssrc={} rid={} repaired_rid={} rtx={}",
                route.source.stream_id,
                route.source.session_id,
                subscriber.session_id,
                track_resolution->mid,
                track_resolution->kind,
                static_cast<unsigned int>(track_resolution->payload_type),
                track_resolution->ssrc,
                track_resolution->rid.has_value() ? *track_resolution->rid : "",
                track_resolution->repaired_rid.has_value() ? *track_resolution->repaired_rid : "",
                track_resolution->rtx ? 1 : 0);

            return std::nullopt;
        }
    }

    auto table = get_or_create_payload_type_mapping_table(route, subscriber);

    if (!table.has_value())
    {
        return std::nullopt;
    }

    if (!track_resolution->mid.empty())
    {
        auto mapping = find_media_payload_type_mapping(*table, track_resolution->mid, track_resolution->payload_type);

        if (mapping.has_value())
        {
            if (!payload_type_mapping_matches_track_resolution_exact_identity(*mapping, *track_resolution))
            {
                WEBRTC_LOG_WARN(
                    "payload type mapping exact mid identity mismatch stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                    "subscriber_mid={} mapping_kind={} track_kind={} publisher_payload_type={} mapping_rtx={} track_rtx={} ssrc={} rid={} "
                    "repaired_rid={}",
                    route.source.stream_id,
                    route.source.session_id,
                    subscriber.session_id,
                    mapping->publisher_mid,
                    mapping->subscriber_mid,
                    mapping->kind,
                    track_resolution->kind,
                    static_cast<unsigned int>(track_resolution->payload_type),
                    mapping->rtx ? 1 : 0,
                    track_resolution->rtx ? 1 : 0,
                    track_resolution->ssrc,
                    track_resolution->rid.has_value() ? *track_resolution->rid : "",
                    track_resolution->repaired_rid.has_value() ? *track_resolution->repaired_rid : "");

                return std::nullopt;
            }

            return mapping;
        }
        WEBRTC_LOG_WARN(
            "payload type mapping exact mid not found stream={} publisher_session={} subscriber_session={} publisher_mid={} kind={} "
            "publisher_payload_type={} ssrc={} rid={} repaired_rid={} rtx={}",
            route.source.stream_id,
            route.source.session_id,
            subscriber.session_id,
            track_resolution->mid,
            track_resolution->kind,
            static_cast<unsigned int>(track_resolution->payload_type),
            track_resolution->ssrc,
            track_resolution->rid.has_value() ? *track_resolution->rid : "",
            track_resolution->repaired_rid.has_value() ? *track_resolution->repaired_rid : "",
            track_resolution->rtx ? 1 : 0);

        return std::nullopt;
    }

    if (!track_resolution->kind.empty())
    {
        const std::size_t candidate_count = count_payload_type_mapping_candidates_by_track_resolution_kind(*table, *track_resolution);

        if (!payload_type_mapping_kind_fallback_has_single_media_pair(*table, *track_resolution))
        {
            WEBRTC_LOG_WARN(
                "payload type mapping fallback by kind disabled by multi track identity stream={} publisher_session={} subscriber_session={} "
                "kind={} publisher_payload_type={} ssrc={} rid={} repaired_rid={} rtx={} candidates={} table_mappings={}",
                route.source.stream_id,
                route.source.session_id,
                subscriber.session_id,
                track_resolution->kind,
                static_cast<unsigned int>(track_resolution->payload_type),
                track_resolution->ssrc,
                track_resolution->rid.has_value() ? *track_resolution->rid : "",
                track_resolution->repaired_rid.has_value() ? *track_resolution->repaired_rid : "",
                track_resolution->rtx ? 1 : 0,
                candidate_count,
                table->mappings.size());

            return std::nullopt;
        }

        if (candidate_count == 1)
        {
            auto mapping = find_unique_payload_type_mapping_by_track_resolution_kind(*table, *track_resolution);

            if (mapping.has_value())
            {
                WEBRTC_LOG_DEBUG(
                    "payload type mapping fallback by kind resolved stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                    "subscriber_mid={} publisher_ordinal={} subscriber_ordinal={} kind={} publisher_payload_type={} ssrc={} rid={} repaired_rid={} "
                    "rtx={}",
                    route.source.stream_id,
                    route.source.session_id,
                    subscriber.session_id,
                    mapping->publisher_mid,
                    mapping->subscriber_mid,
                    mapping->publisher_media_ordinal,
                    mapping->subscriber_media_ordinal,
                    mapping->kind,
                    static_cast<unsigned int>(track_resolution->payload_type),
                    track_resolution->ssrc,
                    track_resolution->rid.has_value() ? *track_resolution->rid : "",
                    track_resolution->repaired_rid.has_value() ? *track_resolution->repaired_rid : "",
                    track_resolution->rtx ? 1 : 0);

                return mapping;
            }
        }

        WEBRTC_LOG_WARN(
            "payload type mapping fallback by kind rejected stream={} publisher_session={} subscriber_session={} kind={} "
            "publisher_payload_type={} ssrc={} rid={} repaired_rid={} rtx={} candidates={} table_mappings={}",
            route.source.stream_id,
            route.source.session_id,
            subscriber.session_id,
            track_resolution->kind,
            static_cast<unsigned int>(track_resolution->payload_type),
            track_resolution->ssrc,
            track_resolution->rid.has_value() ? *track_resolution->rid : "",
            track_resolution->repaired_rid.has_value() ? *track_resolution->repaired_rid : "",
            track_resolution->rtx ? 1 : 0,
            candidate_count,
            table->mappings.size());

        return std::nullopt;
    }
    WEBRTC_LOG_WARN(
        "payload type mapping skipped unresolved media identity stream={} publisher_session={} subscriber_session={} publisher_payload_type={} "
        "ssrc={} rid={} repaired_rid={} rtx={}",
        route.source.stream_id,
        route.source.session_id,
        subscriber.session_id,
        static_cast<unsigned int>(track_resolution->payload_type),
        track_resolution->ssrc,
        track_resolution->rid.has_value() ? *track_resolution->rid : "",
        track_resolution->repaired_rid.has_value() ? *track_resolution->repaired_rid : "",
        track_resolution->rtx ? 1 : 0);

    return std::nullopt;
}

std::optional<media_identity_rid_layer_binding> find_selected_rid_layer_for_subscriber(
    const sdp::webrtc_offer_summary& publisher_offer,
    const std::shared_ptr<media_identity_authority>& identity_authority,
    const media_route_result& route,
    const media_peer_info& target_peer,
    const media_track_resolution& track_resolution,
    const std::optional<std::string>& runtime_target_rid,
    std::vector<std::string>& selected_rid_preference,
    std::string& selected_rid_policy)
{
    selected_rid_preference.clear();
    selected_rid_policy.clear();

    if (identity_authority == nullptr)
    {
        return std::nullopt;
    }

    if (route.source.role != media_peer_role::publisher || target_peer.role != media_peer_role::subscriber)
    {
        return std::nullopt;
    }

    if (!track_resolution.resolved || track_resolution.mid.empty() || track_resolution.kind.empty())
    {
        return std::nullopt;
    }

    if (!is_video_media_kind(track_resolution.kind))
    {
        return std::nullopt;
    }

    const sdp::media_summary* publisher_media = find_offer_media_by_mid(publisher_offer, track_resolution.mid);

    if (publisher_media == nullptr)
    {
        return std::nullopt;
    }

    const simulcast_rid_preference_result preference = make_simulcast_rid_preference_for_subscriber(*publisher_media, target_peer);

    selected_rid_preference = preference.preferred_rids;
    selected_rid_policy = preference.policy;

    if (runtime_target_rid.has_value() && !runtime_target_rid->empty())
    {
        const bool target_available = simulcast_rid_preference_contains(selected_rid_preference, *runtime_target_rid);

        if (target_available)
        {
            selected_rid_preference = make_simulcast_target_first_preference(std::move(selected_rid_preference), *runtime_target_rid);
            selected_rid_policy = "runtime_target:" + *runtime_target_rid + "+" + selected_rid_policy;
        }
        else
        {
            selected_rid_policy.append("+runtime_target_missing:");
            selected_rid_policy.append(*runtime_target_rid);
        }
    }

    if (selected_rid_preference.empty())
    {
        return std::nullopt;
    }

    std::optional<media_identity_rid_layer_binding> selected_layer =
        identity_authority->find_preferred_rid_layer(route.source.stream_id, route.source.session_id, track_resolution.mid, selected_rid_preference);
    if (selected_layer.has_value())
    {
        WEBRTC_LOG_DEBUG(
            "simulcast rid preference selected stream={} publisher_session={} subscriber_session={} mid={} kind={} policy={} selected_rid={} "
            "candidate_count={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            track_resolution.mid,
            track_resolution.kind,
            selected_rid_policy,
            selected_layer->rid,
            selected_rid_preference.size());
    }

    return selected_layer;
}

std::optional<std::string> resolve_packet_rid_for_selection(const std::shared_ptr<media_identity_authority>& identity_authority,
                                                            const media_route_result& route,
                                                            const media_track_resolution& track_resolution)
{
    if (!track_resolution.rtx && track_resolution.rid.has_value() && !track_resolution.rid->empty())
    {
        return track_resolution.rid;
    }

    if (track_resolution.rtx && track_resolution.repaired_rid.has_value() && !track_resolution.repaired_rid->empty())
    {
        return track_resolution.repaired_rid;
    }

    if (!track_resolution.rtx || identity_authority == nullptr)
    {
        return std::nullopt;
    }

    if (track_resolution.rtx_repair_ssrc != 0)
    {
        auto repair_layer = identity_authority->find_rid_layer_by_repair_ssrc(route.source.session_id, track_resolution.rtx_repair_ssrc);

        if (repair_layer.has_value() && !repair_layer->rid.empty())
        {
            return repair_layer->rid;
        }
    }

    if (track_resolution.ssrc != 0)
    {
        auto repair_layer = identity_authority->find_rid_layer_by_repair_ssrc(route.source.session_id, track_resolution.ssrc);

        if (repair_layer.has_value() && !repair_layer->rid.empty())
        {
            return repair_layer->rid;
        }
    }

    if (track_resolution.rtx_primary_ssrc != 0)
    {
        auto primary_layer = identity_authority->find_rid_layer_by_primary_ssrc(route.source.session_id, track_resolution.rtx_primary_ssrc);

        if (primary_layer.has_value() && !primary_layer->rid.empty())
        {
            return primary_layer->rid;
        }
    }

    return std::nullopt;
}

bool publisher_rtp_rid_is_selected_for_subscriber(const sdp::webrtc_offer_summary& publisher_offer,
                                                  const std::shared_ptr<media_identity_authority>& identity_authority,
                                                  const media_route_result& route,
                                                  const media_peer_info& target_peer,
                                                  const media_track_resolution& track_resolution,
                                                  const std::optional<std::string>& runtime_target_rid,
                                                  std::optional<media_identity_rid_layer_binding>& selected_layer,
                                                  std::vector<std::string>& selected_rid_preference,
                                                  std::string& selected_rid_policy)
{
    selected_layer = find_selected_rid_layer_for_subscriber(
        publisher_offer, identity_authority, route, target_peer, track_resolution, runtime_target_rid, selected_rid_preference, selected_rid_policy);
    if (!selected_layer.has_value())
    {
        return true;
    }

    const std::optional<std::string> packet_rid = resolve_packet_rid_for_selection(identity_authority, route, track_resolution);

    if (!packet_rid.has_value() || packet_rid->empty())
    {
        return true;
    }

    if (selected_layer->rid == *packet_rid)
    {
        return true;
    }

    WEBRTC_LOG_DEBUG(
        "simulcast rid layer skipped stream={} publisher_session={} subscriber_session={} mid={} packet_rid={} selected_rid={} ssrc={} rtx={}",
        route.source.stream_id,
        route.source.session_id,
        target_peer.session_id,
        track_resolution.mid,
        *packet_rid,
        selected_layer->rid,
        track_resolution.ssrc,
        track_resolution.rtx ? 1 : 0);

    return false;
}

uint32_t find_whep_preferred_subscriber_ssrc(
    const stream_registry& registry, const media_peer_info& target_peer, std::string_view subscriber_mid, std::string_view kind, bool rtx)
{
    if (target_peer.session_id.empty() || subscriber_mid.empty() || kind.empty())
    {
        return 0;
    }

    const auto subscriber = registry.find_subscriber_by_session_id(target_peer.session_id);

    if (subscriber == nullptr)
    {
        return 0;
    }

    for (const auto& source : subscriber->outbound_media_sources())
    {
        if (source.mid != subscriber_mid)
        {
            continue;
        }

        if (source.kind != kind)
        {
            continue;
        }

        if (rtx)
        {
            return source.rtx_repair_ssrc;
        }

        return source.ssrc;
    }

    return 0;
}
uint32_t find_whep_preferred_rtx_retransmit_subscriber_ssrc(const stream_registry& registry,
                                                            const media_ssrc_mapping& primary_mapping,
                                                            const media_payload_type_mapping& rtx_payload_type_mapping)
{
    if (primary_mapping.subscriber_session_id.empty() || rtx_payload_type_mapping.subscriber_mid.empty() || primary_mapping.kind.empty())
    {
        return 0;
    }

    const auto subscriber = registry.find_subscriber_by_session_id(primary_mapping.subscriber_session_id);

    if (subscriber == nullptr)
    {
        return 0;
    }

    for (const auto& source : subscriber->outbound_media_sources())
    {
        if (source.mid != rtx_payload_type_mapping.subscriber_mid)
        {
            continue;
        }

        if (source.kind != primary_mapping.kind)
        {
            continue;
        }

        return source.rtx_repair_ssrc;
    }

    return 0;
}

std::optional<media_ssrc_mapping> ice_udp_server::get_or_create_ssrc_mapping(const media_route_result& route,
                                                                             const media_peer_info& target_peer,
                                                                             const std::optional<media_track_resolution>& track_resolution,
                                                                             const std::optional<media_payload_type_mapping>& payload_type_mapping)
{
    if (ssrc_mapper_ == nullptr)
    {
        return std::nullopt;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved)
    {
        return std::nullopt;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return std::nullopt;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return std::nullopt;
    }

    if (track_resolution->ssrc == 0 || track_resolution->mid.empty())
    {
        return std::nullopt;
    }

    const std::string subscriber_mid = payload_type_mapping.has_value() ? payload_type_mapping->subscriber_mid : track_resolution->mid;

    std::optional<std::string> mapping_rid = track_resolution->rid;

    std::optional<std::string> mapping_repaired_rid = track_resolution->repaired_rid;

    uint32_t preferred_subscriber_ssrc = 0;

    if (registry_ != nullptr)
    {
        preferred_subscriber_ssrc =
            find_whep_preferred_subscriber_ssrc(*registry_, target_peer, subscriber_mid, track_resolution->kind, track_resolution->rtx);
    }

    auto mapping_result = ssrc_mapper_->get_or_create_mapping_with_subscriber_ssrc(route.source.stream_id,
                                                                                   route.source.session_id,
                                                                                   target_peer.session_id,
                                                                                   track_resolution->mid,
                                                                                   subscriber_mid,
                                                                                   track_resolution->kind,
                                                                                   track_resolution->ssrc,
                                                                                   preferred_subscriber_ssrc,
                                                                                   now_milliseconds(),
                                                                                   track_resolution->rtx,
                                                                                   track_resolution->rtx_primary_ssrc,
                                                                                   track_resolution->rtx_repair_ssrc,
                                                                                   mapping_rid,
                                                                                   mapping_repaired_rid);
    if (!mapping_result)
    {
        WEBRTC_LOG_WARN("media ssrc mapping failed stream={} publisher_session={} subscriber_session={} mid={} ssrc={} error={}",
                        route.source.stream_id,
                        route.source.session_id,
                        target_peer.session_id,
                        track_resolution->mid,
                        track_resolution->ssrc,
                        mapping_result.error());

        return std::nullopt;
    }

    if (mapping_result->packet_count == 1 && preferred_subscriber_ssrc != 0 && mapping_result->subscriber_ssrc != preferred_subscriber_ssrc)
    {
        WEBRTC_LOG_WARN(
            "whep preferred subscriber ssrc fallback stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} "
            "kind={} publisher_ssrc={} preferred_subscriber_ssrc={} actual_subscriber_ssrc={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            track_resolution->mid,
            subscriber_mid,
            track_resolution->kind,
            track_resolution->ssrc,
            preferred_subscriber_ssrc,
            mapping_result->subscriber_ssrc);
    }

    if (mapping_result->packet_count == 1)
    {
        WEBRTC_LOG_INFO("media ssrc mapping created {}", media_ssrc_mapping_to_string(*mapping_result));

        if (!mapping_result->rtx && is_video_media_kind(mapping_result->kind))
        {
            consume_orphan_subscriber_keyframe_request_after_mapping_created(*mapping_result, route, target_peer);
        }
    }
    return *mapping_result;
}

std::optional<media_ssrc_mapping> ice_udp_server::find_primary_feedback_ssrc_mapping(const media_route_result& route,
                                                                                     const media_peer_info& target_peer,
                                                                                     uint32_t subscriber_ssrc,
                                                                                     std::string_view feedback_name,
                                                                                     bool allow_rtx_repair_target) const
{
    if (subscriber_ssrc == 0)
    {
        return std::nullopt;
    }

    if (identity_authority_ == nullptr && ssrc_mapper_ == nullptr)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback mapping skipped identity mapper is null stream={} subscriber_session={} publisher_session={} feedback={} "
            "subscriber_ssrc={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc);

        return std::nullopt;
    }

    auto mapping = find_identity_ssrc_mapping_by_subscriber_ssrc(route.source.session_id, subscriber_ssrc);

    if (!mapping.has_value())
    {
        WEBRTC_LOG_WARN("rtcp feedback mapping not found stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={}",
                        route.source.stream_id,
                        route.source.session_id,
                        target_peer.session_id,
                        feedback_name,
                        subscriber_ssrc);

        return std::nullopt;
    }

    if (mapping->stream_id != route.source.stream_id || mapping->subscriber_session_id != route.source.session_id ||
        mapping->publisher_session_id != target_peer.session_id)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback mapping target mismatch stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "mapping_stream={} mapping_subscriber_session={} mapping_publisher_session={} mapping_publisher_mid={} mapping_subscriber_mid={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->stream_id,
            mapping->subscriber_session_id,
            mapping->publisher_session_id,
            mapping->publisher_mid,
            mapping->subscriber_mid);

        return std::nullopt;
    }

    if (media_ssrc_mapping_is_primary_video(*mapping))
    {
        return mapping;
    }

    if (!media_ssrc_mapping_is_rtx(*mapping))
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback mapping is not primary video stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "publisher_ssrc={} subscriber_mapped_ssrc={} publisher_mid={} subscriber_mid={} kind={} rtx={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_ssrc,
            mapping->subscriber_ssrc,
            mapping->publisher_mid,
            mapping->subscriber_mid,
            mapping->kind,
            media_ssrc_mapping_is_rtx(*mapping) ? 1 : 0);

        return std::nullopt;
    }

    if (!allow_rtx_repair_target)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx repair target is not forwarded stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "publisher_rtx_ssrc={} subscriber_rtx_ssrc={} publisher_mid={} subscriber_mid={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_ssrc,
            mapping->subscriber_ssrc,
            mapping->publisher_mid,
            mapping->subscriber_mid);

        return std::nullopt;
    }

    if (mapping->publisher_rtx_primary_ssrc == 0)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary ssrc missing stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "publisher_rtx_ssrc={} subscriber_rtx_ssrc={} publisher_mid={} subscriber_mid={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_ssrc,
            mapping->subscriber_ssrc,
            mapping->publisher_mid,
            mapping->subscriber_mid);

        return std::nullopt;
    }

    auto primary_mapping = find_identity_ssrc_mapping_by_publisher_ssrc(mapping->stream_id,
                                                                        mapping->publisher_session_id,
                                                                        mapping->subscriber_session_id,
                                                                        mapping->publisher_mid,
                                                                        mapping->publisher_rtx_primary_ssrc);

    if (!primary_mapping.has_value())
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary mapping not found stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "publisher_rtx_ssrc={} publisher_primary_ssrc={} publisher_mid={} subscriber_mid={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_ssrc,
            mapping->publisher_rtx_primary_ssrc,
            mapping->publisher_mid,
            mapping->subscriber_mid);

        return std::nullopt;
    }

    if (primary_mapping->stream_id != route.source.stream_id || primary_mapping->subscriber_session_id != route.source.session_id ||
        primary_mapping->publisher_session_id != target_peer.session_id)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary mapping target mismatch stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "primary_stream={} primary_subscriber_session={} primary_publisher_session={} primary_publisher_mid={} primary_subscriber_mid={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            primary_mapping->stream_id,
            primary_mapping->subscriber_session_id,
            primary_mapping->publisher_session_id,
            primary_mapping->publisher_mid,
            primary_mapping->subscriber_mid);

        return std::nullopt;
    }

    if (!media_ssrc_mapping_is_primary_video(*primary_mapping))
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary mapping is not primary video stream={} subscriber_session={} publisher_session={} feedback={} "
            "subscriber_ssrc={} publisher_primary_ssrc={} subscriber_primary_ssrc={} publisher_mid={} subscriber_mid={} kind={} rtx={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            primary_mapping->publisher_ssrc,
            primary_mapping->subscriber_ssrc,
            primary_mapping->publisher_mid,
            primary_mapping->subscriber_mid,
            primary_mapping->kind,
            media_ssrc_mapping_is_rtx(*primary_mapping) ? 1 : 0);

        return std::nullopt;
    }

    return primary_mapping;
}
std::optional<media_ssrc_mapping> ice_udp_server::resolve_keyframe_feedback_primary_mapping(const rtcp_feedback_route_event& event) const
{
    if (event.media_ssrc == 0)
    {
        return std::nullopt;
    }

    if (event.source.role != media_peer_role::subscriber)
    {
        return std::nullopt;
    }

    if (event.source.stream_id.empty() || event.source.session_id.empty())
    {
        return std::nullopt;
    }

    std::optional<media_ssrc_mapping> mapping = find_identity_ssrc_mapping_by_subscriber_ssrc(event.source.session_id, event.media_ssrc);

    if (!mapping.has_value())
    {
        WEBRTC_LOG_WARN("keyframe feedback mapping not found stream={} subscriber_session={} subscriber_ssrc={} feedback={}",
                        event.source.stream_id,
                        event.source.session_id,
                        event.media_ssrc,
                        event.feedback_name);

        return std::nullopt;
    }

    if (mapping->stream_id != event.source.stream_id || mapping->subscriber_session_id != event.source.session_id)
    {
        WEBRTC_LOG_WARN(
            "keyframe feedback mapping ownership mismatch stream={} subscriber_session={} subscriber_ssrc={} feedback={} mapping_stream={} "
            "mapping_subscriber_session={} mapping_publisher_session={} mapping_publisher_mid={} mapping_subscriber_mid={}",
            event.source.stream_id,
            event.source.session_id,
            event.media_ssrc,
            event.feedback_name,
            mapping->stream_id,
            mapping->subscriber_session_id,
            mapping->publisher_session_id,
            mapping->publisher_mid,
            mapping->subscriber_mid);

        return std::nullopt;
    }

    if (media_ssrc_mapping_is_primary_video(*mapping))
    {
        if (!subscriber_feedback_targets_selected_rid_layer(event, *mapping, event.media_ssrc, false, "keyframe"))
        {
            WEBRTC_LOG_DEBUG(
                "keyframe feedback skipped non selected rid primary stream={} subscriber_session={} feedback_ssrc={} publisher_ssrc={} "
                "subscriber_ssrc={} mid={} kind={}",
                event.source.stream_id,
                event.source.session_id,
                event.media_ssrc,
                mapping->publisher_ssrc,
                mapping->subscriber_ssrc,
                mapping->publisher_mid,
                mapping->kind);

            return std::nullopt;
        }
        return mapping;
    }

    if (!media_ssrc_mapping_is_rtx(*mapping))
    {
        WEBRTC_LOG_WARN(
            "keyframe feedback mapping is not primary video stream={} subscriber_session={} subscriber_ssrc={} feedback={} publisher_ssrc={} "
            "subscriber_mapped_ssrc={} kind={} rtx={}",
            event.source.stream_id,
            event.source.session_id,
            event.media_ssrc,
            event.feedback_name,
            mapping->publisher_ssrc,
            mapping->subscriber_ssrc,
            mapping->kind,
            media_ssrc_mapping_is_rtx(*mapping) ? 1 : 0);

        return std::nullopt;
    }

    if (mapping->publisher_rtx_primary_ssrc == 0)
    {
        WEBRTC_LOG_WARN(
            "keyframe feedback rtx primary ssrc missing stream={} subscriber_session={} subscriber_rtx_ssrc={} feedback={} publisher_rtx_ssrc={}",
            event.source.stream_id,
            event.source.session_id,
            event.media_ssrc,
            event.feedback_name,
            mapping->publisher_ssrc);

        return std::nullopt;
    }

    std::optional<media_ssrc_mapping> primary_mapping = find_identity_ssrc_mapping_by_publisher_ssrc(mapping->stream_id,
                                                                                                     mapping->publisher_session_id,
                                                                                                     mapping->subscriber_session_id,
                                                                                                     mapping->publisher_mid,
                                                                                                     mapping->publisher_rtx_primary_ssrc);

    if (!primary_mapping.has_value())
    {
        WEBRTC_LOG_WARN(
            "keyframe feedback rtx primary mapping not found stream={} subscriber_session={} subscriber_rtx_ssrc={} feedback={} "
            "publisher_primary_ssrc={}",
            event.source.stream_id,
            event.source.session_id,
            event.media_ssrc,
            event.feedback_name,
            mapping->publisher_rtx_primary_ssrc);

        return std::nullopt;
    }

    if (primary_mapping->stream_id != event.source.stream_id || primary_mapping->subscriber_session_id != event.source.session_id)
    {
        WEBRTC_LOG_WARN(
            "keyframe feedback rtx primary mapping ownership mismatch stream={} subscriber_session={} subscriber_rtx_ssrc={} feedback={} "
            "primary_stream={} primary_subscriber_session={} primary_publisher_session={} primary_publisher_mid={} primary_subscriber_mid={}",
            event.source.stream_id,
            event.source.session_id,
            event.media_ssrc,
            event.feedback_name,
            primary_mapping->stream_id,
            primary_mapping->subscriber_session_id,
            primary_mapping->publisher_session_id,
            primary_mapping->publisher_mid,
            primary_mapping->subscriber_mid);

        return std::nullopt;
    }

    if (!media_ssrc_mapping_is_primary_video(*primary_mapping))
    {
        WEBRTC_LOG_WARN(
            "keyframe feedback rtx primary mapping is not primary video stream={} subscriber_session={} subscriber_rtx_ssrc={} feedback={} "
            "publisher_primary_ssrc={} subscriber_primary_ssrc={} kind={} rtx={}",
            event.source.stream_id,
            event.source.session_id,
            event.media_ssrc,
            event.feedback_name,
            primary_mapping->publisher_ssrc,
            primary_mapping->subscriber_ssrc,
            primary_mapping->kind,
            media_ssrc_mapping_is_rtx(*primary_mapping) ? 1 : 0);

        return std::nullopt;
    }

    if (!subscriber_feedback_targets_selected_rid_layer(event, *primary_mapping, event.media_ssrc, false, "keyframe_rtx"))
    {
        WEBRTC_LOG_DEBUG(
            "keyframe feedback skipped rtx media ssrc stream={} subscriber_session={} feedback_ssrc={} publisher_primary_ssrc={} "
            "subscriber_primary_ssrc={} mid={} kind={}",
            event.source.stream_id,
            event.source.session_id,
            event.media_ssrc,
            primary_mapping->publisher_ssrc,
            primary_mapping->subscriber_ssrc,
            primary_mapping->publisher_mid,
            primary_mapping->kind);

        return std::nullopt;
    }
    return primary_mapping;
}

std::optional<std::vector<uint8_t>> ice_udp_server::make_forward_rtcp_feedback_packet(const srtp_packet_process_result& packet,
                                                                                      const media_route_result& route,
                                                                                      const std::vector<rtcp_feedback_route_event>& feedback_events,
                                                                                      const media_peer_info& target_peer)
{
    std::vector<uint8_t> original_packet;

    original_packet.assign(packet.plain_packet.begin(), packet.plain_packet.end());

    if (packet.kind != srtp_packet_kind::rtcp)
    {
        return original_packet;
    }

    if (route.source.role != media_peer_role::subscriber || target_peer.role != media_peer_role::publisher)
    {
        return original_packet;
    }

    if (feedback_events.empty())
    {
        return original_packet;
    }

    if (identity_authority_ == nullptr && ssrc_mapper_ == nullptr)
    {
        WEBRTC_LOG_WARN("rtcp feedback block rewrite skipped identity mapper is null stream={} subscriber_session={} remote={}",
                        route.source.stream_id,
                        route.source.session_id,
                        route.source.remote_endpoint);

        return std::nullopt;
    }
    struct feedback_ssrc_mapping_resolution
    {
        media_ssrc_mapping source_mapping;
        media_ssrc_mapping forward_mapping;
        bool source_was_rtx = false;
        bool skipped_non_video = false;
    };

    const auto resolve_feedback_ssrc = [&](uint32_t subscriber_ssrc,
                                           const rtcp_feedback_route_event& event,
                                           std::string_view field_name) -> std::optional<feedback_ssrc_mapping_resolution>
    {
        auto mapping = find_identity_ssrc_mapping_by_subscriber_ssrc(route.source.session_id, subscriber_ssrc);

        if (!mapping.has_value())
        {
            WEBRTC_LOG_WARN(
                "rtcp feedback block rewrite skipped mapping not found stream={} subscriber_session={} feedback={} field={} subscriber_ssrc={}",
                route.source.stream_id,
                route.source.session_id,
                event.feedback_name,
                field_name,
                subscriber_ssrc);

            return std::nullopt;
        }

        if (mapping->stream_id != route.source.stream_id || mapping->subscriber_session_id != route.source.session_id ||
            mapping->publisher_session_id != target_peer.session_id)
        {
            WEBRTC_LOG_WARN(
                "rtcp feedback block rewrite skipped mapping ownership mismatch stream={} subscriber_session={} publisher_session={} feedback={} "
                "field={} subscriber_ssrc={} mapping_stream={} mapping_subscriber={} mapping_publisher={}",
                route.source.stream_id,
                route.source.session_id,
                target_peer.session_id,
                event.feedback_name,
                field_name,
                subscriber_ssrc,
                mapping->stream_id,
                mapping->subscriber_session_id,
                mapping->publisher_session_id);

            return std::nullopt;
        }

        if (!is_video_media_kind(mapping->kind))
        {
            if (event.has_remb && field_name == "remb_ssrc")
            {
                WEBRTC_LOG_DEBUG(
                    "rtcp remb ssrc rewrite skipped non video media stream={} subscriber_session={} feedback={} field={} subscriber_ssrc={} kind={}",
                    route.source.stream_id,
                    route.source.session_id,
                    event.feedback_name,
                    field_name,
                    subscriber_ssrc,
                    mapping->kind);

                feedback_ssrc_mapping_resolution resolution;

                resolution.source_mapping = *mapping;
                resolution.forward_mapping = *mapping;
                resolution.source_was_rtx = media_ssrc_mapping_is_rtx(*mapping);
                resolution.skipped_non_video = true;
                return resolution;
            }

            WEBRTC_LOG_WARN(
                "rtcp feedback block rewrite skipped non video media stream={} subscriber_session={} feedback={} field={} subscriber_ssrc={} kind={}",
                route.source.stream_id,
                route.source.session_id,
                event.feedback_name,
                field_name,
                subscriber_ssrc,
                mapping->kind);

            return std::nullopt;
        }

        feedback_ssrc_mapping_resolution resolution;

        resolution.source_mapping = *mapping;
        resolution.forward_mapping = *mapping;
        resolution.source_was_rtx = media_ssrc_mapping_is_rtx(*mapping);

        if (!resolution.source_was_rtx)
        {
            return resolution;
        }

        if (event.has_generic_nack)
        {
            return resolution;
        }

        if (mapping->publisher_rtx_primary_ssrc == 0)
        {
            WEBRTC_LOG_WARN(
                "rtcp feedback block rewrite skipped rtx primary missing stream={} subscriber_session={} feedback={} field={} subscriber_ssrc={} "
                "publisher_rtx_ssrc={}",
                route.source.stream_id,
                route.source.session_id,
                event.feedback_name,
                field_name,
                subscriber_ssrc,
                mapping->publisher_ssrc);

            return std::nullopt;
        }

        auto primary_mapping = find_identity_ssrc_mapping_by_publisher_ssrc(mapping->stream_id,
                                                                            mapping->publisher_session_id,
                                                                            mapping->subscriber_session_id,
                                                                            mapping->publisher_mid,
                                                                            mapping->publisher_rtx_primary_ssrc);
        if (!primary_mapping.has_value())
        {
            WEBRTC_LOG_WARN(
                "rtcp feedback block rewrite skipped rtx primary mapping not found stream={} subscriber_session={} feedback={} field={} "
                "subscriber_ssrc={} publisher_primary_ssrc={}",
                route.source.stream_id,
                route.source.session_id,
                event.feedback_name,
                field_name,
                subscriber_ssrc,
                mapping->publisher_rtx_primary_ssrc);

            return std::nullopt;
        }

        if (media_ssrc_mapping_is_rtx(*primary_mapping) || !is_video_media_kind(primary_mapping->kind))
        {
            WEBRTC_LOG_WARN(
                "rtcp feedback block rewrite skipped invalid rtx primary mapping stream={} subscriber_session={} feedback={} field={} "
                "subscriber_ssrc={} publisher_primary_ssrc={} kind={} rtx={}",
                route.source.stream_id,
                route.source.session_id,
                event.feedback_name,
                field_name,
                subscriber_ssrc,
                primary_mapping->publisher_ssrc,
                primary_mapping->kind,
                media_ssrc_mapping_is_rtx(*primary_mapping) ? 1 : 0);

            return std::nullopt;
        }

        resolution.forward_mapping = *primary_mapping;

        return resolution;
    };

    std::vector<rtcp_feedback_block_rewrite> rewrites;

    for (const auto& event : feedback_events)
    {
        const bool needs_rewrite_or_drop = rtcp_feedback_event_needs_block_rewrite(event) || (event.has_generic_nack && event.media_ssrc != 0);

        if (!needs_rewrite_or_drop)
        {
            continue;
        }

        if (!rtcp_feedback_event_has_valid_block_range(event, packet.plain_packet.size()))
        {
            WEBRTC_LOG_WARN(
                "rtcp feedback block rewrite skipped invalid block range stream={} subscriber_session={} feedback={} offset={} size={} "
                "packet_size={}",
                route.source.stream_id,
                route.source.session_id,
                event.feedback_name,
                event.block_offset,
                event.block_size,
                packet.plain_packet.size());

            return std::nullopt;
        }

        rtcp_feedback_block_rewrite rewrite;

        rewrite.block_offset = event.block_offset;
        rewrite.block_size = event.block_size;

        if (event.media_ssrc != 0)
        {
            auto media_resolution = resolve_feedback_ssrc(event.media_ssrc, event, "media_ssrc");

            if (!media_resolution.has_value())
            {
                return std::nullopt;
            }

            if (event.has_generic_nack && media_resolution->source_was_rtx)
            {
                rewrite.drop_block = true;

                rewrites.push_back(std::move(rewrite));

                WEBRTC_LOG_DEBUG(
                    "rtcp feedback rtx nack block dropped stream={} subscriber_session={} publisher_session={} subscriber_rtx_ssrc={} "
                    "publisher_rtx_ssrc={} feedback={}",
                    route.source.stream_id,
                    route.source.session_id,
                    target_peer.session_id,
                    event.media_ssrc,
                    media_resolution->source_mapping.publisher_ssrc,
                    event.feedback_name);

                continue;
            }

            rewrite.rewrite_media_ssrc = true;
            rewrite.source_media_ssrc = event.media_ssrc;
            rewrite.target_media_ssrc = media_resolution->forward_mapping.publisher_ssrc;
        }

        for (std::size_t i = 0; i < event.fir_items.size(); ++i)
        {
            const auto& item = event.fir_items[i];

            auto item_resolution = resolve_feedback_ssrc(item.ssrc, event, "fir_item");

            if (!item_resolution.has_value())
            {
                return std::nullopt;
            }

            rtcp_feedback_block_ssrc_rewrite fci_rewrite;

            fci_rewrite.offset = 12 + (i * 8);
            fci_rewrite.source_ssrc = item.ssrc;
            fci_rewrite.target_ssrc = item_resolution->forward_mapping.publisher_ssrc;

            rewrite.fci_ssrc_rewrites.push_back(fci_rewrite);
        }

        for (std::size_t i = 0; i < event.remb_ssrcs.size(); ++i)
        {
            const uint32_t subscriber_ssrc = event.remb_ssrcs[i];

            auto remb_resolution = resolve_feedback_ssrc(subscriber_ssrc, event, "remb_ssrc");

            if (!remb_resolution.has_value())
            {
                continue;
            }

            if (remb_resolution->skipped_non_video)
            {
                continue;
            }

            rtcp_feedback_block_ssrc_rewrite fci_rewrite;

            fci_rewrite.offset = 20 + (i * 4);
            fci_rewrite.source_ssrc = subscriber_ssrc;
            fci_rewrite.target_ssrc = remb_resolution->forward_mapping.publisher_ssrc;

            rewrite.fci_ssrc_rewrites.push_back(fci_rewrite);
        }
        if (rewrite.drop_block || rewrite.rewrite_media_ssrc || !rewrite.fci_ssrc_rewrites.empty())
        {
            rewrites.push_back(std::move(rewrite));
        }
    }

    if (rewrites.empty())
    {
        return original_packet;
    }

    auto rewrite_result = rewrite_rtcp_feedback_blocks(std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()),
                                                       std::span<const rtcp_feedback_block_rewrite>(rewrites.data(), rewrites.size()));

    if (!rewrite_result)
    {
        WEBRTC_LOG_WARN("rtcp feedback block rewrite failed stream={} subscriber_session={} remote={} error={}",
                        route.source.stream_id,
                        route.source.session_id,
                        route.source.remote_endpoint,
                        rewrite_result.error());

        return std::nullopt;
    }

    WEBRTC_LOG_DEBUG("rtcp feedback block rewrite applied stream={} subscriber_session={} remote={} blocks={} original_size={} rewritten_size={}",
                     route.source.stream_id,
                     route.source.session_id,
                     route.source.remote_endpoint,
                     rewrites.size(),
                     packet.plain_packet.size(),
                     rewrite_result->size());

    return std::move(*rewrite_result);
}

std::optional<media_payload_type_mapping> ice_udp_server::find_rtx_payload_type_mapping(const media_payload_type_mapping_table& table,
                                                                                        const media_payload_type_mapping& primary_mapping) const
{
    for (const auto& mapping : table.mappings)
    {
        if (!media_payload_type_mapping_is_rtx(mapping))
        {
            continue;
        }

        if (mapping.publisher_mid != primary_mapping.publisher_mid)
        {
            continue;
        }

        if (mapping.subscriber_mid != primary_mapping.subscriber_mid)
        {
            continue;
        }

        if (mapping.publisher_apt_payload_type != primary_mapping.publisher_payload_type)
        {
            continue;
        }

        if (mapping.subscriber_apt_payload_type != primary_mapping.subscriber_payload_type)
        {
            continue;
        }

        return mapping;
    }

    return std::nullopt;
}

std::optional<media_ssrc_mapping> ice_udp_server::get_or_create_rtx_ssrc_mapping(const media_ssrc_mapping& primary_mapping,
                                                                                 const media_payload_type_mapping& rtx_payload_type_mapping)
{
    if (ssrc_mapper_ == nullptr)
    {
        return std::nullopt;
    }

    if (primary_mapping.publisher_rtx_repair_ssrc == 0)
    {
        return std::nullopt;
    }

    uint32_t preferred_subscriber_ssrc = 0;

    if (registry_ != nullptr)
    {
        preferred_subscriber_ssrc = find_whep_preferred_rtx_retransmit_subscriber_ssrc(*registry_, primary_mapping, rtx_payload_type_mapping);
    }

    auto mapping_result = ssrc_mapper_->get_or_create_mapping_with_subscriber_ssrc(primary_mapping.stream_id,
                                                                                   primary_mapping.publisher_session_id,
                                                                                   primary_mapping.subscriber_session_id,
                                                                                   primary_mapping.publisher_mid,
                                                                                   rtx_payload_type_mapping.subscriber_mid,
                                                                                   primary_mapping.kind,
                                                                                   primary_mapping.publisher_rtx_repair_ssrc,
                                                                                   preferred_subscriber_ssrc,
                                                                                   now_milliseconds(),
                                                                                   true,
                                                                                   primary_mapping.publisher_ssrc,
                                                                                   primary_mapping.publisher_rtx_repair_ssrc);
    if (!mapping_result)
    {
        WEBRTC_LOG_WARN("rtx ssrc mapping failed stream={} publisher_session={} subscriber_session={} primary_ssrc={} repair_ssrc={} error={}",
                        primary_mapping.stream_id,
                        primary_mapping.publisher_session_id,
                        primary_mapping.subscriber_session_id,
                        primary_mapping.publisher_ssrc,
                        primary_mapping.publisher_rtx_repair_ssrc,
                        mapping_result.error());

        return std::nullopt;
    }

    if (mapping_result->packet_count == 1 && preferred_subscriber_ssrc != 0 && mapping_result->subscriber_ssrc != preferred_subscriber_ssrc)
    {
        WEBRTC_LOG_WARN(
            "whep preferred subscriber rtx ssrc fallback stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} "
            "kind={} publisher_primary_ssrc={} publisher_repair_ssrc={} preferred_subscriber_rtx_ssrc={} actual_subscriber_rtx_ssrc={}",
            primary_mapping.stream_id,
            primary_mapping.publisher_session_id,
            primary_mapping.subscriber_session_id,
            primary_mapping.publisher_mid,
            rtx_payload_type_mapping.subscriber_mid,
            primary_mapping.kind,
            primary_mapping.publisher_ssrc,
            primary_mapping.publisher_rtx_repair_ssrc,
            preferred_subscriber_ssrc,
            mapping_result->subscriber_ssrc);
    }

    if (mapping_result->packet_count == 1)
    {
        WEBRTC_LOG_INFO("rtx ssrc mapping created {}", media_ssrc_mapping_to_string(*mapping_result));
    }

    if (!remember_media_identity_forward_mapping(*mapping_result, rtx_payload_type_mapping))
    {
        return std::nullopt;
    }

    return *mapping_result;
}

std::optional<std::vector<uint8_t>> ice_udp_server::make_rtx_retransmit_plain_packet(const rtcp_feedback_route_event& event,
                                                                                     const rtp_packet_cache_entry& cached_packet,
                                                                                     const media_ssrc_mapping& primary_ssrc_mapping,
                                                                                     const media_payload_type_mapping& primary_payload_type_mapping,
                                                                                     const nack_retransmit_sequence& requested_sequence)
{
    if (rtx_sequence_allocator_ == nullptr)
    {
        rtx_sequence_allocator_ = std::make_shared<rtx_sequence_number_allocator>();
    }

    auto table = get_or_create_payload_type_mapping_table_for_sessions(
        primary_ssrc_mapping.stream_id, primary_ssrc_mapping.publisher_session_id, primary_ssrc_mapping.subscriber_session_id);

    if (!table.has_value())
    {
        return std::nullopt;
    }

    const std::optional<media_payload_type_mapping> rtx_payload_type_mapping = find_rtx_payload_type_mapping(*table, primary_payload_type_mapping);

    if (!rtx_payload_type_mapping.has_value())
    {
        return std::nullopt;
    }

    if (rtx_payload_type_mapping->subscriber_payload_type > 127)
    {
        WEBRTC_LOG_WARN("rtx retransmit skipped invalid subscriber rtx payload type stream={} subscriber={} primary_pt={} rtx_pt={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        primary_payload_type_mapping.publisher_payload_type,
                        rtx_payload_type_mapping->subscriber_payload_type);

        return std::nullopt;
    }

    std::optional<media_ssrc_mapping> rtx_ssrc_mapping = get_or_create_rtx_ssrc_mapping(primary_ssrc_mapping, *rtx_payload_type_mapping);

    if (!rtx_ssrc_mapping.has_value())
    {
        return std::nullopt;
    }

    const outbound_rtp_rewrite_result outbound_rtx = next_outbound_rtp_rewrite(primary_ssrc_mapping.stream_id,
                                                                               primary_ssrc_mapping.publisher_session_id,
                                                                               primary_ssrc_mapping.subscriber_session_id,
                                                                               rtx_ssrc_mapping->subscriber_ssrc,
                                                                               cached_packet.sequence_number,
                                                                               cached_packet.timestamp);

    const uint16_t rtx_sequence_number = outbound_rtx.sequence_number;

    const uint16_t rtx_original_sequence_number =
        requested_sequence.has_subscriber_rtp_identity ? requested_sequence.subscriber_sequence_number : requested_sequence.cache_sequence_number;

    rtp_rtx_packet_options options;

    options.payload_type = static_cast<uint8_t>(rtx_payload_type_mapping->subscriber_payload_type);

    options.ssrc = rtx_ssrc_mapping->subscriber_ssrc;

    options.sequence_number = rtx_sequence_number;

    options.timestamp = outbound_rtx.timestamp;

    options.original_sequence_number = rtx_original_sequence_number;
    if (registry_ != nullptr && identity_authority_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(primary_ssrc_mapping.publisher_session_id);

        if (publisher == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtx retransmit rid selection failed publisher not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                primary_ssrc_mapping.publisher_session_id,
                primary_ssrc_mapping.subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        auto layer =
            identity_authority_->find_rid_layer_by_primary_ssrc(primary_ssrc_mapping.publisher_session_id, primary_ssrc_mapping.publisher_ssrc);

        if (layer.has_value())
        {
            const sdp::media_summary* publisher_media = find_offer_media_by_mid(publisher->remote_offer_summary(), layer->mid);

            if (publisher_media != nullptr)
            {
                const std::vector<std::string> preferred_rids = make_default_simulcast_rid_preference(*publisher_media);

                auto preferred_layer = identity_authority_->find_preferred_rid_layer(
                    event.source.stream_id, primary_ssrc_mapping.publisher_session_id, layer->mid, preferred_rids);

                if (preferred_layer.has_value() && preferred_layer->rid != layer->rid)
                {
                    WEBRTC_LOG_DEBUG(
                        "rtx retransmit skipped non selected rid stream={} subscriber_session={} mid={} packet_rid={} selected_rid={} "
                        "publisher_ssrc={} sequence={}",
                        event.source.stream_id,
                        primary_ssrc_mapping.subscriber_session_id,
                        layer->mid,
                        layer->rid,
                        preferred_layer->rid,
                        primary_ssrc_mapping.publisher_ssrc,
                        cached_packet.sequence_number);

                    return std::nullopt;
                }
            }
        }
    }

    auto rtx_packet = make_rtp_rtx_packet(std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()), options);

    if (!rtx_packet)
    {
        WEBRTC_LOG_WARN("rtx retransmit packet build failed stream={} subscriber={} primary_ssrc={} rtx_ssrc={} sequence={} error={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        primary_ssrc_mapping.publisher_ssrc,
                        rtx_ssrc_mapping->subscriber_ssrc,
                        cached_packet.sequence_number,
                        rtx_packet.error());

        return std::nullopt;
    }

    bool repaired_rid_rewrite_applied = false;

    if (registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(primary_ssrc_mapping.publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(primary_ssrc_mapping.subscriber_session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtx retransmit extmap rewrite skipped session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                primary_ssrc_mapping.publisher_session_id,
                primary_ssrc_mapping.subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        const auto& publisher_offer = publisher->remote_offer_summary();

        const auto& subscriber_offer = subscriber->remote_offer_summary();

        const std::span<const uint8_t> cached_plain_packet_span(cached_packet.plain_packet.data(), cached_packet.plain_packet.size());

        rtp_packet_rewrite_options rewrite_options;

        bool rewrite_required = false;

        const auto make_rtx_packet_span = [&]() -> std::span<const uint8_t>
        { return std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()); };
        auto append_header_extension_id_rewrite = [&](std::string_view rewrite_name,
                                                      std::string_view extension_uri,
                                                      bool remember_runtime_mapping,
                                                      optional_header_extension_id_rewrite_result rewrite_result) -> bool
        {
            if (!rewrite_result)
            {
                WEBRTC_LOG_WARN(
                    "rtx retransmit header extension id rewrite failed name={} stream={} publisher_session={} subscriber_session={} "
                    "publisher_mid={} subscriber_mid={} sequence={} error={}",
                    rewrite_name,
                    event.source.stream_id,
                    primary_ssrc_mapping.publisher_session_id,
                    primary_ssrc_mapping.subscriber_session_id,
                    rtx_payload_type_mapping->publisher_mid,
                    rtx_payload_type_mapping->subscriber_mid,
                    cached_packet.sequence_number,
                    rewrite_result.error());

                return false;
            }

            if (!rewrite_result->has_value())
            {
                return true;
            }

            const auto rewrite = **rewrite_result;

            if (rewrite.source_id == rewrite.target_id)
            {
                return true;
            }

            if (ensured_header_extension_id_exists(rewrite_options.ensured_header_extensions, rewrite.source_id) ||
                ensured_header_extension_id_exists(rewrite_options.ensured_header_extensions, rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtx retransmit header extension id rewrite skipped ensured extension collision name={} stream={} subscriber={} "
                    "publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} kind={} primary_sequence={} "
                    "source_id={} target_id={}",
                    rewrite_name,
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    primary_ssrc_mapping.publisher_session_id,
                    primary_ssrc_mapping.subscriber_session_id,
                    rtx_payload_type_mapping->publisher_mid,
                    rtx_payload_type_mapping->subscriber_mid,
                    rtx_payload_type_mapping->kind,
                    cached_packet.sequence_number,
                    rewrite.source_id,
                    rewrite.target_id);

                return true;
            }

            if (rtp_packet_header_extension_id_exists(make_rtx_packet_span(), rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtx retransmit header extension id rewrite skipped target id collision name={} stream={} subscriber={} "
                    "publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} kind={} primary_sequence={} "
                    "source_id={} target_id={}",
                    rewrite_name,
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    primary_ssrc_mapping.publisher_session_id,
                    primary_ssrc_mapping.subscriber_session_id,
                    rtx_payload_type_mapping->publisher_mid,
                    rtx_payload_type_mapping->subscriber_mid,
                    rtx_payload_type_mapping->kind,
                    cached_packet.sequence_number,
                    rewrite.source_id,
                    rewrite.target_id);

                return true;
            }
            if (remember_runtime_mapping && !remember_extmap_header_extension_id_rewrite(event.source.stream_id,
                                                                                         primary_ssrc_mapping.publisher_session_id,
                                                                                         primary_ssrc_mapping.subscriber_session_id,
                                                                                         rtx_payload_type_mapping->subscriber_mid,
                                                                                         extension_uri,
                                                                                         rewrite))
            {
                return false;
            }

            rewrite_options.header_extension_id_rewrites.push_back(rewrite);

            rewrite_required = true;

            return true;
        };

        auto append_rtx_header_extension_id_rewrite =
            [&](std::string_view rewrite_name, std::string_view extension_uri, optional_rtx_header_extension_id_rewrite_result rewrite_result) -> bool
        {
            if (!rewrite_result)
            {
                WEBRTC_LOG_WARN(
                    "rtx retransmit header extension id rewrite failed name={} stream={} publisher_session={} subscriber_session={} "
                    "publisher_mid={} subscriber_mid={} sequence={} error={}",
                    rewrite_name,
                    event.source.stream_id,
                    primary_ssrc_mapping.publisher_session_id,
                    primary_ssrc_mapping.subscriber_session_id,
                    rtx_payload_type_mapping->publisher_mid,
                    rtx_payload_type_mapping->subscriber_mid,
                    cached_packet.sequence_number,
                    rewrite_result.error());

                return false;
            }

            if (!rewrite_result->has_value())
            {
                return true;
            }

            rtp_header_extension_id_rewrite tracked_rewrite;

            tracked_rewrite.source_id = (*rewrite_result)->source_id;
            tracked_rewrite.target_id = (*rewrite_result)->target_id;

            if (tracked_rewrite.source_id == tracked_rewrite.target_id)
            {
                return true;
            }

            if (ensured_header_extension_id_exists(rewrite_options.ensured_header_extensions, tracked_rewrite.source_id) ||
                ensured_header_extension_id_exists(rewrite_options.ensured_header_extensions, tracked_rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtx retransmit rtx header extension id rewrite skipped ensured extension collision name={} stream={} subscriber={} "
                    "publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} kind={} primary_sequence={} "
                    "source_id={} target_id={}",
                    rewrite_name,
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    primary_ssrc_mapping.publisher_session_id,
                    primary_ssrc_mapping.subscriber_session_id,
                    rtx_payload_type_mapping->publisher_mid,
                    rtx_payload_type_mapping->subscriber_mid,
                    rtx_payload_type_mapping->kind,
                    cached_packet.sequence_number,
                    tracked_rewrite.source_id,
                    tracked_rewrite.target_id);

                return true;
            }

            if (rtp_packet_header_extension_id_exists(make_rtx_packet_span(), tracked_rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtx retransmit rtx header extension id rewrite skipped target id collision name={} stream={} subscriber={} "
                    "publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} kind={} primary_sequence={} "
                    "source_id={} target_id={}",
                    rewrite_name,
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    primary_ssrc_mapping.publisher_session_id,
                    primary_ssrc_mapping.subscriber_session_id,
                    rtx_payload_type_mapping->publisher_mid,
                    rtx_payload_type_mapping->subscriber_mid,
                    rtx_payload_type_mapping->kind,
                    cached_packet.sequence_number,
                    tracked_rewrite.source_id,
                    tracked_rewrite.target_id);

                return true;
            }
            if (!remember_extmap_header_extension_id_rewrite(event.source.stream_id,
                                                             primary_ssrc_mapping.publisher_session_id,
                                                             primary_ssrc_mapping.subscriber_session_id,
                                                             rtx_payload_type_mapping->subscriber_mid,
                                                             extension_uri,
                                                             tracked_rewrite))
            {
                return false;
            }

            rewrite_options.header_extension_id_rewrites.push_back(tracked_rewrite);

            rewrite_required = true;

            repaired_rid_rewrite_applied = true;

            return true;
        };

        if (publisher_subscriber_media_has_negotiated_mid(*publisher, *subscriber, *rtx_payload_type_mapping))
        {
            auto outbound_mid_ensure = make_outbound_mid_header_extension_ensure(*rtx_payload_type_mapping, subscriber_offer);

            if (!outbound_mid_ensure)
            {
                WEBRTC_LOG_WARN(
                    "rtx retransmit outbound mid ensure failed stream={} subscriber={} publisher_session={} subscriber_session={} publisher_mid={} "
                    "subscriber_mid={} kind={} sequence={} error={}",
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    primary_ssrc_mapping.publisher_session_id,
                    primary_ssrc_mapping.subscriber_session_id,
                    rtx_payload_type_mapping->publisher_mid,
                    rtx_payload_type_mapping->subscriber_mid,
                    rtx_payload_type_mapping->kind,
                    cached_packet.sequence_number,
                    outbound_mid_ensure.error());

                return std::nullopt;
            }

            if (outbound_mid_ensure->has_value())
            {
                const auto& mid_ensure = **outbound_mid_ensure;

                if (outbound_header_extension_ensure_would_overwrite_different_uri(
                        *rtx_payload_type_mapping, publisher_offer, make_rtx_packet_span(), mid_ensure, sdp::k_rtp_header_extension_sdes_mid_uri))
                {
                    WEBRTC_LOG_WARN(
                        "rtx retransmit outbound mid ensure skipped target id collision stream={} subscriber={} publisher_session={} "
                        "subscriber_session={} publisher_mid={} subscriber_mid={} kind={} sequence={} extension_id={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        primary_ssrc_mapping.publisher_session_id,
                        primary_ssrc_mapping.subscriber_session_id,
                        rtx_payload_type_mapping->publisher_mid,
                        rtx_payload_type_mapping->subscriber_mid,
                        rtx_payload_type_mapping->kind,
                        cached_packet.sequence_number,
                        mid_ensure.id);
                }
                else
                {
                    rewrite_options.ensured_header_extensions.push_back(std::move(**outbound_mid_ensure));

                    rewrite_required = true;
                }
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtx retransmit mid rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} sequence={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                primary_ssrc_mapping.publisher_session_id,
                primary_ssrc_mapping.subscriber_session_id,
                rtx_payload_type_mapping->publisher_mid,
                rtx_payload_type_mapping->subscriber_mid,
                rtx_payload_type_mapping->kind,
                cached_packet.sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_rtx_repaired_rid(*publisher, *subscriber, *rtx_payload_type_mapping))
        {
            if (!append_rtx_header_extension_id_rewrite(
                    "repaired-rid",
                    sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri,
                    make_rtx_repaired_rid_header_extension_id_rewrite(
                        *rtx_payload_type_mapping,
                        publisher_offer,
                        subscriber_offer,
                        std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()))))
            {
                return std::nullopt;
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp rtx retransmit repaired-rid rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} sequence={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                primary_ssrc_mapping.publisher_session_id,
                primary_ssrc_mapping.subscriber_session_id,
                rtx_payload_type_mapping->publisher_mid,
                rtx_payload_type_mapping->subscriber_mid,
                rtx_payload_type_mapping->kind,
                cached_packet.sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }

        if (publisher_subscriber_media_has_negotiated_transport_cc(*publisher, *subscriber, *rtx_payload_type_mapping))
        {
            const std::optional<uint16_t> publisher_transport_cc_sequence =
                read_publisher_transport_cc_sequence_number(primary_payload_type_mapping, publisher_offer, cached_plain_packet_span);

            if (publisher_transport_cc_sequence.has_value())
            {
                const uint16_t outbound_transport_cc_sequence =
                    next_outbound_transport_cc_sequence(primary_ssrc_mapping.stream_id, primary_ssrc_mapping.subscriber_session_id);

                auto transport_cc_sequence_rewrite = make_transport_wide_cc_header_extension_rewrite(
                    *rtx_payload_type_mapping, publisher_offer, subscriber_offer, make_rtx_packet_span(), outbound_transport_cc_sequence);

                if (!transport_cc_sequence_rewrite)
                {
                    WEBRTC_LOG_WARN(
                        "rtx retransmit transport-cc sequence rewrite failed stream={} subscriber={} publisher_session={} subscriber_session={} "
                        "publisher_mid={} subscriber_mid={} kind={} primary_sequence={} rtx_sequence={} transport_cc_sequence={} error={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        primary_ssrc_mapping.publisher_session_id,
                        primary_ssrc_mapping.subscriber_session_id,
                        rtx_payload_type_mapping->publisher_mid,
                        rtx_payload_type_mapping->subscriber_mid,
                        rtx_payload_type_mapping->kind,
                        cached_packet.sequence_number,
                        rtx_sequence_number,
                        outbound_transport_cc_sequence,
                        transport_cc_sequence_rewrite.error());

                    return std::nullopt;
                }

                if (transport_cc_sequence_rewrite->has_value())
                {
                    outbound_transport_cc_packet_identity identity;

                    identity.stream_id = primary_ssrc_mapping.stream_id;
                    identity.publisher_session_id = primary_ssrc_mapping.publisher_session_id;
                    identity.subscriber_session_id = primary_ssrc_mapping.subscriber_session_id;
                    identity.publisher_mid = rtx_payload_type_mapping->publisher_mid;
                    identity.subscriber_mid = rtx_payload_type_mapping->subscriber_mid;
                    identity.kind = rtx_payload_type_mapping->kind;

                    identity.publisher_ssrc = primary_ssrc_mapping.publisher_ssrc;
                    identity.subscriber_ssrc = rtx_ssrc_mapping->subscriber_ssrc;

                    identity.publisher_payload_type = cached_packet.payload_type;
                    identity.subscriber_payload_type = static_cast<uint8_t>(rtx_payload_type_mapping->subscriber_payload_type);

                    identity.publisher_rtp_sequence_number = cached_packet.sequence_number;
                    identity.subscriber_rtp_sequence_number = rtx_sequence_number;

                    identity.publisher_transport_cc_sequence_number = *publisher_transport_cc_sequence;
                    identity.subscriber_transport_cc_sequence_number = outbound_transport_cc_sequence;
                    identity.sent_at_milliseconds = now_milliseconds();

                    remember_outbound_transport_cc_packet(identity);

                    rewrite_options.header_extensions.push_back(std::move(**transport_cc_sequence_rewrite));

                    rewrite_required = true;
                }
            }

            if (!append_header_extension_id_rewrite(
                    "transport-cc",
                    sdp::k_rtp_header_extension_transport_cc_uri,
                    false,
                    make_transport_wide_cc_header_extension_id_rewrite(*rtx_payload_type_mapping,
                                                                       publisher_offer,
                                                                       subscriber_offer,
                                                                       std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()))))
            {
                return std::nullopt;
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp rtx retransmit transport-cc rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} primary_sequence={} rtx_sequence={} publisher_accepted_mlines={} "
                "subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                primary_ssrc_mapping.publisher_session_id,
                primary_ssrc_mapping.subscriber_session_id,
                rtx_payload_type_mapping->publisher_mid,
                rtx_payload_type_mapping->subscriber_mid,
                rtx_payload_type_mapping->kind,
                cached_packet.sequence_number,
                rtx_sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_absolute_send_time(*publisher, *subscriber, *rtx_payload_type_mapping))
        {
            if (!append_header_extension_id_rewrite(
                    "abs-send-time",
                    k_absolute_send_time_extension_uri,
                    true,
                    make_absolute_send_time_header_extension_id_rewrite(*rtx_payload_type_mapping,
                                                                        publisher_offer,
                                                                        subscriber_offer,
                                                                        std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()))))
            {
                return std::nullopt;
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp rtx retransmit abs-send-time rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                primary_ssrc_mapping.publisher_session_id,
                primary_ssrc_mapping.subscriber_session_id,
                rtx_payload_type_mapping->publisher_mid,
                rtx_payload_type_mapping->subscriber_mid,
                rtx_payload_type_mapping->kind,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (rewrite_required)
        {
            auto rewrite_result = rewrite_rtp_packet(std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()), rewrite_options);

            if (!rewrite_result)
            {
                WEBRTC_LOG_WARN("rtx retransmit packet rewrite failed stream={} subscriber={} sequence={} error={}",
                                event.source.stream_id,
                                event.source.remote_endpoint,
                                cached_packet.sequence_number,
                                rewrite_result.error());

                return std::nullopt;
            }

            rtx_packet = std::move(rewrite_result->packet);
        }
    }

    auto final_rtx_validation =
        validate_rtp_rtx_packet(std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()), options, rtx_original_sequence_number);
    if (!final_rtx_validation)
    {
        WEBRTC_LOG_WARN(
            "rtx retransmit packet validation failed stream={} subscriber={} primary_ssrc={} rtx_ssrc={} subscriber_osn={} rtx_sequence={} "
            "error={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            primary_ssrc_mapping.publisher_ssrc,
            rtx_ssrc_mapping->subscriber_ssrc,
            rtx_original_sequence_number,
            rtx_sequence_number,
            final_rtx_validation.error());

        return std::nullopt;
    }

    auto final_rtx_info = parse_rtp_rtx_packet(std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()));

    if (!final_rtx_info)
    {
        WEBRTC_LOG_WARN(
            "rtx retransmit packet parse failed after validation stream={} subscriber={} primary_ssrc={} rtx_ssrc={} primary_sequence={} "
            "rtx_sequence={} error={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            primary_ssrc_mapping.publisher_ssrc,
            rtx_ssrc_mapping->subscriber_ssrc,
            cached_packet.sequence_number,
            rtx_sequence_number,
            final_rtx_info.error());

        return std::nullopt;
    }

    if (rtx_retransmission_index_ != nullptr)
    {
        rtx_retransmission_index_->remember(primary_ssrc_mapping.stream_id,
                                            primary_ssrc_mapping.subscriber_session_id,
                                            rtx_ssrc_mapping->subscriber_ssrc,
                                            rtx_sequence_number,
                                            primary_ssrc_mapping.publisher_ssrc,
                                            primary_ssrc_mapping.subscriber_ssrc,
                                            cached_packet.sequence_number,
                                            rtx_original_sequence_number,
                                            true,
                                            primary_ssrc_mapping.publisher_mid,
                                            primary_ssrc_mapping.subscriber_mid,
                                            primary_ssrc_mapping.kind,
                                            primary_ssrc_mapping.rid,
                                            primary_ssrc_mapping.repaired_rid,
                                            now_milliseconds());
    }

    WEBRTC_LOG_DEBUG(
        "rtx retransmit packet built stream={} subscriber={} primary_ssrc={} subscriber_primary_ssrc={} rtx_ssrc={} cache_sequence={} "
        "subscriber_osn={} rtx_sequence={} rtx_timestamp={} osn={} primary_pt={} rtx_pt={} repaired_rid_rewrite={} rtx_payload_size={} "
        "size={}",
        event.source.stream_id,
        event.source.remote_endpoint,
        primary_ssrc_mapping.publisher_ssrc,
        primary_ssrc_mapping.subscriber_ssrc,
        rtx_ssrc_mapping->subscriber_ssrc,
        cached_packet.sequence_number,
        rtx_original_sequence_number,
        rtx_sequence_number,
        outbound_rtx.timestamp,
        final_rtx_info->original_sequence_number,
        static_cast<unsigned int>(cached_packet.payload_type),
        rtx_payload_type_mapping->subscriber_payload_type,
        repaired_rid_rewrite_applied ? 1 : 0,
        final_rtx_info->original_payload_size,
        rtx_packet->size());
    return rtx_packet.value();
}

std::optional<std::vector<uint8_t>> ice_udp_server::make_forward_plain_packet(const srtp_packet_process_result& packet,
                                                                              const media_route_result& route,
                                                                              const std::optional<media_track_resolution>& track_resolution,
                                                                              const std::vector<rtcp_feedback_route_event>& feedback_events,
                                                                              const media_peer_info& target_peer)
{
    std::vector<uint8_t> original_packet;

    original_packet.assign(packet.plain_packet.begin(), packet.plain_packet.end());

    if (packet.plain_packet.empty())
    {
        return original_packet;
    }

    if (packet.kind == srtp_packet_kind::rtcp)
    {
        return make_forward_rtcp_feedback_packet(packet, route, feedback_events, target_peer);
    }

    if (packet.kind != srtp_packet_kind::rtp)
    {
        return original_packet;
    }

    const bool subscriber_media_mapping_required = is_publisher_rtp_fanout_to_subscriber(packet, route, target_peer);

    if (subscriber_media_mapping_required && (!track_resolution.has_value() || !track_resolution->resolved))
    {
        WEBRTC_LOG_WARN(
            "media forward skipped unresolved publisher track stream={} publisher_session={} subscriber_session={} ssrc={} payload_type={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            packet.ssrc,
            static_cast<unsigned int>(packet.payload_type));

        return std::nullopt;
    }

    if (subscriber_media_mapping_required && track_resolution.has_value() && track_resolution->resolved && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        if (publisher == nullptr)
        {
            WEBRTC_LOG_WARN("simulcast rid selection skipped publisher not found stream={} publisher_session={} subscriber_session={}",
                            route.source.stream_id,
                            route.source.session_id,
                            target_peer.session_id);

            return std::nullopt;
        }

        std::optional<media_identity_rid_layer_binding> selected_layer;
        std::vector<std::string> selected_rid_preference;
        std::string selected_rid_policy;

        const std::optional<std::string> runtime_target_rid = runtime_selected_rid_target_for_subscriber(route, target_peer, *track_resolution);

        if (!publisher_rtp_rid_is_selected_for_subscriber(publisher->remote_offer_summary(),
                                                          identity_authority_,
                                                          route,
                                                          target_peer,
                                                          *track_resolution,
                                                          runtime_target_rid,
                                                          selected_layer,
                                                          selected_rid_preference,
                                                          selected_rid_policy))
        {
            return std::nullopt;
        }

        if (selected_layer.has_value())
        {
            remember_selected_rid_layer_for_subscriber(
                route, target_peer, *track_resolution, *selected_layer, selected_rid_policy, selected_rid_preference, packet.plain_packet.size());
        }
    }

    auto payload_type_mapping = find_payload_type_mapping(route, target_peer, track_resolution);

    if (subscriber_media_mapping_required && !payload_type_mapping.has_value())
    {
        WEBRTC_LOG_WARN(
            "media forward skipped incompatible subscriber media stream={} publisher_session={} subscriber_session={} mid={} kind={} ssrc={} "
            "payload_type={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            track_resolution.has_value() ? track_resolution->mid : "",
            track_resolution.has_value() ? track_resolution->kind : "",
            packet.ssrc,
            static_cast<unsigned int>(packet.payload_type));

        return std::nullopt;
    }

    auto ssrc_mapping = get_or_create_ssrc_mapping(route, target_peer, track_resolution, payload_type_mapping);

    if (subscriber_media_mapping_required && !ssrc_mapping.has_value())
    {
        WEBRTC_LOG_WARN(
            "media forward skipped missing ssrc mapping stream={} publisher_session={} subscriber_session={} mid={} kind={} ssrc={} payload_type={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            track_resolution.has_value() ? track_resolution->mid : "",
            track_resolution.has_value() ? track_resolution->kind : "",
            packet.ssrc,
            static_cast<unsigned int>(packet.payload_type));

        return std::nullopt;
    }

    if (!payload_type_mapping.has_value() && !ssrc_mapping.has_value())
    {
        return original_packet;
    }

    if (ssrc_mapping.has_value() && !payload_type_mapping.has_value())
    {
        WEBRTC_LOG_WARN("media forward skipped missing payload mapping stream={} publisher_session={} subscriber_session={} publisher_ssrc={}",
                        route.source.stream_id,
                        route.source.session_id,
                        target_peer.session_id,
                        ssrc_mapping->publisher_ssrc);

        return std::nullopt;
    }

    if (ssrc_mapping.has_value() && payload_type_mapping.has_value())
    {
        if (!remember_media_identity_forward_mapping(*ssrc_mapping, *payload_type_mapping))
        {
            return std::nullopt;
        }

        if (identity_authority_ != nullptr)
        {
            const auto forward_binding = identity_authority_->find_forward_by_publisher_ssrc(ssrc_mapping->stream_id,
                                                                                             ssrc_mapping->publisher_session_id,
                                                                                             ssrc_mapping->subscriber_session_id,
                                                                                             ssrc_mapping->publisher_mid,
                                                                                             ssrc_mapping->publisher_ssrc);

            if (forward_binding.has_value() && media_identity_forward_binding_has_audio_ordinal_mismatch(*forward_binding))
            {
                WEBRTC_LOG_WARN(
                    "audio forward ordinal mismatch rejected stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} "
                    "publisher_media_ordinal={} subscriber_media_ordinal={} publisher_ssrc={} subscriber_ssrc={}",
                    forward_binding->stream_id,
                    forward_binding->publisher_session_id,
                    forward_binding->subscriber_session_id,
                    forward_binding->publisher_mid,
                    forward_binding->subscriber_mid,
                    forward_binding->publisher_media_ordinal,
                    forward_binding->subscriber_media_ordinal,
                    forward_binding->publisher_ssrc,
                    forward_binding->subscriber_ssrc);

                return std::nullopt;
            }
        }
    }

    rtp_packet_rewrite_options options;
    bool rewrite_required = false;

    if (payload_type_mapping.has_value() && payload_type_mapping->payload_type_rewrite_required)
    {
        if (payload_type_mapping->subscriber_payload_type > 127)
        {
            WEBRTC_LOG_WARN("rtp payload type rewrite failed invalid target payload type stream={} subscriber_session={} payload_type={}",
                            payload_type_mapping->stream_id,
                            target_peer.session_id,
                            payload_type_mapping->subscriber_payload_type);

            return std::nullopt;
        }

        options.payload_type = static_cast<uint8_t>(payload_type_mapping->subscriber_payload_type);

        rewrite_required = true;
    }

    if (ssrc_mapping.has_value() && media_ssrc_mapping_requires_rewrite(*ssrc_mapping))
    {
        options.ssrc = ssrc_mapping->subscriber_ssrc;

        rewrite_required = true;
    }

    const std::span<const uint8_t> plain_packet_span(packet.plain_packet.data(), packet.plain_packet.size());

    /*
     * Keep RTP sequence numbers and timestamps continuous for each outbound
     * subscriber SSRC.
     *
     * This runs outside the video-only RTP header extension block on purpose.
     * It covers every publisher RTP packet that is fanned out to a subscriber:
     *
     *   - audio primary RTP
     *   - video primary RTP
     *   - publisher RTX / repaired RTP if it is forwarded as RTP
     *
     * Republish keeps the WHEP subscriber PeerConnection and SRTP outbound
     * context alive. Therefore the same subscriber SSRC must not suddenly jump
     * to the new publisher's random sequence number or timestamp base.
     */
    if (ssrc_mapping.has_value() && payload_type_mapping.has_value())
    {
        auto publisher_header = parse_rtp_packet_header(plain_packet_span);

        if (!publisher_header)
        {
            WEBRTC_LOG_WARN("rtp outbound continuity rewrite parse failed stream={} publisher_session={} subscriber_session={} error={}",
                            payload_type_mapping->stream_id,
                            route.source.session_id,
                            target_peer.session_id,
                            publisher_header.error());

            return std::nullopt;
        }

        const outbound_rtp_rewrite_result outbound_rtp = next_outbound_rtp_rewrite(payload_type_mapping->stream_id,
                                                                                   route.source.session_id,
                                                                                   target_peer.session_id,
                                                                                   ssrc_mapping->subscriber_ssrc,
                                                                                   publisher_header->sequence_number,
                                                                                   publisher_header->timestamp);

        if (outbound_rtp.sequence_number_rewrite_required)
        {
            options.sequence_number = outbound_rtp.sequence_number;

            rewrite_required = true;
        }

        if (outbound_rtp.timestamp_rewrite_required)
        {
            options.timestamp = outbound_rtp.timestamp;

            rewrite_required = true;
        }

        outbound_rtp_packet_identity identity;

        identity.stream_id = payload_type_mapping->stream_id;
        identity.publisher_session_id = route.source.session_id;
        identity.subscriber_session_id = target_peer.session_id;
        identity.publisher_mid = payload_type_mapping->publisher_mid;
        identity.subscriber_mid = payload_type_mapping->subscriber_mid;
        identity.kind = payload_type_mapping->kind;
        identity.rtx = payload_type_mapping->rtx;

        identity.publisher_ssrc = publisher_header->ssrc;
        identity.subscriber_ssrc = ssrc_mapping->subscriber_ssrc;

        identity.publisher_payload_type = publisher_header->payload_type;
        identity.subscriber_payload_type = payload_type_mapping->subscriber_payload_type <= 127
                                               ? static_cast<uint8_t>(payload_type_mapping->subscriber_payload_type)
                                               : publisher_header->payload_type;

        identity.publisher_rtp_sequence_number = publisher_header->sequence_number;
        identity.subscriber_rtp_sequence_number = outbound_rtp.sequence_number;

        identity.publisher_rtp_timestamp = publisher_header->timestamp;
        identity.subscriber_rtp_timestamp = outbound_rtp.timestamp;

        identity.sent_at_milliseconds = now_milliseconds();

        remember_outbound_rtp_packet(identity);

        if (outbound_rtp.publisher_switch)
        {
            WEBRTC_LOG_INFO(
                "rtp outbound continuity publisher switched stream={} old_or_new_publisher_session={} subscriber_session={} subscriber_ssrc={} "
                "publisher_sequence={} subscriber_sequence={} publisher_timestamp={} subscriber_timestamp={} kind={} rtx={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                ssrc_mapping->subscriber_ssrc,
                publisher_header->sequence_number,
                outbound_rtp.sequence_number,
                publisher_header->timestamp,
                outbound_rtp.timestamp,
                payload_type_mapping->kind,
                payload_type_mapping->rtx ? 1 : 0);
        }
    }

    if (payload_type_mapping.has_value() && media_payload_type_mapping_allows_rid_header_extension_rewrite(*payload_type_mapping) &&
        registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(target_peer.session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN("rtp header extension rewrite failed session not found stream={} publisher_session={} subscriber_session={}",
                            route.source.stream_id,
                            route.source.session_id,
                            target_peer.session_id);

            return std::nullopt;
        }

        const auto& publisher_offer = publisher->remote_offer_summary();

        const auto& subscriber_offer = subscriber->remote_offer_summary();

        auto append_header_extension_id_rewrite = [&](std::string_view rewrite_name,
                                                      std::string_view extension_uri,
                                                      bool remember_runtime_mapping,
                                                      optional_header_extension_id_rewrite_result rewrite_result) -> bool
        {
            if (!rewrite_result)
            {
                WEBRTC_LOG_WARN(
                    "rtp header extension id rewrite failed name={} stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                    "subscriber_mid={} error={}",
                    rewrite_name,
                    payload_type_mapping->stream_id,
                    route.source.session_id,
                    target_peer.session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    rewrite_result.error());

                return false;
            }

            if (!rewrite_result->has_value())
            {
                return true;
            }
            const auto rewrite = **rewrite_result;

            if (rewrite.source_id == rewrite.target_id)
            {
                return true;
            }

            if (ensured_header_extension_id_exists(options.ensured_header_extensions, rewrite.source_id) ||
                ensured_header_extension_id_exists(options.ensured_header_extensions, rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtp header extension id rewrite skipped ensured extension collision name={} stream={} publisher_session={} "
                    "subscriber_session={} publisher_mid={} subscriber_mid={} kind={} source_id={} target_id={}",
                    rewrite_name,
                    payload_type_mapping->stream_id,
                    route.source.session_id,
                    target_peer.session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    payload_type_mapping->kind,
                    rewrite.source_id,
                    rewrite.target_id);

                return true;
            }

            if (rtp_packet_header_extension_id_exists(plain_packet_span, rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtp header extension id rewrite skipped target id collision name={} stream={} publisher_session={} subscriber_session={} "
                    "publisher_mid={} subscriber_mid={} kind={} source_id={} target_id={}",
                    rewrite_name,
                    payload_type_mapping->stream_id,
                    route.source.session_id,
                    target_peer.session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    payload_type_mapping->kind,
                    rewrite.source_id,
                    rewrite.target_id);

                return true;
            }
            if (remember_runtime_mapping && !remember_extmap_header_extension_id_rewrite(route.source.stream_id,
                                                                                         route.source.session_id,
                                                                                         target_peer.session_id,
                                                                                         payload_type_mapping->subscriber_mid,
                                                                                         extension_uri,
                                                                                         **rewrite_result))
            {
                return false;
            }

            options.header_extension_id_rewrites.push_back(**rewrite_result);

            rewrite_required = true;

            return true;
        };

        if (publisher_subscriber_media_has_negotiated_mid(*publisher, *subscriber, *payload_type_mapping))
        {
            auto outbound_mid_ensure = make_outbound_mid_header_extension_ensure(*payload_type_mapping, subscriber_offer);

            if (!outbound_mid_ensure)
            {
                WEBRTC_LOG_WARN(
                    "rtp outbound mid ensure failed stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} error={}",
                    payload_type_mapping->stream_id,
                    route.source.session_id,
                    target_peer.session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    outbound_mid_ensure.error());

                return std::nullopt;
            }

            if (outbound_mid_ensure->has_value())
            {
                const auto& mid_ensure = **outbound_mid_ensure;

                if (outbound_header_extension_ensure_would_overwrite_different_uri(
                        *payload_type_mapping, publisher_offer, plain_packet_span, mid_ensure, sdp::k_rtp_header_extension_sdes_mid_uri))
                {
                    WEBRTC_LOG_WARN(
                        "rtp outbound mid ensure skipped target id collision stream={} publisher_session={} subscriber_session={} "
                        "publisher_mid={} subscriber_mid={} extension_id={}",
                        payload_type_mapping->stream_id,
                        route.source.session_id,
                        target_peer.session_id,
                        payload_type_mapping->publisher_mid,
                        payload_type_mapping->subscriber_mid,
                        mid_ensure.id);
                }
                else
                {
                    options.ensured_header_extensions.push_back(std::move(**outbound_mid_ensure));

                    rewrite_required = true;
                }
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp mid rewrite skipped not negotiated stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} "
                "kind={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_transport_cc(*publisher, *subscriber, *payload_type_mapping))
        {
            const std::optional<uint16_t> publisher_transport_cc_sequence =
                read_publisher_transport_cc_sequence_number(*payload_type_mapping, publisher_offer, plain_packet_span);

            if (publisher_transport_cc_sequence.has_value())
            {
                const uint16_t outbound_transport_cc_sequence =
                    next_outbound_transport_cc_sequence(payload_type_mapping->stream_id, target_peer.session_id);

                auto transport_cc_sequence_rewrite = make_transport_wide_cc_header_extension_rewrite(
                    *payload_type_mapping, publisher_offer, subscriber_offer, plain_packet_span, outbound_transport_cc_sequence);

                if (!transport_cc_sequence_rewrite)
                {
                    WEBRTC_LOG_WARN(
                        "rtp transport-cc sequence rewrite failed stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                        "subscriber_mid={} kind={} publisher_transport_cc_sequence={} subscriber_transport_cc_sequence={} error={}",
                        payload_type_mapping->stream_id,
                        route.source.session_id,
                        target_peer.session_id,
                        payload_type_mapping->publisher_mid,
                        payload_type_mapping->subscriber_mid,
                        payload_type_mapping->kind,
                        *publisher_transport_cc_sequence,
                        outbound_transport_cc_sequence,
                        transport_cc_sequence_rewrite.error());

                    return std::nullopt;
                }

                if (transport_cc_sequence_rewrite->has_value())
                {
                    auto publisher_header = parse_rtp_packet_header(plain_packet_span);

                    if (!publisher_header)
                    {
                        WEBRTC_LOG_WARN(
                            "rtp transport-cc identity parse failed stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                            "subscriber_mid={} kind={} publisher_transport_cc_sequence={} subscriber_transport_cc_sequence={} error={}",
                            payload_type_mapping->stream_id,
                            route.source.session_id,
                            target_peer.session_id,
                            payload_type_mapping->publisher_mid,
                            payload_type_mapping->subscriber_mid,
                            payload_type_mapping->kind,
                            *publisher_transport_cc_sequence,
                            outbound_transport_cc_sequence,
                            publisher_header.error());

                        return std::nullopt;
                    }

                    outbound_transport_cc_packet_identity identity;

                    identity.stream_id = payload_type_mapping->stream_id;
                    identity.publisher_session_id = route.source.session_id;
                    identity.subscriber_session_id = target_peer.session_id;
                    identity.publisher_mid = payload_type_mapping->publisher_mid;
                    identity.subscriber_mid = payload_type_mapping->subscriber_mid;
                    identity.kind = payload_type_mapping->kind;

                    identity.publisher_ssrc = publisher_header->ssrc;
                    identity.subscriber_ssrc = ssrc_mapping->subscriber_ssrc;

                    identity.publisher_payload_type = publisher_header->payload_type;
                    identity.subscriber_payload_type = payload_type_mapping->subscriber_payload_type <= 127U
                                                           ? static_cast<uint8_t>(payload_type_mapping->subscriber_payload_type)
                                                           : publisher_header->payload_type;

                    identity.publisher_rtp_sequence_number = publisher_header->sequence_number;
                    identity.subscriber_rtp_sequence_number =
                        options.sequence_number.has_value() ? *options.sequence_number : publisher_header->sequence_number;

                    identity.publisher_transport_cc_sequence_number = *publisher_transport_cc_sequence;
                    identity.subscriber_transport_cc_sequence_number = outbound_transport_cc_sequence;
                    identity.sent_at_milliseconds = now_milliseconds();

                    remember_outbound_transport_cc_packet(identity);

                    options.header_extensions.push_back(std::move(**transport_cc_sequence_rewrite));

                    rewrite_required = true;
                }
            }

            if (!append_header_extension_id_rewrite(
                    "transport-cc",
                    sdp::k_rtp_header_extension_transport_cc_uri,
                    false,
                    make_transport_wide_cc_header_extension_id_rewrite(*payload_type_mapping, publisher_offer, subscriber_offer, plain_packet_span)))
            {
                return std::nullopt;
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp transport-cc rewrite skipped not negotiated stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                "subscriber_mid={} "
                "kind={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_rid_header_extension(*publisher, *subscriber, *payload_type_mapping))
        {
            const std::string_view rid_extension_uri = payload_type_mapping->rtx ? sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri
                                                                                 : sdp::k_rtp_header_extension_sdes_rtp_stream_id_uri;

            const std::string_view rid_rewrite_name = payload_type_mapping->rtx ? "repaired-rid" : "rid";

            optional_header_extension_id_rewrite_result rid_rewrite =
                payload_type_mapping->rtx
                    ? make_repaired_rid_header_extension_id_rewrite(*payload_type_mapping, publisher_offer, subscriber_offer, plain_packet_span)
                    : make_rid_header_extension_id_rewrite(*payload_type_mapping, publisher_offer, subscriber_offer, plain_packet_span);

            if (!append_header_extension_id_rewrite(rid_rewrite_name, rid_extension_uri, true, std::move(rid_rewrite)))
            {
                return std::nullopt;
            }
        }
        else if (media_payload_type_mapping_allows_rid_header_extension_rewrite(*payload_type_mapping))
        {
            WEBRTC_LOG_DEBUG(
                "rtp rid rewrite skipped not negotiated stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} "
                "kind={} rtx={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                payload_type_mapping->rtx ? 1 : 0,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_absolute_send_time(*publisher, *subscriber, *payload_type_mapping))
        {
            if (!append_header_extension_id_rewrite(
                    "abs-send-time",
                    k_absolute_send_time_extension_uri,
                    true,
                    make_absolute_send_time_header_extension_id_rewrite(*payload_type_mapping, publisher_offer, subscriber_offer, plain_packet_span)))
            {
                return std::nullopt;
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp abs-send-time rewrite skipped not negotiated stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                "subscriber_mid={} "
                "kind={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }

        if (publisher_subscriber_media_has_negotiated_audio_level(*publisher, *subscriber, *payload_type_mapping))
        {
            if (!append_header_extension_id_rewrite("audio-level",
                                                    k_audio_level_extension_uri,
                                                    true,
                                                    make_forwarded_rtp_header_extension_id_rewrite(*payload_type_mapping,
                                                                                                   publisher_offer,
                                                                                                   subscriber_offer,
                                                                                                   plain_packet_span,
                                                                                                   k_audio_level_extension_uri,
                                                                                                   "rtp audio-level rewrite")))
            {
                return std::nullopt;
            }
        }
        else if (payload_type_mapping->kind == "audio")
        {
            WEBRTC_LOG_DEBUG(
                "rtp audio-level rewrite skipped not negotiated stream={} publisher_session={} subscriber_session={} publisher_mid={} "
                "subscriber_mid={} "
                "kind={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
    }

    if (!rewrite_required)
    {
        return original_packet;
    }

    auto rewrite_result = rewrite_rtp_packet(std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()), options);

    if (!rewrite_result)
    {
        WEBRTC_LOG_WARN("rtp packet rewrite failed stream={} publisher_session={} subscriber_session={} error={}",
                        route.source.stream_id,
                        route.source.session_id,
                        target_peer.session_id,
                        rewrite_result.error());

        return std::nullopt;
    }

    if (rewrite_result->changed)
    {
        WEBRTC_LOG_DEBUG(
            "rtp packet rewrite applied stream={} publisher_session={} subscriber_session={} publisher_ssrc={} subscriber_ssrc={} plain_size={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            ssrc_mapping.has_value() ? ssrc_mapping->publisher_ssrc : packet.ssrc,
            ssrc_mapping.has_value() ? ssrc_mapping->subscriber_ssrc : packet.ssrc,
            rewrite_result->packet.size());
    }

    return std::move(rewrite_result->packet);
}

std::optional<ice_udp_server::retransmit_plain_packet_result> ice_udp_server::make_retransmit_plain_packet(
    const rtcp_feedback_route_event& event,
    const rtp_packet_cache_entry& cached_packet,
    const std::optional<media_ssrc_mapping>& ssrc_mapping,
    const nack_retransmit_sequence& requested_sequence)
{
    std::vector<uint8_t> original_packet;

    original_packet.assign(cached_packet.plain_packet.begin(), cached_packet.plain_packet.end());

    const auto make_primary_result = [](std::vector<uint8_t> packet)
    {
        retransmit_plain_packet_result result;

        result.packet = std::move(packet);

        result.kind = retransmit_plain_packet_kind::primary;

        return result;
    };

    const auto make_rtx_result = [](std::vector<uint8_t> packet)
    {
        retransmit_plain_packet_result result;

        result.packet = std::move(packet);

        result.kind = retransmit_plain_packet_kind::rtx;

        return result;
    };

    if (!ssrc_mapping.has_value())
    {
        WEBRTC_LOG_WARN("rtp nack retransmit skipped missing ssrc mapping stream={} subscriber={} cache_ssrc={} sequence={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        cached_packet.ssrc,
                        cached_packet.sequence_number);

        return make_primary_result(std::move(original_packet));
    }

    rtp_packet_rewrite_options options;

    bool rewrite_required = false;

    if (media_ssrc_mapping_requires_rewrite(*ssrc_mapping))
    {
        options.ssrc = ssrc_mapping->subscriber_ssrc;

        rewrite_required = true;
    }

    auto table = get_or_create_payload_type_mapping_table_for_sessions(
        ssrc_mapping->stream_id, ssrc_mapping->publisher_session_id, ssrc_mapping->subscriber_session_id);

    std::optional<media_payload_type_mapping> payload_type_mapping;

    if (table.has_value())
    {
        payload_type_mapping = find_media_payload_type_mapping(*table, ssrc_mapping->publisher_mid, cached_packet.payload_type);
    }

    if (!payload_type_mapping.has_value())
    {
        WEBRTC_LOG_WARN(
            "rtp nack retransmit skipped incompatible subscriber media stream={} subscriber={} publisher_session={} subscriber_session={} "
            "publisher_mid={} cache_ssrc={} sequence={} payload_type={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            ssrc_mapping->publisher_session_id,
            ssrc_mapping->subscriber_session_id,
            ssrc_mapping->publisher_mid,
            cached_packet.ssrc,
            cached_packet.sequence_number,
            static_cast<unsigned int>(cached_packet.payload_type));

        return std::nullopt;
    }

    if (!remember_media_identity_forward_mapping(*ssrc_mapping, *payload_type_mapping))
    {
        return std::nullopt;
    }

    if (media_ssrc_mapping_is_primary_video(*ssrc_mapping))
    {
        std::optional<std::vector<uint8_t>> rtx_packet =
            make_rtx_retransmit_plain_packet(event, cached_packet, *ssrc_mapping, *payload_type_mapping, requested_sequence);

        if (rtx_packet.has_value())
        {
            return make_rtx_result(std::move(*rtx_packet));
        }

        if (requested_sequence.rtx_feedback && !requested_sequence.has_subscriber_rtp_identity)
        {
            WEBRTC_LOG_WARN(
                "rtp nack retransmit skipped rtx feedback primary fallback without subscriber identity stream={} subscriber={} feedback_sequence={} "
                "cache_sequence={} publisher_ssrc={} subscriber_ssrc={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                requested_sequence.feedback_sequence_number,
                requested_sequence.cache_sequence_number,
                ssrc_mapping->publisher_ssrc,
                ssrc_mapping->subscriber_ssrc);

            return std::nullopt;
        }
    }

    if (requested_sequence.has_subscriber_rtp_identity)
    {
        options.sequence_number = requested_sequence.subscriber_sequence_number;
        options.timestamp = requested_sequence.subscriber_timestamp;

        rewrite_required = true;
    }
    else if (!requested_sequence.rtx_feedback && requested_sequence.feedback_sequence_number != cached_packet.sequence_number)
    {
        options.sequence_number = requested_sequence.feedback_sequence_number;

        rewrite_required = true;
    }

    if (payload_type_mapping->payload_type_rewrite_required)
    {
        if (payload_type_mapping->subscriber_payload_type > 127)
        {
            WEBRTC_LOG_WARN("rtp nack retransmit rewrite failed invalid target payload type stream={} subscriber={} sequence={} payload_type={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            payload_type_mapping->subscriber_payload_type);

            return std::nullopt;
        }

        options.payload_type = static_cast<uint8_t>(payload_type_mapping->subscriber_payload_type);

        rewrite_required = true;
    }

    if (registry_ != nullptr && identity_authority_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(ssrc_mapping->publisher_session_id);

        if (publisher == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtp nack retransmit rid selection failed publisher not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        auto layer = identity_authority_->find_rid_layer_by_primary_ssrc(ssrc_mapping->publisher_session_id, ssrc_mapping->publisher_ssrc);

        if (layer.has_value())
        {
            const sdp::media_summary* publisher_media = find_offer_media_by_mid(publisher->remote_offer_summary(), layer->mid);

            if (publisher_media != nullptr)
            {
                const std::vector<std::string> preferred_rids = make_default_simulcast_rid_preference(*publisher_media);

                auto preferred_layer = identity_authority_->find_preferred_rid_layer(
                    event.source.stream_id, ssrc_mapping->publisher_session_id, layer->mid, preferred_rids);

                if (preferred_layer.has_value() && preferred_layer->rid != layer->rid)
                {
                    WEBRTC_LOG_DEBUG(
                        "rtp nack retransmit skipped non selected rid stream={} subscriber_session={} mid={} packet_rid={} selected_rid={} "
                        "publisher_ssrc={} sequence={}",
                        event.source.stream_id,
                        ssrc_mapping->subscriber_session_id,
                        layer->mid,
                        layer->rid,
                        preferred_layer->rid,
                        ssrc_mapping->publisher_ssrc,
                        cached_packet.sequence_number);

                    return std::nullopt;
                }
            }
        }
    }

    if (registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(ssrc_mapping->publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(ssrc_mapping->subscriber_session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtp nack retransmit extmap rewrite failed session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        const auto& publisher_offer = publisher->remote_offer_summary();

        const auto& subscriber_offer = subscriber->remote_offer_summary();

        const std::span<const uint8_t> cached_plain_packet_span(cached_packet.plain_packet.data(), cached_packet.plain_packet.size());

        auto append_header_extension_id_rewrite = [&](std::string_view rewrite_name,
                                                      std::string_view extension_uri,
                                                      bool remember_runtime_mapping,
                                                      optional_header_extension_id_rewrite_result rewrite_result) -> bool
        {
            if (!rewrite_result)
            {
                WEBRTC_LOG_WARN(
                    "rtp nack retransmit header extension id rewrite failed name={} stream={} subscriber={} publisher_session={} "
                    "subscriber_session={} publisher_mid={} subscriber_mid={} sequence={} error={}",
                    rewrite_name,
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    ssrc_mapping->publisher_session_id,
                    ssrc_mapping->subscriber_session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    cached_packet.sequence_number,
                    rewrite_result.error());

                return false;
            }

            if (!rewrite_result->has_value())
            {
                return true;
            }
            const auto rewrite = **rewrite_result;

            if (rewrite.source_id == rewrite.target_id)
            {
                return true;
            }

            if (ensured_header_extension_id_exists(options.ensured_header_extensions, rewrite.source_id) ||
                ensured_header_extension_id_exists(options.ensured_header_extensions, rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtp nack retransmit header extension id rewrite skipped ensured extension collision name={} stream={} subscriber={} "
                    "publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} kind={} sequence={} source_id={} target_id={}",
                    rewrite_name,
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    ssrc_mapping->publisher_session_id,
                    ssrc_mapping->subscriber_session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    payload_type_mapping->kind,
                    cached_packet.sequence_number,
                    rewrite.source_id,
                    rewrite.target_id);

                return true;
            }

            if (rtp_packet_header_extension_id_exists(cached_plain_packet_span, rewrite.target_id))
            {
                WEBRTC_LOG_WARN(
                    "rtp nack retransmit header extension id rewrite skipped target id collision name={} stream={} subscriber={} "
                    "publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} kind={} sequence={} source_id={} target_id={}",
                    rewrite_name,
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    ssrc_mapping->publisher_session_id,
                    ssrc_mapping->subscriber_session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    payload_type_mapping->kind,
                    cached_packet.sequence_number,
                    rewrite.source_id,
                    rewrite.target_id);

                return true;
            }
            if (remember_runtime_mapping && !remember_extmap_header_extension_id_rewrite(event.source.stream_id,
                                                                                         ssrc_mapping->publisher_session_id,
                                                                                         ssrc_mapping->subscriber_session_id,
                                                                                         payload_type_mapping->subscriber_mid,
                                                                                         extension_uri,
                                                                                         rewrite))
            {
                return false;
            }

            options.header_extension_id_rewrites.push_back(rewrite);

            rewrite_required = true;

            return true;
        };

        if (publisher_subscriber_media_has_negotiated_mid(*publisher, *subscriber, *payload_type_mapping))
        {
            auto outbound_mid_ensure = make_outbound_mid_header_extension_ensure(*payload_type_mapping, subscriber_offer);

            if (!outbound_mid_ensure)
            {
                WEBRTC_LOG_WARN("rtp nack retransmit outbound mid ensure failed stream={} subscriber={} sequence={} error={}",
                                event.source.stream_id,
                                event.source.remote_endpoint,
                                cached_packet.sequence_number,
                                outbound_mid_ensure.error());

                return std::nullopt;
            }

            if (outbound_mid_ensure->has_value())
            {
                const auto& mid_ensure = **outbound_mid_ensure;

                if (outbound_header_extension_ensure_would_overwrite_different_uri(
                        *payload_type_mapping, publisher_offer, cached_plain_packet_span, mid_ensure, sdp::k_rtp_header_extension_sdes_mid_uri))
                {
                    WEBRTC_LOG_WARN(
                        "rtp nack retransmit outbound mid ensure skipped target id collision stream={} subscriber={} publisher_session={} "
                        "subscriber_session={} publisher_mid={} subscriber_mid={} kind={} sequence={} extension_id={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        ssrc_mapping->publisher_session_id,
                        ssrc_mapping->subscriber_session_id,
                        payload_type_mapping->publisher_mid,
                        payload_type_mapping->subscriber_mid,
                        payload_type_mapping->kind,
                        cached_packet.sequence_number,
                        mid_ensure.id);
                }
                else
                {
                    options.ensured_header_extensions.push_back(std::move(**outbound_mid_ensure));

                    rewrite_required = true;
                }
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit mid rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} sequence={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                cached_packet.sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_transport_cc(*publisher, *subscriber, *payload_type_mapping))
        {
            const std::optional<uint16_t> publisher_transport_cc_sequence =
                read_publisher_transport_cc_sequence_number(*payload_type_mapping, publisher_offer, cached_plain_packet_span);

            if (publisher_transport_cc_sequence.has_value())
            {
                const uint16_t outbound_transport_cc_sequence =
                    next_outbound_transport_cc_sequence(ssrc_mapping->stream_id, ssrc_mapping->subscriber_session_id);

                auto transport_cc_sequence_rewrite = make_transport_wide_cc_header_extension_rewrite(
                    *payload_type_mapping, publisher_offer, subscriber_offer, cached_plain_packet_span, outbound_transport_cc_sequence);

                if (!transport_cc_sequence_rewrite)
                {
                    WEBRTC_LOG_WARN(
                        "rtp nack retransmit transport-cc sequence rewrite failed stream={} subscriber={} publisher_session={} subscriber_session={} "
                        "publisher_mid={} subscriber_mid={} kind={} sequence={} transport_cc_sequence={} error={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        ssrc_mapping->publisher_session_id,
                        ssrc_mapping->subscriber_session_id,
                        payload_type_mapping->publisher_mid,
                        payload_type_mapping->subscriber_mid,
                        payload_type_mapping->kind,
                        cached_packet.sequence_number,
                        outbound_transport_cc_sequence,
                        transport_cc_sequence_rewrite.error());

                    return std::nullopt;
                }

                if (transport_cc_sequence_rewrite->has_value())
                {
                    outbound_transport_cc_packet_identity identity;

                    identity.stream_id = ssrc_mapping->stream_id;
                    identity.publisher_session_id = ssrc_mapping->publisher_session_id;
                    identity.subscriber_session_id = ssrc_mapping->subscriber_session_id;
                    identity.publisher_mid = payload_type_mapping->publisher_mid;
                    identity.subscriber_mid = payload_type_mapping->subscriber_mid;
                    identity.kind = payload_type_mapping->kind;

                    identity.publisher_ssrc = ssrc_mapping->publisher_ssrc;
                    identity.subscriber_ssrc = ssrc_mapping->subscriber_ssrc;

                    identity.publisher_payload_type = cached_packet.payload_type;
                    identity.subscriber_payload_type = payload_type_mapping->subscriber_payload_type <= 127U
                                                           ? static_cast<uint8_t>(payload_type_mapping->subscriber_payload_type)
                                                           : cached_packet.payload_type;

                    identity.publisher_rtp_sequence_number = cached_packet.sequence_number;
                    identity.subscriber_rtp_sequence_number =
                        options.sequence_number.has_value() ? *options.sequence_number : cached_packet.sequence_number;

                    identity.publisher_transport_cc_sequence_number = *publisher_transport_cc_sequence;
                    identity.subscriber_transport_cc_sequence_number = outbound_transport_cc_sequence;
                    identity.sent_at_milliseconds = now_milliseconds();

                    remember_outbound_transport_cc_packet(identity);

                    options.header_extensions.push_back(std::move(**transport_cc_sequence_rewrite));

                    rewrite_required = true;
                }
            }

            if (!append_header_extension_id_rewrite("transport-cc",
                                                    sdp::k_rtp_header_extension_transport_cc_uri,
                                                    false,
                                                    make_transport_wide_cc_header_extension_id_rewrite(
                                                        *payload_type_mapping, publisher_offer, subscriber_offer, cached_plain_packet_span)))
            {
                return std::nullopt;
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit transport-cc rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} sequence={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                cached_packet.sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }

        if (publisher_subscriber_media_has_negotiated_rid_header_extension(*publisher, *subscriber, *payload_type_mapping))
        {
            const std::string_view rid_extension_uri = payload_type_mapping->rtx ? sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri
                                                                                 : sdp::k_rtp_header_extension_sdes_rtp_stream_id_uri;

            const std::string_view rid_rewrite_name = payload_type_mapping->rtx ? "repaired-rid" : "rid";

            optional_header_extension_id_rewrite_result rid_rewrite =
                payload_type_mapping->rtx
                    ? make_repaired_rid_header_extension_id_rewrite(
                          *payload_type_mapping, publisher_offer, subscriber_offer, cached_plain_packet_span)
                    : make_rid_header_extension_id_rewrite(*payload_type_mapping, publisher_offer, subscriber_offer, cached_plain_packet_span);

            if (!append_header_extension_id_rewrite(rid_rewrite_name, rid_extension_uri, true, std::move(rid_rewrite)))
            {
                return std::nullopt;
            }
        }
        else if (media_payload_type_mapping_allows_rid_header_extension_rewrite(*payload_type_mapping))
        {
            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit rid rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} rtx={} sequence={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                payload_type_mapping->rtx ? 1 : 0,
                cached_packet.sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_absolute_send_time(*publisher, *subscriber, *payload_type_mapping))
        {
            if (!append_header_extension_id_rewrite("abs-send-time",
                                                    k_absolute_send_time_extension_uri,
                                                    true,
                                                    make_absolute_send_time_header_extension_id_rewrite(
                                                        *payload_type_mapping, publisher_offer, subscriber_offer, cached_plain_packet_span)))
            {
                return std::nullopt;
            }
        }
        else
        {
            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit abs-send-time rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} sequence={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                cached_packet.sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
        if (publisher_subscriber_media_has_negotiated_audio_level(*publisher, *subscriber, *payload_type_mapping))
        {
            if (!append_header_extension_id_rewrite("audio-level",
                                                    k_audio_level_extension_uri,
                                                    true,
                                                    make_forwarded_rtp_header_extension_id_rewrite(*payload_type_mapping,
                                                                                                   publisher_offer,
                                                                                                   subscriber_offer,
                                                                                                   cached_plain_packet_span,
                                                                                                   k_audio_level_extension_uri,
                                                                                                   "rtp audio-level rewrite")))
            {
                return std::nullopt;
            }
        }
        else if (payload_type_mapping->kind == "audio")
        {
            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit audio-level rewrite skipped not negotiated stream={} subscriber={} publisher_session={} subscriber_session={} "
                "publisher_mid={} subscriber_mid={} kind={} sequence={} publisher_accepted_mlines={} subscriber_accepted_mlines={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->kind,
                cached_packet.sequence_number,
                publisher->accepted_remote_media_mline_indexes().size(),
                subscriber->accepted_remote_media_mline_indexes().size());
        }
    }

    if (!rewrite_required)
    {
        return make_primary_result(std::move(original_packet));
    }

    auto rewrite_result = rewrite_rtp_packet(std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()), options);

    if (!rewrite_result)
    {
        WEBRTC_LOG_WARN("rtp nack retransmit rewrite failed stream={} subscriber={} publisher_ssrc={} subscriber_ssrc={} sequence={} error={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        ssrc_mapping->publisher_ssrc,
                        ssrc_mapping->subscriber_ssrc,
                        cached_packet.sequence_number,
                        rewrite_result.error());

        return std::nullopt;
    }

    return make_primary_result(std::move(rewrite_result->packet));
}

void ice_udp_server::cache_inbound_rtp_packet(const srtp_packet_process_result& packet,
                                              const media_route_result& route,
                                              const std::optional<media_track_resolution>& track_resolution)
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return;
    }

    if (packet.plain_packet.empty())
    {
        return;
    }

    if (!is_resolved_video_track(track_resolution))
    {
        return;
    }

    if (rtp_packet_cache_ == nullptr)
    {
        return;
    }

    if (track_resolution.has_value() && track_resolution->resolved && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        if (publisher != nullptr &&
            media_offer_payload_type_is_rtx(publisher->remote_offer_summary(), track_resolution->mid, track_resolution->payload_type))
        {
            WEBRTC_LOG_DEBUG("rtp cache skip rtx stream={} remote={} mid={} ssrc={} sequence={} payload_type={}",
                             route.source.stream_id,
                             route.source.remote_endpoint,
                             track_resolution->mid,
                             packet.ssrc,
                             packet.sequence_number,
                             static_cast<unsigned int>(packet.payload_type));

            return;
        }
    }

    auto result = rtp_packet_cache_->put(route.source.stream_id, std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

    if (!result)
    {
        WEBRTC_LOG_WARN("rtp cache put failed stream={} remote={} ssrc={} sequence={} error={}",
                        route.source.stream_id,
                        route.source.remote_endpoint,
                        packet.ssrc,
                        packet.sequence_number,
                        result.error());

        return;
    }

    WEBRTC_LOG_DEBUG("rtp cache put stream={} remote={} ssrc={} sequence={} payload_type={} size={}",
                     result->stream_id,
                     route.source.remote_endpoint,
                     result->ssrc,
                     result->sequence_number,
                     static_cast<unsigned int>(result->payload_type),
                     result->plain_packet.size());
}

void ice_udp_server::handle_rtcp_bye_packet(const srtp_packet_process_result& packet, const media_route_result& route)
{
    if (packet.kind != srtp_packet_kind::rtcp)
    {
        return;
    }

    if (!packet.rtcp_has_bye)
    {
        return;
    }

    if (!route.known_peer)
    {
        return;
    }

    if (route.source.session_id.empty())
    {
        return;
    }

    WEBRTC_LOG_INFO("rtcp bye received stream={} session={} role={} remote={} ssrc_count={} reason={}",
                    route.source.stream_id,
                    route.source.session_id,
                    media_peer_role_to_string(route.source.role),
                    route.source.remote_endpoint,
                    packet.rtcp_bye_ssrcs.size(),
                    packet.rtcp_bye_reason);

    remove_expired_session(route.source.session_id, "rtcp bye");
}
void ice_udp_server::handle_transport_cc_feedback_event(const rtcp_feedback_route_event& event)
{
    if (!event.has_transport_cc || event.transport_cc_packet_status_count == 0)
    {
        return;
    }

    if (event.source.stream_id.empty() || event.source.session_id.empty())
    {
        transport_cc_feedback_lookup_miss_total_.fetch_add(event.transport_cc_packet_status_count, std::memory_order_relaxed);

        return;
    }

    const uint64_t observed_at_milliseconds = now_milliseconds();

    std::size_t hit_count = 0;
    std::size_t miss_count = 0;
    std::size_t received_hit_count = 0;
    std::size_t lost_hit_count = 0;
    std::size_t local_drop_ignored_count = 0;

    bool feedback_packet_begin = true;

    for (const auto& status : event.transport_cc_packet_statuses)
    {
        auto identity = find_outbound_transport_cc_packet(event.source.stream_id, event.source.session_id, status.sequence_number);

        outbound_transport_cc_feedback_observation observation;

        observation.feedback_packet_begin = feedback_packet_begin;
        feedback_packet_begin = false;

        observation.small_delta = status.symbol == rtcp_transport_cc_packet_status_symbol::small_delta;
        observation.large_delta = status.symbol == rtcp_transport_cc_packet_status_symbol::large_or_negative_delta;

        observation.subscriber_transport_cc_sequence_number = status.sequence_number;
        observation.lookup_hit = identity.has_value();
        observation.received = status.received;
        observation.has_delta = status.has_delta;
        observation.delta_ticks = status.delta_ticks;
        observation.delta_microseconds = status.delta_microseconds;
        observation.arrival_offset_microseconds = status.arrival_offset_microseconds;
        observation.observed_at_milliseconds = observed_at_milliseconds;

        if (identity.has_value())
        {
            hit_count += 1;

            if (identity->locally_dropped)
            {
                local_drop_ignored_count += 1;

                WEBRTC_LOG_DEBUG(
                    "transport cc feedback ignored local drop stream={} subscriber_session={} transport_cc_sequence={} reason={} received={}",
                    event.source.stream_id,
                    event.source.session_id,
                    status.sequence_number,
                    identity->local_drop_reason,
                    status.received);

                continue;
            }

            observation.sent_at_milliseconds = identity->sent_at_milliseconds;
            observation.publisher_ssrc = identity->publisher_ssrc;
            observation.subscriber_ssrc = identity->subscriber_ssrc;
            observation.publisher_rtp_sequence_number = identity->publisher_rtp_sequence_number;
            observation.subscriber_rtp_sequence_number = identity->subscriber_rtp_sequence_number;

            if (status.received)
            {
                received_hit_count += 1;
            }
            else
            {
                lost_hit_count += 1;
            }
        }
        else
        {
            miss_count += 1;
            observation.counts_for_downlink_control = false;
        }

        remember_outbound_transport_cc_feedback_observation(event.source.stream_id, event.source.session_id, observation);
    }

    if (event.transport_cc_packet_statuses.empty())
    {
        bool fallback_feedback_packet_begin = true;

        for (uint16_t offset = 0; offset < event.transport_cc_packet_status_count; ++offset)
        {
            const uint16_t sequence_number = advance_transport_cc_sequence(event.transport_cc_base_sequence_number, offset);

            auto identity = find_outbound_transport_cc_packet(event.source.stream_id, event.source.session_id, sequence_number);

            outbound_transport_cc_feedback_observation observation;

            observation.feedback_packet_begin = fallback_feedback_packet_begin;
            fallback_feedback_packet_begin = false;
            observation.subscriber_transport_cc_sequence_number = sequence_number;
            observation.lookup_hit = identity.has_value();
            observation.received = false;
            observation.has_delta = false;
            observation.observed_at_milliseconds = observed_at_milliseconds;

            if (identity.has_value())
            {
                hit_count += 1;

                if (identity->locally_dropped)
                {
                    local_drop_ignored_count += 1;

                    WEBRTC_LOG_DEBUG(
                        "transport cc fallback feedback ignored local drop stream={} subscriber_session={} transport_cc_sequence={} reason={}",
                        event.source.stream_id,
                        event.source.session_id,
                        sequence_number,
                        identity->local_drop_reason);

                    continue;
                }

                observation.sent_at_milliseconds = identity->sent_at_milliseconds;
                observation.publisher_ssrc = identity->publisher_ssrc;
                observation.subscriber_ssrc = identity->subscriber_ssrc;
                observation.publisher_rtp_sequence_number = identity->publisher_rtp_sequence_number;
                observation.subscriber_rtp_sequence_number = identity->subscriber_rtp_sequence_number;

                lost_hit_count += 1;
            }
            else
            {
                miss_count += 1;
                observation.counts_for_downlink_control = false;
            }

            remember_outbound_transport_cc_feedback_observation(event.source.stream_id, event.source.session_id, observation);
        }
    }

    transport_cc_feedback_total_.fetch_add(1, std::memory_order_relaxed);
    transport_cc_feedback_packet_status_total_.fetch_add(event.transport_cc_packet_status_count, std::memory_order_relaxed);
    transport_cc_feedback_lookup_hit_total_.fetch_add(hit_count, std::memory_order_relaxed);
    transport_cc_feedback_lookup_miss_total_.fetch_add(miss_count, std::memory_order_relaxed);

    transport_cc_feedback_received_packet_total_.fetch_add(event.transport_cc_received_packet_count, std::memory_order_relaxed);
    transport_cc_feedback_not_received_packet_total_.fetch_add(event.transport_cc_not_received_packet_count, std::memory_order_relaxed);
    transport_cc_feedback_small_delta_total_.fetch_add(event.transport_cc_small_delta_count, std::memory_order_relaxed);
    transport_cc_feedback_large_delta_total_.fetch_add(event.transport_cc_large_delta_count, std::memory_order_relaxed);

    WEBRTC_LOG_DEBUG(
        "transport cc feedback resolved stream={} subscriber_session={} sender_ssrc={} media_ssrc={} base_sequence={} "
        "packet_status_count={} feedback_packet_count={} received={} not_received={} small_delta={} large_delta={} hit={} miss={} "
        "received_hit={} lost_hit={} local_drop_ignored={}",
        event.source.stream_id,
        event.source.session_id,
        event.sender_ssrc,
        event.media_ssrc,
        event.transport_cc_base_sequence_number,
        event.transport_cc_packet_status_count,
        event.transport_cc_feedback_packet_count,
        event.transport_cc_received_packet_count,
        event.transport_cc_not_received_packet_count,
        event.transport_cc_small_delta_count,
        event.transport_cc_large_delta_count,
        hit_count,
        miss_count,
        received_hit_count,
        lost_hit_count,
        local_drop_ignored_count);
}
void ice_udp_server::remember_orphan_subscriber_keyframe_request(const rtcp_feedback_route_event& event)
{
    if (!event.valid)
    {
        return;
    }

    if (!event.has_keyframe_request && event.fir_count == 0)
    {
        return;
    }

    if (event.source.role != media_peer_role::subscriber)
    {
        return;
    }

    if (event.source.stream_id.empty() || event.source.session_id.empty())
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();
    const std::string key = make_subscriber_downlink_bandwidth_state_key(event.source.stream_id, event.source.session_id);

    std::lock_guard lock(endpoint_mutex_);

    auto& state = orphan_subscriber_keyframe_requests_by_key_[key];

    if (state.stream_id.empty())
    {
        state.stream_id = event.source.stream_id;
        state.subscriber_session_id = event.source.session_id;
        state.first_requested_at_milliseconds = current_time_milliseconds;
    }

    state.last_requested_at_milliseconds = current_time_milliseconds;
    state.request_count += 1;
    state.feedback_name = event.feedback_name;
    state.last_media_ssrc = event.media_ssrc;

    WEBRTC_LOG_DEBUG("orphan subscriber keyframe request remembered stream={} subscriber_session={} feedback={} media_ssrc={} count={}",
                     state.stream_id,
                     state.subscriber_session_id,
                     state.feedback_name,
                     state.last_media_ssrc,
                     state.request_count);
}

void ice_udp_server::consume_orphan_subscriber_keyframe_request_after_mapping_created(const media_ssrc_mapping& mapping,
                                                                                      const media_route_result& route,
                                                                                      const media_peer_info& target_peer)
{
    if (!media_ssrc_mapping_is_primary_video(mapping))
    {
        return;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (mapping.stream_id.empty() || mapping.subscriber_session_id.empty())
    {
        return;
    }

    if (mapping.stream_id != route.source.stream_id || mapping.publisher_session_id != route.source.session_id ||
        mapping.subscriber_session_id != target_peer.session_id)
    {
        WEBRTC_LOG_WARN(
            "orphan subscriber keyframe request consume skipped mapping mismatch mapping_stream={} route_stream={} mapping_publisher={} "
            "route_publisher={} mapping_subscriber={} target_subscriber={} publisher_ssrc={} subscriber_ssrc={}",
            mapping.stream_id,
            route.source.stream_id,
            mapping.publisher_session_id,
            route.source.session_id,
            mapping.subscriber_session_id,
            target_peer.session_id,
            mapping.publisher_ssrc,
            mapping.subscriber_ssrc);

        return;
    }

    orphan_subscriber_keyframe_request_state pending;

    {
        std::lock_guard lock(endpoint_mutex_);

        const std::string key = make_subscriber_downlink_bandwidth_state_key(mapping.stream_id, mapping.subscriber_session_id);

        const auto iterator = orphan_subscriber_keyframe_requests_by_key_.find(key);

        if (iterator == orphan_subscriber_keyframe_requests_by_key_.end())
        {
            return;
        }

        pending = iterator->second;

        orphan_subscriber_keyframe_requests_by_key_.erase(iterator);
    }

    WEBRTC_LOG_INFO(
        "orphan subscriber keyframe request consumed stream={} subscriber_session={} publisher_session={} feedback={} pending_count={} "
        "publisher_ssrc={} subscriber_ssrc={}",
        mapping.stream_id,
        mapping.subscriber_session_id,
        mapping.publisher_session_id,
        pending.feedback_name,
        pending.request_count,
        mapping.publisher_ssrc,
        mapping.subscriber_ssrc);

    /*
     * Do not send RTCP PLI directly here.
     *
     * This function runs at SSRC mapping creation time, inside the RTP forwarding
     * path. The existing keyframe request path already sends PLI from
     * maybe_request_keyframe_from_publisher(...) after mapping creation, using
     * the current publisher RTP packet and the current track_resolution.
     *
     * Consuming the orphan pending state here is still useful: it confirms that
     * the orphan subscriber request was matched to the new publisher generation
     * and prevents stale pending state from leaking after republish.
     */
}

void ice_udp_server::handle_rtcp_feedback_event(const rtcp_feedback_route_event& event)
{
    if (!event.valid)
    {
        return;
    }
    if (event.event_type == rtcp_feedback_event_type::transport_cc)
    {
        handle_transport_cc_feedback_event(event);

        return;
    }
    if (event.has_generic_nack)
    {
        retransmit_cached_rtp_packets(event);

        return;
    }

    if (!event.has_keyframe_request)
    {
        return;
    }

    const std::optional<media_ssrc_mapping> mapping = resolve_keyframe_feedback_primary_mapping(event);

    if (!mapping.has_value())
    {
        remember_orphan_subscriber_keyframe_request(event);

        WEBRTC_LOG_WARN("keyframe feedback skipped unresolved media target stream={} subscriber_session={} remote={} feedback={} media_ssrc={}",
                        event.source.stream_id,
                        event.source.session_id,
                        event.source.remote_endpoint,
                        event.feedback_name,
                        event.media_ssrc);

        return;
    }
    open_subscriber_downlink_keyframe_request_recovery_window(event, *mapping);

    WEBRTC_LOG_DEBUG(
        "keyframe feedback resolved stream={} subscriber_session={} publisher_session={} feedback={} subscriber_media_ssrc={} "
        "publisher_media_ssrc={} publisher_mid={} subscriber_mid={} kind={} rid={} repaired_rid={}",
        event.source.stream_id,
        mapping->subscriber_session_id,
        mapping->publisher_session_id,
        event.feedback_name,
        event.media_ssrc,
        mapping->publisher_ssrc,
        mapping->publisher_mid,
        mapping->subscriber_mid,
        mapping->kind,
        mapping->rid.value_or(""),
        mapping->repaired_rid.value_or(""));
}

bool ice_udp_server::subscriber_feedback_targets_selected_rid_layer(const rtcp_feedback_route_event& event,
                                                                    const media_ssrc_mapping& primary_mapping,
                                                                    uint32_t feedback_media_ssrc,
                                                                    bool allow_rtx_feedback,
                                                                    std::string_view feedback_reason) const
{
    if (!media_ssrc_mapping_is_primary_video(primary_mapping))
    {
        return false;
    }

    if (event.source.role != media_peer_role::subscriber)
    {
        return true;
    }

    if (primary_mapping.stream_id.empty() || primary_mapping.publisher_session_id.empty() || primary_mapping.subscriber_session_id.empty() ||
        primary_mapping.publisher_mid.empty() || primary_mapping.kind.empty())
    {
        WEBRTC_LOG_WARN(
            "simulcast feedback selected rid check skipped invalid mapping feedback={} stream={} subscriber_session={} feedback_ssrc={} "
            "publisher_session={} publisher_mid={} kind={}",
            feedback_reason,
            event.source.stream_id,
            event.source.session_id,
            feedback_media_ssrc,
            primary_mapping.publisher_session_id,
            primary_mapping.publisher_mid,
            primary_mapping.kind);

        return false;
    }

    if (primary_mapping.stream_id != event.source.stream_id || primary_mapping.subscriber_session_id != event.source.session_id)
    {
        WEBRTC_LOG_WARN(
            "simulcast feedback selected rid check ownership mismatch feedback={} event_stream={} mapping_stream={} event_subscriber_session={} "
            "mapping_subscriber_session={} feedback_ssrc={} publisher_session={} publisher_mid={} kind={}",
            feedback_reason,
            event.source.stream_id,
            primary_mapping.stream_id,
            event.source.session_id,
            primary_mapping.subscriber_session_id,
            feedback_media_ssrc,
            primary_mapping.publisher_session_id,
            primary_mapping.publisher_mid,
            primary_mapping.kind);

        return false;
    }

    if (!allow_rtx_feedback && feedback_media_ssrc != 0 && primary_mapping.subscriber_ssrc != 0 &&
        feedback_media_ssrc != primary_mapping.subscriber_ssrc)
    {
        WEBRTC_LOG_WARN(
            "simulcast keyframe feedback rejected non primary ssrc stream={} subscriber_session={} feedback_ssrc={} subscriber_primary_ssrc={} "
            "publisher_primary_ssrc={} publisher_mid={} kind={}",
            event.source.stream_id,
            event.source.session_id,
            feedback_media_ssrc,
            primary_mapping.subscriber_ssrc,
            primary_mapping.publisher_ssrc,
            primary_mapping.publisher_mid,
            primary_mapping.kind);

        return false;
    }

    const std::string key = make_selected_rid_layer_key(primary_mapping.stream_id,
                                                        primary_mapping.publisher_session_id,
                                                        primary_mapping.subscriber_session_id,
                                                        primary_mapping.publisher_mid,
                                                        primary_mapping.kind);

    std::lock_guard lock(endpoint_mutex_);

    const auto state_iterator = selected_rid_layer_state_by_key_.find(key);

    if (state_iterator == selected_rid_layer_state_by_key_.end())
    {
        return true;
    }

    const selected_rid_layer_runtime_state& state = state_iterator->second;

    if (state.rid.empty() || state.kind.empty())
    {
        WEBRTC_LOG_WARN(
            "simulcast feedback selected rid state invalid feedback={} stream={} publisher_session={} subscriber_session={} mid={} kind={} "
            "feedback_ssrc={}",
            feedback_reason,
            primary_mapping.stream_id,
            primary_mapping.publisher_session_id,
            primary_mapping.subscriber_session_id,
            primary_mapping.publisher_mid,
            primary_mapping.kind,
            feedback_media_ssrc);

        return false;
    }

    if (state.kind != primary_mapping.kind || state.mid != primary_mapping.publisher_mid)
    {
        WEBRTC_LOG_WARN(
            "simulcast feedback selected rid media mismatch feedback={} stream={} publisher_session={} subscriber_session={} state_mid={} "
            "mapping_mid={} state_kind={} mapping_kind={} selected_rid={} feedback_ssrc={}",
            feedback_reason,
            primary_mapping.stream_id,
            primary_mapping.publisher_session_id,
            primary_mapping.subscriber_session_id,
            state.mid,
            primary_mapping.publisher_mid,
            state.kind,
            primary_mapping.kind,
            state.rid,
            feedback_media_ssrc);

        return false;
    }

    if (state.primary_ssrc != 0 && primary_mapping.publisher_ssrc != 0 && state.primary_ssrc != primary_mapping.publisher_ssrc)
    {
        WEBRTC_LOG_DEBUG(
            "simulcast feedback rejected non selected rid feedback={} stream={} publisher_session={} subscriber_session={} mid={} kind={} "
            "selected_rid={} selected_primary_ssrc={} feedback_primary_ssrc={} feedback_ssrc={} allow_rtx={}",
            feedback_reason,
            primary_mapping.stream_id,
            primary_mapping.publisher_session_id,
            primary_mapping.subscriber_session_id,
            primary_mapping.publisher_mid,
            primary_mapping.kind,
            state.rid,
            state.primary_ssrc,
            primary_mapping.publisher_ssrc,
            feedback_media_ssrc,
            allow_rtx_feedback ? 1 : 0);

        return false;
    }

    return true;
}

void ice_udp_server::remember_selected_rid_layer_nack_quality(const media_ssrc_mapping& mapping,
                                                              std::size_t feedback_count,
                                                              std::size_t sequence_count)
{
    if (!media_ssrc_mapping_is_primary_video(mapping))
    {
        return;
    }

    if (mapping.stream_id.empty() || mapping.publisher_session_id.empty() || mapping.subscriber_session_id.empty() || mapping.publisher_mid.empty() ||
        mapping.kind.empty())
    {
        return;
    }

    const std::string key = make_selected_rid_layer_key(
        mapping.stream_id, mapping.publisher_session_id, mapping.subscriber_session_id, mapping.publisher_mid, mapping.kind);

    std::lock_guard lock(endpoint_mutex_);

    auto state_iterator = selected_rid_layer_state_by_key_.find(key);

    if (state_iterator == selected_rid_layer_state_by_key_.end())
    {
        return;
    }

    selected_rid_layer_runtime_state& state = state_iterator->second;

    if (state.primary_ssrc != 0 && mapping.publisher_ssrc != state.primary_ssrc)
    {
        return;
    }

    state.nack_feedback_count += static_cast<uint64_t>(feedback_count);
    state.nack_sequence_count += static_cast<uint64_t>(sequence_count);
    state.last_nack_milliseconds = now_milliseconds();
}
std::optional<ice_udp_server::nack_retransmit_resolution> ice_udp_server::resolve_nack_retransmit_resolution(
    const rtcp_feedback_route_event& event, uint32_t feedback_media_ssrc, const std::vector<uint16_t>& feedback_sequence_numbers) const
{
    if (identity_authority_ == nullptr && ssrc_mapper_ == nullptr)
    {
        WEBRTC_LOG_WARN("rtp nack retransmit skipped identity mapper is null stream={} subscriber={} feedback_ssrc={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        feedback_media_ssrc);

        return std::nullopt;
    }

    std::optional<media_ssrc_mapping> feedback_mapping = find_identity_ssrc_mapping_by_subscriber_ssrc(event.source.session_id, feedback_media_ssrc);
    if (!feedback_mapping.has_value())
    {
        WEBRTC_LOG_WARN("rtp nack retransmit skipped mapping not found stream={} subscriber={} feedback_ssrc={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        feedback_media_ssrc);

        return std::nullopt;
    }

    nack_retransmit_resolution resolution;

    resolution.feedback_media_ssrc = feedback_media_ssrc;

    if (!media_ssrc_mapping_is_rtx(*feedback_mapping))
    {
        const bool primary_video_feedback = media_ssrc_mapping_is_primary_video(*feedback_mapping);

        if (primary_video_feedback && !subscriber_feedback_targets_selected_rid_layer(event, *feedback_mapping, feedback_media_ssrc, true, "nack"))
        {
            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit skipped non selected rid primary feedback stream={} subscriber={} feedback_ssrc={} publisher_ssrc={} "
                "subscriber_ssrc={} mid={} kind={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                feedback_media_ssrc,
                feedback_mapping->publisher_ssrc,
                feedback_mapping->subscriber_ssrc,
                feedback_mapping->publisher_mid,
                feedback_mapping->kind);

            return std::nullopt;
        }

        resolution.ssrc_mapping = feedback_mapping;

        resolution.cache_media_ssrc = feedback_mapping->publisher_ssrc;

        resolution.primary_video = primary_video_feedback;
        resolution.rtx_feedback = false;

        resolution.sequences.reserve(feedback_sequence_numbers.size());

        for (uint16_t subscriber_sequence_number : feedback_sequence_numbers)
        {
            nack_retransmit_sequence sequence;

            sequence.feedback_sequence_number = subscriber_sequence_number;
            sequence.subscriber_sequence_number = subscriber_sequence_number;
            sequence.cache_sequence_number = subscriber_sequence_number;
            sequence.rtx_feedback = false;

            const std::optional<outbound_rtp_packet_identity> identity = find_outbound_rtp_packet(
                event.source.stream_id, event.source.session_id, feedback_mapping->subscriber_ssrc, subscriber_sequence_number);

            if (identity.has_value())
            {
                if (identity->publisher_ssrc != feedback_mapping->publisher_ssrc || identity->subscriber_ssrc != feedback_mapping->subscriber_ssrc ||
                    identity->publisher_mid != feedback_mapping->publisher_mid || identity->subscriber_mid != feedback_mapping->subscriber_mid ||
                    identity->kind != feedback_mapping->kind)
                {
                    resolution.rtx_sequence_index_miss_count += 1;

                    WEBRTC_LOG_WARN(
                        "rtp nack retransmit subscriber identity mismatch stream={} subscriber={} feedback_ssrc={} subscriber_sequence={} "
                        "identity_publisher_ssrc={} mapping_publisher_ssrc={} identity_subscriber_ssrc={} mapping_subscriber_ssrc={} "
                        "identity_publisher_mid={} mapping_publisher_mid={} identity_subscriber_mid={} mapping_subscriber_mid={} "
                        "identity_kind={} mapping_kind={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        feedback_media_ssrc,
                        subscriber_sequence_number,
                        identity->publisher_ssrc,
                        feedback_mapping->publisher_ssrc,
                        identity->subscriber_ssrc,
                        feedback_mapping->subscriber_ssrc,
                        identity->publisher_mid,
                        feedback_mapping->publisher_mid,
                        identity->subscriber_mid,
                        feedback_mapping->subscriber_mid,
                        identity->kind,
                        feedback_mapping->kind);

                    continue;
                }

                sequence.cache_sequence_number = identity->publisher_rtp_sequence_number;
                sequence.subscriber_sequence_number = identity->subscriber_rtp_sequence_number;
                sequence.subscriber_timestamp = identity->subscriber_rtp_timestamp;
                sequence.has_subscriber_rtp_identity = true;
            }
            else
            {
                resolution.rtx_sequence_index_miss_count += 1;

                WEBRTC_LOG_DEBUG(
                    "rtp nack retransmit subscriber identity not found stream={} subscriber={} feedback_ssrc={} subscriber_sequence={} "
                    "fallback_cache_sequence={}",
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    feedback_media_ssrc,
                    subscriber_sequence_number,
                    sequence.cache_sequence_number);
            }

            resolution.sequences.push_back(sequence);
        }

        WEBRTC_LOG_DEBUG(
            "rtp nack retransmit primary feedback resolved stream={} subscriber={} feedback_ssrc={} publisher_ssrc={} requested={} mapped={} "
            "identity_miss={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            resolution.cache_media_ssrc,
            feedback_sequence_numbers.size(),
            resolution.sequences.size(),
            resolution.rtx_sequence_index_miss_count);

        return resolution;
    }
    if (!media_ssrc_mapping_is_rtx(*feedback_mapping))
    {
        WEBRTC_LOG_WARN(
            "rtp nack retransmit skipped non primary video mapping stream={} subscriber={} feedback_ssrc={} publisher_ssrc={} subscriber_ssrc={} "
            "kind={} rtx={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            feedback_mapping->publisher_ssrc,
            feedback_mapping->subscriber_ssrc,
            feedback_mapping->kind,
            media_ssrc_mapping_is_rtx(*feedback_mapping) ? 1 : 0);

        return std::nullopt;
    }

    if (rtx_retransmission_index_ == nullptr)
    {
        WEBRTC_LOG_WARN("rtp nack retransmit skipped rtx index unavailable stream={} subscriber={} feedback_ssrc={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        feedback_media_ssrc);

        return std::nullopt;
    }

    if (feedback_mapping->publisher_rtx_primary_ssrc == 0)
    {
        WEBRTC_LOG_WARN("rtp nack retransmit skipped rtx primary ssrc missing stream={} subscriber={} feedback_ssrc={} rtx_publisher_ssrc={}",
                        event.source.stream_id,
                        event.source.remote_endpoint,
                        feedback_media_ssrc,
                        feedback_mapping->publisher_ssrc);

        return std::nullopt;
    }

    std::optional<media_ssrc_mapping> primary_mapping = find_identity_ssrc_mapping_by_publisher_ssrc(feedback_mapping->stream_id,
                                                                                                     feedback_mapping->publisher_session_id,
                                                                                                     feedback_mapping->subscriber_session_id,
                                                                                                     feedback_mapping->publisher_mid,
                                                                                                     feedback_mapping->publisher_rtx_primary_ssrc);
    if (!primary_mapping.has_value())
    {
        WEBRTC_LOG_WARN(
            "rtp nack retransmit skipped rtx primary mapping not found stream={} subscriber={} feedback_ssrc={} publisher_primary_ssrc={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            feedback_mapping->publisher_rtx_primary_ssrc);

        return std::nullopt;
    }

    if (!media_ssrc_mapping_is_primary_video(*primary_mapping))
    {
        WEBRTC_LOG_WARN(
            "rtp nack retransmit skipped rtx primary mapping is not primary video stream={} subscriber={} feedback_ssrc={} publisher_primary_ssrc={} "
            "kind={} rtx={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            primary_mapping->publisher_ssrc,
            primary_mapping->kind,
            media_ssrc_mapping_is_rtx(*primary_mapping) ? 1 : 0);

        return std::nullopt;
    }
    if (!subscriber_feedback_targets_selected_rid_layer(event, *primary_mapping, feedback_media_ssrc, true, "nack_rtx"))
    {
        WEBRTC_LOG_DEBUG(
            "rtp nack retransmit skipped non selected rid rtx feedback stream={} subscriber={} feedback_ssrc={} publisher_primary_ssrc={} "
            "subscriber_primary_ssrc={} mid={} kind={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            primary_mapping->publisher_ssrc,
            primary_mapping->subscriber_ssrc,
            primary_mapping->publisher_mid,
            primary_mapping->kind);

        return std::nullopt;
    }

    resolution.ssrc_mapping = primary_mapping;

    resolution.cache_media_ssrc = primary_mapping->publisher_ssrc;

    resolution.primary_video = true;
    resolution.rtx_feedback = true;

    resolution.sequences.reserve(feedback_sequence_numbers.size());

    for (uint16_t rtx_sequence_number : feedback_sequence_numbers)
    {
        const std::optional<rtx_retransmission_mapping> indexed =
            rtx_retransmission_index_->find(event.source.stream_id, event.source.session_id, feedback_media_ssrc, rtx_sequence_number);

        if (!indexed.has_value())
        {
            resolution.rtx_sequence_index_miss_count += 1;

            WEBRTC_LOG_DEBUG("rtp nack retransmit rtx sequence mapping not found stream={} subscriber={} rtx_ssrc={} rtx_sequence={}",
                             event.source.stream_id,
                             event.source.remote_endpoint,
                             feedback_media_ssrc,
                             rtx_sequence_number);

            continue;
        }

        if (indexed->publisher_primary_ssrc != primary_mapping->publisher_ssrc)
        {
            resolution.rtx_sequence_index_miss_count += 1;

            WEBRTC_LOG_WARN(
                "rtp nack retransmit rtx sequence mapping publisher primary ssrc mismatch stream={} subscriber={} rtx_ssrc={} rtx_sequence={} "
                "indexed_primary_ssrc={} mapping_primary_ssrc={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                feedback_media_ssrc,
                rtx_sequence_number,
                indexed->publisher_primary_ssrc,
                primary_mapping->publisher_ssrc);

            continue;
        }

        if (indexed->subscriber_primary_ssrc != primary_mapping->subscriber_ssrc)
        {
            resolution.rtx_sequence_index_miss_count += 1;

            WEBRTC_LOG_WARN(
                "rtp nack retransmit rtx sequence mapping subscriber primary ssrc mismatch stream={} subscriber={} rtx_ssrc={} rtx_sequence={} "
                "indexed_subscriber_primary_ssrc={} mapping_subscriber_primary_ssrc={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                feedback_media_ssrc,
                rtx_sequence_number,
                indexed->subscriber_primary_ssrc,
                primary_mapping->subscriber_ssrc);

            continue;
        }

        if (indexed->publisher_mid != primary_mapping->publisher_mid || indexed->subscriber_mid != primary_mapping->subscriber_mid ||
            indexed->kind != primary_mapping->kind || indexed->rid != primary_mapping->rid || indexed->repaired_rid != primary_mapping->repaired_rid)
        {
            resolution.rtx_sequence_index_miss_count += 1;

            WEBRTC_LOG_WARN(
                "rtp nack retransmit rtx sequence mapping track identity mismatch stream={} subscriber={} rtx_ssrc={} rtx_sequence={} "
                "indexed_publisher_mid={} mapping_publisher_mid={} indexed_subscriber_mid={} mapping_subscriber_mid={} "
                "indexed_kind={} mapping_kind={} indexed_rid={} mapping_rid={} indexed_repaired_rid={} mapping_repaired_rid={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                feedback_media_ssrc,
                rtx_sequence_number,
                indexed->publisher_mid,
                primary_mapping->publisher_mid,
                indexed->subscriber_mid,
                primary_mapping->subscriber_mid,
                indexed->kind,
                primary_mapping->kind,
                indexed->rid.value_or(""),
                primary_mapping->rid.value_or(""),
                indexed->repaired_rid.value_or(""),
                primary_mapping->repaired_rid.value_or(""));

            continue;
        }

        nack_retransmit_sequence sequence;

        sequence.feedback_sequence_number = rtx_sequence_number;
        sequence.cache_sequence_number = indexed->primary_sequence_number;
        sequence.rtx_feedback = true;

        if (indexed->has_subscriber_primary_sequence_number)
        {
            sequence.subscriber_sequence_number = indexed->subscriber_primary_sequence_number;
            sequence.has_subscriber_rtp_identity = true;

            const std::optional<outbound_rtp_packet_identity> identity = find_outbound_rtp_packet(
                event.source.stream_id, event.source.session_id, primary_mapping->subscriber_ssrc, indexed->subscriber_primary_sequence_number);

            if (identity.has_value())
            {
                sequence.subscriber_timestamp = identity->subscriber_rtp_timestamp;
            }
        }

        resolution.sequences.push_back(sequence);
    }
    WEBRTC_LOG_DEBUG(
        "rtp nack retransmit rtx feedback resolved stream={} subscriber={} rtx_ssrc={} primary_ssrc={} requested={} mapped={} index_miss={}",
        event.source.stream_id,
        event.source.remote_endpoint,
        feedback_media_ssrc,
        resolution.cache_media_ssrc,
        feedback_sequence_numbers.size(),
        resolution.sequences.size(),
        resolution.rtx_sequence_index_miss_count);

    return resolution;
}

void ice_udp_server::retransmit_cached_rtp_packets(const rtcp_feedback_route_event& event)
{
    if (event.source.role != media_peer_role::subscriber)
    {
        return;
    }

    if (rtp_packet_cache_ == nullptr || srtp_transport_ == nullptr)
    {
        return;
    }

    if (event.nack_items.empty())
    {
        return;
    }

    const uint32_t feedback_media_ssrc = event.media_ssrc != 0 ? event.media_ssrc : event.ssrc;

    if (feedback_media_ssrc == 0)
    {
        WEBRTC_LOG_WARN("rtp nack retransmit skipped empty media ssrc stream={} subscriber={}", event.source.stream_id, event.source.remote_endpoint);

        return;
    }

    auto target_endpoint = find_remote_endpoint(event.source.remote_endpoint);

    if (!target_endpoint)
    {
        WEBRTC_LOG_WARN(
            "rtp nack retransmit subscriber endpoint not found stream={} subscriber={}", event.source.stream_id, event.source.remote_endpoint);

        return;
    }

    const nack_sequence_expansion nack_sequences = expand_nack_sequences(event.nack_items, k_max_nack_retransmit_sequences);

    const std::vector<uint16_t>& sequence_numbers = nack_sequences.sequence_numbers;

    std::optional<nack_retransmit_resolution> retransmit_resolution =
        resolve_nack_retransmit_resolution(event, feedback_media_ssrc, sequence_numbers);

    if (!retransmit_resolution.has_value())
    {
        return;
    }

    const std::optional<media_ssrc_mapping>& ssrc_mapping = retransmit_resolution->ssrc_mapping;

    const uint32_t cache_media_ssrc = retransmit_resolution->cache_media_ssrc;

    const bool nack_mapping_is_primary_video = retransmit_resolution->primary_video;

    if (ssrc_mapping.has_value())
    {
        remember_selected_rid_layer_nack_quality(*ssrc_mapping, 1, retransmit_resolution->sequences.size());
    }
    if (nack_sequences.truncated || nack_sequences.duplicate_count != 0)
    {
        WEBRTC_LOG_DEBUG(
            "rtp nack sequence expansion stream={} subscriber={} nack_items={} raw_requested={} requested={} max={} duplicate={} truncated={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            event.nack_items.size(),
            nack_sequences.raw_sequence_count,
            sequence_numbers.size(),
            k_max_nack_retransmit_sequences,
            nack_sequences.duplicate_count,
            nack_sequences.truncated ? 1 : 0);
    }

    std::size_t hit_count = 0;
    std::size_t miss_count = retransmit_resolution->rtx_sequence_index_miss_count;
    std::size_t sent_count = 0;
    std::size_t ignored_count = 0;
    std::size_t failed_count = 0;
    std::size_t rtx_sent_count = 0;
    std::size_t primary_fallback_sent_count = 0;
    std::size_t throttled_count = 0;

    for (const nack_retransmit_sequence& requested_sequence : retransmit_resolution->sequences)
    {
        const uint16_t sequence_number = requested_sequence.cache_sequence_number;

        if (nack_retransmit_throttle_ == nullptr)
        {
            nack_retransmit_throttle_ = std::make_shared<nack_retransmit_throttle>();
        }

        const uint64_t throttle_check_time_milliseconds = now_milliseconds();

        const nack_retransmit_throttle_decision throttle_decision = nack_retransmit_throttle_->check(event.source.stream_id,
                                                                                                     event.source.session_id,
                                                                                                     feedback_media_ssrc,
                                                                                                     cache_media_ssrc,
                                                                                                     requested_sequence.feedback_sequence_number,
                                                                                                     requested_sequence.cache_sequence_number,
                                                                                                     requested_sequence.rtx_feedback,
                                                                                                     throttle_check_time_milliseconds);

        if (!throttle_decision.allowed)
        {
            throttled_count += 1;

            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit throttled stream={} subscriber={} feedback_ssrc={} cache_ssrc={} feedback_sequence={} cache_sequence={} "
                "rtx_feedback={} elapsed_ms={} wait_ms={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                feedback_media_ssrc,
                cache_media_ssrc,
                requested_sequence.feedback_sequence_number,
                requested_sequence.cache_sequence_number,
                requested_sequence.rtx_feedback ? 1 : 0,
                throttle_decision.elapsed_milliseconds,
                throttle_decision.wait_milliseconds);

            continue;
        }

        auto cached = rtp_packet_cache_->find(event.source.stream_id, cache_media_ssrc, sequence_number);
        if (!cached)
        {
            miss_count += 1;

            continue;
        }

        hit_count += 1;

        auto retransmit_plain_packet = make_retransmit_plain_packet(event, *cached, ssrc_mapping, requested_sequence);

        if (!retransmit_plain_packet.has_value())
        {
            failed_count += 1;

            continue;
        }

        const bool retransmit_is_rtx = retransmit_plain_packet->kind == retransmit_plain_packet_kind::rtx;
        if (!outbound_media_runtime_ready(event.source.remote_endpoint,
                                          event.source.session_id,
                                          event.source.stream_id,
                                          media_peer_role::subscriber,
                                          "rtp nack retransmit protect"))
        {
            ignored_count += 1;

            WEBRTC_LOG_DEBUG(
                "rtp nack retransmit protect skipped outbound runtime not ready stream={} subscriber={} feedback_ssrc={} cache_ssrc={} "
                "feedback_sequence={} cache_sequence={} rtx_feedback={} retransmit_kind={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                feedback_media_ssrc,
                cache_media_ssrc,
                requested_sequence.feedback_sequence_number,
                requested_sequence.cache_sequence_number,
                requested_sequence.rtx_feedback ? 1 : 0,
                retransmit_is_rtx ? "rtx" : "primary");

            continue;
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(retransmit_plain_packet->packet.data(), retransmit_plain_packet->packet.size()),
            event.source.remote_endpoint,
            srtp_packet_kind::rtp);
        if (!protected_packet)
        {
            failed_count += 1;

            WEBRTC_LOG_WARN("rtp nack retransmit protect failed stream={} subscriber={} feedback_ssrc={} cache_ssrc={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            feedback_media_ssrc,
                            cache_media_ssrc,
                            sequence_number,
                            protected_packet.error());

            continue;
        }

        if (protected_packet->state == srtp_packet_process_state::ignored)
        {
            ignored_count += 1;

            WEBRTC_LOG_DEBUG("rtp nack retransmit ignored stream={} subscriber={} feedback_ssrc={} cache_ssrc={} sequence={} reason={}",
                             event.source.stream_id,
                             event.source.remote_endpoint,
                             feedback_media_ssrc,
                             cache_media_ssrc,
                             sequence_number,
                             protected_packet->reason);

            continue;
        }

        const std::span<const uint8_t> retransmit_span(retransmit_plain_packet->packet.data(), retransmit_plain_packet->packet.size());

        if (!retransmit_is_rtx)
        {
            const std::optional<media_ssrc_mapping> outbound_mapping = find_outbound_ssrc_mapping(event.source, retransmit_span);

            observe_outbound_rtp_stats(event.source, retransmit_span, outbound_mapping);

            observe_outbound_track_stats(event.source, retransmit_span, outbound_mapping);
        }
        else
        {
            WEBRTC_LOG_DEBUG("rtx retransmit outbound stats skipped stream={} subscriber={} feedback_ssrc={} cache_ssrc={} sequence={}",
                             event.source.stream_id,
                             event.source.remote_endpoint,
                             feedback_media_ssrc,
                             cache_media_ssrc,
                             sequence_number);
        }

        send_response(std::move(protected_packet->protected_packet), *target_endpoint);

        if (nack_retransmit_throttle_ != nullptr)
        {
            nack_retransmit_throttle_->remember_sent(event.source.stream_id,
                                                     event.source.session_id,
                                                     feedback_media_ssrc,
                                                     cache_media_ssrc,
                                                     requested_sequence.feedback_sequence_number,
                                                     requested_sequence.cache_sequence_number,
                                                     requested_sequence.rtx_feedback,
                                                     now_milliseconds());
        }

        sent_count += 1;
        if (retransmit_is_rtx)
        {
            rtx_sent_count += 1;
        }
        else
        {
            primary_fallback_sent_count += 1;
        }

        WEBRTC_LOG_DEBUG(
            "rtp nack retransmit send stream={} subscriber={} feedback_ssrc={} cache_ssrc={} feedback_sequence={} cache_sequence={} rtx_feedback={} "
            "mode={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            cache_media_ssrc,
            requested_sequence.feedback_sequence_number,
            requested_sequence.cache_sequence_number,
            requested_sequence.rtx_feedback ? 1 : 0,
            retransmit_is_rtx ? "rtx" : "primary");
    }

    const bool has_hard_error = failed_count != 0 || ignored_count != 0 || nack_sequences.truncated;

    const bool has_soft_event = miss_count != 0 || throttled_count != 0 || nack_sequences.duplicate_count != 0;

    if (has_hard_error)
    {
        WEBRTC_LOG_WARN(
            "rtp nack retransmit summary stream={} subscriber={} feedback_ssrc={} cache_ssrc={} primary_video={} rtx_feedback={} nack_items={} "
            "raw_requested={} requested={} cache_requested={} max={} "
            "duplicate={} truncated={} rtx_index_miss={} throttled={} hit={} miss={} sent={} rtx_sent={} primary_fallback_sent={} ignored={} "
            "failed={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            cache_media_ssrc,
            nack_mapping_is_primary_video ? 1 : 0,
            retransmit_resolution->rtx_feedback ? 1 : 0,
            event.nack_items.size(),
            nack_sequences.raw_sequence_count,
            sequence_numbers.size(),
            retransmit_resolution->sequences.size(),
            k_max_nack_retransmit_sequences,
            nack_sequences.duplicate_count,
            nack_sequences.truncated ? 1 : 0,
            retransmit_resolution->rtx_sequence_index_miss_count,
            throttled_count,
            hit_count,
            miss_count,
            sent_count,
            rtx_sent_count,
            primary_fallback_sent_count,
            ignored_count,
            failed_count);
    }

    if (has_soft_event)
    {
        WEBRTC_LOG_INFO(
            "rtp nack retransmit summary stream={} subscriber={} feedback_ssrc={} cache_ssrc={} primary_video={} rtx_feedback={} nack_items={} "
            "raw_requested={} requested={} cache_requested={} max={} "
            "duplicate={} truncated={} rtx_index_miss={} throttled={} hit={} miss={} sent={} rtx_sent={} primary_fallback_sent={} ignored={} "
            "failed={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            feedback_media_ssrc,
            cache_media_ssrc,
            nack_mapping_is_primary_video ? 1 : 0,
            retransmit_resolution->rtx_feedback ? 1 : 0,
            event.nack_items.size(),
            nack_sequences.raw_sequence_count,
            sequence_numbers.size(),
            retransmit_resolution->sequences.size(),
            k_max_nack_retransmit_sequences,
            nack_sequences.duplicate_count,
            nack_sequences.truncated ? 1 : 0,
            retransmit_resolution->rtx_sequence_index_miss_count,
            throttled_count,
            hit_count,
            miss_count,
            sent_count,
            rtx_sent_count,
            primary_fallback_sent_count,
            ignored_count,
            failed_count);
    }

    WEBRTC_LOG_DEBUG(
        "rtp nack retransmit summary stream={} subscriber={} feedback_ssrc={} cache_ssrc={} primary_video={} rtx_feedback={} nack_items={} "
        "raw_requested={} requested={} cache_requested={} max={} "
        "duplicate={} truncated={} rtx_index_miss={} throttled={} hit={} miss={} sent={} rtx_sent={} primary_fallback_sent={} ignored={} "
        "failed={}",
        event.source.stream_id,
        event.source.remote_endpoint,
        feedback_media_ssrc,
        cache_media_ssrc,
        nack_mapping_is_primary_video ? 1 : 0,
        retransmit_resolution->rtx_feedback ? 1 : 0,
        event.nack_items.size(),
        nack_sequences.raw_sequence_count,
        sequence_numbers.size(),
        retransmit_resolution->sequences.size(),
        k_max_nack_retransmit_sequences,
        nack_sequences.duplicate_count,
        nack_sequences.truncated ? 1 : 0,
        retransmit_resolution->rtx_sequence_index_miss_count,
        throttled_count,
        hit_count,
        miss_count,
        sent_count,
        rtx_sent_count,
        primary_fallback_sent_count,
        ignored_count,
        failed_count);
}

void ice_udp_server::erase_rtp_cache(std::string_view stream_id) { cleanup_stream_runtime_state(stream_id); }

void ice_udp_server::cleanup_stream_runtime_state(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    bool cache_erased = false;
    std::size_t cache_packets_before = 0;
    std::size_t cache_packets_after = 0;
    std::size_t cache_packets_erased = 0;
    std::size_t remaining_packets = 0;

    if (rtp_packet_cache_ != nullptr)
    {
        cache_packets_before = rtp_packet_cache_->size();

        rtp_packet_cache_->erase_stream(stream_id);

        cache_packets_after = rtp_packet_cache_->size();
        cache_packets_erased = cache_packets_before >= cache_packets_after ? cache_packets_before - cache_packets_after : 0;
        remaining_packets = cache_packets_after;

        cache_erased = true;
    }
    if (rtcp_report_service_ != nullptr)
    {
        rtcp_report_service_->forget_stream(stream_id);
    }

    if (rtcp_transport_cc_feedback_service_ != nullptr)
    {
        rtcp_transport_cc_feedback_service_->forget_stream(stream_id);
    }
    if (ssrc_mapper_ != nullptr)
    {
        ssrc_mapper_->forget_stream(stream_id);
    }

    if (identity_authority_ != nullptr)
    {
        identity_authority_->forget_stream(stream_id);
    }

    if (track_resolver_ != nullptr)
    {
        track_resolver_->forget_stream(stream_id);
    }
    if (rtx_sequence_allocator_ != nullptr)
    {
        rtx_sequence_allocator_->forget_stream(stream_id);
    }

    if (rtx_retransmission_index_ != nullptr)
    {
        rtx_retransmission_index_->forget_stream(stream_id);
    }

    if (nack_retransmit_throttle_ != nullptr)
    {
        nack_retransmit_throttle_->forget_stream(stream_id);
    }

    std::size_t media_router_stream_count_before = 0;
    std::size_t media_router_stream_count_after = 0;

    if (media_router_ != nullptr)
    {
        const media_router_stats_snapshot before_snapshot = media_router_->get_stats_snapshot();

        media_router_stream_count_before = before_snapshot.stream_count;

        media_router_->forget_stream(stream_id);

        const media_router_stats_snapshot after_snapshot = media_router_->get_stats_snapshot();

        media_router_stream_count_after = after_snapshot.stream_count;
    }

    std::size_t erased_payload_type_mappings = 0;
    std::size_t erased_keyframe_request_states = 0;
    {
        std::lock_guard lock(endpoint_mutex_);

        erased_payload_type_mappings = erase_payload_type_mappings_for_stream_locked(stream_id);
        erased_keyframe_request_states = erase_keyframe_request_states_for_stream_locked(stream_id);
        const std::size_t erased_extmap_rewrite_states = erase_extmap_rewrite_states_for_stream_locked(stream_id);
        (void)erased_extmap_rewrite_states;
        const std::size_t erased_selected_rid_states = erase_selected_rid_layer_states_for_stream_locked(stream_id);
        (void)erased_selected_rid_states;
        const std::size_t erased_outbound_rtp_sequences = erase_outbound_rtp_sequences_for_stream_locked(stream_id);
        (void)erased_outbound_rtp_sequences;
        const std::size_t erased_outbound_transport_cc_sequences = erase_outbound_transport_cc_sequences_for_stream_locked(stream_id);
        (void)erased_outbound_transport_cc_sequences;
        const std::size_t erased_outbound_transport_cc_packets = erase_outbound_transport_cc_packets_for_stream_locked(stream_id);
        (void)erased_outbound_transport_cc_packets;

        const std::size_t erased_outbound_transport_cc_feedback_windows = erase_outbound_transport_cc_feedback_windows_for_stream_locked(stream_id);
        (void)erased_outbound_transport_cc_feedback_windows;

        const std::size_t erased_republish_grace = erase_subscriber_downlink_republish_grace_for_stream_locked(stream_id);
        (void)erased_republish_grace;

        const std::size_t erased_subscriber_downlink_bandwidth_states = erase_subscriber_downlink_bandwidth_states_for_stream_locked(stream_id);
        (void)erased_subscriber_downlink_bandwidth_states;

        const std::size_t erased_subscriber_downlink_pacing_states = erase_subscriber_downlink_pacing_states_for_stream_locked(stream_id);
        (void)erased_subscriber_downlink_pacing_states;
        erase_orphan_subscriber_keyframe_requests_for_stream_locked(stream_id);

        for (auto iterator = fir_sequence_number_by_key_.begin(); iterator != fir_sequence_number_by_key_.end();)
        {
            if (iterator->first.starts_with(std::string(stream_id) + "|"))
            {
                iterator = fir_sequence_number_by_key_.erase(iterator);
                continue;
            }
            ++iterator;
        }

        const std::string publisher_video_ssrc_exact_key = std::string(stream_id);
        const std::string publisher_video_ssrc_prefix = publisher_video_ssrc_exact_key + "|";

        for (auto iterator = publisher_video_ssrc_by_stream_.begin(); iterator != publisher_video_ssrc_by_stream_.end();)
        {
            if (iterator->first == publisher_video_ssrc_exact_key || iterator->first.starts_with(publisher_video_ssrc_prefix))
            {
                iterator = publisher_video_ssrc_by_stream_.erase(iterator);

                continue;
            }

            ++iterator;
        }

        pending_republish_keyframe_state_by_stream_.erase(std::string(stream_id));
    }
    WEBRTC_LOG_INFO(
        "ice udp stream runtime state cleanup stream={} cache_erased={} cache_packets_before={} cache_packets_erased={} "
        "remaining_cache_packets={} media_router_streams_before={} media_router_streams_after={} payload_type_mappings_erased={} "
        "keyframe_request_states_erased={}",
        stream_id,
        cache_erased ? 1 : 0,
        cache_packets_before,
        cache_packets_erased,
        remaining_packets,
        media_router_stream_count_before,
        media_router_stream_count_after,
        erased_payload_type_mappings,
        erased_keyframe_request_states);
}
std::unordered_set<std::string> ice_udp_server::collect_republish_keyframe_eligible_subscribers(std::string_view stream_id) const
{
    std::unordered_set<std::string> subscriber_session_ids;

    if (stream_id.empty() || registry_ == nullptr)
    {
        return subscriber_session_ids;
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    for (const auto& snapshot : snapshots)
    {
        if (snapshot.kind != stream_session_kind::subscriber)
        {
            continue;
        }

        if (snapshot.stream_id != stream_id)
        {
            continue;
        }

        if (snapshot.session_id.empty())
        {
            continue;
        }

        subscriber_session_ids.insert(snapshot.session_id);
    }

    return subscriber_session_ids;
}

void ice_udp_server::mark_republish_keyframe_request_pending(std::string_view stream_id, std::string_view new_publisher_session_id)
{
    if (stream_id.empty() || new_publisher_session_id.empty())
    {
        return;
    }

    std::unordered_set<std::string> eligible_subscriber_session_ids = collect_republish_keyframe_eligible_subscribers(stream_id);

    const uint64_t current_time_milliseconds = now_milliseconds();
    const uint64_t expires_at_milliseconds = current_time_milliseconds + k_republish_keyframe_request_pending_timeout_milliseconds;

    std::size_t eligible_subscriber_count = 0;
    std::size_t erased_stale_count = 0;

    {
        std::lock_guard lock(endpoint_mutex_);

        if (eligible_subscriber_session_ids.empty())
        {
            erased_stale_count = pending_republish_keyframe_state_by_stream_.erase(std::string(stream_id));
        }
        else
        {
            republish_keyframe_request_state state;
            state.publisher_session_id = std::string(new_publisher_session_id);
            state.pending_since_milliseconds = current_time_milliseconds;
            state.expires_at_milliseconds = expires_at_milliseconds;
            state.eligible_subscriber_session_ids = std::move(eligible_subscriber_session_ids);

            eligible_subscriber_count = state.eligible_subscriber_session_ids.size();

            pending_republish_keyframe_state_by_stream_[std::string(stream_id)] = std::move(state);
        }
    }

    if (eligible_subscriber_count == 0)
    {
        WEBRTC_LOG_INFO("publisher republish keyframe request skipped stream={} publisher_session={} eligible_subscribers=0 erased_stale={}",
                        stream_id,
                        new_publisher_session_id,
                        erased_stale_count);

        return;
    }

    WEBRTC_LOG_INFO(
        "publisher republish keyframe request pending stream={} publisher_session={} eligible_subscribers={} timeout_ms={} "
        "expires_at_ms={}",
        stream_id,
        new_publisher_session_id,
        eligible_subscriber_count,
        k_republish_keyframe_request_pending_timeout_milliseconds,
        expires_at_milliseconds);
}
void ice_udp_server::forget_republish_keyframe_request_pending_for_subscriber(std::string_view stream_id, std::string_view subscriber_session_id)
{
    if (stream_id.empty() || subscriber_session_id.empty())
    {
        return;
    }

    std::string publisher_session_id;
    std::size_t removed_eligible_count = 0;
    std::size_t removed_consumed_count = 0;
    std::size_t remaining_eligible_count = 0;
    std::size_t consumed_subscriber_count = 0;
    bool pending_erased = false;

    {
        std::lock_guard lock(endpoint_mutex_);

        auto iterator = pending_republish_keyframe_state_by_stream_.find(std::string(stream_id));

        if (iterator == pending_republish_keyframe_state_by_stream_.end())
        {
            return;
        }

        republish_keyframe_request_state& state = iterator->second;

        publisher_session_id = state.publisher_session_id;

        const std::string subscriber_session_id_string(subscriber_session_id);

        removed_eligible_count = state.eligible_subscriber_session_ids.erase(subscriber_session_id_string);

        removed_consumed_count = state.consumed_subscriber_session_ids.erase(subscriber_session_id_string);

        state.last_request_milliseconds_by_subscriber_session_id.erase(subscriber_session_id_string);
        state.request_count_by_subscriber_session_id.erase(subscriber_session_id_string);

        remaining_eligible_count = state.eligible_subscriber_session_ids.size();

        consumed_subscriber_count = state.consumed_subscriber_session_ids.size();
        if (state.eligible_subscriber_session_ids.empty() ||
            state.consumed_subscriber_session_ids.size() >= state.eligible_subscriber_session_ids.size())
        {
            pending_republish_keyframe_state_by_stream_.erase(iterator);

            pending_erased = true;
        }
    }

    if (removed_eligible_count == 0 && removed_consumed_count == 0 && !pending_erased)
    {
        return;
    }

    WEBRTC_LOG_INFO(
        "publisher republish keyframe request subscriber forgotten stream={} publisher_session={} subscriber_session={} removed_eligible={} "
        "removed_consumed={} remaining_eligible={} consumed_subscribers={} pending_erased={}",
        stream_id,
        publisher_session_id,
        subscriber_session_id,
        removed_eligible_count,
        removed_consumed_count,
        remaining_eligible_count,
        consumed_subscriber_count,
        pending_erased ? 1 : 0);
}
void ice_udp_server::remember_selected_rid_keyframe_request_pending_locked(std::string_view key,
                                                                           selected_rid_layer_runtime_state& state,
                                                                           uint64_t current_time_milliseconds,
                                                                           std::string_view reason)
{
    if (key.empty())
    {
        return;
    }

    pending_selected_rid_keyframe_request_keys_.insert(std::string(key));

    selected_rid_keyframe_request_pending_state& pending_state = pending_selected_rid_keyframe_request_state_by_key_[std::string(key)];

    if (pending_state.pending_since_milliseconds != 0)
    {
        pending_state.restore_count += 1;
    }

    pending_state.pending_since_milliseconds = current_time_milliseconds;
    pending_state.expires_at_milliseconds = current_time_milliseconds + k_selected_rid_keyframe_request_pending_timeout_milliseconds;

    state.last_keyframe_request_milliseconds = current_time_milliseconds;
    state.last_keyframe_request_result = "pending";
    state.last_keyframe_request_reason = std::string(reason);
}
std::optional<std::string> ice_udp_server::runtime_selected_rid_target_for_subscriber(const media_route_result& route,
                                                                                      const media_peer_info& target_peer,
                                                                                      const media_track_resolution& track_resolution) const
{
    if (route.source.stream_id.empty() || route.source.session_id.empty() || target_peer.session_id.empty())
    {
        return std::nullopt;
    }

    if (!track_resolution.resolved || track_resolution.mid.empty() || track_resolution.kind.empty())
    {
        return std::nullopt;
    }

    if (!is_video_media_kind(track_resolution.kind))
    {
        return std::nullopt;
    }

    const std::string key = make_selected_rid_layer_key(
        route.source.stream_id, route.source.session_id, target_peer.session_id, track_resolution.mid, track_resolution.kind);

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = runtime_selected_rid_targets_by_key_.find(key);

    if (iterator == runtime_selected_rid_targets_by_key_.end())
    {
        return std::nullopt;
    }

    if (iterator->second.target_rid.empty())
    {
        return std::nullopt;
    }

    return iterator->second.target_rid;
}
void ice_udp_server::remember_runtime_selected_rid_target_locked(std::string_view key,
                                                                 selected_rid_layer_runtime_state& state,
                                                                 std::string_view target_rid,
                                                                 std::string_view policy,
                                                                 std::string_view reason,
                                                                 uint64_t current_time_milliseconds)
{
    if (key.empty() || target_rid.empty())
    {
        return;
    }

    runtime_selected_rid_target_state& target_state = runtime_selected_rid_targets_by_key_[std::string(key)];

    target_state.stream_id = state.stream_id;
    target_state.publisher_session_id = state.publisher_session_id;
    target_state.subscriber_session_id = state.subscriber_session_id;
    target_state.mid = state.mid;
    target_state.kind = state.kind;
    target_state.target_rid = std::string(target_rid);
    target_state.policy = std::string(policy);
    target_state.reason = std::string(reason);
    target_state.updated_at_milliseconds = current_time_milliseconds;
    target_state.applied_count += 1;

    state.target_rid = std::string(target_rid);
    state.target_policy = std::string(policy);
    state.manual_target_active = policy == "manual_api";

    if (policy == "manual_api")
    {
        state.last_adaptive_decision = "manual_target";
        state.last_adaptive_decision_reason = std::string(reason);
        state.last_adaptive_decision_milliseconds = current_time_milliseconds;

        return;
    }

    remember_adaptive_selected_rid_suggestion_locked(state, target_rid, policy, reason, current_time_milliseconds);
}
bool ice_udp_server::runtime_selected_rid_target_is_manual_locked(std::string_view key) const
{
    if (key.empty())
    {
        return false;
    }

    const auto iterator = runtime_selected_rid_targets_by_key_.find(std::string(key));

    if (iterator == runtime_selected_rid_targets_by_key_.end())
    {
        return false;
    }

    return iterator->second.policy == "manual_api" && !iterator->second.target_rid.empty();
}

void ice_udp_server::remember_adaptive_selected_rid_suggestion_locked(selected_rid_layer_runtime_state& state,
                                                                      std::string_view suggested_rid,
                                                                      std::string_view policy,
                                                                      std::string_view reason,
                                                                      uint64_t current_time_milliseconds)
{
    state.adaptive_suggested_rid = std::string(suggested_rid);
    state.adaptive_suggested_policy = std::string(policy);
    state.adaptive_suggested_reason = std::string(reason);
    state.adaptive_suggested_at_milliseconds = current_time_milliseconds;

    state.last_adaptive_decision = std::string(policy);
    state.last_adaptive_decision_reason = std::string(reason);
    state.last_adaptive_decision_milliseconds = current_time_milliseconds;
}
void ice_udp_server::maybe_update_adaptive_selected_rid_target_locked(std::string_view key,
                                                                      selected_rid_layer_runtime_state& state,
                                                                      const std::vector<std::string>& rid_preference,
                                                                      uint64_t current_time_milliseconds)
{
    state.adaptive_enabled = simulcast_adaptive_enabled_from_env();

    if (!state.adaptive_enabled)
    {
        return;
    }

    if (state.rid.empty() || rid_preference.size() < 2)
    {
        return;
    }

    const uint64_t check_interval_milliseconds = simulcast_adaptive_check_interval_milliseconds_from_env();

    if (state.last_adaptive_check_milliseconds != 0 &&
        current_time_milliseconds < state.last_adaptive_check_milliseconds + check_interval_milliseconds)
    {
        return;
    }

    const uint64_t cooldown_milliseconds = simulcast_adaptive_switch_cooldown_milliseconds_from_env();

    if (state.last_switch_milliseconds != 0 && current_time_milliseconds < state.last_switch_milliseconds + cooldown_milliseconds)
    {
        state.last_adaptive_check_milliseconds = current_time_milliseconds;
        state.last_adaptive_decision = "cooldown";
        state.last_adaptive_decision_reason = "switch cooldown active";
        state.last_adaptive_decision_milliseconds = current_time_milliseconds;

        return;
    }

    const std::optional<std::size_t> current_index = find_simulcast_rid_preference_index(rid_preference, state.rid);

    if (!current_index.has_value())
    {
        state.last_adaptive_check_milliseconds = current_time_milliseconds;
        state.last_adaptive_decision = "skip";
        state.last_adaptive_decision_reason = "selected rid not found in preference";
        state.last_adaptive_decision_milliseconds = current_time_milliseconds;

        return;
    }

    const uint64_t delta_primary_packets = state.primary_packet_count >= state.last_adaptive_primary_packet_count
                                               ? state.primary_packet_count - state.last_adaptive_primary_packet_count
                                               : 0;

    const uint64_t delta_nack_sequences = state.nack_sequence_count >= state.last_adaptive_nack_sequence_count
                                              ? state.nack_sequence_count - state.last_adaptive_nack_sequence_count
                                              : 0;

    state.last_adaptive_check_milliseconds = current_time_milliseconds;
    state.last_adaptive_primary_packet_count = state.primary_packet_count;
    state.last_adaptive_nack_sequence_count = state.nack_sequence_count;

    const uint64_t min_packets = simulcast_adaptive_min_packets_per_window_from_env();

    if (delta_primary_packets < min_packets)
    {
        state.last_adaptive_decision = "skip";
        state.last_adaptive_decision_reason = "insufficient packets";
        state.last_adaptive_decision_milliseconds = current_time_milliseconds;

        return;
    }

    const uint64_t downgrade_ratio_per_mille = simulcast_adaptive_downgrade_nack_ratio_per_mille_from_env();

    const bool downgrade_required = delta_nack_sequences * 1000U >= delta_primary_packets * downgrade_ratio_per_mille;

    if (downgrade_required && *current_index + 1 < rid_preference.size())
    {
        const std::string& target_rid = rid_preference[*current_index + 1];

        if (runtime_selected_rid_target_is_manual_locked(key))
        {
            remember_adaptive_selected_rid_suggestion_locked(
                state, target_rid, "adaptive_downgrade", "nack ratio exceeded threshold but manual target is active", current_time_milliseconds);

            WEBRTC_LOG_INFO(
                "simulcast adaptive downgrade suggestion suppressed by manual target stream={} publisher_session={} subscriber_session={} mid={} "
                "kind={} current_rid={} manual_target_rid={} suggested_rid={} packets={} nack_sequences={} threshold_per_mille={}",
                state.stream_id,
                state.publisher_session_id,
                state.subscriber_session_id,
                state.mid,
                state.kind,
                state.rid,
                state.target_rid,
                target_rid,
                delta_primary_packets,
                delta_nack_sequences,
                downgrade_ratio_per_mille);

            return;
        }

        remember_runtime_selected_rid_target_locked(
            key, state, target_rid, "adaptive_downgrade", "nack ratio exceeded threshold", current_time_milliseconds);

        WEBRTC_LOG_INFO(
            "simulcast adaptive downgrade target selected stream={} publisher_session={} subscriber_session={} mid={} kind={} current_rid={} "
            "target_rid={} packets={} nack_sequences={} threshold_per_mille={}",
            state.stream_id,
            state.publisher_session_id,
            state.subscriber_session_id,
            state.mid,
            state.kind,
            state.rid,
            target_rid,
            delta_primary_packets,
            delta_nack_sequences,
            downgrade_ratio_per_mille);

        return;
    }
    const uint64_t stable_window_milliseconds = simulcast_adaptive_upgrade_stable_window_milliseconds_from_env();

    const bool stable_for_upgrade = delta_nack_sequences == 0 && state.last_switch_milliseconds != 0 &&
                                    current_time_milliseconds >= state.last_switch_milliseconds + stable_window_milliseconds;

    if (stable_for_upgrade && *current_index > 0)
    {
        const std::string& target_rid = rid_preference[*current_index - 1];

        if (runtime_selected_rid_target_is_manual_locked(key))
        {
            remember_adaptive_selected_rid_suggestion_locked(
                state, target_rid, "adaptive_upgrade", "stable window without nack but manual target is active", current_time_milliseconds);

            WEBRTC_LOG_INFO(
                "simulcast adaptive upgrade suggestion suppressed by manual target stream={} publisher_session={} subscriber_session={} mid={} "
                "kind={} current_rid={} manual_target_rid={} suggested_rid={} stable_window_ms={}",
                state.stream_id,
                state.publisher_session_id,
                state.subscriber_session_id,
                state.mid,
                state.kind,
                state.rid,
                state.target_rid,
                target_rid,
                stable_window_milliseconds);

            return;
        }

        remember_runtime_selected_rid_target_locked(
            key, state, target_rid, "adaptive_upgrade", "stable window without nack", current_time_milliseconds);

        WEBRTC_LOG_INFO(
            "simulcast adaptive upgrade target selected stream={} publisher_session={} subscriber_session={} mid={} kind={} current_rid={} "
            "target_rid={} stable_window_ms={}",
            state.stream_id,
            state.publisher_session_id,
            state.subscriber_session_id,
            state.mid,
            state.kind,
            state.rid,
            target_rid,
            stable_window_milliseconds);

        return;
    }
    state.last_adaptive_decision = "keep";
    state.last_adaptive_decision_reason = "quality window healthy";
    state.last_adaptive_decision_milliseconds = current_time_milliseconds;
}

void ice_udp_server::remember_selected_rid_layer_quality_packet_locked(selected_rid_layer_runtime_state& state,
                                                                       const media_track_resolution& track_resolution,
                                                                       std::size_t packet_size,
                                                                       uint64_t current_time_milliseconds)
{
    const uint64_t current_byte_count = static_cast<uint64_t>(packet_size);

    state.packet_count += 1;
    state.byte_count += current_byte_count;
    state.last_packet_milliseconds = current_time_milliseconds;

    if (track_resolution.rtx)
    {
        state.repair_packet_count += 1;
        state.repair_byte_count += current_byte_count;
    }
    else
    {
        state.primary_packet_count += 1;
        state.primary_byte_count += current_byte_count;
    }

    if (state.bitrate_window_started_milliseconds == 0)
    {
        state.bitrate_window_started_milliseconds = current_time_milliseconds;
        state.bitrate_window_byte_count = current_byte_count;

        return;
    }

    state.bitrate_window_byte_count += current_byte_count;

    const uint64_t elapsed_milliseconds = current_time_milliseconds > state.bitrate_window_started_milliseconds
                                              ? current_time_milliseconds - state.bitrate_window_started_milliseconds
                                              : 0;

    if (elapsed_milliseconds < 1000)
    {
        return;
    }

    state.bitrate_bps = (state.bitrate_window_byte_count * 8000U) / elapsed_milliseconds;
    state.bitrate_window_started_milliseconds = current_time_milliseconds;
    state.bitrate_window_byte_count = 0;
}
void ice_udp_server::remember_selected_rid_layer_for_subscriber(const media_route_result& route,
                                                                const media_peer_info& target_peer,
                                                                const media_track_resolution& track_resolution,
                                                                const media_identity_rid_layer_binding& selected_layer,
                                                                std::string_view selection_policy,
                                                                const std::vector<std::string>& rid_preference,
                                                                std::size_t packet_size)
{
    if (route.source.stream_id.empty() || route.source.session_id.empty() || target_peer.session_id.empty())
    {
        return;
    }

    if (!track_resolution.resolved || !is_video_media_kind(track_resolution.kind))
    {
        return;
    }

    if (track_resolution.mid.empty() || track_resolution.kind.empty() || selected_layer.mid.empty() || selected_layer.kind.empty() ||
        selected_layer.rid.empty())
    {
        return;
    }

    if (!selected_layer.stream_id.empty() && selected_layer.stream_id != route.source.stream_id)
    {
        WEBRTC_LOG_WARN("simulcast selected rid ignored stream mismatch route_stream={} layer_stream={} publisher_session={} subscriber_session={}",
                        route.source.stream_id,
                        selected_layer.stream_id,
                        route.source.session_id,
                        target_peer.session_id);

        return;
    }

    if (!selected_layer.session_id.empty() && selected_layer.session_id != route.source.session_id)
    {
        WEBRTC_LOG_WARN("simulcast selected rid ignored session mismatch stream={} route_publisher_session={} layer_session={} subscriber_session={}",
                        route.source.stream_id,
                        route.source.session_id,
                        selected_layer.session_id,
                        target_peer.session_id);

        return;
    }

    if (selected_layer.mid != track_resolution.mid || selected_layer.kind != track_resolution.kind)
    {
        WEBRTC_LOG_WARN(
            "simulcast selected rid ignored media identity mismatch stream={} publisher_session={} subscriber_session={} layer_mid={} "
            "packet_mid={} layer_kind={} packet_kind={} selected_rid={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            selected_layer.mid,
            track_resolution.mid,
            selected_layer.kind,
            track_resolution.kind,
            selected_layer.rid);

        return;
    }

    if (track_resolution.rtx)
    {
        if (selected_layer.repair_ssrc != 0 && track_resolution.ssrc != selected_layer.repair_ssrc)
        {
            return;
        }

        if (selected_layer.repair_ssrc == 0 && selected_layer.primary_ssrc != 0 && track_resolution.rtx_primary_ssrc != selected_layer.primary_ssrc)
        {
            return;
        }
    }
    else if (selected_layer.primary_ssrc != 0 && track_resolution.ssrc != selected_layer.primary_ssrc)
    {
        return;
    }

    const std::string key =
        make_selected_rid_layer_key(route.source.stream_id, route.source.session_id, target_peer.session_id, selected_layer.mid, selected_layer.kind);

    std::lock_guard lock(endpoint_mutex_);

    auto iterator = selected_rid_layer_state_by_key_.find(key);

    if (iterator != selected_rid_layer_state_by_key_.end())
    {
        selected_rid_layer_runtime_state& state = iterator->second;

        if (state.kind == selected_layer.kind && state.rid == selected_layer.rid && state.primary_ssrc == selected_layer.primary_ssrc &&
            state.repair_ssrc == selected_layer.repair_ssrc)
        {
            state.selection_policy = std::string(selection_policy);
            state.rid_preference = rid_preference;

            remember_selected_rid_layer_quality_packet_locked(state, track_resolution, packet_size, now_milliseconds());
            maybe_update_adaptive_selected_rid_target_locked(key, state, rid_preference, now_milliseconds());

            return;
        }

        state.kind = selected_layer.kind;

        const std::string previous_rid = state.rid;

        state.previous_rid = previous_rid;
        state.rid = selected_layer.rid;
        state.selection_policy = std::string(selection_policy);
        state.rid_preference = rid_preference;
        state.primary_ssrc = selected_layer.primary_ssrc;
        state.repair_ssrc = selected_layer.repair_ssrc;

        state.switch_count += 1;

        state.adaptive_enabled = simulcast_adaptive_enabled_from_env();

        if (const auto target_iterator = runtime_selected_rid_targets_by_key_.find(key);
            target_iterator != runtime_selected_rid_targets_by_key_.end())
        {
            state.target_rid = target_iterator->second.target_rid;
            state.target_policy = target_iterator->second.policy;
            state.manual_target_active = target_iterator->second.policy == "manual_api" && !target_iterator->second.target_rid.empty();
        }

        state.last_switch_milliseconds = now_milliseconds();

        if (!state.target_rid.empty() && state.target_rid == selected_layer.rid)
        {
            state.last_switch_reason = "runtime target applied:" + state.target_policy;

            auto target_iterator = runtime_selected_rid_targets_by_key_.find(key);

            if (target_iterator != runtime_selected_rid_targets_by_key_.end())
            {
                target_iterator->second.applied_count += 1;
            }
        }
        else
        {
            state.last_switch_reason = "selected rid changed by preference";
        }

        state.packet_count = 0;
        state.byte_count = 0;
        state.primary_packet_count = 0;
        state.primary_byte_count = 0;
        state.repair_packet_count = 0;
        state.repair_byte_count = 0;
        state.last_packet_milliseconds = 0;
        state.bitrate_window_started_milliseconds = 0;
        state.bitrate_window_byte_count = 0;
        state.bitrate_bps = 0;
        state.nack_feedback_count = 0;
        state.nack_sequence_count = 0;
        state.last_nack_milliseconds = 0;

        remember_selected_rid_layer_quality_packet_locked(state, track_resolution, packet_size, now_milliseconds());

        state.keyframe_request_attempt_count = 0;
        state.keyframe_request_success_count = 0;
        state.keyframe_request_restore_count = 0;
        state.last_keyframe_request_milliseconds = 0;
        state.last_keyframe_request_result.clear();
        state.last_keyframe_request_reason.clear();
        maybe_update_adaptive_selected_rid_target_locked(key, state, rid_preference, now_milliseconds());

        remember_selected_rid_keyframe_request_pending_locked(key, state, now_milliseconds(), "selected rid changed");

        WEBRTC_LOG_INFO(
            "simulcast selected rid changed stream={} publisher_session={} subscriber_session={} mid={} kind={} selected_rid={} primary_ssrc={} "
            "repair_ssrc={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            selected_layer.mid,
            selected_layer.kind,
            selected_layer.rid,
            selected_layer.primary_ssrc,
            selected_layer.repair_ssrc);

        return;
    }

    selected_rid_layer_runtime_state state;

    state.stream_id = route.source.stream_id;

    state.publisher_session_id = route.source.session_id;

    state.subscriber_session_id = target_peer.session_id;

    state.mid = selected_layer.mid;

    state.kind = selected_layer.kind;

    state.rid = selected_layer.rid;

    state.selection_policy = std::string(selection_policy);
    state.rid_preference = rid_preference;

    state.primary_ssrc = selected_layer.primary_ssrc;

    state.repair_ssrc = selected_layer.repair_ssrc;

    state.adaptive_enabled = simulcast_adaptive_enabled_from_env();

    if (const auto target_iterator = runtime_selected_rid_targets_by_key_.find(key); target_iterator != runtime_selected_rid_targets_by_key_.end())
    {
        state.target_rid = target_iterator->second.target_rid;
        state.target_policy = target_iterator->second.policy;
        state.manual_target_active = target_iterator->second.policy == "manual_api" && !target_iterator->second.target_rid.empty();

        if (!state.target_rid.empty() && state.target_rid == selected_layer.rid)
        {
            state.last_switch_reason = "runtime target applied:" + state.target_policy;

            target_iterator->second.applied_count += 1;
        }
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    remember_selected_rid_layer_quality_packet_locked(state, track_resolution, packet_size, current_time_milliseconds);

    maybe_update_adaptive_selected_rid_target_locked(key, state, rid_preference, current_time_milliseconds);

    remember_selected_rid_keyframe_request_pending_locked(key, state, current_time_milliseconds, "selected rid established");

    selected_rid_layer_state_by_key_.emplace(key, std::move(state));
    WEBRTC_LOG_INFO(
        "simulcast selected rid established stream={} publisher_session={} subscriber_session={} mid={} kind={} selected_rid={} primary_ssrc={} "
        "repair_ssrc={}",
        route.source.stream_id,
        route.source.session_id,
        target_peer.session_id,
        selected_layer.mid,
        selected_layer.kind,
        selected_layer.rid,
        selected_layer.primary_ssrc,
        selected_layer.repair_ssrc);
}

bool ice_udp_server::consume_selected_rid_keyframe_request_pending_for_subscriber(const srtp_packet_process_result& packet,
                                                                                  const media_route_result& route,
                                                                                  const std::optional<media_track_resolution>& track_resolution,
                                                                                  const media_peer_info& target_peer)
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return false;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return false;
    }

    if (route.source.role != media_peer_role::publisher || target_peer.role != media_peer_role::subscriber)
    {
        return false;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved || !is_video_media_kind(track_resolution->kind))
    {
        return false;
    }

    if (track_resolution->rtx)
    {
        return false;
    }

    if (track_resolution->mid.empty() || track_resolution->kind.empty() || route.source.stream_id.empty() || route.source.session_id.empty() ||
        target_peer.session_id.empty())
    {
        return false;
    }

    if (packet.ssrc == 0 || track_resolution->ssrc == 0)
    {
        return false;
    }

    const std::string key = make_selected_rid_layer_key(
        route.source.stream_id, route.source.session_id, target_peer.session_id, track_resolution->mid, track_resolution->kind);

    std::lock_guard lock(endpoint_mutex_);

    const auto pending_iterator = pending_selected_rid_keyframe_request_keys_.find(key);

    if (pending_iterator == pending_selected_rid_keyframe_request_keys_.end())
    {
        return false;
    }

    const auto state_iterator = selected_rid_layer_state_by_key_.find(key);

    if (state_iterator == selected_rid_layer_state_by_key_.end())
    {
        pending_selected_rid_keyframe_request_keys_.erase(pending_iterator);
        pending_selected_rid_keyframe_request_state_by_key_.erase(key);

        return false;
    }

    const selected_rid_layer_runtime_state& state = state_iterator->second;

    if (state.rid.empty() || state.kind.empty())
    {
        pending_selected_rid_keyframe_request_keys_.erase(pending_iterator);
        pending_selected_rid_keyframe_request_state_by_key_.erase(key);

        return false;
    }

    if (state.kind != track_resolution->kind)
    {
        pending_selected_rid_keyframe_request_keys_.erase(pending_iterator);
        pending_selected_rid_keyframe_request_state_by_key_.erase(key);

        return false;
    }

    if (state.primary_ssrc != 0 && track_resolution->ssrc != state.primary_ssrc)
    {
        return false;
    }

    if (state.primary_ssrc != 0 && packet.ssrc != state.primary_ssrc)
    {
        return false;
    }

    pending_selected_rid_keyframe_request_keys_.erase(pending_iterator);
    pending_selected_rid_keyframe_request_state_by_key_.erase(key);

    WEBRTC_LOG_INFO(
        "simulcast selected rid keyframe request consumed stream={} publisher_session={} subscriber_session={} mid={} kind={} selected_rid={} "
        "media_ssrc={}",
        route.source.stream_id,
        route.source.session_id,
        target_peer.session_id,
        track_resolution->mid,
        track_resolution->kind,
        state.rid,
        packet.ssrc);

    return true;
}
void ice_udp_server::restore_selected_rid_keyframe_request_pending_for_subscriber(const media_route_result& route,
                                                                                  const std::optional<media_track_resolution>& track_resolution,
                                                                                  const media_peer_info& target_peer,
                                                                                  std::string_view reason)
{
    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return;
    }

    if (route.source.role != media_peer_role::publisher || target_peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved || !is_video_media_kind(track_resolution->kind))
    {
        return;
    }

    if (track_resolution->mid.empty() || track_resolution->kind.empty() || route.source.stream_id.empty() || route.source.session_id.empty() ||
        target_peer.session_id.empty())
    {
        return;
    }

    const std::string key = make_selected_rid_layer_key(
        route.source.stream_id, route.source.session_id, target_peer.session_id, track_resolution->mid, track_resolution->kind);

    std::lock_guard lock(endpoint_mutex_);

    const auto state_iterator = selected_rid_layer_state_by_key_.find(key);

    if (state_iterator == selected_rid_layer_state_by_key_.end())
    {
        return;
    }

    const selected_rid_layer_runtime_state& state = state_iterator->second;

    if (state.rid.empty() || state.kind.empty())
    {
        return;
    }

    selected_rid_layer_runtime_state& mutable_state = state_iterator->second;

    mutable_state.keyframe_request_attempt_count += 1;
    mutable_state.keyframe_request_restore_count += 1;

    remember_selected_rid_keyframe_request_pending_locked(key, mutable_state, now_milliseconds(), reason);

    mutable_state.last_keyframe_request_result = "restored";
    mutable_state.last_keyframe_request_reason = std::string(reason);

    WEBRTC_LOG_INFO(
        "simulcast selected rid keyframe request restored stream={} publisher_session={} subscriber_session={} mid={} kind={} selected_rid={} "
        "primary_ssrc={} repair_ssrc={} reason={}",
        route.source.stream_id,
        route.source.session_id,
        target_peer.session_id,
        state.mid,
        state.kind,
        state.rid,
        state.primary_ssrc,
        state.repair_ssrc,
        reason);
}
void ice_udp_server::remember_selected_rid_keyframe_request_result(const media_route_result& route,
                                                                   const std::optional<media_track_resolution>& track_resolution,
                                                                   const media_peer_info& target_peer,
                                                                   std::string_view result,
                                                                   std::string_view reason,
                                                                   bool success)
{
    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return;
    }

    if (route.source.role != media_peer_role::publisher || target_peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved || !is_video_media_kind(track_resolution->kind))
    {
        return;
    }

    if (track_resolution->mid.empty() || track_resolution->kind.empty() || route.source.stream_id.empty() || route.source.session_id.empty() ||
        target_peer.session_id.empty())
    {
        return;
    }

    const std::string key = make_selected_rid_layer_key(
        route.source.stream_id, route.source.session_id, target_peer.session_id, track_resolution->mid, track_resolution->kind);

    std::lock_guard lock(endpoint_mutex_);

    auto state_iterator = selected_rid_layer_state_by_key_.find(key);

    if (state_iterator == selected_rid_layer_state_by_key_.end())
    {
        return;
    }

    selected_rid_layer_runtime_state& state = state_iterator->second;

    if (state.rid.empty() || state.kind.empty())
    {
        return;
    }

    state.keyframe_request_attempt_count += 1;

    if (success)
    {
        state.keyframe_request_success_count += 1;
    }

    state.last_keyframe_request_milliseconds = now_milliseconds();
    state.last_keyframe_request_result = std::string(result);
    state.last_keyframe_request_reason = std::string(reason);
}

uint16_t ice_udp_server::next_outbound_transport_cc_sequence(std::string_view stream_id, std::string_view subscriber_session_id)
{
    if (stream_id.empty() || subscriber_session_id.empty())
    {
        return 0;
    }

    const std::string key = make_outbound_transport_cc_sequence_key(stream_id, subscriber_session_id);

    std::lock_guard lock(endpoint_mutex_);

    uint16_t& next_sequence_number = outbound_transport_cc_sequence_by_key_[key];

    const uint16_t sequence_number = next_sequence_number;

    next_sequence_number = static_cast<uint16_t>(next_sequence_number + 1U);

    return sequence_number;
}
ice_udp_server::outbound_rtp_rewrite_result ice_udp_server::next_outbound_rtp_rewrite(std::string_view stream_id,
                                                                                      std::string_view publisher_session_id,
                                                                                      std::string_view subscriber_session_id,
                                                                                      uint32_t subscriber_ssrc,
                                                                                      uint16_t publisher_sequence_number,
                                                                                      uint32_t publisher_timestamp)
{
    outbound_rtp_rewrite_result result;

    result.sequence_number = publisher_sequence_number;
    result.timestamp = publisher_timestamp;

    if (stream_id.empty() || publisher_session_id.empty() || subscriber_session_id.empty() || subscriber_ssrc == 0)
    {
        return result;
    }

    const std::string key = make_outbound_rtp_sequence_key(stream_id, subscriber_session_id, subscriber_ssrc);

    std::lock_guard lock(endpoint_mutex_);

    outbound_rtp_sequence_rewrite_state& state = outbound_rtp_sequence_by_key_[key];

    if (state.stream_id.empty())
    {
        state.stream_id = stream_id;
        state.publisher_session_id = publisher_session_id;
        state.subscriber_session_id = subscriber_session_id;
        state.subscriber_ssrc = subscriber_ssrc;

        state.last_publisher_sequence_number = publisher_sequence_number;
        state.last_subscriber_sequence_number = publisher_sequence_number;
        state.next_subscriber_sequence_number = static_cast<uint16_t>(publisher_sequence_number + 1U);

        state.last_publisher_timestamp = publisher_timestamp;
        state.last_subscriber_timestamp = publisher_timestamp;

        state.packet_count = 1;

        return result;
    }

    const bool publisher_switch = state.publisher_session_id != publisher_session_id;

    if (publisher_switch)
    {
        state.publisher_session_id = publisher_session_id;
        state.publisher_switch_count += 1;
    }

    const uint16_t subscriber_sequence_number = state.next_subscriber_sequence_number;

    /*
     * Timestamp must also stay continuous for the same outbound subscriber SSRC.
     *
     * When publisher switches, the new publisher RTP timestamp has a new random
     * clock base. Do not forward that random jump to the existing WHEP receiver.
     * Start the new publisher generation from the previous subscriber timestamp
     * plus one RTP tick, then keep preserving publisher deltas from there.
     *
     * This applies to every subscriber-bound RTP stream, including audio, video,
     * and publisher RTX RTP, because the key is the outbound subscriber SSRC.
     */
    uint32_t subscriber_timestamp = static_cast<uint32_t>(state.last_subscriber_timestamp + 1U);

    if (!publisher_switch)
    {
        const uint32_t publisher_timestamp_delta = static_cast<uint32_t>(publisher_timestamp - state.last_publisher_timestamp);

        subscriber_timestamp = static_cast<uint32_t>(state.last_subscriber_timestamp + publisher_timestamp_delta);
    }

    state.last_publisher_sequence_number = publisher_sequence_number;
    state.last_subscriber_sequence_number = subscriber_sequence_number;
    state.next_subscriber_sequence_number = static_cast<uint16_t>(subscriber_sequence_number + 1U);

    state.last_publisher_timestamp = publisher_timestamp;
    state.last_subscriber_timestamp = subscriber_timestamp;

    state.packet_count += 1;

    result.sequence_number = subscriber_sequence_number;
    result.timestamp = subscriber_timestamp;
    result.sequence_number_rewrite_required = subscriber_sequence_number != publisher_sequence_number;
    result.timestamp_rewrite_required = subscriber_timestamp != publisher_timestamp;
    result.publisher_switch = publisher_switch;

    return result;
}
void ice_udp_server::remember_outbound_rtp_packet(const outbound_rtp_packet_identity& identity)
{
    if (identity.stream_id.empty() || identity.publisher_session_id.empty() || identity.subscriber_session_id.empty() ||
        identity.subscriber_ssrc == 0)
    {
        return;
    }

    const std::string key = make_outbound_rtp_packet_key(
        identity.stream_id, identity.subscriber_session_id, identity.subscriber_ssrc, identity.subscriber_rtp_sequence_number);

    std::lock_guard lock(endpoint_mutex_);

    const bool inserted = !outbound_rtp_packets_by_key_.contains(key);

    outbound_rtp_packets_by_key_[key] = identity;

    if (inserted)
    {
        outbound_rtp_packet_insertion_order_.push_back(key);
    }

    while (outbound_rtp_packets_by_key_.size() > k_max_outbound_rtp_packet_identities && !outbound_rtp_packet_insertion_order_.empty())
    {
        const std::string oldest_key = std::move(outbound_rtp_packet_insertion_order_.front());

        outbound_rtp_packet_insertion_order_.pop_front();

        outbound_rtp_packets_by_key_.erase(oldest_key);
    }
}

std::optional<ice_udp_server::outbound_rtp_packet_identity> ice_udp_server::find_outbound_rtp_packet(std::string_view stream_id,
                                                                                                     std::string_view subscriber_session_id,
                                                                                                     uint32_t subscriber_ssrc,
                                                                                                     uint16_t subscriber_sequence_number) const
{
    if (stream_id.empty() || subscriber_session_id.empty() || subscriber_ssrc == 0)
    {
        return std::nullopt;
    }

    const std::string key = make_outbound_rtp_packet_key(stream_id, subscriber_session_id, subscriber_ssrc, subscriber_sequence_number);

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = outbound_rtp_packets_by_key_.find(key);

    if (iterator == outbound_rtp_packets_by_key_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}
void ice_udp_server::forget_outbound_rtp_sequences_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = outbound_rtp_sequence_by_key_.begin(); iterator != outbound_rtp_sequence_by_key_.end();)
    {
        /*
         * The key layout is:
         *
         *   stream_id|subscriber_session_id|subscriber_ssrc
         *
         * Republish removes the old publisher session, but the subscriber SRTP
         * outbound context remains alive. Therefore publisher-session cleanup
         * must not erase this state. Otherwise the next publisher packet would
         * restart from the new publisher's random RTP sequence number and libsrtp
         * would reject it as replay_old.
         *
         * Only erase this state when the subscriber session itself is removed.
         * Stream cleanup still erases all remaining stream-level states.
         */
        if (outbound_rtp_sequence_key_matches_session(iterator->first, session_id) || iterator->second.subscriber_session_id == session_id)
        {
            iterator = outbound_rtp_sequence_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
    for (auto iterator = outbound_rtp_packets_by_key_.begin(); iterator != outbound_rtp_packets_by_key_.end();)
    {
        if (outbound_rtp_sequence_key_matches_session(iterator->first, session_id) || iterator->second.subscriber_session_id == session_id)
        {
            iterator = outbound_rtp_packets_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    std::erase_if(outbound_rtp_packet_insertion_order_,
                  [session_id](const std::string& key) { return outbound_rtp_sequence_key_matches_session(key, session_id); });
}

std::size_t ice_udp_server::erase_outbound_rtp_sequences_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = outbound_rtp_sequence_by_key_.begin(); iterator != outbound_rtp_sequence_by_key_.end();)
    {
        if (outbound_rtp_sequence_key_matches_stream(iterator->first, stream_id))
        {
            iterator = outbound_rtp_sequence_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    for (auto iterator = outbound_rtp_packets_by_key_.begin(); iterator != outbound_rtp_packets_by_key_.end();)
    {
        if (outbound_rtp_sequence_key_matches_stream(iterator->first, stream_id))
        {
            iterator = outbound_rtp_packets_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    std::erase_if(outbound_rtp_packet_insertion_order_,
                  [stream_id](const std::string& key) { return outbound_rtp_sequence_key_matches_stream(key, stream_id); });

    return erased_count;
}

void ice_udp_server::remember_outbound_transport_cc_packet(const outbound_transport_cc_packet_identity& identity)
{
    if (identity.stream_id.empty() || identity.publisher_session_id.empty() || identity.subscriber_session_id.empty() ||
        identity.subscriber_mid.empty() || identity.kind.empty())
    {
        return;
    }

    const std::string key =
        make_outbound_transport_cc_packet_key(identity.stream_id, identity.subscriber_session_id, identity.subscriber_transport_cc_sequence_number);

    const std::string rtp_key = make_outbound_transport_cc_rtp_packet_key(
        identity.stream_id, identity.subscriber_session_id, identity.subscriber_ssrc, identity.subscriber_rtp_sequence_number);

    std::lock_guard lock(endpoint_mutex_);

    const auto old_iterator = outbound_transport_cc_packets_by_key_.find(key);

    if (old_iterator != outbound_transport_cc_packets_by_key_.end())
    {
        const outbound_transport_cc_packet_identity& old_identity = old_iterator->second;

        const std::string old_rtp_key = make_outbound_transport_cc_rtp_packet_key(
            old_identity.stream_id, old_identity.subscriber_session_id, old_identity.subscriber_ssrc, old_identity.subscriber_rtp_sequence_number);

        outbound_transport_cc_packet_key_by_rtp_key_.erase(old_rtp_key);
    }

    const bool inserted = old_iterator == outbound_transport_cc_packets_by_key_.end();

    outbound_transport_cc_packets_by_key_[key] = identity;
    outbound_transport_cc_packet_key_by_rtp_key_[rtp_key] = key;

    if (inserted)
    {
        outbound_transport_cc_packet_insertion_order_.push_back(key);
    }

    while (outbound_transport_cc_packets_by_key_.size() > k_max_outbound_transport_cc_packet_identities &&
           !outbound_transport_cc_packet_insertion_order_.empty())
    {
        const std::string oldest_key = std::move(outbound_transport_cc_packet_insertion_order_.front());

        outbound_transport_cc_packet_insertion_order_.pop_front();

        const auto oldest_iterator = outbound_transport_cc_packets_by_key_.find(oldest_key);

        if (oldest_iterator != outbound_transport_cc_packets_by_key_.end())
        {
            const outbound_transport_cc_packet_identity& oldest_identity = oldest_iterator->second;

            const std::string oldest_rtp_key = make_outbound_transport_cc_rtp_packet_key(oldest_identity.stream_id,
                                                                                         oldest_identity.subscriber_session_id,
                                                                                         oldest_identity.subscriber_ssrc,
                                                                                         oldest_identity.subscriber_rtp_sequence_number);

            outbound_transport_cc_packet_key_by_rtp_key_.erase(oldest_rtp_key);
        }

        outbound_transport_cc_packets_by_key_.erase(oldest_key);
    }
}
std::optional<ice_udp_server::outbound_transport_cc_packet_identity> ice_udp_server::find_outbound_transport_cc_packet_by_rtp(
    std::string_view stream_id, std::string_view subscriber_session_id, uint32_t subscriber_ssrc, uint16_t subscriber_rtp_sequence_number) const
{
    if (stream_id.empty() || subscriber_session_id.empty() || subscriber_ssrc == 0)
    {
        return std::nullopt;
    }

    const std::string rtp_key =
        make_outbound_transport_cc_rtp_packet_key(stream_id, subscriber_session_id, subscriber_ssrc, subscriber_rtp_sequence_number);

    std::lock_guard lock(endpoint_mutex_);

    const auto index_iterator = outbound_transport_cc_packet_key_by_rtp_key_.find(rtp_key);

    if (index_iterator == outbound_transport_cc_packet_key_by_rtp_key_.end())
    {
        return std::nullopt;
    }

    const auto packet_iterator = outbound_transport_cc_packets_by_key_.find(index_iterator->second);

    if (packet_iterator == outbound_transport_cc_packets_by_key_.end())
    {
        return std::nullopt;
    }

    return packet_iterator->second;
}

void ice_udp_server::mark_outbound_transport_cc_packet_locally_dropped_by_rtp(std::string_view stream_id,
                                                                              std::string_view subscriber_session_id,
                                                                              uint32_t subscriber_ssrc,
                                                                              uint16_t subscriber_rtp_sequence_number,
                                                                              std::string_view reason)
{
    std::lock_guard lock(endpoint_mutex_);

    mark_outbound_transport_cc_packet_locally_dropped_by_rtp_locked(
        stream_id, subscriber_session_id, subscriber_ssrc, subscriber_rtp_sequence_number, reason);
}

void ice_udp_server::mark_outbound_transport_cc_packet_locally_dropped_by_rtp_locked(std::string_view stream_id,
                                                                                     std::string_view subscriber_session_id,
                                                                                     uint32_t subscriber_ssrc,
                                                                                     uint16_t subscriber_rtp_sequence_number,
                                                                                     std::string_view reason)
{
    if (stream_id.empty() || subscriber_session_id.empty() || subscriber_ssrc == 0)
    {
        return;
    }

    const std::string rtp_key =
        make_outbound_transport_cc_rtp_packet_key(stream_id, subscriber_session_id, subscriber_ssrc, subscriber_rtp_sequence_number);

    const auto index_iterator = outbound_transport_cc_packet_key_by_rtp_key_.find(rtp_key);

    if (index_iterator == outbound_transport_cc_packet_key_by_rtp_key_.end())
    {
        return;
    }

    const auto packet_iterator = outbound_transport_cc_packets_by_key_.find(index_iterator->second);

    if (packet_iterator == outbound_transport_cc_packets_by_key_.end())
    {
        return;
    }

    outbound_transport_cc_packet_identity& identity = packet_iterator->second;

    identity.locally_dropped = true;
    identity.local_drop_reason = std::string(reason);
    identity.locally_dropped_at_milliseconds = now_milliseconds();
}

void ice_udp_server::mark_outbound_transport_cc_packet_locally_dropped_from_rtp_packet(const media_route_result& route,
                                                                                       const media_peer_info& target_peer,
                                                                                       std::span<const uint8_t> outbound_plain_packet,
                                                                                       const std::optional<media_ssrc_mapping>& outbound_mapping,
                                                                                       std::string_view reason)
{
    if (route.source.role != media_peer_role::publisher)
    {
        return;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return;
    }

    if (!outbound_mapping.has_value())
    {
        return;
    }

    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        return;
    }

    mark_outbound_transport_cc_packet_locally_dropped_by_rtp(
        target_peer.stream_id, target_peer.session_id, header->ssrc, header->sequence_number, reason);
}
std::optional<ice_udp_server::outbound_transport_cc_packet_identity> ice_udp_server::find_outbound_transport_cc_packet(
    std::string_view stream_id, std::string_view subscriber_session_id, uint16_t subscriber_transport_cc_sequence_number) const
{
    if (stream_id.empty() || subscriber_session_id.empty())
    {
        return std::nullopt;
    }

    const std::string key = make_outbound_transport_cc_packet_key(stream_id, subscriber_session_id, subscriber_transport_cc_sequence_number);

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = outbound_transport_cc_packets_by_key_.find(key);

    if (iterator == outbound_transport_cc_packets_by_key_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}
void ice_udp_server::remember_outbound_transport_cc_feedback_observation(std::string_view stream_id,
                                                                         std::string_view subscriber_session_id,
                                                                         const outbound_transport_cc_feedback_observation& observation)
{
    if (stream_id.empty() || subscriber_session_id.empty())
    {
        return;
    }

    const std::string key = make_outbound_transport_cc_feedback_window_key(stream_id, subscriber_session_id);

    std::lock_guard lock(endpoint_mutex_);

    auto& window = outbound_transport_cc_feedback_windows_by_key_[key];

    if (window.stream_id.empty())
    {
        window.stream_id = stream_id;
        window.subscriber_session_id = subscriber_session_id;
    }

    const uint64_t now = observation.observed_at_milliseconds != 0 ? observation.observed_at_milliseconds : now_milliseconds();

    if (window.first_feedback_at_milliseconds == 0)
    {
        window.first_feedback_at_milliseconds = now;
    }

    if (observation.feedback_packet_begin)
    {
        window.feedback_count += 1;
    }

    window.last_feedback_at_milliseconds = now;

    window.feedback_packet_status_count += 1;

    if (observation.lookup_hit)
    {
        window.lookup_hit_count += 1;
    }
    else
    {
        window.lookup_miss_count += 1;
    }

    if (observation.lookup_hit && observation.counts_for_downlink_control)
    {
        if (observation.received)
        {
            window.received_count += 1;
        }
        else
        {
            window.lost_count += 1;
        }
    }
    if (observation.has_delta)
    {
        if (observation.delta_microseconds >= -8192000 && observation.delta_microseconds <= 8192000)
        {
            add_outbound_transport_cc_feedback_delta(window, observation.delta_microseconds);

            if (observation.small_delta)
            {
                window.small_delta_count += 1;
            }
            else if (observation.large_delta)
            {
                window.large_delta_count += 1;
            }
        }
    }
    window.observations.push_back(observation);

    while (window.observations.size() > k_max_outbound_transport_cc_feedback_observations_per_window)
    {
        const outbound_transport_cc_feedback_observation oldest = window.observations.front();

        window.observations.pop_front();

        if (oldest.lookup_hit && window.lookup_hit_count != 0)
        {
            window.lookup_hit_count -= 1;
        }
        else if (!oldest.lookup_hit && window.lookup_miss_count != 0)
        {
            window.lookup_miss_count -= 1;
        }

        if (oldest.lookup_hit && oldest.counts_for_downlink_control)
        {
            if (oldest.received && window.received_count != 0)
            {
                window.received_count -= 1;
            }
            else if (!oldest.received && window.lost_count != 0)
            {
                window.lost_count -= 1;
            }
        }
        if (oldest.has_delta)
        {
            if (oldest.delta_microseconds >= -8192000 && oldest.delta_microseconds <= 8192000)
            {
                subtract_outbound_transport_cc_feedback_delta(window, oldest.delta_microseconds);

                if (oldest.small_delta && window.small_delta_count != 0)
                {
                    window.small_delta_count -= 1;
                }
                else if (oldest.large_delta && window.large_delta_count != 0)
                {
                    window.large_delta_count -= 1;
                }
            }
        }
        if (window.feedback_packet_status_count != 0)
        {
            window.feedback_packet_status_count -= 1;
        }
    }

    remember_subscriber_downlink_bandwidth_feedback_window_locked(stream_id, subscriber_session_id, window, now);
}

void ice_udp_server::forget_outbound_transport_cc_feedback_windows_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = outbound_transport_cc_feedback_windows_by_key_.begin(); iterator != outbound_transport_cc_feedback_windows_by_key_.end();)
    {
        if (outbound_transport_cc_feedback_window_key_matches_session(iterator->first, session_id))
        {
            iterator = outbound_transport_cc_feedback_windows_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

std::size_t ice_udp_server::erase_outbound_transport_cc_feedback_windows_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = outbound_transport_cc_feedback_windows_by_key_.begin(); iterator != outbound_transport_cc_feedback_windows_by_key_.end();)
    {
        if (outbound_transport_cc_feedback_window_key_matches_stream(iterator->first, stream_id))
        {
            iterator = outbound_transport_cc_feedback_windows_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}

std::size_t ice_udp_server::outbound_transport_cc_feedback_window_observation_count_locked() const
{
    std::size_t count = 0;

    for (const auto& [key, window] : outbound_transport_cc_feedback_windows_by_key_)
    {
        (void)key;

        count += window.observations.size();
    }

    return count;
}
void ice_udp_server::remember_subscriber_downlink_bandwidth_feedback_window_locked(std::string_view stream_id,
                                                                                   std::string_view subscriber_session_id,
                                                                                   outbound_transport_cc_feedback_window_state& window,
                                                                                   uint64_t current_time_milliseconds)
{
    if (stream_id.empty() || subscriber_session_id.empty())
    {
        return;
    }

    const std::string key = make_subscriber_downlink_bandwidth_state_key(stream_id, subscriber_session_id);

    auto& state = subscriber_downlink_bandwidth_by_key_[key];

    if (state.stream_id.empty())
    {
        const auto& downlink_config = ice_udp_server_runtime_config_instance().subscriber_downlink_control;

        state.stream_id = stream_id;
        state.subscriber_session_id = subscriber_session_id;
        state.created_at_milliseconds = current_time_milliseconds;
        state.updated_at_milliseconds = current_time_milliseconds;
        state.last_feedback_at_milliseconds = current_time_milliseconds;
        state.last_transition_at_milliseconds = current_time_milliseconds;
        state.state_entered_at_milliseconds = current_time_milliseconds;
        state.hold_down_until_milliseconds = 0;
        state.healthy_window_count = 0;
        state.bad_window_count = 0;
        state.unreliable_window_count = 0;
        state.last_transition_reason = "created";

        state.target_bitrate_bps = downlink_config.initial_target_bitrate_bps;
        state.min_bitrate_bps = downlink_config.min_bitrate_bps;
        state.max_bitrate_bps = downlink_config.max_bitrate_bps;
    }
    const uint64_t observation_count = static_cast<uint64_t>(window.observations.size());
    const uint64_t lookup_feedback_count = window.lookup_hit_count + window.lookup_miss_count;
    const uint64_t packet_status_count = window.received_count + window.lost_count;

    const uint64_t lookup_hit_rate_ppm = make_rate_ppm(window.lookup_hit_count, lookup_feedback_count);
    const uint64_t loss_rate_ppm = make_rate_ppm(window.lost_count, packet_status_count);

    bool republish_grace_active = false;

    const std::string republish_grace_key = make_subscriber_downlink_republish_grace_key(state.stream_id, state.subscriber_session_id);

    auto republish_grace_iterator = subscriber_downlink_republish_grace_until_by_key_.find(republish_grace_key);

    if (republish_grace_iterator != subscriber_downlink_republish_grace_until_by_key_.end())
    {
        if (now_milliseconds() <= republish_grace_iterator->second)
        {
            republish_grace_active = true;
        }
        else
        {
            subscriber_downlink_republish_grace_until_by_key_.erase(republish_grace_iterator);
        }
    }

    if (republish_grace_active)
    {
        reset_outbound_transport_cc_feedback_window_runtime(window, current_time_milliseconds);

        state.updated_at_milliseconds = current_time_milliseconds;
        state.last_feedback_at_milliseconds = current_time_milliseconds;
        state.feedback_count = 0;

        state.control_state = subscriber_downlink_control_state::probing;
        state.state_entered_at_milliseconds = current_time_milliseconds;

        state.hold_down_until_milliseconds = 0;
        state.healthy_window_count = 0;
        state.bad_window_count = 0;
        state.unreliable_window_count = 0;
        state.keyframe_recovery_until_milliseconds = 0;
        state.keyframe_recovery_remaining_packet_count = 0;
        state.last_keyframe_request_at_milliseconds = 0;
        state.target_bitrate_bps = clamp_subscriber_downlink_republish_grace_bitrate(
            k_subscriber_downlink_republish_grace_target_bitrate_bps, state.min_bitrate_bps, state.max_bitrate_bps);

        state.window_observation_count = 0;
        state.window_packet_status_count = 0;
        state.lookup_hit_rate_ppm = 1000000;
        state.loss_rate_ppm = 0;
        state.received_count = 0;
        state.lost_count = 0;
        state.avg_delta_microseconds = 0;
        state.min_delta_microseconds = 0;
        state.max_delta_microseconds = 0;
        state.last_transition_reason = "publisher republish grace";

        return;
    }

    const auto& downlink_config = ice_udp_server_runtime_config_instance().subscriber_downlink_control;

    const bool has_enough_samples = observation_count >= downlink_config.probe_observation_count;
    const bool has_reliable_lookup = lookup_hit_rate_ppm >= downlink_config.min_reliable_lookup_hit_rate_ppm;

    const bool healthy_window = has_enough_samples && has_reliable_lookup && loss_rate_ppm <= downlink_config.healthy_loss_rate_ppm;

    const bool bad_window = has_enough_samples && has_reliable_lookup && loss_rate_ppm >= downlink_config.constrained_loss_rate_ppm;

    const bool unreliable_window = !has_enough_samples || !has_reliable_lookup;

    const uint64_t next_healthy_window_count = healthy_window ? state.healthy_window_count + 1 : 0;
    const uint64_t next_bad_window_count = bad_window ? state.bad_window_count + 1 : 0;
    const uint64_t next_unreliable_window_count = unreliable_window ? state.unreliable_window_count + 1 : 0;

    const subscriber_downlink_control_state next_state = select_subscriber_downlink_control_state(state,
                                                                                                  downlink_config,
                                                                                                  current_time_milliseconds,
                                                                                                  observation_count,
                                                                                                  lookup_hit_rate_ppm,
                                                                                                  loss_rate_ppm,
                                                                                                  next_healthy_window_count,
                                                                                                  next_bad_window_count);

    if (state.control_state != next_state)
    {
        state.control_state = next_state;
        state.transition_count += 1;
        state.last_transition_at_milliseconds = current_time_milliseconds;
        state.state_entered_at_milliseconds = current_time_milliseconds;

        if (next_state == subscriber_downlink_control_state::hold_down)
        {
            state.hold_down_until_milliseconds = current_time_milliseconds + downlink_config.hold_down_duration_milliseconds;
        }
        else
        {
            state.hold_down_until_milliseconds = 0;
        }

        state.last_transition_reason = make_subscriber_downlink_transition_reason(next_state,
                                                                                  observation_count,
                                                                                  lookup_hit_rate_ppm,
                                                                                  loss_rate_ppm,
                                                                                  next_healthy_window_count,
                                                                                  next_bad_window_count,
                                                                                  next_unreliable_window_count);
    }

    state.healthy_window_count = next_healthy_window_count;
    state.bad_window_count = next_bad_window_count;
    state.unreliable_window_count = next_unreliable_window_count;

    state.updated_at_milliseconds = current_time_milliseconds;
    state.last_feedback_at_milliseconds =
        window.last_feedback_at_milliseconds != 0 ? window.last_feedback_at_milliseconds : current_time_milliseconds;

    if (!unreliable_window)
    {
        state.target_bitrate_bps = estimate_subscriber_downlink_target_bitrate_bps(state, downlink_config, next_state, loss_rate_ppm);
    }

    state.feedback_count = window.feedback_count;
    state.window_observation_count = observation_count;
    state.window_packet_status_count = window.feedback_packet_status_count;

    state.lookup_hit_rate_ppm = lookup_hit_rate_ppm;
    state.loss_rate_ppm = loss_rate_ppm;

    state.received_count = window.received_count;
    state.lost_count = window.lost_count;

    state.avg_delta_microseconds = make_average_delta_microseconds(window);
    state.min_delta_microseconds = window.min_delta_microseconds;
    state.max_delta_microseconds = window.max_delta_microseconds;
}

bool ice_udp_server::subscriber_downlink_bitrate_gate_allows_packet(const media_route_result& route,
                                                                    const media_peer_info& target_peer,
                                                                    const std::optional<media_track_resolution>& track_resolution,
                                                                    const srtp_packet_process_result& packet,
                                                                    std::span<const uint8_t> outbound_plain_packet,
                                                                    const std::optional<media_ssrc_mapping>& outbound_mapping)
{
    const auto& downlink_config = ice_udp_server_runtime_config_instance().subscriber_downlink_control;

    if (downlink_config.mode == subscriber_downlink_control_mode::disabled)
    {
        return true;
    }

    if (packet.kind != srtp_packet_kind::rtp)
    {
        return true;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return true;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return true;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return true;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved)
    {
        return true;
    }

    if (!outbound_mapping.has_value())
    {
        return true;
    }

    if (outbound_mapping->kind != "video")
    {
        return true;
    }

    if (outbound_mapping->rtx)
    {
        return true;
    }

    if (outbound_plain_packet.empty())
    {
        return true;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    const std::string key = make_subscriber_downlink_bandwidth_state_key(target_peer.stream_id, target_peer.session_id);

    auto iterator = subscriber_downlink_bandwidth_by_key_.find(key);

    if (iterator == subscriber_downlink_bandwidth_by_key_.end())
    {
        return true;
    }

    subscriber_downlink_bandwidth_state& state = iterator->second;

    if (!subscriber_downlink_state_enables_bitrate_gate(state.control_state))
    {
        return true;
    }

    refill_subscriber_downlink_bitrate_gate_budget(state, current_time_milliseconds);

    const uint64_t packet_size = static_cast<uint64_t>(outbound_plain_packet.size());

    const bool packet_is_keyframe = subscriber_downlink_packet_is_keyframe(route, track_resolution, packet, outbound_plain_packet);

    if (packet_is_keyframe)
    {
        state.keyframe_recovery_until_milliseconds = current_time_milliseconds + downlink_config.keyframe_recovery_bypass_duration_milliseconds;
        state.keyframe_recovery_remaining_packet_count = downlink_config.keyframe_recovery_bypass_packet_count;

        state.bitrate_gate_observed_allowed_packet_count += 1;
        state.bitrate_gate_observed_allowed_byte_count += packet_size;

        if (downlink_config.mode == subscriber_downlink_control_mode::enabled)
        {
            state.bitrate_gate_allowed_packet_count += 1;
            state.bitrate_gate_allowed_byte_count += packet_size;
            state.bitrate_gate_keyframe_bypass_packet_count += 1;
            state.bitrate_gate_keyframe_bypass_byte_count += packet_size;
        }

        WEBRTC_LOG_DEBUG(
            "subscriber downlink bitrate gate keyframe bypass stream={} subscriber_session={} target_bitrate_bps={} control_state={} "
            "packet_size={} recovery_until={} recovery_remaining_packets={}",
            target_peer.stream_id,
            target_peer.session_id,
            state.target_bitrate_bps,
            subscriber_downlink_control_state_to_string(state.control_state),
            packet_size,
            state.keyframe_recovery_until_milliseconds,
            state.keyframe_recovery_remaining_packet_count);

        return true;
    }

    const bool recovery_bypass_active = state.keyframe_recovery_until_milliseconds != 0 &&
                                        current_time_milliseconds <= state.keyframe_recovery_until_milliseconds &&
                                        state.keyframe_recovery_remaining_packet_count > 0;

    if (recovery_bypass_active)
    {
        state.keyframe_recovery_remaining_packet_count -= 1;

        state.bitrate_gate_observed_allowed_packet_count += 1;
        state.bitrate_gate_observed_allowed_byte_count += packet_size;

        if (downlink_config.mode == subscriber_downlink_control_mode::enabled)
        {
            state.bitrate_gate_allowed_packet_count += 1;
            state.bitrate_gate_allowed_byte_count += packet_size;
            state.bitrate_gate_recovery_bypass_packet_count += 1;
            state.bitrate_gate_recovery_bypass_byte_count += packet_size;
        }

        return true;
    }

    if (state.bitrate_gate_budget_bytes >= packet_size)
    {
        state.bitrate_gate_budget_bytes -= packet_size;

        state.bitrate_gate_observed_allowed_packet_count += 1;
        state.bitrate_gate_observed_allowed_byte_count += packet_size;

        if (downlink_config.mode == subscriber_downlink_control_mode::enabled)
        {
            state.bitrate_gate_allowed_packet_count += 1;
            state.bitrate_gate_allowed_byte_count += packet_size;
        }

        return true;
    }

    state.bitrate_gate_observed_dropped_packet_count += 1;
    state.bitrate_gate_observed_dropped_byte_count += packet_size;
    if (downlink_config.mode == subscriber_downlink_control_mode::observe_only)
    {
        WEBRTC_LOG_DEBUG(
            "subscriber downlink bitrate gate observe only would drop stream={} subscriber_session={} target_bitrate_bps={} "
            "control_state={} budget_bytes={} packet_size={} observed_dropped_packets={} observed_dropped_bytes={} loss_rate_ppm={} "
            "lookup_hit_rate_ppm={}",
            target_peer.stream_id,
            target_peer.session_id,
            state.target_bitrate_bps,
            subscriber_downlink_control_state_to_string(state.control_state),
            state.bitrate_gate_budget_bytes,
            packet_size,
            state.bitrate_gate_observed_dropped_packet_count,
            state.bitrate_gate_observed_dropped_byte_count,
            state.loss_rate_ppm,
            state.lookup_hit_rate_ppm);

        return true;
    }

    state.bitrate_gate_dropped_packet_count += 1;
    state.bitrate_gate_dropped_byte_count += packet_size;

    WEBRTC_LOG_DEBUG(
        "subscriber downlink bitrate gate drop stream={} subscriber_session={} target_bitrate_bps={} control_state={} budget_bytes={} "
        "packet_size={} dropped_packets={} dropped_bytes={} loss_rate_ppm={} lookup_hit_rate_ppm={}",
        target_peer.stream_id,
        target_peer.session_id,
        state.target_bitrate_bps,
        subscriber_downlink_control_state_to_string(state.control_state),
        state.bitrate_gate_budget_bytes,
        packet_size,
        state.bitrate_gate_dropped_packet_count,
        state.bitrate_gate_dropped_byte_count,
        state.loss_rate_ppm,
        state.lookup_hit_rate_ppm);

    return false;
}

bool ice_udp_server::subscriber_downlink_pacing_should_enqueue_packet(const media_route_result& route,
                                                                      const media_peer_info& target_peer,
                                                                      const srtp_packet_process_result& packet,
                                                                      const std::optional<media_ssrc_mapping>& outbound_mapping,
                                                                      uint64_t protected_packet_size)
{
    const auto& downlink_config = ice_udp_server_runtime_config_instance().subscriber_downlink_control;

    if (downlink_config.mode == subscriber_downlink_control_mode::disabled)
    {
        return false;
    }

    if (packet.kind != srtp_packet_kind::rtp)
    {
        return false;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return false;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return false;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return false;
    }

    if (!outbound_mapping.has_value())
    {
        return false;
    }

    if (outbound_mapping->kind != "video")
    {
        return false;
    }

    if (outbound_mapping->rtx)
    {
        return false;
    }

    const std::string key = make_subscriber_downlink_bandwidth_state_key(target_peer.stream_id, target_peer.session_id);
    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = subscriber_downlink_bandwidth_by_key_.find(key);

    if (iterator == subscriber_downlink_bandwidth_by_key_.end())
    {
        return false;
    }

    const subscriber_downlink_bandwidth_state& bandwidth_state = iterator->second;

    if (!subscriber_downlink_state_enables_bitrate_gate(bandwidth_state.control_state))
    {
        return false;
    }

    if (downlink_config.mode == subscriber_downlink_control_mode::observe_only)
    {
        auto& pacing_state = subscriber_downlink_pacing_by_key_[key];

        if (pacing_state.stream_id.empty())
        {
            pacing_state.stream_id = target_peer.stream_id;
            pacing_state.subscriber_session_id = target_peer.session_id;
            pacing_state.pacing_last_update_milliseconds = current_time_milliseconds;
        }

        pacing_state.observed_enqueued_packet_count += 1;
        pacing_state.observed_enqueued_byte_count += protected_packet_size;

        return false;
    }

    if (subscriber_downlink_keyframe_recovery_window_active(bandwidth_state, current_time_milliseconds))
    {
        WEBRTC_LOG_DEBUG(
            "subscriber downlink pacing recovery bypass stream={} subscriber_session={} control_state={} target_bitrate_bps={} "
            "protected_packet_size={} recovery_until={} recovery_remaining_packets={}",
            target_peer.stream_id,
            target_peer.session_id,
            subscriber_downlink_control_state_to_string(bandwidth_state.control_state),
            bandwidth_state.target_bitrate_bps,
            protected_packet_size,
            bandwidth_state.keyframe_recovery_until_milliseconds,
            bandwidth_state.keyframe_recovery_remaining_packet_count);

        return false;
    }

    return downlink_config.mode == subscriber_downlink_control_mode::enabled;
}

void ice_udp_server::enqueue_subscriber_downlink_paced_packet(const media_route_result& route,
                                                              const media_peer_info& target_peer,
                                                              std::string_view remote_address,
                                                              const boost::asio::ip::udp::endpoint& remote_endpoint,
                                                              std::vector<uint8_t> protected_packet,
                                                              std::optional<outbound_transport_cc_packet_identity> transport_cc_identity)
{
    const auto& downlink_config = ice_udp_server_runtime_config_instance().subscriber_downlink_control;

    const std::size_t max_pacing_queue_packets_per_subscriber = downlink_config.max_pacing_queue_packets_per_subscriber;
    const uint64_t max_pacing_queue_bytes_per_subscriber = downlink_config.max_pacing_queue_bytes_per_subscriber;

    if (protected_packet.empty())
    {
        return;
    }

    const uint64_t packet_size = static_cast<uint64_t>(protected_packet.size());
    const uint64_t now = now_milliseconds();

    const std::string key = make_subscriber_downlink_bandwidth_state_key(target_peer.stream_id, target_peer.session_id);

    bool should_schedule = false;

    {
        std::lock_guard lock(endpoint_mutex_);

        auto& pacing_state = subscriber_downlink_pacing_by_key_[key];

        if (pacing_state.stream_id.empty())
        {
            pacing_state.stream_id = target_peer.stream_id;
            pacing_state.subscriber_session_id = target_peer.session_id;
            pacing_state.pacing_last_update_milliseconds = now;
        }

        if (packet_size > max_pacing_queue_bytes_per_subscriber)
        {
            pacing_state.dropped_packet_count += 1;
            pacing_state.dropped_byte_count += packet_size;

            rtp_rtcp_drop_media_forward_pacing_queue_total_.fetch_add(1, std::memory_order_relaxed);

            WEBRTC_LOG_WARN("subscriber downlink pacing packet too large stream={} subscriber_session={} target={} packet_size={} max_bytes={}",
                            route.source.stream_id,
                            target_peer.session_id,
                            remote_address,
                            packet_size,
                            max_pacing_queue_bytes_per_subscriber);

            return;
        }

        while (!pacing_state.queue.empty() && (pacing_state.queue.size() >= max_pacing_queue_packets_per_subscriber ||
                                               pacing_state.queue_byte_count + packet_size > max_pacing_queue_bytes_per_subscriber))
        {
            subscriber_downlink_pacing_packet dropped_packet = std::move(pacing_state.queue.front());

            pacing_state.queue.pop_front();

            pacing_state.queue_byte_count =
                pacing_state.queue_byte_count >= dropped_packet.protected_size ? pacing_state.queue_byte_count - dropped_packet.protected_size : 0;

            pacing_state.dropped_packet_count += 1;
            pacing_state.dropped_byte_count += dropped_packet.protected_size;

            if (dropped_packet.transport_cc_identity.has_value())
            {
                const outbound_transport_cc_packet_identity& identity = *dropped_packet.transport_cc_identity;

                mark_outbound_transport_cc_packet_locally_dropped_by_rtp_locked(identity.stream_id,
                                                                                identity.subscriber_session_id,
                                                                                identity.subscriber_ssrc,
                                                                                identity.subscriber_rtp_sequence_number,
                                                                                "pacing_queue");
            }
            rtp_rtcp_drop_media_forward_pacing_queue_total_.fetch_add(1, std::memory_order_relaxed);
        }

        subscriber_downlink_pacing_packet packet_to_queue;

        packet_to_queue.stream_id = target_peer.stream_id;
        packet_to_queue.subscriber_session_id = target_peer.session_id;
        packet_to_queue.remote_address = std::string(remote_address);
        packet_to_queue.remote_endpoint = remote_endpoint;
        packet_to_queue.protected_size = packet_size;
        packet_to_queue.enqueued_at_milliseconds = now;
        packet_to_queue.transport_cc_identity = std::move(transport_cc_identity);
        packet_to_queue.protected_packet = std::move(protected_packet);

        pacing_state.queue_byte_count += packet_size;

        pacing_state.observed_enqueued_packet_count += 1;
        pacing_state.observed_enqueued_byte_count += packet_size;

        pacing_state.enqueued_packet_count += 1;
        pacing_state.enqueued_byte_count += packet_size;

        pacing_state.queue.push_back(std::move(packet_to_queue));

        should_schedule = !subscriber_downlink_pacing_timer_scheduled_;
    }

    if (should_schedule)
    {
        schedule_subscriber_downlink_pacing_timer();
    }
}

std::vector<ice_udp_server::subscriber_downlink_pacing_packet> ice_udp_server::pop_subscriber_downlink_pacing_packets()
{
    const auto& downlink_config = ice_udp_server_runtime_config_instance().subscriber_downlink_control;

    const uint64_t max_pacing_packet_age_milliseconds = downlink_config.max_pacing_packet_age_milliseconds;
    const std::size_t max_pacing_packets_per_tick = downlink_config.max_pacing_packets_per_tick;
    const std::size_t max_pacing_packets_per_subscriber_per_tick = downlink_config.max_pacing_packets_per_subscriber_per_tick;

    std::vector<subscriber_downlink_pacing_packet> packets;

    packets.reserve(max_pacing_packets_per_tick);

    const uint64_t now = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    std::vector<std::string> pacing_keys;

    pacing_keys.reserve(subscriber_downlink_pacing_by_key_.size());

    for (const auto& [key, pacing_state] : subscriber_downlink_pacing_by_key_)
    {
        if (!pacing_state.queue.empty())
        {
            pacing_keys.push_back(key);
        }
    }

    if (pacing_keys.empty())
    {
        subscriber_downlink_pacing_round_robin_after_key.clear();

        return packets;
    }

    std::sort(pacing_keys.begin(), pacing_keys.end());

    std::size_t start_index = 0;

    if (!subscriber_downlink_pacing_round_robin_after_key.empty())
    {
        const auto iterator = std::upper_bound(pacing_keys.begin(), pacing_keys.end(), subscriber_downlink_pacing_round_robin_after_key);

        if (iterator != pacing_keys.end())
        {
            start_index = static_cast<std::size_t>(std::distance(pacing_keys.begin(), iterator));
        }
    }

    std::string last_served_key;

    for (std::size_t offset = 0; offset < pacing_keys.size() && packets.size() < max_pacing_packets_per_tick; ++offset)
    {
        const std::string& key = pacing_keys[(start_index + offset) % pacing_keys.size()];

        auto pacing_iterator = subscriber_downlink_pacing_by_key_.find(key);

        if (pacing_iterator == subscriber_downlink_pacing_by_key_.end())
        {
            continue;
        }

        subscriber_downlink_pacing_state& pacing_state = pacing_iterator->second;

        const auto bandwidth_iterator = subscriber_downlink_bandwidth_by_key_.find(key);

        const subscriber_downlink_bandwidth_state* bandwidth_state =
            bandwidth_iterator == subscriber_downlink_bandwidth_by_key_.end() ? nullptr : &bandwidth_iterator->second;

        refill_subscriber_downlink_pacing_budget(pacing_state, bandwidth_state, now);

        std::size_t sent_for_subscriber = 0;

        while (!pacing_state.queue.empty() && packets.size() < max_pacing_packets_per_tick)
        {
            subscriber_downlink_pacing_packet& front_packet = pacing_state.queue.front();

            if (front_packet.enqueued_at_milliseconds != 0 && now > front_packet.enqueued_at_milliseconds + max_pacing_packet_age_milliseconds)
            {
                subscriber_downlink_pacing_packet dropped_packet = std::move(front_packet);

                const uint64_t dropped_size = dropped_packet.protected_size;

                pacing_state.queue.pop_front();

                pacing_state.queue_byte_count = pacing_state.queue_byte_count >= dropped_size ? pacing_state.queue_byte_count - dropped_size : 0;

                pacing_state.dropped_packet_count += 1;
                pacing_state.dropped_byte_count += dropped_size;

                if (dropped_packet.transport_cc_identity.has_value())
                {
                    const outbound_transport_cc_packet_identity& identity = *dropped_packet.transport_cc_identity;

                    mark_outbound_transport_cc_packet_locally_dropped_by_rtp_locked(identity.stream_id,
                                                                                    identity.subscriber_session_id,
                                                                                    identity.subscriber_ssrc,
                                                                                    identity.subscriber_rtp_sequence_number,
                                                                                    "pacing_expired");
                }
                rtp_rtcp_drop_media_forward_pacing_queue_total_.fetch_add(1, std::memory_order_relaxed);

                continue;
            }
            if (sent_for_subscriber >= max_pacing_packets_per_subscriber_per_tick)
            {
                break;
            }

            if (front_packet.protected_size > pacing_state.pacing_budget_bytes)
            {
                break;
            }

            pacing_state.pacing_budget_bytes -= front_packet.protected_size;

            pacing_state.sent_packet_count += 1;
            pacing_state.sent_byte_count += front_packet.protected_size;

            packets.push_back(std::move(front_packet));

            pacing_state.queue.pop_front();

            const uint64_t sent_size = packets.back().protected_size;

            pacing_state.queue_byte_count = pacing_state.queue_byte_count >= sent_size ? pacing_state.queue_byte_count - sent_size : 0;

            sent_for_subscriber += 1;
            last_served_key = key;
        }
    }

    if (!last_served_key.empty())
    {
        subscriber_downlink_pacing_round_robin_after_key = last_served_key;
    }

    return packets;
}

void ice_udp_server::schedule_subscriber_downlink_pacing_timer()
{
    {
        std::lock_guard lock(endpoint_mutex_);

        if (subscriber_downlink_pacing_timer_scheduled_)
        {
            return;
        }

        subscriber_downlink_pacing_timer_scheduled_ = true;
    }

    auto self = shared_from_this();

    subscriber_downlink_pacing_timer_.expires_after(std::chrono::milliseconds(
        static_cast<int64_t>(ice_udp_server_runtime_config_instance().subscriber_downlink_control.pacing_timer_interval_milliseconds)));

    subscriber_downlink_pacing_timer_.async_wait(
        [self](const boost::system::error_code& error)
        {
            if (error)
            {
                std::lock_guard lock(self->endpoint_mutex_);

                self->subscriber_downlink_pacing_timer_scheduled_ = false;

                return;
            }

            self->handle_subscriber_downlink_pacing_timer();
        });
}

void ice_udp_server::handle_subscriber_downlink_pacing_timer()
{
    {
        std::lock_guard lock(endpoint_mutex_);

        subscriber_downlink_pacing_timer_scheduled_ = false;
    }

    std::vector<subscriber_downlink_pacing_packet> packets = pop_subscriber_downlink_pacing_packets();

    for (auto& packet : packets)
    {
        WEBRTC_LOG_DEBUG("subscriber downlink pacing send stream={} subscriber_session={} target={} protected_size={}",
                         packet.stream_id,
                         packet.subscriber_session_id,
                         packet.remote_address,
                         packet.protected_packet.size());

        send_response(std::move(packet.protected_packet), packet.remote_endpoint);
    }

    bool has_pending_packets = false;

    {
        std::lock_guard lock(endpoint_mutex_);

        for (const auto& [key, pacing_state] : subscriber_downlink_pacing_by_key_)
        {
            (void)key;

            if (!pacing_state.queue.empty())
            {
                has_pending_packets = true;

                break;
            }
        }
    }

    if (has_pending_packets)
    {
        schedule_subscriber_downlink_pacing_timer();
    }
}

void ice_udp_server::forget_subscriber_downlink_bandwidth_states_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = subscriber_downlink_bandwidth_by_key_.begin(); iterator != subscriber_downlink_bandwidth_by_key_.end();)
    {
        if (subscriber_downlink_bandwidth_state_key_matches_session(iterator->first, session_id))
        {
            iterator = subscriber_downlink_bandwidth_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

std::size_t ice_udp_server::erase_subscriber_downlink_bandwidth_states_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = subscriber_downlink_bandwidth_by_key_.begin(); iterator != subscriber_downlink_bandwidth_by_key_.end();)
    {
        if (subscriber_downlink_bandwidth_state_key_matches_stream(iterator->first, stream_id))
        {
            iterator = subscriber_downlink_bandwidth_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}

std::size_t ice_udp_server::subscriber_downlink_bandwidth_state_count_locked() const { return subscriber_downlink_bandwidth_by_key_.size(); }

void ice_udp_server::forget_subscriber_downlink_pacing_states_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    erase_orphan_subscriber_keyframe_requests_for_session_locked(session_id);
    const std::size_t erased_count = erase_subscriber_downlink_pacing_states_for_session_locked(session_id);
    if (erased_count > 0)
    {
        WEBRTC_LOG_DEBUG("subscriber downlink pacing states forgotten session={} count={}", session_id, erased_count);
    }
}
std::size_t ice_udp_server::erase_subscriber_downlink_pacing_states_for_session_locked(std::string_view session_id)
{
    if (session_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = subscriber_downlink_pacing_by_key_.begin(); iterator != subscriber_downlink_pacing_by_key_.end();)
    {
        if (subscriber_downlink_pacing_state_key_matches_session(iterator->first, session_id))
        {
            if (iterator->first == subscriber_downlink_pacing_round_robin_after_key)
            {
                subscriber_downlink_pacing_round_robin_after_key.clear();
            }

            iterator = subscriber_downlink_pacing_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}

std::size_t ice_udp_server::erase_subscriber_downlink_pacing_states_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = subscriber_downlink_pacing_by_key_.begin(); iterator != subscriber_downlink_pacing_by_key_.end();)
    {
        if (subscriber_downlink_pacing_state_key_matches_stream(iterator->first, stream_id))
        {
            if (iterator->first == subscriber_downlink_pacing_round_robin_after_key)
            {
                subscriber_downlink_pacing_round_robin_after_key.clear();
            }

            iterator = subscriber_downlink_pacing_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }
        ++iterator;
    }

    return erased_count;
}

std::size_t ice_udp_server::subscriber_downlink_pacing_queue_packet_count_locked() const
{
    std::size_t count = 0;

    for (const auto& [key, pacing_state] : subscriber_downlink_pacing_by_key_)
    {
        (void)key;

        count += pacing_state.queue.size();
    }

    return count;
}

std::size_t ice_udp_server::subscriber_downlink_pacing_queue_byte_count_locked() const
{
    std::size_t count = 0;

    for (const auto& [key, pacing_state] : subscriber_downlink_pacing_by_key_)
    {
        (void)key;

        count += static_cast<std::size_t>(pacing_state.queue_byte_count);
    }

    return count;
}

void ice_udp_server::forget_outbound_transport_cc_packets_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = outbound_transport_cc_packets_by_key_.begin(); iterator != outbound_transport_cc_packets_by_key_.end();)
    {
        if (outbound_transport_cc_packet_key_matches_session(iterator->first, session_id))
        {
            iterator = outbound_transport_cc_packets_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    std::erase_if(outbound_transport_cc_packet_key_by_rtp_key_,
                  [session_id](const auto& item) { return outbound_transport_cc_rtp_packet_key_matches_session(item.first, session_id); });

    std::erase_if(outbound_transport_cc_packet_insertion_order_,
                  [session_id](const std::string& key) { return outbound_transport_cc_packet_key_matches_session(key, session_id); });
}

std::size_t ice_udp_server::erase_outbound_transport_cc_packets_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = outbound_transport_cc_packets_by_key_.begin(); iterator != outbound_transport_cc_packets_by_key_.end();)
    {
        if (outbound_transport_cc_packet_key_matches_stream(iterator->first, stream_id))
        {
            iterator = outbound_transport_cc_packets_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    std::erase_if(outbound_transport_cc_packet_key_by_rtp_key_,
                  [stream_id](const auto& item) { return outbound_transport_cc_rtp_packet_key_matches_stream(item.first, stream_id); });

    std::erase_if(outbound_transport_cc_packet_insertion_order_,
                  [stream_id](const std::string& key) { return outbound_transport_cc_packet_key_matches_stream(key, stream_id); });

    return erased_count;
}

void ice_udp_server::forget_outbound_transport_cc_sequences_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = outbound_transport_cc_sequence_by_key_.begin(); iterator != outbound_transport_cc_sequence_by_key_.end();)
    {
        if (outbound_transport_cc_sequence_key_matches_session(iterator->first, session_id))
        {
            iterator = outbound_transport_cc_sequence_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

std::size_t ice_udp_server::erase_outbound_transport_cc_sequences_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = outbound_transport_cc_sequence_by_key_.begin(); iterator != outbound_transport_cc_sequence_by_key_.end();)
    {
        if (outbound_transport_cc_sequence_key_matches_stream(iterator->first, stream_id))
        {
            iterator = outbound_transport_cc_sequence_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}
bool ice_udp_server::remember_extmap_header_extension_id_rewrite(std::string_view stream_id,
                                                                 std::string_view publisher_session_id,
                                                                 std::string_view subscriber_session_id,
                                                                 std::string_view subscriber_mid,
                                                                 std::string_view uri,
                                                                 const rtp_header_extension_id_rewrite& rewrite)
{
    if (stream_id.empty() || publisher_session_id.empty() || subscriber_session_id.empty() || subscriber_mid.empty() || uri.empty() ||
        rewrite.source_id == 0 || rewrite.target_id == 0)
    {
        return false;
    }

    const std::string key = make_extmap_rewrite_runtime_state_key(stream_id, publisher_session_id, subscriber_session_id, subscriber_mid, uri);

    std::lock_guard lock(endpoint_mutex_);

    auto iterator = extmap_rewrite_state_by_key_.find(key);

    if (iterator != extmap_rewrite_state_by_key_.end())
    {
        extmap_rewrite_runtime_state& state = iterator->second;

        if (state.source_id != rewrite.source_id || state.target_id != rewrite.target_id)
        {
            WEBRTC_LOG_WARN(
                "rtp extmap rewrite conflict stream={} publisher_session={} subscriber_session={} subscriber_mid={} uri={} old_source_id={} "
                "old_target_id={} new_source_id={} new_target_id={}",
                stream_id,
                publisher_session_id,
                subscriber_session_id,
                subscriber_mid,
                uri,
                state.source_id,
                state.target_id,
                rewrite.source_id,
                rewrite.target_id);

            return false;
        }

        state.packet_count += 1;

        return true;
    }

    extmap_rewrite_runtime_state state;

    state.stream_id = std::string(stream_id);

    state.publisher_session_id = std::string(publisher_session_id);

    state.subscriber_session_id = std::string(subscriber_session_id);

    state.subscriber_mid = std::string(subscriber_mid);

    state.uri = std::string(uri);

    state.source_id = rewrite.source_id;

    state.target_id = rewrite.target_id;

    state.packet_count = 1;

    extmap_rewrite_state_by_key_.emplace(key, std::move(state));

    return true;
}
void ice_udp_server::forget_extmap_rewrite_states_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = extmap_rewrite_state_by_key_.begin(); iterator != extmap_rewrite_state_by_key_.end();)
    {
        const extmap_rewrite_runtime_state& state = iterator->second;

        if (state.publisher_session_id == session_id || state.subscriber_session_id == session_id)
        {
            iterator = extmap_rewrite_state_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

std::size_t ice_udp_server::erase_extmap_rewrite_states_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = extmap_rewrite_state_by_key_.begin(); iterator != extmap_rewrite_state_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = extmap_rewrite_state_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}
void ice_udp_server::forget_selected_rid_layer_states_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = selected_rid_layer_state_by_key_.begin(); iterator != selected_rid_layer_state_by_key_.end();)
    {
        const selected_rid_layer_runtime_state& state = iterator->second;

        if (state.publisher_session_id == session_id || state.subscriber_session_id == session_id)
        {
            pending_selected_rid_keyframe_request_keys_.erase(iterator->first);
            pending_selected_rid_keyframe_request_state_by_key_.erase(iterator->first);
            runtime_selected_rid_targets_by_key_.erase(iterator->first);

            iterator = selected_rid_layer_state_by_key_.erase(iterator);

            continue;
        }
        ++iterator;
    }
}

std::size_t ice_udp_server::expire_selected_rid_keyframe_request_pending_locked(uint64_t current_time_milliseconds)
{
    std::size_t expired_count = 0;

    for (auto iterator = pending_selected_rid_keyframe_request_state_by_key_.begin();
         iterator != pending_selected_rid_keyframe_request_state_by_key_.end();)
    {
        const std::string key = iterator->first;
        const selected_rid_keyframe_request_pending_state& pending_state = iterator->second;

        if (pending_state.expires_at_milliseconds == 0 || current_time_milliseconds < pending_state.expires_at_milliseconds)
        {
            ++iterator;

            continue;
        }

        pending_selected_rid_keyframe_request_keys_.erase(key);

        auto state_iterator = selected_rid_layer_state_by_key_.find(key);

        if (state_iterator != selected_rid_layer_state_by_key_.end())
        {
            selected_rid_layer_runtime_state& state = state_iterator->second;

            state.last_keyframe_request_milliseconds = current_time_milliseconds;
            state.last_keyframe_request_result = "expired";
            state.last_keyframe_request_reason = "selected rid keyframe pending timeout";

            WEBRTC_LOG_WARN(
                "simulcast selected rid keyframe request expired stream={} publisher_session={} subscriber_session={} mid={} kind={} "
                "selected_rid={} pending_ms={} restore_count={}",
                state.stream_id,
                state.publisher_session_id,
                state.subscriber_session_id,
                state.mid,
                state.kind,
                state.rid,
                current_time_milliseconds > pending_state.pending_since_milliseconds
                    ? current_time_milliseconds - pending_state.pending_since_milliseconds
                    : 0,
                pending_state.restore_count);
        }

        iterator = pending_selected_rid_keyframe_request_state_by_key_.erase(iterator);

        expired_count += 1;
    }

    return expired_count;
}
std::size_t ice_udp_server::erase_selected_rid_layer_states_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = selected_rid_layer_state_by_key_.begin(); iterator != selected_rid_layer_state_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            pending_selected_rid_keyframe_request_keys_.erase(iterator->first);
            pending_selected_rid_keyframe_request_state_by_key_.erase(iterator->first);
            runtime_selected_rid_targets_by_key_.erase(iterator->first);

            iterator = selected_rid_layer_state_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}

bool ice_udp_server::consume_republish_keyframe_request_pending_for_subscriber(const srtp_packet_process_result& packet,
                                                                               const media_route_result& route,
                                                                               const std::optional<media_track_resolution>& track_resolution,
                                                                               const media_peer_info& target_peer)
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return false;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return false;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return false;
    }

    if (target_peer.role != media_peer_role::subscriber)
    {
        return false;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved || !is_video_media_kind(track_resolution->kind))
    {
        return false;
    }

    if (route.source.stream_id.empty() || route.source.session_id.empty() || target_peer.session_id.empty() || packet.ssrc == 0)
    {
        return false;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::string stale_publisher_session_id;
    std::size_t request_count = 0;
    std::size_t eligible_subscriber_count = 0;
    std::size_t first_request_subscriber_count = 0;
    bool pending_erased = false;
    bool stale_pending_erased = false;
    bool pending_expired = false;
    bool request_limit_reached = false;

    {
        std::lock_guard lock(endpoint_mutex_);

        auto iterator = pending_republish_keyframe_state_by_stream_.find(route.source.stream_id);

        if (iterator == pending_republish_keyframe_state_by_stream_.end())
        {
            return false;
        }

        republish_keyframe_request_state& state = iterator->second;

        if (state.publisher_session_id != route.source.session_id)
        {
            stale_publisher_session_id = state.publisher_session_id;

            pending_republish_keyframe_state_by_stream_.erase(iterator);

            stale_pending_erased = true;
        }
        else if (state.expires_at_milliseconds != 0 && current_time_milliseconds >= state.expires_at_milliseconds)
        {
            pending_republish_keyframe_state_by_stream_.erase(iterator);

            pending_expired = true;
        }
        else if (state.eligible_subscriber_session_ids.empty())
        {
            pending_republish_keyframe_state_by_stream_.erase(iterator);

            pending_erased = true;
        }
        else if (!state.eligible_subscriber_session_ids.contains(target_peer.session_id))
        {
            return false;
        }
        else
        {
            eligible_subscriber_count = state.eligible_subscriber_session_ids.size();

            const std::string subscriber_session_id = target_peer.session_id;

            const auto last_request_iterator = state.last_request_milliseconds_by_subscriber_session_id.find(subscriber_session_id);

            if (last_request_iterator != state.last_request_milliseconds_by_subscriber_session_id.end())
            {
                const uint64_t elapsed_milliseconds =
                    current_time_milliseconds > last_request_iterator->second ? current_time_milliseconds - last_request_iterator->second : 0;

                if (elapsed_milliseconds < k_keyframe_request_interval_milliseconds)
                {
                    return false;
                }
            }

            request_count = state.request_count_by_subscriber_session_id[subscriber_session_id];

            if (request_count >= k_republish_keyframe_request_max_attempts_per_subscriber)
            {
                request_limit_reached = true;

                bool all_subscribers_reached_limit = true;

                for (const std::string& eligible_subscriber_session_id : state.eligible_subscriber_session_ids)
                {
                    const auto count_iterator = state.request_count_by_subscriber_session_id.find(eligible_subscriber_session_id);

                    const std::size_t subscriber_request_count =
                        count_iterator == state.request_count_by_subscriber_session_id.end() ? 0 : count_iterator->second;

                    if (subscriber_request_count < k_republish_keyframe_request_max_attempts_per_subscriber)
                    {
                        all_subscribers_reached_limit = false;

                        break;
                    }
                }

                if (all_subscribers_reached_limit)
                {
                    pending_republish_keyframe_state_by_stream_.erase(iterator);

                    pending_erased = true;
                }
            }
            else
            {
                request_count += 1;

                state.request_count_by_subscriber_session_id[subscriber_session_id] = request_count;
                state.last_request_milliseconds_by_subscriber_session_id[subscriber_session_id] = current_time_milliseconds;

                state.consumed_subscriber_session_ids.insert(subscriber_session_id);

                first_request_subscriber_count = state.consumed_subscriber_session_ids.size();

                if (request_count >= k_republish_keyframe_request_max_attempts_per_subscriber)
                {
                    bool all_subscribers_reached_limit = true;

                    for (const std::string& eligible_subscriber_session_id : state.eligible_subscriber_session_ids)
                    {
                        const auto count_iterator = state.request_count_by_subscriber_session_id.find(eligible_subscriber_session_id);

                        const std::size_t subscriber_request_count =
                            count_iterator == state.request_count_by_subscriber_session_id.end() ? 0 : count_iterator->second;

                        if (subscriber_request_count < k_republish_keyframe_request_max_attempts_per_subscriber)
                        {
                            all_subscribers_reached_limit = false;

                            break;
                        }
                    }

                    if (all_subscribers_reached_limit)
                    {
                        pending_republish_keyframe_state_by_stream_.erase(iterator);

                        pending_erased = true;
                    }
                }
            }
        }
    }

    if (stale_pending_erased)
    {
        WEBRTC_LOG_DEBUG("publisher republish keyframe stale request erased stream={} stale_publisher_session={} current_publisher_session={}",
                         route.source.stream_id,
                         stale_publisher_session_id,
                         route.source.session_id);

        return false;
    }

    if (pending_expired)
    {
        WEBRTC_LOG_WARN("publisher republish keyframe request expired stream={} publisher_session={} subscriber_session={} timeout_ms={}",
                        route.source.stream_id,
                        route.source.session_id,
                        target_peer.session_id,
                        k_republish_keyframe_request_pending_timeout_milliseconds);

        return false;
    }

    if (request_limit_reached)
    {
        WEBRTC_LOG_WARN(
            "publisher republish keyframe request limit reached stream={} publisher_session={} subscriber_session={} max_attempts={} "
            "pending_erased={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            k_republish_keyframe_request_max_attempts_per_subscriber,
            pending_erased ? 1 : 0);

        return false;
    }

    if (eligible_subscriber_count == 0 || request_count == 0)
    {
        return false;
    }

    WEBRTC_LOG_INFO(
        "publisher republish keyframe request retry stream={} publisher_session={} subscriber_session={} request_count={} max_attempts={} "
        "first_request_subscribers={} eligible_subscribers={} pending_erased={} media_ssrc={}",
        route.source.stream_id,
        route.source.session_id,
        target_peer.session_id,
        request_count,
        k_republish_keyframe_request_max_attempts_per_subscriber,
        first_request_subscriber_count,
        eligible_subscriber_count,
        pending_erased ? 1 : 0,
        packet.ssrc);

    return true;
}

void ice_udp_server::complete_republish_keyframe_request_pending_for_publisher_keyframe(const srtp_packet_process_result& packet,
                                                                                        const media_route_result& route,
                                                                                        const std::optional<media_track_resolution>& track_resolution)
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return;
    }

    if (packet.plain_packet.empty())
    {
        return;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return;
    }

    if (route.source.stream_id.empty() || route.source.session_id.empty())
    {
        return;
    }

    if (route.target_endpoints.empty())
    {
        return;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved || !is_video_media_kind(track_resolution->kind))
    {
        return;
    }

    if (track_resolution->rtx)
    {
        return;
    }

    if (registry_ == nullptr)
    {
        return;
    }

    auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

    if (publisher == nullptr)
    {
        return;
    }

    const uint16_t payload_type = static_cast<uint16_t>(track_resolution->payload_type);

    const std::optional<std::string> codec_name =
        find_offer_codec_name_by_payload_type(publisher->remote_offer_summary(), track_resolution->mid, payload_type);

    if (!codec_name.has_value())
    {
        return;
    }

    const publisher_video_keyframe_codec keyframe_codec = publisher_video_keyframe_codec_from_name(*codec_name);

    if (keyframe_codec == publisher_video_keyframe_codec::unknown)
    {
        return;
    }

    std::span<const uint8_t> plain_packet(packet.plain_packet.data(), packet.plain_packet.size());

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        WEBRTC_LOG_DEBUG("publisher republish keyframe detect skipped parse failed stream={} publisher_session={} ssrc={} error={}",
                         route.source.stream_id,
                         route.source.session_id,
                         packet.ssrc,
                         header.error());

        return;
    }

    auto payload = rtp_payload_span(plain_packet, *header);

    if (!payload.has_value())
    {
        return;
    }

    if (!is_publisher_video_keyframe_payload(keyframe_codec, *payload))
    {
        return;
    }

    std::size_t eligible_subscriber_count = 0;
    std::size_t first_request_subscriber_count = 0;
    std::size_t target_endpoint_count = route.target_endpoints.size();
    uint64_t pending_age_milliseconds = 0;
    bool pending_erased = false;

    {
        std::lock_guard lock(endpoint_mutex_);

        auto iterator = pending_republish_keyframe_state_by_stream_.find(route.source.stream_id);

        if (iterator == pending_republish_keyframe_state_by_stream_.end())
        {
            return;
        }

        republish_keyframe_request_state& state = iterator->second;

        if (state.publisher_session_id != route.source.session_id)
        {
            return;
        }

        eligible_subscriber_count = state.eligible_subscriber_session_ids.size();
        first_request_subscriber_count = state.consumed_subscriber_session_ids.size();

        const uint64_t current_time_milliseconds = now_milliseconds();

        if (state.pending_since_milliseconds != 0 && current_time_milliseconds >= state.pending_since_milliseconds)
        {
            pending_age_milliseconds = current_time_milliseconds - state.pending_since_milliseconds;
        }

        pending_republish_keyframe_state_by_stream_.erase(iterator);

        pending_erased = true;
    }

    if (!pending_erased)
    {
        return;
    }

    WEBRTC_LOG_INFO(
        "publisher republish keyframe observed pending cleared stream={} publisher_session={} mid={} kind={} codec={} ssrc={} sequence={} "
        "payload_type={} eligible_subscribers={} first_request_subscribers={} target_endpoints={} pending_age_ms={}",
        route.source.stream_id,
        route.source.session_id,
        track_resolution->mid,
        track_resolution->kind,
        publisher_video_keyframe_codec_to_string(keyframe_codec),
        header->ssrc,
        header->sequence_number,
        static_cast<unsigned int>(header->payload_type),
        eligible_subscriber_count,
        first_request_subscriber_count,
        target_endpoint_count,
        pending_age_milliseconds);
}
bool ice_udp_server::subscriber_downlink_packet_is_keyframe(const media_route_result& route,
                                                            const std::optional<media_track_resolution>& track_resolution,
                                                            const srtp_packet_process_result& packet,
                                                            std::span<const uint8_t> outbound_plain_packet) const
{
    if (packet.kind != srtp_packet_kind::rtp)
    {
        return false;
    }

    if (outbound_plain_packet.empty())
    {
        return false;
    }

    if (route.action != media_route_action::fanout_to_subscribers)
    {
        return false;
    }

    if (route.source.role != media_peer_role::publisher)
    {
        return false;
    }

    if (route.source.session_id.empty())
    {
        return false;
    }

    if (!track_resolution.has_value() || !track_resolution->resolved || !is_video_media_kind(track_resolution->kind))
    {
        return false;
    }

    if (track_resolution->rtx)
    {
        return false;
    }

    if (registry_ == nullptr)
    {
        return false;
    }

    auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

    if (publisher == nullptr)
    {
        return false;
    }

    const uint16_t payload_type = static_cast<uint16_t>(track_resolution->payload_type);

    const std::optional<std::string> codec_name =
        find_offer_codec_name_by_payload_type(publisher->remote_offer_summary(), track_resolution->mid, payload_type);

    if (!codec_name.has_value())
    {
        return false;
    }

    const publisher_video_keyframe_codec keyframe_codec = publisher_video_keyframe_codec_from_name(*codec_name);

    if (keyframe_codec == publisher_video_keyframe_codec::unknown)
    {
        return false;
    }

    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        WEBRTC_LOG_DEBUG("subscriber downlink keyframe detect skipped parse failed stream={} publisher_session={} ssrc={} error={}",
                         route.source.stream_id,
                         route.source.session_id,
                         packet.ssrc,
                         header.error());

        return false;
    }

    auto payload = rtp_payload_span(outbound_plain_packet, *header);

    if (!payload.has_value())
    {
        return false;
    }

    return is_publisher_video_keyframe_payload(keyframe_codec, *payload);
}
void ice_udp_server::open_subscriber_downlink_keyframe_request_recovery_window(const rtcp_feedback_route_event& event,
                                                                               const media_ssrc_mapping& mapping)
{
    const auto& downlink_config = ice_udp_server_runtime_config_instance().subscriber_downlink_control;

    if (downlink_config.mode == subscriber_downlink_control_mode::disabled)
    {
        return;
    }

    if (event.source.role != media_peer_role::subscriber)
    {
        return;
    }

    if (!event.has_keyframe_request && event.fir_count == 0)
    {
        return;
    }

    if (!media_ssrc_mapping_is_primary_video(mapping))
    {
        return;
    }

    if (mapping.stream_id.empty() || mapping.subscriber_session_id.empty())
    {
        return;
    }

    if (mapping.stream_id != event.source.stream_id || mapping.subscriber_session_id != event.source.session_id)
    {
        WEBRTC_LOG_WARN(
            "subscriber downlink keyframe request recovery skipped mapping mismatch event_stream={} mapping_stream={} event_subscriber={} "
            "mapping_subscriber={} media_ssrc={} publisher_ssrc={} subscriber_ssrc={}",
            event.source.stream_id,
            mapping.stream_id,
            event.source.session_id,
            mapping.subscriber_session_id,
            event.media_ssrc,
            mapping.publisher_ssrc,
            mapping.subscriber_ssrc);

        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    const std::string key = make_subscriber_downlink_bandwidth_state_key(mapping.stream_id, mapping.subscriber_session_id);

    std::lock_guard lock(endpoint_mutex_);

    auto iterator = subscriber_downlink_bandwidth_by_key_.find(key);

    if (iterator == subscriber_downlink_bandwidth_by_key_.end())
    {
        WEBRTC_LOG_DEBUG(
            "subscriber downlink keyframe request recovery skipped missing bandwidth state stream={} subscriber_session={} media_ssrc={} "
            "publisher_ssrc={} subscriber_ssrc={}",
            mapping.stream_id,
            mapping.subscriber_session_id,
            event.media_ssrc,
            mapping.publisher_ssrc,
            mapping.subscriber_ssrc);

        return;
    }

    subscriber_downlink_bandwidth_state& state = iterator->second;

    const bool already_active = state.keyframe_recovery_until_milliseconds != 0 &&
                                current_time_milliseconds <= state.keyframe_recovery_until_milliseconds &&
                                state.keyframe_recovery_remaining_packet_count > 0;

    state.keyframe_recovery_until_milliseconds = current_time_milliseconds + downlink_config.keyframe_recovery_bypass_duration_milliseconds;

    state.keyframe_recovery_remaining_packet_count =
        std::max<uint64_t>(state.keyframe_recovery_remaining_packet_count, downlink_config.keyframe_recovery_bypass_packet_count);

    state.last_keyframe_request_at_milliseconds = current_time_milliseconds;

    if (already_active)
    {
        state.bitrate_gate_keyframe_request_recovery_refresh_count += 1;
    }
    else
    {
        state.bitrate_gate_keyframe_request_recovery_open_count += 1;
    }

    WEBRTC_LOG_DEBUG(
        "subscriber downlink keyframe request recovery opened stream={} subscriber_session={} feedback={} media_ssrc={} "
        "publisher_ssrc={} subscriber_ssrc={} already_active={} recovery_until={} recovery_remaining_packets={} open_count={} "
        "refresh_count={}",
        mapping.stream_id,
        mapping.subscriber_session_id,
        event.feedback_name,
        event.media_ssrc,
        mapping.publisher_ssrc,
        mapping.subscriber_ssrc,
        already_active ? 1 : 0,
        state.keyframe_recovery_until_milliseconds,
        state.keyframe_recovery_remaining_packet_count,
        state.bitrate_gate_keyframe_request_recovery_open_count,
        state.bitrate_gate_keyframe_request_recovery_refresh_count);
}

void ice_udp_server::forward_media_packet(const srtp_packet_process_result& packet,
                                          const media_route_result& route,
                                          const std::optional<media_track_resolution>& track_resolution,
                                          const std::vector<rtcp_feedback_route_event>& feedback_events)
{
    if (packet.plain_packet.empty())
    {
        WEBRTC_LOG_WARN("media forward skipped empty plain packet stream={} session={} kind={}",
                        route.source.stream_id,
                        route.source.session_id,
                        srtp_packet_kind_to_string(packet.kind));

        return;
    }

    if (route.action == media_route_action::none || route.target_endpoints.empty())
    {
        rtp_rtcp_drop_media_forward_no_target_total_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    if (srtp_transport_ == nullptr)
    {
        WEBRTC_LOG_WARN("media forward skipped srtp transport is null stream={} session={}", route.source.stream_id, route.source.session_id);
        rtp_rtcp_drop_media_forward_transport_missing_total_.fetch_add(1, std::memory_order_relaxed);

        return;
    }

    for (const auto& target_address : route.target_endpoints)
    {
        auto target_endpoint = find_remote_endpoint(target_address);

        if (!target_endpoint)
        {
            WEBRTC_LOG_WARN("media forward target endpoint not found stream={} source={} target={} kind={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind));

            rtp_rtcp_drop_media_forward_target_endpoint_missing_total_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        auto target_peer = media_router_->get_peer(target_address);

        if (!target_peer.has_value())
        {
            WEBRTC_LOG_WARN("media forward target peer not found stream={} source={} target={} kind={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind));

            rtp_rtcp_drop_media_forward_target_peer_missing_total_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        auto outbound_plain_packet = make_forward_plain_packet(packet, route, track_resolution, feedback_events, *target_peer);
        if (!outbound_plain_packet.has_value())
        {
            rtp_rtcp_drop_media_forward_rewrite_failed_total_.fetch_add(1, std::memory_order_relaxed);
            WEBRTC_LOG_WARN("media forward skipped rewrite failed stream={} source={} target={} kind={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind));

            continue;
        }

        if (outbound_plain_packet->empty())
        {
            rtp_rtcp_drop_media_forward_rewrite_empty_total_.fetch_add(1, std::memory_order_relaxed);
            WEBRTC_LOG_WARN("media forward skipped empty rewritten packet stream={} source={} target={} kind={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind));

            continue;
        }

        if (!outbound_media_runtime_ready(
                target_address, target_peer->session_id, target_peer->stream_id, target_peer->role, "media forward protect"))
        {
            rtp_rtcp_drop_media_forward_runtime_gate_total_.fetch_add(1, std::memory_order_relaxed);
            WEBRTC_LOG_DEBUG(
                "media forward skipped outbound runtime not ready stream={} source={} target={} target_session={} target_role={} kind={}",
                route.source.stream_id,
                route.source.remote_endpoint,
                target_address,
                target_peer->session_id,
                media_peer_role_to_string(target_peer->role),
                srtp_packet_kind_to_string(packet.kind));

            continue;
        }

        std::optional<media_ssrc_mapping> outbound_mapping;

        if (packet.kind == srtp_packet_kind::rtp)
        {
            const std::span<const uint8_t> outbound_span(outbound_plain_packet->data(), outbound_plain_packet->size());

            outbound_mapping = find_outbound_ssrc_mapping(*target_peer, outbound_span);

            if (!subscriber_downlink_bitrate_gate_allows_packet(route, *target_peer, track_resolution, packet, outbound_span, outbound_mapping))
            {
                mark_outbound_transport_cc_packet_locally_dropped_from_rtp_packet(
                    route, *target_peer, outbound_span, outbound_mapping, "bitrate_gate");

                rtp_rtcp_drop_media_forward_bitrate_gate_total_.fetch_add(1, std::memory_order_relaxed);

                continue;
            }
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(outbound_plain_packet->data(), outbound_plain_packet->size()), target_address, packet.kind);
        if (!protected_packet)
        {
            rtp_rtcp_drop_media_forward_protect_failed_total_.fetch_add(1, std::memory_order_relaxed);
            WEBRTC_LOG_WARN("media forward protect failed stream={} source={} target={} kind={} error={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind),
                            protected_packet.error());

            continue;
        }

        if (protected_packet->state == srtp_packet_process_state::ignored)
        {
            rtp_rtcp_drop_media_forward_protect_ignored_total_.fetch_add(1, std::memory_order_relaxed);
            WEBRTC_LOG_DEBUG("media forward target ignored stream={} source={} target={} kind={} reason={}",
                             route.source.stream_id,
                             route.source.remote_endpoint,
                             target_address,
                             srtp_packet_kind_to_string(packet.kind),
                             protected_packet->reason);

            continue;
        }

        if (packet.kind == srtp_packet_kind::rtp)
        {
            const std::span<const uint8_t> outbound_span(outbound_plain_packet->data(), outbound_plain_packet->size());

            observe_outbound_rtp_stats(*target_peer, outbound_span, outbound_mapping);

            observe_outbound_track_stats(*target_peer, outbound_span, outbound_mapping);

            maybe_request_keyframe_from_publisher(packet, route, track_resolution, *target_peer);
        }
        const uint64_t protected_packet_size = static_cast<uint64_t>(protected_packet->protected_packet.size());
        if (subscriber_downlink_pacing_should_enqueue_packet(route, *target_peer, packet, outbound_mapping, protected_packet_size))
        {
            std::optional<outbound_transport_cc_packet_identity> pacing_transport_cc_identity;

            if (packet.kind == srtp_packet_kind::rtp && outbound_mapping.has_value())
            {
                const std::span<const uint8_t> outbound_span(outbound_plain_packet->data(), outbound_plain_packet->size());

                auto outbound_header = parse_rtp_packet_header(outbound_span);

                if (outbound_header)
                {
                    pacing_transport_cc_identity = find_outbound_transport_cc_packet_by_rtp(
                        target_peer->stream_id, target_peer->session_id, outbound_header->ssrc, outbound_header->sequence_number);
                }
            }

            WEBRTC_LOG_DEBUG("media forward pacing enqueue stream={} source={} target={} kind={} plain_size={} protected_size={}",
                             route.source.stream_id,
                             route.source.remote_endpoint,
                             target_address,
                             srtp_packet_kind_to_string(packet.kind),
                             outbound_plain_packet->size(),
                             protected_packet->protected_packet.size());

            enqueue_subscriber_downlink_paced_packet(route,
                                                     *target_peer,
                                                     target_address,
                                                     *target_endpoint,
                                                     std::move(protected_packet->protected_packet),
                                                     std::move(pacing_transport_cc_identity));

            continue;
        }
        WEBRTC_LOG_DEBUG("media forward send stream={} source={} target={} kind={} plain_size={} protected_size={}",
                         route.source.stream_id,
                         route.source.remote_endpoint,
                         target_address,
                         srtp_packet_kind_to_string(packet.kind),
                         outbound_plain_packet->size(),
                         protected_packet->protected_packet.size());

        send_response(std::move(protected_packet->protected_packet), *target_endpoint);
    }
}

void ice_udp_server::send_response(std::vector<uint8_t> response, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    auto response_buffer = std::make_shared<std::vector<uint8_t>>(std::move(response));

    auto self = shared_from_this();

    socket_.async_send_to(boost::asio::buffer(*response_buffer),
                          remote_endpoint,
                          [self, response_buffer, remote_address](boost::system::error_code ec, std::size_t bytes_transferred)
                          {
                              (void)response_buffer;

                              if (ec)
                              {
                                  WEBRTC_LOG_WARN("ice udp send failed remote={} error={}", remote_address, ec.message());

                                  return;
                              }

                              WEBRTC_LOG_DEBUG("ice udp send success remote={} bytes={}", remote_address, bytes_transferred);
                          });
}

void ice_udp_server::remember_candidate_pair(std::string_view session_id,
                                             std::string_view stream_id,
                                             std::string_view remote_address,
                                             uint32_t remote_priority,
                                             uint64_t remote_tie_breaker,
                                             bool nominated)
{
    if (session_id.empty() || stream_id.empty() || remote_address.empty())
    {
        return;
    }

    const std::string key = make_candidate_pair_key(session_id, remote_address);

    std::lock_guard lock(endpoint_mutex_);

    auto& pair = candidate_pairs_by_key_[key];

    pair.session_id = std::string(session_id);

    pair.stream_id = std::string(stream_id);

    pair.remote_address = std::string(remote_address);

    pair.remote_priority = remote_priority;
    pair.remote_tie_breaker = remote_tie_breaker;
    pair.last_binding_at_milliseconds = now_milliseconds();
    if (pair.last_consent_response_at_milliseconds == 0)
    {
        pair.last_consent_response_at_milliseconds = pair.last_binding_at_milliseconds;
    }
    pair.nominated = pair.nominated || nominated;
}

std::expected<ice_udp_server::candidate_pair_selection_result, std::string> ice_udp_server::select_candidate_pair(
    std::string_view session_id,
    std::string_view stream_id,
    const boost::asio::ip::udp::endpoint& remote_endpoint,
    uint32_t remote_priority,
    uint64_t remote_tie_breaker)
{
    if (session_id.empty())
    {
        return make_error("ice candidate pair session id is empty");
    }

    if (stream_id.empty())
    {
        return make_error("ice candidate pair stream id is empty");
    }

    const std::string remote_address = endpoint_to_string(remote_endpoint);

    if (remote_address.empty() || remote_address == "<unknown>")
    {
        return make_error("ice candidate pair remote address is invalid");
    }

    candidate_pair_selection_result result;

    std::lock_guard lock(endpoint_mutex_);

    const auto reused_remote_owner = session_id_by_endpoint_address_.find(remote_address);

    if (reused_remote_owner != session_id_by_endpoint_address_.end() && reused_remote_owner->second != session_id)
    {
        result.remote_address_reused_by_different_session = true;
        result.replaced_session_id = reused_remote_owner->second;

        const auto replaced_forward = endpoint_address_by_session_id_.find(result.replaced_session_id);

        if (replaced_forward != endpoint_address_by_session_id_.end() && replaced_forward->second == remote_address)
        {
            endpoint_address_by_session_id_.erase(replaced_forward);
        }

        session_id_by_endpoint_address_.erase(reused_remote_owner);

        endpoints_by_address_.erase(remote_address);

        endpoint_last_seen_milliseconds_by_address_.erase(remote_address);

        erase_candidate_pairs_for_session_locked(result.replaced_session_id);

        erase_candidate_pairs_for_endpoint_locked(remote_address);

        erase_payload_type_mappings_for_session_locked(result.replaced_session_id);

        const std::size_t erased_keyframe_request_state_count = erase_keyframe_request_states_for_session_locked(result.replaced_session_id);

        WEBRTC_LOG_INFO(
            "ice selected candidate pair remote reused by different session old_session={} new_session={} stream={} remote={} "
            "keyframe_states_erased={}",
            result.replaced_session_id,
            session_id,
            stream_id,
            remote_address,
            erased_keyframe_request_state_count);
    }

    const auto current_selection = endpoint_address_by_session_id_.find(std::string(session_id));

    if (current_selection != endpoint_address_by_session_id_.end())
    {
        if (current_selection->second == remote_address)
        {
            unretire_endpoint_locked(remote_address);

            endpoints_by_address_[remote_address] = remote_endpoint;
            const std::string key = make_candidate_pair_key(session_id, remote_address);

            auto& pair = candidate_pairs_by_key_[key];

            pair.session_id = std::string(session_id);

            pair.stream_id = std::string(stream_id);

            pair.remote_address = remote_address;

            pair.remote_priority = remote_priority;

            pair.remote_tie_breaker = remote_tie_breaker;

            pair.selected = true;
            pair.nominated = true;
            pair.last_binding_at_milliseconds = now_milliseconds();
            if (pair.last_consent_response_at_milliseconds == 0)
            {
                pair.last_consent_response_at_milliseconds = pair.last_binding_at_milliseconds;
            }
            return result;
        }

        result.previous_remote_address = current_selection->second;

        erase_endpoint_indexes_for_remote_locked(result.previous_remote_address);
        retire_endpoint_locked(result.previous_remote_address, session_id, now_milliseconds(), "candidate pair replaced");
    }

    unretire_endpoint_locked(remote_address);
    endpoint_address_by_session_id_[std::string(session_id)] = remote_address;

    session_id_by_endpoint_address_[remote_address] = std::string(session_id);

    endpoints_by_address_[remote_address] = remote_endpoint;

    const std::string key = make_candidate_pair_key(session_id, remote_address);

    auto& pair = candidate_pairs_by_key_[key];

    pair.session_id = std::string(session_id);

    pair.stream_id = std::string(stream_id);

    pair.remote_address = remote_address;

    pair.remote_priority = remote_priority;

    pair.remote_tie_breaker = remote_tie_breaker;

    pair.last_binding_at_milliseconds = now_milliseconds();

    pair.nominated = true;
    pair.selected = true;

    result.changed = true;
    if (pair.last_consent_response_at_milliseconds == 0)
    {
        pair.last_consent_response_at_milliseconds = pair.last_binding_at_milliseconds;
    }
    return result;
}

bool ice_udp_server::is_selected_endpoint(std::string_view remote_address) const
{
    if (remote_address.empty())
    {
        return false;
    }

    std::lock_guard lock(endpoint_mutex_);

    return session_id_by_endpoint_address_.contains(std::string(remote_address));
}

std::vector<ice_udp_server::ice_consent_request> ice_udp_server::collect_due_ice_consent_requests(uint64_t current_time_milliseconds)
{
    struct selected_consent_candidate
    {
        ice_candidate_pair pair;
        boost::asio::ip::udp::endpoint remote_endpoint;
    };

    std::vector<selected_consent_candidate> selected_candidates;

    {
        std::lock_guard lock(endpoint_mutex_);

        for (const auto& [key, pair] : candidate_pairs_by_key_)
        {
            (void)key;

            if (!pair.selected)
            {
                continue;
            }

            if (pair.session_id.empty() || pair.stream_id.empty() || pair.remote_address.empty())
            {
                continue;
            }

            const auto endpoint_iterator = endpoints_by_address_.find(pair.remote_address);

            if (endpoint_iterator == endpoints_by_address_.end())
            {
                continue;
            }

            const uint64_t request_age_milliseconds = pair.last_consent_request_at_milliseconds == 0 ? std::numeric_limits<uint64_t>::max()
                                                      : current_time_milliseconds > pair.last_consent_request_at_milliseconds
                                                          ? current_time_milliseconds - pair.last_consent_request_at_milliseconds
                                                          : 0;

            if (pair.consent_request_in_flight)
            {
                if (request_age_milliseconds < k_ice_consent_request_retry_milliseconds)
                {
                    continue;
                }
            }
            else if (pair.last_consent_request_at_milliseconds != 0 && request_age_milliseconds < k_ice_consent_request_interval_milliseconds)
            {
                continue;
            }

            selected_consent_candidate candidate;
            candidate.pair = pair;
            candidate.remote_endpoint = endpoint_iterator->second;
            selected_candidates.push_back(std::move(candidate));
        }
    }

    std::vector<ice_consent_request> requests;

    requests.reserve(selected_candidates.size());

    for (const auto& candidate : selected_candidates)
    {
        std::string local_ufrag;
        std::string remote_ufrag;
        std::string remote_pwd;

        if (registry_ == nullptr)
        {
            continue;
        }

        auto publisher = registry_->find_publisher_by_session_id(candidate.pair.session_id);

        if (publisher != nullptr)
        {
            local_ufrag = publisher->local_ice().ufrag;

            remote_ufrag = publisher->remote_offer_summary().ice_ufrag;

            remote_pwd = publisher->remote_offer_summary().ice_pwd;
        }
        else
        {
            auto subscriber = registry_->find_subscriber_by_session_id(candidate.pair.session_id);

            if (subscriber == nullptr)
            {
                continue;
            }

            local_ufrag = subscriber->local_ice().ufrag;

            remote_ufrag = subscriber->remote_offer_summary().ice_ufrag;

            remote_pwd = subscriber->remote_offer_summary().ice_pwd;
        }

        if (local_ufrag.empty() || remote_ufrag.empty() || remote_pwd.empty())
        {
            continue;
        }

        ice_consent_request request;
        request.session_id = candidate.pair.session_id;
        request.stream_id = candidate.pair.stream_id;
        request.remote_address = candidate.pair.remote_address;
        request.remote_endpoint = candidate.remote_endpoint;
        request.username = make_ice_consent_username(remote_ufrag, local_ufrag);
        request.message_integrity_key = std::move(remote_pwd);
        request.ice_controlled_tie_breaker =
            make_ice_consent_tie_breaker(candidate.pair.session_id, candidate.pair.remote_address, candidate.pair.remote_tie_breaker);

        requests.push_back(std::move(request));
    }

    return requests;
}

void ice_udp_server::remember_ice_consent_request_sent(std::string_view session_id,
                                                       std::string_view remote_address,
                                                       const std::array<uint8_t, 12>& transaction_id,
                                                       uint64_t current_time_milliseconds)
{
    if (session_id.empty() || remote_address.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    const std::string key = make_candidate_pair_key(session_id, remote_address);

    auto iterator = candidate_pairs_by_key_.find(key);

    if (iterator == candidate_pairs_by_key_.end())
    {
        return;
    }

    auto& pair = iterator->second;

    if (!pair.selected)
    {
        return;
    }

    if (pair.consent_request_in_flight && pair.last_consent_request_at_milliseconds != 0)
    {
        const uint64_t request_age_milliseconds = current_time_milliseconds > pair.last_consent_request_at_milliseconds
                                                      ? current_time_milliseconds - pair.last_consent_request_at_milliseconds
                                                      : 0;

        if (request_age_milliseconds >= k_ice_consent_request_retry_milliseconds)
        {
            pair.consent_request_failures += 1;
        }
    }

    pair.pending_consent_transaction_id = transaction_id;
    pair.last_consent_request_at_milliseconds = current_time_milliseconds;
    pair.consent_request_in_flight = true;
}

void ice_udp_server::send_ice_consent_requests(uint64_t current_time_milliseconds)
{
    auto requests = collect_due_ice_consent_requests(current_time_milliseconds);

    for (const auto& request : requests)
    {
        const current_session_endpoint_state current_session =
            validate_current_session_endpoint(request.remote_address, request.session_id, request.stream_id, "ice consent request");

        if (!current_session.allowed)
        {
            continue;
        }

        stun_binding_request_options options;
        options.username = request.username;
        options.message_integrity_key = request.message_integrity_key;
        options.ice_controlled = request.ice_controlled_tie_breaker;
        options.include_fingerprint = true;

        std::array<uint8_t, 12> transaction_id{};

        auto packet = write_stun_binding_request(options, transaction_id);

        if (!packet)
        {
            WEBRTC_LOG_WARN("ice consent request build failed stream={} session={} remote={} error={}",
                            request.stream_id,
                            request.session_id,
                            request.remote_address,
                            packet.error());

            continue;
        }

        remember_ice_consent_request_sent(request.session_id, request.remote_address, transaction_id, current_time_milliseconds);

        send_response(std::move(*packet), request.remote_endpoint);

        WEBRTC_LOG_DEBUG("ice consent request sent stream={} session={} remote={}", request.stream_id, request.session_id, request.remote_address);
    }
}

std::vector<ice_udp_server::ice_consent_timeout_event> ice_udp_server::collect_expired_ice_consent_timeout_events(uint64_t current_time_milliseconds)
{
    std::vector<ice_consent_timeout_event> events;

    std::vector<std::string> expired_session_ids;

    std::lock_guard lock(endpoint_mutex_);

    for (const auto& [key, pair] : candidate_pairs_by_key_)
    {
        (void)key;

        if (!pair.selected)
        {
            continue;
        }

        if (pair.session_id.empty() || pair.remote_address.empty())
        {
            continue;
        }

        if (contains_string(expired_session_ids, pair.session_id))
        {
            continue;
        }

        const uint64_t consent_freshness_at_milliseconds =
            pair.last_consent_response_at_milliseconds != 0 ? pair.last_consent_response_at_milliseconds : pair.last_binding_at_milliseconds;

        if (consent_freshness_at_milliseconds == 0)
        {
            continue;
        }

        const uint64_t consent_age_milliseconds =
            current_time_milliseconds > consent_freshness_at_milliseconds ? current_time_milliseconds - consent_freshness_at_milliseconds : 0;

        if (consent_age_milliseconds < ice_udp_server_runtime_config_instance().ice_consent_timeout_milliseconds)
        {
            continue;
        }
        ice_consent_timeout_event event;

        event.session_id = pair.session_id;

        event.stream_id = pair.stream_id;

        event.remote_address = pair.remote_address;

        event.consent_age_milliseconds = consent_age_milliseconds;

        event.last_binding_at_milliseconds = pair.last_binding_at_milliseconds;

        event.last_consent_request_at_milliseconds = pair.last_consent_request_at_milliseconds;

        event.last_consent_response_at_milliseconds = pair.last_consent_response_at_milliseconds;

        event.consent_request_failures = pair.consent_request_failures;

        event.consent_request_in_flight = pair.consent_request_in_flight;

        events.push_back(std::move(event));

        expired_session_ids.push_back(pair.session_id);
    }

    return events;
}
void ice_udp_server::expire_ice_consent_session(const ice_consent_timeout_event& event)
{
    if (event.session_id.empty())
    {
        return;
    }

    WEBRTC_LOG_WARN(
        "ice consent timeout stream={} session={} remote={} age_ms={} failures={} in_flight={} last_binding_ms={} last_request_ms={} "
        "last_response_ms={}",
        event.stream_id,
        event.session_id,
        event.remote_address,
        event.consent_age_milliseconds,
        event.consent_request_failures,
        event.consent_request_in_flight ? 1 : 0,
        event.last_binding_at_milliseconds,
        event.last_consent_request_at_milliseconds,
        event.last_consent_response_at_milliseconds);

    if (!event.remote_address.empty())
    {
        send_dtls_close_notify(event.remote_address);
    }

    remove_expired_session(event.session_id, "ice consent timeout");
}

void ice_udp_server::cleanup_unselected_candidate_pairs(uint64_t current_time_milliseconds)
{
    std::lock_guard lock(endpoint_mutex_);

    for (auto iterator = candidate_pairs_by_key_.begin(); iterator != candidate_pairs_by_key_.end();)
    {
        const ice_candidate_pair& pair = iterator->second;

        if (pair.selected || pair.last_binding_at_milliseconds == 0)
        {
            ++iterator;

            continue;
        }

        const uint64_t age_milliseconds =
            current_time_milliseconds > pair.last_binding_at_milliseconds ? current_time_milliseconds - pair.last_binding_at_milliseconds : 0;
        if (age_milliseconds < ice_udp_server_runtime_config_instance().unselected_candidate_pair_retention_milliseconds)
        {
            ++iterator;

            continue;
        }
        WEBRTC_LOG_DEBUG("ice unselected candidate pair expired stream={} session={} remote={} age_ms={}",
                         pair.stream_id,
                         pair.session_id,
                         pair.remote_address,
                         age_milliseconds);

        iterator = candidate_pairs_by_key_.erase(iterator);
    }
    const std::size_t orphan_endpoint_indexes_erased = erase_orphan_endpoint_indexes_locked();

    if (orphan_endpoint_indexes_erased != 0)
    {
        WEBRTC_LOG_INFO("ice orphan endpoint indexes erased during candidate cleanup count={}", orphan_endpoint_indexes_erased);
    }
}

void ice_udp_server::forget_peer_endpoint(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    std::string session_id;
    std::optional<boost::asio::ip::udp::endpoint> close_notify_endpoint;

    {
        std::lock_guard lock(endpoint_mutex_);

        const auto endpoint_iterator = endpoints_by_address_.find(std::string(remote_address));

        if (endpoint_iterator != endpoints_by_address_.end())
        {
            close_notify_endpoint = endpoint_iterator->second;
        }

        const auto session_iterator = session_id_by_endpoint_address_.find(std::string(remote_address));
        if (session_iterator != session_id_by_endpoint_address_.end())
        {
            session_id = session_iterator->second;
        }
    }

    if (!session_id.empty())
    {
        WEBRTC_LOG_WARN("ice udp peer endpoint failed remote={} session={}", remote_address, session_id);

        remove_expired_session(session_id, "peer endpoint");

        return;
    }

    {
        std::lock_guard lock(endpoint_mutex_);

        erase_endpoint_indexes_for_remote_locked(remote_address);

        retire_endpoint_locked(remote_address, "", now_milliseconds(), "peer endpoint cleanup");

        const std::size_t orphan_endpoint_indexes_erased = erase_orphan_endpoint_indexes_locked();

        if (orphan_endpoint_indexes_erased != 0)
        {
            WEBRTC_LOG_INFO(
                "ice orphan endpoint indexes erased during peer endpoint cleanup remote={} count={}", remote_address, orphan_endpoint_indexes_erased);
        }
    }
    if (close_notify_endpoint.has_value())
    {
        send_dtls_close_notify_to_endpoint(remote_address, *close_notify_endpoint);
    }
    else
    {
        send_dtls_close_notify(remote_address);
    }

    forget_peer_transport_state(remote_address);
}

void ice_udp_server::send_dtls_close_notify(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    auto remote_endpoint = find_remote_endpoint(remote_address);

    if (!remote_endpoint.has_value())
    {
        return;
    }

    send_dtls_close_notify_to_endpoint(remote_address, *remote_endpoint);
}

void ice_udp_server::send_dtls_close_notify_to_endpoint(std::string_view remote_address, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    if (remote_address.empty())
    {
        return;
    }

    if (dtls_transport_ == nullptr)
    {
        return;
    }

    auto packets = dtls_transport_->close_peer(remote_address);

    if (!packets)
    {
        WEBRTC_LOG_WARN("dtls close notify failed remote={} error={}", remote_address, packets.error());

        return;
    }

    for (auto& packet : *packets)
    {
        if (packet.empty())
        {
            continue;
        }

        send_response(std::move(packet), remote_endpoint);
    }
}

void ice_udp_server::forget_peer_transport_state(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    bool dtls_forgot = false;
    bool srtp_forgot = false;
    bool router_forgot = false;
    bool track_forgot = false;
    bool rtcp_forgot = false;
    bool transport_cc_forgot = false;

    if (dtls_transport_ != nullptr)
    {
        dtls_transport_->forget_peer(remote_address);

        dtls_forgot = true;
    }

    if (srtp_transport_ != nullptr)
    {
        srtp_transport_->forget_peer(remote_address);

        srtp_forgot = true;
    }

    if (media_router_ != nullptr)
    {
        media_router_->forget_peer(remote_address);

        router_forgot = true;
    }

    if (track_resolver_ != nullptr)
    {
        track_resolver_->forget_peer(remote_address);

        track_forgot = true;
    }

    if (identity_authority_ != nullptr)
    {
        identity_authority_->forget_peer(remote_address);
    }

    if (rtcp_report_service_ != nullptr)
    {
        rtcp_report_service_->forget_peer(remote_address);

        rtcp_forgot = true;
    }

    if (rtcp_transport_cc_feedback_service_ != nullptr)
    {
        rtcp_transport_cc_feedback_service_->forget_peer(remote_address);

        transport_cc_forgot = true;
    }

    WEBRTC_LOG_INFO("ice udp peer transport state forgotten remote={} dtls={} srtp={} router={} track={} rtcp={} transport_cc={}",
                    remote_address,
                    dtls_forgot ? 1 : 0,
                    srtp_forgot ? 1 : 0,
                    router_forgot ? 1 : 0,
                    track_forgot ? 1 : 0,
                    rtcp_forgot ? 1 : 0,
                    transport_cc_forgot ? 1 : 0);
}

void ice_udp_server::forget_peer_runtime_state_without_dtls_srtp(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    bool router_forgot = false;
    bool track_forgot = false;
    bool rtcp_forgot = false;
    bool transport_cc_forgot = false;

    if (media_router_ != nullptr)
    {
        media_router_->forget_peer(remote_address);

        router_forgot = true;
    }

    if (track_resolver_ != nullptr)
    {
        track_resolver_->forget_peer(remote_address);

        track_forgot = true;
    }

    if (identity_authority_ != nullptr)
    {
        identity_authority_->forget_peer(remote_address);
    }

    if (rtcp_report_service_ != nullptr)
    {
        rtcp_report_service_->forget_peer(remote_address);

        rtcp_forgot = true;
    }

    if (rtcp_transport_cc_feedback_service_ != nullptr)
    {
        rtcp_transport_cc_feedback_service_->forget_peer(remote_address);

        transport_cc_forgot = true;
    }

    WEBRTC_LOG_INFO("ice udp peer runtime state forgotten without dtls srtp remote={} router={} track={} rtcp={} transport_cc={}",
                    remote_address,
                    router_forgot ? 1 : 0,
                    track_forgot ? 1 : 0,
                    rtcp_forgot ? 1 : 0,
                    transport_cc_forgot ? 1 : 0);
}

bool ice_udp_server::migrate_peer_transport_state_for_ice_restart(std::string_view old_remote_address,
                                                                  std::string_view new_remote_address,
                                                                  const dtls_peer_identity& identity)
{
    if (old_remote_address.empty() || new_remote_address.empty())
    {
        return false;
    }

    bool dtls_migrated = false;
    bool srtp_migrated = false;

    if (dtls_transport_ != nullptr)
    {
        dtls_migrated = dtls_transport_->move_peer(old_remote_address, new_remote_address, identity);
    }

    if (srtp_transport_ != nullptr)
    {
        srtp_migrated = srtp_transport_->move_peer(old_remote_address, new_remote_address, identity);
    }

    if (!dtls_migrated && !srtp_migrated)
    {
        WEBRTC_LOG_DEBUG("ice udp peer transport migration skipped old_remote={} new_remote={} session={} stream={} generation={}",
                         old_remote_address,
                         new_remote_address,
                         identity.session_id,
                         identity.stream_id,
                         identity.generation);

        return false;
    }

    if (old_remote_address != new_remote_address)
    {
        forget_peer_runtime_state_without_dtls_srtp(old_remote_address);
    }

    WEBRTC_LOG_INFO("ice udp peer transport state migrated old_remote={} new_remote={} session={} stream={} generation={} dtls={} srtp={}",
                    old_remote_address,
                    new_remote_address,
                    identity.session_id,
                    identity.stream_id,
                    identity.generation,
                    dtls_migrated ? 1 : 0,
                    srtp_migrated ? 1 : 0);

    return true;
}
void ice_udp_server::erase_candidate_pairs_for_session_locked(std::string_view session_id)
{
    for (auto iterator = candidate_pairs_by_key_.begin(); iterator != candidate_pairs_by_key_.end();)
    {
        if (iterator->second.session_id == session_id)
        {
            iterator = candidate_pairs_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void ice_udp_server::erase_candidate_pairs_for_endpoint_locked(std::string_view remote_address)
{
    for (auto iterator = candidate_pairs_by_key_.begin(); iterator != candidate_pairs_by_key_.end();)
    {
        if (iterator->second.remote_address == remote_address)
        {
            iterator = candidate_pairs_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}
std::vector<std::pair<std::string, boost::asio::ip::udp::endpoint>> ice_udp_server::collect_session_endpoint_snapshots_locked(
    std::string_view session_id) const
{
    std::vector<std::pair<std::string, boost::asio::ip::udp::endpoint>> snapshots;

    if (session_id.empty())
    {
        return snapshots;
    }

    const std::string session_key(session_id);

    auto remember_remote_address = [&](std::string_view remote_address)
    {
        if (remote_address.empty())
        {
            return;
        }

        const std::string remote_key(remote_address);

        for (const auto& snapshot : snapshots)
        {
            if (snapshot.first == remote_key)
            {
                return;
            }
        }

        const auto endpoint_iterator = endpoints_by_address_.find(remote_key);

        if (endpoint_iterator == endpoints_by_address_.end())
        {
            return;
        }

        snapshots.emplace_back(remote_key, endpoint_iterator->second);
    };

    const auto forward_iterator = endpoint_address_by_session_id_.find(session_key);

    if (forward_iterator != endpoint_address_by_session_id_.end())
    {
        remember_remote_address(forward_iterator->second);
    }

    for (const auto& [remote_address, current_session_id] : session_id_by_endpoint_address_)
    {
        if (current_session_id != session_key)
        {
            continue;
        }

        remember_remote_address(remote_address);
    }

    for (const auto& [key, pair] : candidate_pairs_by_key_)
    {
        (void)key;

        if (pair.session_id != session_key)
        {
            continue;
        }

        remember_remote_address(pair.remote_address);
    }

    return snapshots;
}

std::vector<std::string> ice_udp_server::erase_endpoint_indexes_for_session_locked(std::string_view session_id)
{
    std::vector<std::string> remote_addresses;

    if (session_id.empty())
    {
        return remote_addresses;
    }

    const std::string session_key(session_id);

    const auto forward_iterator = endpoint_address_by_session_id_.find(session_key);

    if (forward_iterator != endpoint_address_by_session_id_.end())
    {
        if (!contains_string(remote_addresses, forward_iterator->second))
        {
            remote_addresses.push_back(forward_iterator->second);
        }
    }

    for (const auto& [remote_address, current_session_id] : session_id_by_endpoint_address_)
    {
        if (current_session_id != session_key)
        {
            continue;
        }

        if (contains_string(remote_addresses, remote_address))
        {
            continue;
        }

        remote_addresses.push_back(remote_address);
    }

    for (const auto& [key, pair] : candidate_pairs_by_key_)
    {
        (void)key;

        if (pair.session_id != session_key)
        {
            continue;
        }

        if (pair.remote_address.empty())
        {
            continue;
        }

        if (contains_string(remote_addresses, pair.remote_address))
        {
            continue;
        }

        remote_addresses.push_back(pair.remote_address);
    }

    endpoint_address_by_session_id_.erase(session_key);

    for (const auto& remote_address : remote_addresses)
    {
        session_id_by_endpoint_address_.erase(remote_address);

        endpoints_by_address_.erase(remote_address);

        endpoint_last_seen_milliseconds_by_address_.erase(remote_address);
    }

    return remote_addresses;
}

void ice_udp_server::erase_endpoint_indexes_for_remote_locked(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    const std::string remote_key(remote_address);

    const auto reverse_iterator = session_id_by_endpoint_address_.find(remote_key);

    if (reverse_iterator != session_id_by_endpoint_address_.end())
    {
        const std::string session_id = reverse_iterator->second;

        session_id_by_endpoint_address_.erase(reverse_iterator);

        const auto forward_iterator = endpoint_address_by_session_id_.find(session_id);

        if (forward_iterator != endpoint_address_by_session_id_.end() && forward_iterator->second == remote_key)
        {
            endpoint_address_by_session_id_.erase(forward_iterator);
        }
    }

    for (auto iterator = endpoint_address_by_session_id_.begin(); iterator != endpoint_address_by_session_id_.end();)
    {
        if (iterator->second == remote_key)
        {
            iterator = endpoint_address_by_session_id_.erase(iterator);

            continue;
        }

        ++iterator;
    }

    endpoints_by_address_.erase(remote_key);

    endpoint_last_seen_milliseconds_by_address_.erase(remote_key);

    erase_candidate_pairs_for_endpoint_locked(remote_key);
}

void ice_udp_server::cleanup_stale_current_session_endpoint(std::string remote_address, std::string session_id, std::string reason)
{
    if (remote_address.empty())
    {
        return;
    }

    bool had_endpoint_index = false;
    std::size_t orphan_endpoint_indexes_erased = 0;

    {
        std::lock_guard lock(endpoint_mutex_);

        had_endpoint_index = endpoints_by_address_.contains(remote_address) || session_id_by_endpoint_address_.contains(remote_address) ||
                             endpoint_last_seen_milliseconds_by_address_.contains(remote_address);

        if (!session_id.empty())
        {
            had_endpoint_index = had_endpoint_index || endpoint_address_by_session_id_.contains(session_id);
        }

        erase_endpoint_indexes_for_remote_locked(remote_address);

        retire_endpoint_locked(remote_address, session_id, now_milliseconds(), reason);

        orphan_endpoint_indexes_erased = erase_orphan_endpoint_indexes_locked();
    }

    forget_peer_transport_state(remote_address);

    WEBRTC_LOG_INFO("ice udp current session gate cleanup remote={} session={} reason={} had_endpoint_index={} orphan_endpoint_indexes_erased={}",
                    remote_address,
                    session_id,
                    reason,
                    had_endpoint_index ? 1 : 0,
                    orphan_endpoint_indexes_erased);
}

void ice_udp_server::retire_endpoint_locked(std::string_view remote_address,
                                            std::string_view session_id,
                                            uint64_t current_time_milliseconds,
                                            std::string_view reason)
{
    if (remote_address.empty())
    {
        return;
    }

    expire_retired_endpoints_locked(current_time_milliseconds);

    const std::string remote_key(remote_address);

    retired_endpoint_state& state = retired_endpoints_by_address_[remote_key];

    if (state.expires_at_milliseconds != 0 && current_time_milliseconds >= state.expires_at_milliseconds)
    {
        state.suppressed_packets = 0;
    }

    state.expires_at_milliseconds = current_time_milliseconds + k_retired_endpoint_retention_milliseconds;

    state.session_id = std::string(session_id);

    state.reason = std::string(reason);

    const std::size_t pruned_count = prune_retired_endpoints_to_limit_locked(current_time_milliseconds, remote_key);

    if (pruned_count != 0)
    {
        WEBRTC_LOG_INFO("ice udp retired endpoint limit prune count={} size={} limit={}",
                        pruned_count,
                        retired_endpoints_by_address_.size(),
                        k_max_retired_endpoints);
    }

    WEBRTC_LOG_DEBUG("ice udp endpoint retired remote={} session={} reason={} ttl_ms={}",
                     remote_address,
                     session_id,
                     reason,
                     k_retired_endpoint_retention_milliseconds);
}

void ice_udp_server::retire_removed_session_ice_credentials(const stream_removed_session& removed_session, std::string_view reason)
{
    if (removed_session.local_ice_ufrag.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    retire_ice_credentials_locked(removed_session.local_ice_ufrag,
                                  removed_session.remote_ice_ufrag,
                                  removed_session.stream_id,
                                  removed_session.session_id,
                                  now_milliseconds(),
                                  reason);
}
void ice_udp_server::retire_restarted_session_ice_credentials(const stream_restarted_session& restarted_session, std::string_view reason)
{
    if (restarted_session.old_local_ice_ufrag.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    retire_ice_credentials_locked(restarted_session.old_local_ice_ufrag,
                                  restarted_session.old_remote_ice_ufrag,
                                  restarted_session.stream_id,
                                  restarted_session.session_id,
                                  now_milliseconds(),
                                  reason);
}

void ice_udp_server::retire_republished_publisher_ice_credentials(const stream_republished_session& republished_session, std::string_view reason)
{
    if (republished_session.old_local_ice_ufrag.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    retire_ice_credentials_locked(republished_session.old_local_ice_ufrag,
                                  republished_session.old_remote_ice_ufrag,
                                  republished_session.stream_id,
                                  republished_session.old_session_id,
                                  now_milliseconds(),
                                  reason);
}
void ice_udp_server::retire_old_publisher_endpoint_for_republish(const stream_republished_session& republished_session, std::string_view reason)
{
    if (republished_session.old_session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = endpoint_address_by_session_id_.find(republished_session.old_session_id);

    if (iterator == endpoint_address_by_session_id_.end())
    {
        return;
    }

    /*
     * Republish creates a new logical publisher session id.
     * Keep the retired endpoint associated with the old session id:
     *   - old DTLS/SRTP from the old publisher endpoint is suppressed
     *   - new publisher STUN uses a different session id and can be selected
     */
    retire_endpoint_locked(iterator->second, republished_session.old_session_id, now_milliseconds(), reason);
}
void ice_udp_server::retire_session_endpoint_for_ice_restart(const stream_restarted_session& restarted_session, std::string_view reason)
{
    if (restarted_session.session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = endpoint_address_by_session_id_.find(restarted_session.session_id);

    if (iterator == endpoint_address_by_session_id_.end())
    {
        return;
    }

    /*
     * ICE restart keeps the same logical session id.
     * Retire the old endpoint with an empty session id so that:
     *   - old DTLS/SRTP from the old endpoint is suppressed by remote address
     *   - new valid STUN for the same logical session can pass verification
     *     and clear the retired endpoint in accept_retired_endpoint_reuse_after_valid_stun
     */
    retire_endpoint_locked(iterator->second, "", now_milliseconds(), reason);
}

void ice_udp_server::retire_ice_credentials_locked(std::string_view local_ice_ufrag,
                                                   std::string_view remote_ice_ufrag,
                                                   std::string_view stream_id,
                                                   std::string_view session_id,
                                                   uint64_t current_time_milliseconds,
                                                   std::string_view reason)
{
    if (local_ice_ufrag.empty())
    {
        return;
    }

    expire_retired_ice_credentials_locked(current_time_milliseconds);

    const std::string local_ice_ufrag_key(local_ice_ufrag);

    retired_ice_credential_state& state = retired_ice_credentials_by_local_ufrag_[local_ice_ufrag_key];

    if (state.expires_at_milliseconds != 0 && current_time_milliseconds >= state.expires_at_milliseconds)
    {
        state.suppressed_stun_packets = 0;
    }

    state.expires_at_milliseconds = current_time_milliseconds + k_retired_endpoint_retention_milliseconds;

    state.stream_id = std::string(stream_id);

    state.session_id = std::string(session_id);

    state.local_ice_ufrag = std::string(local_ice_ufrag);

    state.remote_ice_ufrag = std::string(remote_ice_ufrag);

    state.reason = std::string(reason);

    const std::size_t pruned_count = prune_retired_ice_credentials_to_limit_locked(current_time_milliseconds, local_ice_ufrag_key);

    if (pruned_count != 0)
    {
        WEBRTC_LOG_INFO("ice retired credential limit prune count={} size={} limit={}",
                        pruned_count,
                        retired_ice_credentials_by_local_ufrag_.size(),
                        k_max_retired_ice_credentials);
    }

    WEBRTC_LOG_DEBUG("ice credentials retired stream={} session={} local_ufrag={} remote_ufrag={} reason={} ttl_ms={}",
                     stream_id,
                     session_id,
                     local_ice_ufrag,
                     remote_ice_ufrag,
                     reason,
                     k_retired_endpoint_retention_milliseconds);
}

bool ice_udp_server::suppress_retired_ice_credential_stun(std::string_view local_ice_ufrag,
                                                          std::string_view remote_ice_ufrag,
                                                          std::string_view remote_address)
{
    if (local_ice_ufrag.empty())
    {
        return false;
    }

    std::lock_guard lock(endpoint_mutex_);

    const uint64_t current_time_milliseconds = now_milliseconds();
    const std::size_t expired_count = expire_retired_ice_credentials_locked(current_time_milliseconds);

    if (expired_count != 0)
    {
        WEBRTC_LOG_DEBUG("ice retired credentials expired during retired credential stun suppression count={}", expired_count);
    }

    const auto iterator = retired_ice_credentials_by_local_ufrag_.find(std::string(local_ice_ufrag));
    if (iterator == retired_ice_credentials_by_local_ufrag_.end())
    {
        return false;
    }

    retired_ice_credential_state& state = iterator->second;

    if (!state.remote_ice_ufrag.empty() && std::string_view(state.remote_ice_ufrag) != remote_ice_ufrag)
    {
        return false;
    }

    state.suppressed_stun_packets += 1;

    if (state.suppressed_stun_packets == 1)
    {
        WEBRTC_LOG_DEBUG("ice retired credential stun ignored remote={} stream={} session={} local_ufrag={} remote_ufrag={} reason={}",
                         remote_address,
                         state.stream_id,
                         state.session_id,
                         local_ice_ufrag,
                         remote_ice_ufrag,
                         state.reason);
    }

    return true;
}

std::size_t ice_udp_server::expire_retired_ice_credentials_locked(uint64_t current_time_milliseconds)
{
    std::size_t expired_count = 0;

    for (auto iterator = retired_ice_credentials_by_local_ufrag_.begin(); iterator != retired_ice_credentials_by_local_ufrag_.end();)
    {
        const retired_ice_credential_state& state = iterator->second;

        if (state.expires_at_milliseconds == 0 || current_time_milliseconds < state.expires_at_milliseconds)
        {
            ++iterator;

            continue;
        }

        if (state.suppressed_stun_packets != 0)
        {
            WEBRTC_LOG_INFO("ice retired credential expired stream={} session={} local_ufrag={} remote_ufrag={} reason={} suppressed_stun_packets={}",
                            state.stream_id,
                            state.session_id,
                            state.local_ice_ufrag,
                            state.remote_ice_ufrag,
                            state.reason,
                            state.suppressed_stun_packets);
        }
        else
        {
            WEBRTC_LOG_DEBUG("ice retired credential expired stream={} session={} local_ufrag={} remote_ufrag={} reason={}",
                             state.stream_id,
                             state.session_id,
                             state.local_ice_ufrag,
                             state.remote_ice_ufrag,
                             state.reason);
        }

        iterator = retired_ice_credentials_by_local_ufrag_.erase(iterator);

        expired_count += 1;
    }

    return expired_count;
}

std::size_t ice_udp_server::prune_retired_ice_credentials_to_limit_locked(uint64_t current_time_milliseconds,
                                                                          std::string_view protected_local_ice_ufrag)
{
    std::size_t pruned_count = 0;

    while (retired_ice_credentials_by_local_ufrag_.size() > k_max_retired_ice_credentials)
    {
        auto oldest_iterator = retired_ice_credentials_by_local_ufrag_.end();

        for (auto iterator = retired_ice_credentials_by_local_ufrag_.begin(); iterator != retired_ice_credentials_by_local_ufrag_.end(); ++iterator)
        {
            if (std::string_view(iterator->first) == protected_local_ice_ufrag)
            {
                continue;
            }

            if (oldest_iterator == retired_ice_credentials_by_local_ufrag_.end() ||
                iterator->second.expires_at_milliseconds < oldest_iterator->second.expires_at_milliseconds)
            {
                oldest_iterator = iterator;
            }
        }

        if (oldest_iterator == retired_ice_credentials_by_local_ufrag_.end())
        {
            return pruned_count;
        }

        const retired_ice_credential_state state = oldest_iterator->second;

        WEBRTC_LOG_WARN(
            "ice retired credential pruned by limit stream={} session={} local_ufrag={} remote_ufrag={} reason={} expires_at={} now={} "
            "suppressed_stun_packets={}",
            state.stream_id,
            state.session_id,
            state.local_ice_ufrag,
            state.remote_ice_ufrag,
            state.reason,
            state.expires_at_milliseconds,
            current_time_milliseconds,
            state.suppressed_stun_packets);

        retired_ice_credentials_by_local_ufrag_.erase(oldest_iterator);

        pruned_count += 1;
    }

    return pruned_count;
}

void ice_udp_server::unretire_endpoint_locked(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    const auto iterator = retired_endpoints_by_address_.find(std::string(remote_address));

    if (iterator == retired_endpoints_by_address_.end())
    {
        return;
    }

    const retired_endpoint_state state = iterator->second;

    retired_endpoints_by_address_.erase(iterator);

    if (state.suppressed_packets != 0)
    {
        WEBRTC_LOG_INFO("ice udp retired endpoint resumed remote={} session={} reason={} suppressed_packets={}",
                        remote_address,
                        state.session_id,
                        state.reason,
                        state.suppressed_packets);
    }
}

void ice_udp_server::unretire_endpoint(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    unretire_endpoint_locked(remote_address);
}

std::optional<ice_udp_server::retired_endpoint_state> ice_udp_server::find_retired_endpoint_state_locked(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return std::nullopt;
    }

    const auto iterator = retired_endpoints_by_address_.find(std::string(remote_address));

    if (iterator == retired_endpoints_by_address_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

void ice_udp_server::accept_retired_endpoint_reuse_after_valid_stun(std::string_view remote_address,
                                                                    std::string_view stream_id,
                                                                    std::string_view session_id,
                                                                    std::string_view local_ice_ufrag,
                                                                    std::string_view remote_ice_ufrag)
{
    if (remote_address.empty())
    {
        return;
    }

    std::optional<retired_endpoint_state> previous_state;

    {
        std::lock_guard lock(endpoint_mutex_);

        expire_retired_endpoints_locked(now_milliseconds());

        previous_state = find_retired_endpoint_state_locked(remote_address);

        if (!previous_state.has_value())
        {
            return;
        }

        retired_endpoints_by_address_.erase(std::string(remote_address));
    }

    const bool reused_by_different_session = previous_state->session_id.empty() || previous_state->session_id != session_id;

    if (reused_by_different_session)
    {
        WEBRTC_LOG_INFO(
            "ice udp retired endpoint reused by valid stun remote={} old_session={} new_session={} stream={} local_ufrag={} remote_ufrag={} "
            "retired_reason={} suppressed_packets={}",
            remote_address,
            previous_state->session_id,
            session_id,
            stream_id,
            local_ice_ufrag,
            remote_ice_ufrag,
            previous_state->reason,
            previous_state->suppressed_packets);

        return;
    }

    if (previous_state->suppressed_packets != 0)
    {
        WEBRTC_LOG_INFO(
            "ice udp retired endpoint resumed by valid stun remote={} session={} stream={} local_ufrag={} remote_ufrag={} retired_reason={} "
            "suppressed_packets={}",
            remote_address,
            session_id,
            stream_id,
            local_ice_ufrag,
            remote_ice_ufrag,
            previous_state->reason,
            previous_state->suppressed_packets);

        return;
    }

    WEBRTC_LOG_DEBUG("ice udp retired endpoint resumed by valid stun remote={} session={} stream={} local_ufrag={} remote_ufrag={} retired_reason={}",
                     remote_address,
                     session_id,
                     stream_id,
                     local_ice_ufrag,
                     remote_ice_ufrag,
                     previous_state->reason);
}

bool ice_udp_server::retired_endpoint_matches_session(std::string_view remote_address, std::string_view session_id)
{
    if (remote_address.empty() || session_id.empty())
    {
        return false;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    expire_retired_endpoints_locked(current_time_milliseconds);

    const auto iterator = retired_endpoints_by_address_.find(std::string(remote_address));

    if (iterator == retired_endpoints_by_address_.end())
    {
        return false;
    }

    if (iterator->second.session_id.empty())
    {
        return false;
    }

    return iterator->second.session_id == session_id;
}

bool ice_udp_server::suppress_retired_endpoint_packet(std::string_view remote_address, std::string_view packet_kind)
{
    if (remote_address.empty())
    {
        return false;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::lock_guard lock(endpoint_mutex_);

    expire_retired_endpoints_locked(current_time_milliseconds);

    const auto iterator = retired_endpoints_by_address_.find(std::string(remote_address));

    if (iterator == retired_endpoints_by_address_.end())
    {
        return false;
    }

    iterator->second.suppressed_packets += 1;

    if (iterator->second.suppressed_packets == 1)
    {
        WEBRTC_LOG_DEBUG("ice udp retired endpoint packet ignored remote={} kind={} session={} reason={}",
                         remote_address,
                         packet_kind,
                         iterator->second.session_id,
                         iterator->second.reason);
    }

    return true;
}

std::size_t ice_udp_server::expire_retired_endpoints_locked(uint64_t current_time_milliseconds)
{
    std::size_t expired_count = 0;

    for (auto iterator = retired_endpoints_by_address_.begin(); iterator != retired_endpoints_by_address_.end();)
    {
        if (iterator->second.expires_at_milliseconds == 0 || current_time_milliseconds < iterator->second.expires_at_milliseconds)
        {
            ++iterator;

            continue;
        }

        if (iterator->second.suppressed_packets != 0)
        {
            WEBRTC_LOG_INFO("ice udp retired endpoint expired remote={} session={} reason={} suppressed_packets={}",
                            iterator->first,
                            iterator->second.session_id,
                            iterator->second.reason,
                            iterator->second.suppressed_packets);
        }
        else
        {
            WEBRTC_LOG_DEBUG("ice udp retired endpoint expired remote={} session={} reason={}",
                             iterator->first,
                             iterator->second.session_id,
                             iterator->second.reason);
        }

        iterator = retired_endpoints_by_address_.erase(iterator);

        expired_count += 1;
    }

    return expired_count;
}

std::size_t ice_udp_server::prune_retired_endpoints_to_limit_locked(uint64_t current_time_milliseconds, std::string_view protected_remote_address)
{
    std::size_t pruned_count = 0;

    while (retired_endpoints_by_address_.size() > k_max_retired_endpoints)
    {
        auto oldest_iterator = retired_endpoints_by_address_.end();

        for (auto iterator = retired_endpoints_by_address_.begin(); iterator != retired_endpoints_by_address_.end(); ++iterator)
        {
            if (std::string_view(iterator->first) == protected_remote_address)
            {
                continue;
            }

            if (oldest_iterator == retired_endpoints_by_address_.end() ||
                iterator->second.expires_at_milliseconds < oldest_iterator->second.expires_at_milliseconds)
            {
                oldest_iterator = iterator;
            }
        }

        if (oldest_iterator == retired_endpoints_by_address_.end())
        {
            return pruned_count;
        }

        const retired_endpoint_state state = oldest_iterator->second;

        WEBRTC_LOG_WARN("ice udp retired endpoint pruned by limit remote={} session={} reason={} expires_at={} now={} suppressed_packets={}",
                        oldest_iterator->first,
                        state.session_id,
                        state.reason,
                        state.expires_at_milliseconds,
                        current_time_milliseconds,
                        state.suppressed_packets);

        retired_endpoints_by_address_.erase(oldest_iterator);

        pruned_count += 1;
    }

    return pruned_count;
}

std::size_t ice_udp_server::erase_orphan_endpoint_indexes_locked()
{
    std::vector<std::string> orphan_remote_addresses;

    for (const auto& [remote_address, session_id] : session_id_by_endpoint_address_)
    {
        const auto forward_iterator = endpoint_address_by_session_id_.find(session_id);

        if (forward_iterator != endpoint_address_by_session_id_.end() && forward_iterator->second == remote_address)
        {
            continue;
        }

        if (!contains_string(orphan_remote_addresses, remote_address))
        {
            orphan_remote_addresses.push_back(remote_address);
        }
    }

    for (const auto& [session_id, remote_address] : endpoint_address_by_session_id_)
    {
        const auto reverse_iterator = session_id_by_endpoint_address_.find(remote_address);

        if (reverse_iterator != session_id_by_endpoint_address_.end() && reverse_iterator->second == session_id)
        {
            continue;
        }

        if (!contains_string(orphan_remote_addresses, remote_address))
        {
            orphan_remote_addresses.push_back(remote_address);
        }
    }

    for (const auto& [remote_address, endpoint] : endpoints_by_address_)
    {
        (void)endpoint;

        if (session_id_by_endpoint_address_.contains(remote_address))
        {
            continue;
        }

        if (!contains_string(orphan_remote_addresses, remote_address))
        {
            orphan_remote_addresses.push_back(remote_address);
        }
    }

    for (const auto& [remote_address, last_seen] : endpoint_last_seen_milliseconds_by_address_)
    {
        (void)last_seen;

        if (session_id_by_endpoint_address_.contains(remote_address))
        {
            continue;
        }

        if (!contains_string(orphan_remote_addresses, remote_address))
        {
            orphan_remote_addresses.push_back(remote_address);
        }
    }

    for (const auto& remote_address : orphan_remote_addresses)
    {
        erase_endpoint_indexes_for_remote_locked(remote_address);
    }

    return orphan_remote_addresses.size();
}

void ice_udp_server::erase_payload_type_mappings_for_session_locked(std::string_view session_id)
{
    for (auto iterator = payload_type_mappings_by_key_.begin(); iterator != payload_type_mappings_by_key_.end();)
    {
        if (iterator->second.publisher_session_id == session_id || iterator->second.subscriber_session_id == session_id)
        {
            iterator = payload_type_mappings_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

std::size_t ice_udp_server::erase_payload_type_mappings_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = payload_type_mappings_by_key_.begin(); iterator != payload_type_mappings_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = payload_type_mappings_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}

std::size_t ice_udp_server::erase_keyframe_request_states_for_session_locked(std::string_view session_id)
{
    if (session_id.empty())
    {
        return 0;
    }

    std::size_t erased_count = 0;

    for (auto iterator = keyframe_request_last_time_milliseconds_by_key_.begin(); iterator != keyframe_request_last_time_milliseconds_by_key_.end();)
    {
        if (keyframe_request_key_matches_session(iterator->first, session_id))
        {
            iterator = keyframe_request_last_time_milliseconds_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}
void ice_udp_server::forget_keyframe_request_states_for_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    const std::size_t erased_count = erase_keyframe_request_states_for_session_locked(session_id);

    WEBRTC_LOG_DEBUG("ice udp keyframe request states forgotten session={} count={}", session_id, erased_count);
}

std::size_t ice_udp_server::erase_keyframe_request_states_for_stream_locked(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return 0;
    }

    const std::string prefix = std::string(stream_id) + "|";

    std::size_t erased_count = 0;

    for (auto iterator = keyframe_request_last_time_milliseconds_by_key_.begin(); iterator != keyframe_request_last_time_milliseconds_by_key_.end();)
    {
        if (iterator->first.starts_with(prefix))
        {
            iterator = keyframe_request_last_time_milliseconds_by_key_.erase(iterator);

            erased_count += 1;

            continue;
        }

        ++iterator;
    }

    return erased_count;
}

std::optional<std::string> ice_udp_server::find_session_id_by_endpoint(std::string_view remote_address) const
{
    if (remote_address.empty())
    {
        return std::nullopt;
    }

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = session_id_by_endpoint_address_.find(std::string(remote_address));

    if (iterator == session_id_by_endpoint_address_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

ice_udp_server::current_session_endpoint_state ice_udp_server::find_current_session_endpoint(std::string_view remote_address,
                                                                                             std::string_view packet_kind)
{
    return validate_current_session_endpoint(remote_address, "", "", packet_kind);
}

ice_udp_server::current_session_endpoint_state ice_udp_server::validate_current_session_endpoint(std::string_view remote_address,
                                                                                                 std::string_view expected_session_id,
                                                                                                 std::string_view expected_stream_id,
                                                                                                 std::string_view packet_kind)
{
    current_session_endpoint_state state;

    state.remote_address = std::string(remote_address);

    if (remote_address.empty())
    {
        state.reject_reason = "remote endpoint is empty";

        return state;
    }

    std::string mapped_session_id;

    {
        std::lock_guard lock(endpoint_mutex_);

        const auto iterator = session_id_by_endpoint_address_.find(std::string(remote_address));

        if (iterator == session_id_by_endpoint_address_.end())
        {
            state.reject_reason = "endpoint is not selected";

            return state;
        }

        mapped_session_id = iterator->second;
    }

    state.session_id = mapped_session_id;

    if (!expected_session_id.empty() && mapped_session_id != expected_session_id)
    {
        state.reject_reason = "endpoint session does not match expected session";

        return state;
    }

    if (registry_ == nullptr)
    {
        state.reject_reason = "registry is unavailable";

        return state;
    }

    auto publisher = registry_->find_publisher_by_session_id(mapped_session_id);

    if (publisher != nullptr)
    {
        state.kind = stream_session_kind::publisher;
        state.stream_id = publisher->stream_id();
    }
    else
    {
        auto subscriber = registry_->find_subscriber_by_session_id(mapped_session_id);

        if (subscriber != nullptr)
        {
            state.kind = stream_session_kind::subscriber;
            state.stream_id = subscriber->stream_id();
        }
    }

    if (state.stream_id.empty())
    {
        state.stale_endpoint = true;
        state.reject_reason = "session is missing from registry";

        std::string cleanup_reason(packet_kind);

        cleanup_reason.append(" current session gate");

        cleanup_stale_current_session_endpoint(std::string(remote_address), std::move(mapped_session_id), std::move(cleanup_reason));

        return state;
    }

    if (!expected_stream_id.empty() && state.stream_id != expected_stream_id)
    {
        state.reject_reason = "endpoint stream does not match expected stream";

        return state;
    }

    state.allowed = true;

    return state;
}

bool ice_udp_server::outbound_media_runtime_ready(std::string_view remote_address,
                                                  std::string_view expected_session_id,
                                                  std::string_view expected_stream_id,
                                                  media_peer_role expected_role,
                                                  std::string_view packet_kind)
{
    if (remote_address.empty() || expected_session_id.empty() || expected_stream_id.empty())
    {
        WEBRTC_LOG_DEBUG("outbound media runtime gate rejected empty identity remote={} session={} stream={} kind={}",
                         remote_address,
                         expected_session_id,
                         expected_stream_id,
                         packet_kind);

        return false;
    }

    if (expected_role != media_peer_role::publisher && expected_role != media_peer_role::subscriber)
    {
        WEBRTC_LOG_DEBUG("outbound media runtime gate rejected unknown role remote={} session={} stream={} kind={}",
                         remote_address,
                         expected_session_id,
                         expected_stream_id,
                         packet_kind);

        return false;
    }

    if (registry_ == nullptr)
    {
        WEBRTC_LOG_WARN("outbound media runtime gate rejected registry unavailable remote={} session={} stream={} role={} kind={}",
                        remote_address,
                        expected_session_id,
                        expected_stream_id,
                        media_peer_role_to_string(expected_role),
                        packet_kind);

        return false;
    }

    if (media_router_ == nullptr)
    {
        WEBRTC_LOG_WARN("outbound media runtime gate rejected media router unavailable remote={} session={} stream={} role={} kind={}",
                        remote_address,
                        expected_session_id,
                        expected_stream_id,
                        media_peer_role_to_string(expected_role),
                        packet_kind);

        return false;
    }

    const stream_session_kind expected_session_kind =
        expected_role == media_peer_role::publisher ? stream_session_kind::publisher : stream_session_kind::subscriber;

    const current_session_endpoint_state current_session =
        validate_current_session_endpoint(remote_address, expected_session_id, expected_stream_id, packet_kind);

    if (!current_session.allowed)
    {
        WEBRTC_LOG_DEBUG("outbound media runtime gate rejected by current session gate remote={} session={} stream={} role={} kind={} reason={}",
                         remote_address,
                         expected_session_id,
                         expected_stream_id,
                         media_peer_role_to_string(expected_role),
                         packet_kind,
                         current_session.reject_reason);

        return false;
    }

    if (current_session.kind != expected_session_kind)
    {
        WEBRTC_LOG_DEBUG("outbound media runtime gate rejected session kind mismatch remote={} session={} stream={} expected_role={} kind={}",
                         remote_address,
                         expected_session_id,
                         expected_stream_id,
                         media_peer_role_to_string(expected_role),
                         packet_kind);

        return false;
    }

    const std::optional<media_peer_info> peer = media_router_->get_peer(remote_address);

    if (!peer.has_value())
    {
        WEBRTC_LOG_DEBUG("outbound media runtime gate rejected peer not found remote={} session={} stream={} role={} kind={}",
                         remote_address,
                         expected_session_id,
                         expected_stream_id,
                         media_peer_role_to_string(expected_role),
                         packet_kind);

        return false;
    }

    if (peer->session_id != expected_session_id || peer->stream_id != expected_stream_id || peer->role != expected_role)
    {
        WEBRTC_LOG_DEBUG(
            "outbound media runtime gate rejected peer mismatch remote={} expected_session={} expected_stream={} expected_role={} "
            "peer_session={} peer_stream={} peer_role={} kind={}",
            remote_address,
            expected_session_id,
            expected_stream_id,
            media_peer_role_to_string(expected_role),
            peer->session_id,
            peer->stream_id,
            media_peer_role_to_string(peer->role),
            packet_kind);

        return false;
    }

    std::size_t accepted_mline_count = 0;

    if (expected_role == media_peer_role::publisher)
    {
        auto publisher = registry_->find_publisher_by_session_id(expected_session_id);

        if (publisher == nullptr)
        {
            WEBRTC_LOG_DEBUG("outbound media runtime gate rejected publisher missing remote={} session={} stream={} kind={}",
                             remote_address,
                             expected_session_id,
                             expected_stream_id,
                             packet_kind);

            return false;
        }

        if (publisher->stream_id() != expected_stream_id)
        {
            WEBRTC_LOG_DEBUG(
                "outbound media runtime gate rejected publisher stream mismatch remote={} session={} expected_stream={} actual_stream={} kind={}",
                remote_address,
                expected_session_id,
                expected_stream_id,
                publisher->stream_id(),
                packet_kind);

            return false;
        }

        accepted_mline_count = publisher->accepted_remote_media_mline_indexes().size();
    }
    else
    {
        auto subscriber = registry_->find_subscriber_by_session_id(expected_session_id);

        if (subscriber == nullptr)
        {
            WEBRTC_LOG_DEBUG("outbound media runtime gate rejected subscriber missing remote={} session={} stream={} kind={}",
                             remote_address,
                             expected_session_id,
                             expected_stream_id,
                             packet_kind);

            return false;
        }

        if (subscriber->stream_id() != expected_stream_id)
        {
            WEBRTC_LOG_DEBUG(
                "outbound media runtime gate rejected subscriber stream mismatch remote={} session={} expected_stream={} actual_stream={} kind={}",
                remote_address,
                expected_session_id,
                expected_stream_id,
                subscriber->stream_id(),
                packet_kind);

            return false;
        }

        accepted_mline_count = subscriber->accepted_remote_media_mline_indexes().size();
    }

    if (accepted_mline_count == 0)
    {
        WEBRTC_LOG_DEBUG("outbound media runtime gate rejected accepted media not ready remote={} session={} stream={} role={} kind={}",
                         remote_address,
                         expected_session_id,
                         expected_stream_id,
                         media_peer_role_to_string(expected_role),
                         packet_kind);

        return false;
    }

    return true;
}

std::optional<dtls_peer_identity> ice_udp_server::current_dtls_identity_for_session(std::string_view session_id) const
{
    if (registry_ == nullptr || session_id.empty())
    {
        return std::nullopt;
    }

    auto publisher = registry_->find_publisher_by_session_id(session_id);

    if (publisher != nullptr)
    {
        return make_publisher_dtls_identity(publisher);
    }

    auto subscriber = registry_->find_subscriber_by_session_id(session_id);

    if (subscriber != nullptr)
    {
        return make_subscriber_dtls_identity(subscriber);
    }

    return std::nullopt;
}
std::optional<boost::asio::ip::udp::endpoint> ice_udp_server::find_remote_endpoint(std::string_view remote_address) const
{
    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = endpoints_by_address_.find(std::string(remote_address));

    if (iterator == endpoints_by_address_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

std::shared_ptr<publisher_session> ice_udp_server::find_publisher_for_username(std::string_view username) const
{
    if (registry_ == nullptr)
    {
        return nullptr;
    }

    auto username_parts = parse_ice_username(username);

    if (!username_parts)
    {
        return nullptr;
    }

    auto session = registry_->find_publisher_by_local_ice_ufrag(username_parts->recipient_ufrag);

    if (session == nullptr)
    {
        return nullptr;
    }

    const std::string& expected_remote_ufrag = session->remote_offer_summary().ice_ufrag;

    if (expected_remote_ufrag != username_parts->sender_ufrag)
    {
        WEBRTC_LOG_WARN("ice stun publisher remote ufrag mismatch stream={} session={} expected={} actual={}",
                        session->stream_id(),
                        session->session_id(),
                        expected_remote_ufrag,
                        username_parts->sender_ufrag);

        return nullptr;
    }

    return session;
}

std::shared_ptr<subscriber_session> ice_udp_server::find_subscriber_for_username(std::string_view username) const
{
    if (registry_ == nullptr)
    {
        return nullptr;
    }

    auto username_parts = parse_ice_username(username);

    if (!username_parts)
    {
        return nullptr;
    }

    auto session = registry_->find_subscriber_by_local_ice_ufrag(username_parts->recipient_ufrag);

    if (session == nullptr)
    {
        return nullptr;
    }

    const std::string& expected_remote_ufrag = session->remote_offer_summary().ice_ufrag;

    if (expected_remote_ufrag != username_parts->sender_ufrag)
    {
        WEBRTC_LOG_WARN("ice stun subscriber remote ufrag mismatch stream={} session={} expected={} actual={}",
                        session->stream_id(),
                        session->session_id(),
                        expected_remote_ufrag,
                        username_parts->sender_ufrag);

        return nullptr;
    }

    return session;
}

std::string ice_udp_server::extract_local_ufrag(std::string_view username)
{
    auto username_parts = parse_ice_username(username);

    if (!username_parts)
    {
        return {};
    }

    return std::string(username_parts->recipient_ufrag);
}

std::string ice_udp_server::endpoint_ip(const boost::asio::ip::udp::endpoint& endpoint) { return get_endpoint_ip(endpoint); }
}    // namespace webrtc
