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
constexpr std::size_t k_rtcp_bye_max_ssrcs_per_packet = 31;

constexpr std::size_t k_max_ice_username_fragment_size = 256;

constexpr std::size_t k_max_ice_username_size = k_max_ice_username_fragment_size * 2 + 1;

constexpr auto k_minimum_dtls_timer_delay = std::chrono::milliseconds(1);

constexpr auto k_ice_consent_check_interval = std::chrono::seconds(5);

constexpr auto k_rtcp_report_interval = std::chrono::milliseconds(200);

constexpr auto k_rtcp_report_empty_generation_log_interval = std::chrono::seconds(60);

constexpr uint64_t k_ice_consent_timeout_milliseconds = 30000;

constexpr uint64_t k_unselected_candidate_pair_retention_milliseconds = 120000;

constexpr std::string_view k_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";
constexpr std::string_view k_absolute_send_time_extension_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

constexpr uint64_t k_fnv_offset_basis = 1469598103934665603ULL;

constexpr uint64_t k_fnv_prime = 1099511628211ULL;

constexpr auto k_endpoint_idle_cleanup_interval = std::chrono::seconds(5);

constexpr uint64_t k_retired_endpoint_retention_milliseconds = 15000;

constexpr uint64_t k_lifecycle_fast_convergence_check_delay_milliseconds = 3000;
constexpr uint64_t k_lifecycle_final_convergence_check_delay_milliseconds = k_retired_endpoint_retention_milliseconds + 1000;

constexpr uint64_t k_default_endpoint_idle_timeout_milliseconds = 120000;

constexpr std::size_t k_max_nack_retransmit_sequences = 128;

constexpr std::size_t k_nack_sequences_per_item = 17;

constexpr auto k_pending_session_cleanup_interval = std::chrono::seconds(5);

constexpr uint64_t k_default_pending_session_timeout_milliseconds = 60000;

constexpr uint64_t k_keyframe_request_interval_milliseconds = 1000;

constexpr std::size_t k_default_rtp_packet_cache_max_packets = 4096;

constexpr std::size_t k_min_rtp_packet_cache_max_packets = 128;

constexpr std::size_t k_max_rtp_packet_cache_max_packets = 262144;

struct ice_username_parts
{
    std::string_view recipient_ufrag;
    std::string_view sender_ufrag;
};

using optional_mid_rewrite_result = std::expected<std::optional<rtp_header_extension_rewrite>, std::string>;
using optional_rtx_header_extension_id_rewrite_result = std::expected<std::optional<rtp_rtx_header_extension_id_rewrite>, std::string>;

void append_pli_u16(std::vector<uint8_t>& packet, uint16_t value)
{
    packet.push_back(static_cast<uint8_t>(value >> 8U));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void append_pli_u32(std::vector<uint8_t>& packet, uint32_t value)
{
    packet.push_back(static_cast<uint8_t>(value >> 24U));

    packet.push_back(static_cast<uint8_t>((value >> 16U) & 0xffU));

    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

std::vector<uint8_t> make_rtcp_picture_loss_indication_packet(uint32_t sender_ssrc, uint32_t media_ssrc)
{
    std::vector<uint8_t> packet;

    packet.reserve(12);

    packet.push_back(0x81U);

    packet.push_back(206U);

    append_pli_u16(packet, 2);

    append_pli_u32(packet, sender_ssrc);

    append_pli_u32(packet, media_ssrc);

    return packet;
}

std::string make_keyframe_request_key(const media_route_result& route, const media_peer_info& target_peer, uint32_t media_ssrc)
{
    std::string key;

    key.reserve(route.source.stream_id.size() + route.source.session_id.size() + target_peer.session_id.size() + 48);

    key.append(route.source.stream_id);

    key.push_back('|');

    key.append(route.source.session_id);

    key.push_back('|');

    key.append(target_peer.session_id);

    key.push_back('|');

    key.append(std::to_string(media_ssrc));

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
    for (const auto& current : values)
    {
        if (current == value)
        {
            return true;
        }
    }

    return false;
}

uint64_t to_debug_count(std::size_t value) { return static_cast<uint64_t>(value); }

void add_lifecycle_inconsistency(lifecycle_debug_snapshot& snapshot, std::string message)
{
    snapshot.consistent = false;

    snapshot.inconsistencies.push_back(std::move(message));

    snapshot.inconsistency_count = to_debug_count(snapshot.inconsistencies.size());
}

void add_lifecycle_residual(lifecycle_debug_snapshot& snapshot, std::string message) { snapshot.residuals.push_back(std::move(message)); }

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

bool lifecycle_runtime_state_is_empty(const lifecycle_debug_snapshot& snapshot)
{
    return snapshot.endpoint_count == 0 && snapshot.endpoint_session_index_count == 0 && snapshot.endpoint_reverse_index_count == 0 &&
           snapshot.endpoint_last_seen_count == 0 && snapshot.candidate_pair_count == 0 && snapshot.payload_type_mapping_count == 0 &&
           snapshot.keyframe_request_state_count == 0 && snapshot.dtls_peer_count == 0 && snapshot.srtp_peer_count == 0 &&
           snapshot.media_router_peer_count == 0 && snapshot.media_router_stream_count == 0 && snapshot.media_router_active_publisher_count == 0 &&
           snapshot.media_router_active_subscriber_count == 0 && snapshot.track_binding_count == 0 && snapshot.ssrc_mapping_count == 0 &&
           snapshot.identity_authority_rid_layer_binding_count == 0 && snapshot.identity_authority_track_binding_count == 0 &&
           snapshot.identity_authority_forward_binding_count == 0 && snapshot.rtcp_report_source_count == 0 &&
           snapshot.rtcp_transport_cc_source_count == 0 && snapshot.rtcp_transport_cc_pending_packet_count == 0 &&
           snapshot.rtp_cache_packet_count == 0 && snapshot.rtx_retransmission_index_count == 0 && snapshot.nack_retransmit_throttle_count == 0 &&
           snapshot.fir_sequence_number_state_count == 0 && snapshot.publisher_video_ssrc_state_count == 0 &&
           snapshot.pending_republish_keyframe_request_count == 0 && snapshot.extmap_rewrite_state_count == 0;
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

    const uint8_t version = static_cast<uint8_t>(packet[0] >> 6U);

    if (version != 2)
    {
        return make_error("rtp payload size version is invalid");
    }

    const bool has_padding = (packet[0] & 0x20U) != 0;

    const bool has_extension = (packet[0] & 0x10U) != 0;

    const uint8_t csrc_count = static_cast<uint8_t>(packet[0] & 0x0fU);

    std::size_t offset = 12 + static_cast<std::size_t>(csrc_count) * 4;

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

        offset += 4 + static_cast<std::size_t>(extension_length_words) * 4;

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

    const unsigned long long parsed = std::strtoull(value, &end, 10);

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

std::size_t make_rtp_packet_cache_max_packets_from_env()
{
    std::size_t max_packets = get_env_size_or_default("WEBRTC_RTP_CACHE_MAX_PACKETS", k_default_rtp_packet_cache_max_packets);

    max_packets = std::max(max_packets, k_min_rtp_packet_cache_max_packets);

    max_packets = std::min(max_packets, k_max_rtp_packet_cache_max_packets);

    return max_packets;
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

dtls_peer_identity make_publisher_dtls_identity(const std::shared_ptr<publisher_session>& session)
{
    dtls_peer_identity identity;

    identity.role = dtls_peer_role::publisher;

    identity.session_id = session->session_id();

    identity.stream_id = session->stream_id();

    identity.local_ice_ufrag = session->local_ice().ufrag;

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

optional_mid_rewrite_result make_mid_header_extension_rewrite(const media_payload_type_mapping& mapping,
                                                              const sdp::webrtc_offer_summary& publisher_offer,
                                                              const sdp::webrtc_offer_summary& subscriber_offer,
                                                              std::span<const uint8_t> plain_packet)
{
    if (!mapping.mid_rewrite_required)
    {
        return std::optional<rtp_header_extension_rewrite>{};
    }

    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return make_error("rtp mid rewrite publisher media not found");
    }

    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        return make_error("rtp mid rewrite subscriber media not found");
    }

    auto publisher_mid_extension_id = find_rtp_header_extension_id(*publisher_media, k_mid_extension_uri);

    if (!publisher_mid_extension_id.has_value())
    {
        return std::optional<rtp_header_extension_rewrite>{};
    }

    auto subscriber_mid_extension_id = find_rtp_header_extension_id(*subscriber_media, k_mid_extension_uri);

    if (!subscriber_mid_extension_id.has_value())
    {
        return make_error("rtp mid rewrite subscriber mid extension is missing");
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "rtp mid rewrite parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    auto existing_payload = find_rtp_header_extension(plain_packet, *header, *publisher_mid_extension_id);

    if (!existing_payload.has_value())
    {
        return std::optional<rtp_header_extension_rewrite>{};
    }

    if (existing_payload->size() != mapping.subscriber_mid.size())
    {
        return make_error("rtp mid extension payload size rewrite is unsupported");
    }

    rtp_header_extension_rewrite rewrite;

    rewrite.id = *publisher_mid_extension_id;

    rewrite.payload = string_to_bytes(mapping.subscriber_mid);

    return std::optional<rtp_header_extension_rewrite>(std::move(rewrite));
}
using optional_header_extension_id_rewrite_result = std::expected<std::optional<rtp_header_extension_id_rewrite>, std::string>;

optional_header_extension_id_rewrite_result make_mid_header_extension_id_rewrite(const media_payload_type_mapping& mapping,
                                                                                 const sdp::webrtc_offer_summary& publisher_offer,
                                                                                 const sdp::webrtc_offer_summary& subscriber_offer,
                                                                                 std::span<const uint8_t> plain_packet)
{
    const sdp::media_summary* publisher_media = find_media_summary_by_mid(publisher_offer, mapping.publisher_mid);

    if (publisher_media == nullptr)
    {
        return make_error("rtp mid id rewrite publisher media not found");
    }

    const sdp::media_summary* subscriber_media = find_media_summary_by_mid(subscriber_offer, mapping.subscriber_mid);

    if (subscriber_media == nullptr)
    {
        return make_error("rtp mid id rewrite subscriber media not found");
    }

    const std::optional<uint8_t> publisher_mid_extension_id = find_rtp_header_extension_id(*publisher_media, k_mid_extension_uri);

    if (!publisher_mid_extension_id.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "rtp mid id rewrite parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    auto publisher_payload = find_rtp_header_extension(plain_packet, *header, *publisher_mid_extension_id);

    if (!publisher_payload.has_value())
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    const std::optional<uint8_t> subscriber_mid_extension_id = find_rtp_header_extension_id(*subscriber_media, k_mid_extension_uri);

    if (!subscriber_mid_extension_id.has_value())
    {
        return make_error("rtp mid id rewrite subscriber mid extension is missing");
    }

    if (*publisher_mid_extension_id == *subscriber_mid_extension_id)
    {
        return std::optional<rtp_header_extension_id_rewrite>{};
    }

    rtp_header_extension_id_rewrite rewrite;

    rewrite.source_id = *publisher_mid_extension_id;

    rewrite.target_id = *subscriber_mid_extension_id;

    return std::optional<rtp_header_extension_id_rewrite>(rewrite);
}

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
        return make_error("rtx repaired-rid extension id overlaps publisher rid extension id");
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
void append_unique_keyframe_media_ssrc(std::vector<uint32_t>& ssrcs, uint32_t ssrc)
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

    for (unsigned char ch : value)
    {
        result.push_back(static_cast<char>(std::tolower(ch)));
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
      bind_host_(std::move(bind_host)),
      bind_port_(bind_port),
      registry_(std::move(registry)),
      media_router_(std::move(media_router)),
      track_resolver_(std::make_shared<media_track_resolver>()),
      ssrc_mapper_(std::make_shared<media_ssrc_mapper>()),
      identity_authority_(std::make_shared<media_identity_authority>()),
      rtcp_report_service_(make_rtcp_report_service_from_env()),
      rtcp_transport_cc_feedback_service_(std::make_shared<rtcp_transport_cc_feedback_service>()),
      endpoint_idle_timeout_milliseconds_(make_endpoint_idle_timeout_milliseconds_from_env()),
      pending_session_timeout_milliseconds_(make_pending_session_timeout_milliseconds_from_env())
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
        rtcp_report_service_ = make_rtcp_report_service_from_env();
    }
    if (rtcp_transport_cc_feedback_service_ == nullptr)
    {
        rtcp_transport_cc_feedback_service_ = std::make_shared<rtcp_transport_cc_feedback_service>();
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

    udp::endpoint endpoint(address, bind_port_);

    socket_.open(endpoint.protocol(), ec);

    if (ec)
    {
        std::string message = "ice udp socket open failed: ";

        message.append(ec.message());

        return std::unexpected(std::move(message));
    }

    boost::asio::socket_base::reuse_address reuse_address(true);

    socket_.set_option(reuse_address, ec);

    if (ec)
    {
        WEBRTC_LOG_WARN("ice udp socket set reuse_address failed: {}", ec.message());
    }

    socket_.bind(endpoint, ec);

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

        endpoint_last_seen_milliseconds_by_address_.clear();

        retired_endpoints_by_address_.clear();

        retired_ice_credentials_by_local_ufrag_.clear();
    }

    track_resolver_ = std::make_shared<media_track_resolver>();

    ssrc_mapper_ = std::make_shared<media_ssrc_mapper>();

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

void ice_udp_server::forget_subscriber_session_runtime_state(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    forget_extmap_rewrite_states_for_session(session_id);
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
void ice_udp_server::forget_republished_publisher_runtime_state(std::string_view stream_id, std::string_view old_publisher_session_id)
{
    if (stream_id.empty() || old_publisher_session_id.empty())
    {
        return;
    }

    /*
     * Clear old publisher transport/runtime by session id first.
     * This removes old endpoint, DTLS, SRTP, publisher media_router peer,
     * track binding, SSRC mapping, identity authority, RTCP/TWCC and
     * session-scoped RTX/NACK state.
     *
     * Do not call cleanup_stream_runtime_state(stream_id) here because it
     * would remove the stream's subscribers from media_router.
     */
    forget_session(old_publisher_session_id);

    bool cache_erased = false;
    std::size_t remaining_packets = 0;

    if (rtp_packet_cache_ != nullptr)
    {
        rtp_packet_cache_->erase_stream(stream_id);

        remaining_packets = rtp_packet_cache_->size();

        cache_erased = true;
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

    {
        std::lock_guard lock(endpoint_mutex_);
        erased_payload_type_mappings = erase_payload_type_mappings_for_stream_locked(stream_id);
        erased_keyframe_request_states = erase_keyframe_request_states_for_stream_locked(stream_id);
        const std::size_t erased_extmap_rewrite_states = erase_extmap_rewrite_states_for_stream_locked(stream_id);
        (void)erased_extmap_rewrite_states;
        for (auto iterator = fir_sequence_number_by_key_.begin(); iterator != fir_sequence_number_by_key_.end();)
        {
            if (iterator->first.starts_with(std::string(stream_id) + "|"))
            {
                iterator = fir_sequence_number_by_key_.erase(iterator);
                continue;
            }
            ++iterator;
        }
        publisher_video_ssrc_by_stream_.erase(std::string(stream_id));
        pending_republish_keyframe_state_by_stream_.erase(std::string(stream_id));
    }
    WEBRTC_LOG_INFO(
        "publisher republish runtime state forgotten stream={} old_session={} cache_erased={} remaining_cache_packets={} "
        "payload_type_mappings_erased={} keyframe_states_erased={}",
        stream_id,
        old_publisher_session_id,
        cache_erased ? 1 : 0,
        remaining_packets,
        erased_payload_type_mappings,
        erased_keyframe_request_states);
}
void ice_udp_server::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::string remote_address;
    bool endpoint_removed = false;

    {
        std::lock_guard lock(endpoint_mutex_);
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
            remote_address = erased_remote_addresses.front();
            endpoint_address_by_session_id_.erase(remote_address);
            session_id_by_endpoint_address_.erase(remote_address);
            endpoints_by_address_.erase(remote_address);
            endpoint_last_seen_milliseconds_by_address_.erase(remote_address);
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

    forget_subscriber_session_runtime_state(session_id);

    if (endpoint_removed)
    {
        send_dtls_close_notify(remote_address);
        forget_peer_transport_state(remote_address);
    }

    WEBRTC_LOG_INFO(
        "ice udp session cleanup completed session={} endpoint_removed={} remote={}", session_id, endpoint_removed ? 1 : 0, remote_address);
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

            erase_candidate_pairs_for_endpoint_locked(orphan_remote_address);

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

    schedule_pending_session_cleanup();
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

    for (const auto& snapshot : snapshots)
    {
        if (snapshot.kind != stream_session_kind::publisher)
        {
            continue;
        }

        if (!is_pending_connection_state(snapshot.state))
        {
            continue;
        }

        const uint64_t reference_time_milliseconds =
            snapshot.updated_at_milliseconds != 0 ? snapshot.updated_at_milliseconds : snapshot.created_at_milliseconds;

        const uint64_t age_milliseconds =
            current_time_milliseconds > reference_time_milliseconds ? current_time_milliseconds - reference_time_milliseconds : 0;

        if (age_milliseconds < pending_session_timeout_milliseconds_)
        {
            continue;
        }

        if (!contains_string(expired_session_ids, snapshot.session_id))
        {
            expired_session_ids.push_back(snapshot.session_id);
        }

        if (!contains_string(expired_publisher_stream_ids, snapshot.stream_id))
        {
            expired_publisher_stream_ids.push_back(snapshot.stream_id);
        }
    }

    for (const auto& snapshot : snapshots)
    {
        if (snapshot.kind != stream_session_kind::subscriber)
        {
            continue;
        }

        if (contains_string(expired_publisher_stream_ids, snapshot.stream_id))
        {
            continue;
        }

        if (!is_pending_connection_state(snapshot.state))
        {
            continue;
        }

        const uint64_t reference_time_milliseconds =
            snapshot.updated_at_milliseconds != 0 ? snapshot.updated_at_milliseconds : snapshot.created_at_milliseconds;

        const uint64_t age_milliseconds =
            current_time_milliseconds > reference_time_milliseconds ? current_time_milliseconds - reference_time_milliseconds : 0;

        if (age_milliseconds < pending_session_timeout_milliseconds_)
        {
            continue;
        }

        if (!contains_string(expired_session_ids, snapshot.session_id))
        {
            expired_session_ids.push_back(snapshot.session_id);
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

            const std::string stream_id = publisher->stream_id();

            forget_session(session_id);

            cleanup_stream_runtime_state(stream_id);

            schedule_lifecycle_snapshot_log(std::string(reason) + " publisher removal failed", stream_id, std::string(session_id));
        }

        return;

        if (!registry_callback_registered_)
        {
            forget_session(session_id);

            erase_rtp_cache(stream_id);
        }

        WEBRTC_LOG_WARN("{} publisher session removed stream={} session={}", reason, stream_id, session_id);

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

            const std::string stream_id = subscriber->stream_id();

            forget_session(session_id);

            schedule_lifecycle_snapshot_log(std::string(reason) + " subscriber removal failed", stream_id, std::string(session_id));
        }

        return;
        if (!registry_callback_registered_)
        {
            forget_session(session_id);
        }

        WEBRTC_LOG_WARN("{} subscriber session removed stream={} session={}", reason, stream_id, session_id);

        return;
    }

    WEBRTC_LOG_WARN("{} session not found in registry session={}", reason, session_id);

    forget_session(session_id);

    schedule_lifecycle_snapshot_log(std::string(reason) + " session missing", "", std::string(session_id));
}

uint16_t ice_udp_server::local_port() const { return bind_port_; }
lifecycle_debug_snapshot ice_udp_server::debug_state_snapshot() const
{
    lifecycle_debug_snapshot snapshot;

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

        snapshot.registry_stream_count = to_debug_count(stream_ids.size());
    }

    {
        std::lock_guard lock(endpoint_mutex_);

        snapshot.endpoint_count = to_debug_count(endpoints_by_address_.size());

        snapshot.endpoint_session_index_count = to_debug_count(endpoint_address_by_session_id_.size());

        snapshot.endpoint_reverse_index_count = to_debug_count(session_id_by_endpoint_address_.size());

        snapshot.endpoint_last_seen_count = to_debug_count(endpoint_last_seen_milliseconds_by_address_.size());

        snapshot.candidate_pair_count = to_debug_count(candidate_pairs_by_key_.size());

        for (const auto& [key, pair] : candidate_pairs_by_key_)
        {
            (void)key;

            if (pair.selected)
            {
                snapshot.selected_candidate_pair_count += 1;
            }
        }

        snapshot.payload_type_mapping_count = to_debug_count(payload_type_mappings_by_key_.size());
        snapshot.keyframe_request_state_count = to_debug_count(keyframe_request_last_time_milliseconds_by_key_.size());
        snapshot.fir_sequence_number_state_count = to_debug_count(fir_sequence_number_by_key_.size());
        snapshot.publisher_video_ssrc_state_count = to_debug_count(publisher_video_ssrc_by_stream_.size());
        snapshot.pending_republish_keyframe_request_count = to_debug_count(pending_republish_keyframe_state_by_stream_.size());
        snapshot.extmap_rewrite_state_count = to_debug_count(extmap_rewrite_state_by_key_.size());

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
        snapshot.track_binding_count = to_debug_count(track_resolver_->binding_count());
    }

    if (ssrc_mapper_ != nullptr)
    {
        snapshot.ssrc_mapping_count = to_debug_count(ssrc_mapper_->mapping_count());
    }
    if (identity_authority_ != nullptr)
    {
        snapshot.identity_authority_track_binding_count = to_debug_count(identity_authority_->track_binding_count());
        snapshot.identity_authority_rid_layer_binding_count = to_debug_count(identity_authority_->rid_layer_binding_count());
        snapshot.identity_authority_forward_binding_count = to_debug_count(identity_authority_->forward_binding_count());
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
    if (rtp_packet_cache_ != nullptr)
    {
        snapshot.rtp_cache_packet_count = to_debug_count(rtp_packet_cache_->size());
    }
    if (rtx_retransmission_index_ != nullptr)
    {
        snapshot.rtx_retransmission_index_count = to_debug_count(rtx_retransmission_index_->size());
    }
    if (nack_retransmit_throttle_ != nullptr)
    {
        snapshot.nack_retransmit_throttle_count = to_debug_count(nack_retransmit_throttle_->size());
    }
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

    if (snapshot.registry_session_count == 0 && !lifecycle_runtime_state_is_empty(snapshot))
    {
        add_lifecycle_inconsistency(snapshot, "registry is empty but runtime state remains");
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
        if (snapshot.extmap_rewrite_state_count != 0)
        {
            add_lifecycle_residual(snapshot, "extmap rewrite state remains count=" + std::to_string(snapshot.extmap_rewrite_state_count));
        }

        if (snapshot.rtcp_report_source_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtcp report source remains count=" + std::to_string(snapshot.rtcp_report_source_count));
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
        if (snapshot.rtx_retransmission_index_count != 0)
        {
            add_lifecycle_residual(snapshot, "rtx retransmission index remains count=" + std::to_string(snapshot.rtx_retransmission_index_count));
        }

        if (snapshot.nack_retransmit_throttle_count != 0)
        {
            add_lifecycle_residual(snapshot, "nack retransmit throttle remains count=" + std::to_string(snapshot.nack_retransmit_throttle_count));
        }
    }
    snapshot.idle_clean = snapshot.registry_session_count == 0 && lifecycle_runtime_state_is_empty(snapshot);

    snapshot.inconsistency_count = to_debug_count(snapshot.inconsistencies.size());

    snapshot.consistent = snapshot.inconsistency_count == 0;

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

    const bool runtime_residual_after_idle = snapshot.registry_session_count == 0 && !snapshot.idle_clean;

    if (!snapshot.consistent || runtime_residual_after_idle)
    {
        WEBRTC_LOG_WARN(
            "lifecycle snapshot residual reason={} stream={} session={} registry_sessions={} registry_publishers={} registry_subscribers={} "
            "endpoints={} endpoint_index={} endpoint_reverse_index={} dtls_peers={} srtp_peers={} media_router_peers={} media_router_streams={} "
            "track_bindings={} "
            "ssrc_mappings={} payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} "
            "pending_republish_keyframes={} rtcp_report_sources={} rtcp_report_stats_sources={} rtp_cache_packets={} "
            "rtx_retransmission_index={} nack_retransmit_throttle={} idle_clean={} consistent={} inconsistencies={}",
            reason,
            stream_id,
            session_id,
            snapshot.registry_session_count,
            snapshot.registry_publisher_count,
            snapshot.registry_subscriber_count,
            snapshot.endpoint_count,
            snapshot.endpoint_session_index_count,
            snapshot.endpoint_reverse_index_count,
            snapshot.dtls_peer_count,
            snapshot.srtp_peer_count,
            snapshot.media_router_peer_count,
            snapshot.media_router_stream_count,
            snapshot.track_binding_count,
            snapshot.ssrc_mapping_count,
            snapshot.payload_type_mapping_count,
            snapshot.keyframe_request_state_count,
            snapshot.fir_sequence_number_state_count,
            snapshot.publisher_video_ssrc_state_count,
            snapshot.pending_republish_keyframe_request_count,
            snapshot.rtcp_report_source_count,
            snapshot.rtcp_report_stats_source_count,
            snapshot.rtp_cache_packet_count,
            snapshot.rtx_retransmission_index_count,
            snapshot.nack_retransmit_throttle_count,
            snapshot.idle_clean ? 1 : 0,
            snapshot.consistent ? 1 : 0,
            snapshot.inconsistency_count);

        return;
    }

    WEBRTC_LOG_INFO(
        "lifecycle snapshot clean reason={} stream={} session={} registry_sessions={} registry_publishers={} registry_subscribers={} endpoints={} "
        "dtls_peers={} srtp_peers={} media_router_peers={} media_router_streams={} track_bindings={} ssrc_mappings={} payload_type_mappings={} "
        "keyframe_states={} "
        "rtcp_report_sources={} rtp_cache_packets={} rtx_retransmission_index={} nack_retransmit_throttle={}  idle_clean={} consistent={}",
        reason,
        stream_id,
        session_id,
        snapshot.registry_session_count,
        snapshot.registry_publisher_count,
        snapshot.registry_subscriber_count,
        snapshot.endpoint_count,
        snapshot.dtls_peer_count,
        snapshot.srtp_peer_count,
        snapshot.media_router_peer_count,
        snapshot.media_router_stream_count,
        snapshot.track_binding_count,
        snapshot.ssrc_mapping_count,
        snapshot.payload_type_mapping_count,
        snapshot.keyframe_request_state_count,
        snapshot.rtcp_report_source_count,
        snapshot.rtp_cache_packet_count,
        snapshot.rtx_retransmission_index_count,
        snapshot.nack_retransmit_throttle_count,
        snapshot.idle_clean ? 1 : 0,
        snapshot.consistent ? 1 : 0);
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
    std::size_t retired_endpoint_count = 0;
    std::size_t retired_ice_credential_count = 0;

    {
        std::lock_guard lock(endpoint_mutex_);

        const uint64_t current_time_milliseconds = now_milliseconds();

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

        retired_endpoint_count = retired_endpoints_by_address_.size();

        retired_ice_credential_count = retired_ice_credentials_by_local_ufrag_.size();
    }
    const lifecycle_debug_snapshot snapshot = debug_state_snapshot();

    if (snapshot.registry_session_count != 0)
    {
        WEBRTC_LOG_DEBUG(
            "lifecycle convergence waiting generation={} delay_ms={} reason={} stream={} session={} registry_sessions={} registry_publishers={} "
            "registry_subscribers={} endpoints={} dtls_peers={} srtp_peers={} media_router_peers={} media_router_streams={} retired_endpoints={} "
            "retired_ice_credentials={}",
            generation,
            delay_milliseconds,
            reason,
            stream_id,
            session_id,
            snapshot.registry_session_count,
            snapshot.registry_publisher_count,
            snapshot.registry_subscriber_count,
            snapshot.endpoint_count,
            snapshot.dtls_peer_count,
            snapshot.srtp_peer_count,
            snapshot.media_router_peer_count,
            snapshot.media_router_stream_count,
            retired_endpoint_count,
            retired_ice_credential_count);

        return;
    }

    const bool retired_state_clean = !require_retired_endpoints_empty || (retired_endpoint_count == 0 && retired_ice_credential_count == 0);
    if (snapshot.idle_clean && snapshot.consistent && retired_state_clean)
    {
        WEBRTC_LOG_INFO(
            "lifecycle convergence clean generation={} delay_ms={} reason={} stream={} session={} endpoints={} endpoint_index={} "
            "endpoint_reverse_index={} endpoint_last_seen={} candidate_pairs={} selected_candidate_pairs={} dtls_peers={} srtp_peers={} "
            "media_router_peers={} media_router_streams={} track_bindings={} ssrc_mappings={} identity_tracks={} identity_forwards={} "
            "payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} pending_republish_keyframes={} "
            "rtcp_report_sources={} rtcp_report_stats_sources={} rtp_cache_packets={} retired_endpoints={} retired_ice_credentials={} idle_clean={} "
            "consistent={}",
            generation,
            delay_milliseconds,
            reason,
            stream_id,
            session_id,
            snapshot.endpoint_count,
            snapshot.endpoint_session_index_count,
            snapshot.endpoint_reverse_index_count,
            snapshot.endpoint_last_seen_count,
            snapshot.candidate_pair_count,
            snapshot.selected_candidate_pair_count,
            snapshot.dtls_peer_count,
            snapshot.srtp_peer_count,
            snapshot.media_router_peer_count,
            snapshot.media_router_stream_count,
            snapshot.track_binding_count,
            snapshot.ssrc_mapping_count,
            snapshot.identity_authority_track_binding_count,
            snapshot.identity_authority_forward_binding_count,
            snapshot.payload_type_mapping_count,
            snapshot.keyframe_request_state_count,
            snapshot.fir_sequence_number_state_count,
            snapshot.publisher_video_ssrc_state_count,
            snapshot.pending_republish_keyframe_request_count,
            snapshot.rtcp_report_source_count,
            snapshot.rtcp_report_stats_source_count,
            snapshot.rtp_cache_packet_count,
            retired_endpoint_count,
            retired_ice_credential_count,
            snapshot.idle_clean ? 1 : 0,
            snapshot.consistent ? 1 : 0);

        return;
    }

    WEBRTC_LOG_WARN(
        "lifecycle convergence residual generation={} delay_ms={} reason={} stream={} session={} endpoints={} endpoint_index={} "
        "endpoint_reverse_index={} endpoint_last_seen={} candidate_pairs={} selected_candidate_pairs={} dtls_peers={} srtp_peers={} "
        "media_router_peers={} media_router_streams={} track_bindings={} ssrc_mappings={} identity_tracks={} identity_forwards={} "
        "payload_type_mappings={} keyframe_states={} fir_sequence_states={} publisher_video_ssrc_states={} pending_republish_keyframes={}"
        "rtcp_report_sources={} rtcp_report_stats_sources={} rtp_cache_packets={} rtx_retransmission_index={} nack_retransmit_throttle={} "
        "retired_endpoints={} retired_ice_credentials={} idle_clean={} "
        "consistent={} inconsistencies={}",
        generation,
        delay_milliseconds,
        reason,
        stream_id,
        session_id,
        snapshot.endpoint_count,
        snapshot.endpoint_session_index_count,
        snapshot.endpoint_reverse_index_count,
        snapshot.endpoint_last_seen_count,
        snapshot.candidate_pair_count,
        snapshot.selected_candidate_pair_count,
        snapshot.dtls_peer_count,
        snapshot.srtp_peer_count,
        snapshot.media_router_peer_count,
        snapshot.media_router_stream_count,
        snapshot.track_binding_count,
        snapshot.ssrc_mapping_count,
        snapshot.identity_authority_track_binding_count,
        snapshot.identity_authority_forward_binding_count,
        snapshot.payload_type_mapping_count,
        snapshot.keyframe_request_state_count,
        snapshot.fir_sequence_number_state_count,
        snapshot.publisher_video_ssrc_state_count,
        snapshot.pending_republish_keyframe_request_count,
        snapshot.rtcp_report_source_count,
        snapshot.rtcp_report_stats_source_count,
        snapshot.rtp_cache_packet_count,
        snapshot.rtx_retransmission_index_count,
        snapshot.nack_retransmit_throttle_count,
        retired_endpoint_count,
        retired_ice_credential_count,
        snapshot.idle_clean ? 1 : 0,
        snapshot.consistent ? 1 : 0,
        snapshot.inconsistency_count);
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

    dtls_transport_config transport_config;

    transport_config.handshake_timeout = std::chrono::seconds(30);

    dtls_transport_ = std::make_shared<dtls_transport>(*context, transport_config);

    srtp_transport_ = std::make_shared<srtp_transport>(dtls_transport_);

    rtp_packet_cache_config cache_config;

    cache_config.max_packets = make_rtp_packet_cache_max_packets_from_env();

    rtp_packet_cache_ = std::make_shared<rtp_packet_cache>(cache_config);

    rtx_sequence_allocator_ = std::make_shared<rtx_sequence_number_allocator>();

    rtx_retransmission_index_ = std::make_shared<rtx_retransmission_index>();
    nack_retransmit_throttle_ = std::make_shared<nack_retransmit_throttle>();

    WEBRTC_LOG_INFO("dtls transport initialized handshake_timeout_ms={}", transport_config.handshake_timeout.count());

    WEBRTC_LOG_INFO("srtp transport initialized");

    WEBRTC_LOG_INFO("rtp packet cache initialized max_packets={}", cache_config.max_packets);

    WEBRTC_LOG_INFO("rtx sequence allocator initialized");
    WEBRTC_LOG_INFO("nack retransmit throttle initialized");
    return {};
}

std::optional<std::string> ice_udp_server::remote_address_for_session(std::string_view session_id)
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

    std::lock_guard lock(endpoint_mutex_);

    publisher_video_ssrc_by_stream_[peer.stream_id] = packet.ssrc;
}

ice_udp_server::keyframe_request_feedback_type ice_udp_server::select_keyframe_request_feedback_type(std::string_view stream_id) const
{
    if (stream_id.empty() || registry_ == nullptr)
    {
        return keyframe_request_feedback_type::none;
    }

    auto publisher = registry_->find_publisher_by_stream_id(stream_id);

    if (publisher == nullptr)
    {
        return keyframe_request_feedback_type::none;
    }

    const sdp::webrtc_offer_summary& offer_summary = publisher->remote_offer_summary();

    bool supports_pli = false;
    bool supports_fir = false;

    for (const auto& media : offer_summary.media)
    {
        if (!is_video_media_kind(media.kind))
        {
            continue;
        }

        supports_pli = supports_pli || media_supports_rtcp_feedback(media, "nack pli");

        supports_fir = supports_fir || media_supports_rtcp_feedback(media, "ccm fir");
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
std::vector<uint32_t> ice_udp_server::collect_keyframe_request_media_ssrcs(std::string_view stream_id) const
{
    std::vector<uint32_t> media_ssrcs;

    if (stream_id.empty())
    {
        return media_ssrcs;
    }

    if (ssrc_mapper_ != nullptr)
    {
        const std::vector<media_ssrc_mapping> mappings = ssrc_mapper_->find_by_stream_id(stream_id);

        for (const auto& mapping : mappings)
        {
            if (!media_ssrc_mapping_is_primary_video(mapping))
            {
                WEBRTC_LOG_DEBUG(
                    "keyframe request skip non primary video mapping stream={} publisher_session={} subscriber_session={} publisher_ssrc={} "
                    "subscriber_ssrc={} kind={} rtx={}",
                    mapping.stream_id,
                    mapping.publisher_session_id,
                    mapping.subscriber_session_id,
                    mapping.publisher_ssrc,
                    mapping.subscriber_ssrc,
                    mapping.kind,
                    media_ssrc_mapping_is_rtx(mapping) ? 1 : 0);

                continue;
            }

            append_unique_keyframe_media_ssrc(media_ssrcs, mapping.publisher_ssrc);
        }
    }

    {
        std::lock_guard lock(endpoint_mutex_);

        const auto iterator = publisher_video_ssrc_by_stream_.find(std::string(stream_id));

        if (iterator != publisher_video_ssrc_by_stream_.end())
        {
            append_unique_keyframe_media_ssrc(media_ssrcs, iterator->second);
        }
    }

    return media_ssrcs;
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

    const keyframe_request_feedback_type feedback_type = select_keyframe_request_feedback_type(stream_id);

    if (feedback_type == keyframe_request_feedback_type::none)
    {
        return make_error("publisher does not support pli or fir");
    }

    const std::vector<uint32_t> media_ssrcs = collect_keyframe_request_media_ssrcs(stream_id);

    if (media_ssrcs.empty())
    {
        return make_error("publisher media ssrc not found");
    }

    result.media_ssrc_count = static_cast<uint64_t>(media_ssrcs.size());

    for (uint32_t media_ssrc : media_ssrcs)
    {
        const uint32_t sender_ssrc = 1;

        auto plain_packet = make_keyframe_request_packet(feedback_type, stream_id, sender_ssrc, media_ssrc);
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

            continue;
        }

        if (protected_packet->state == srtp_packet_process_state::ignored)
        {
            result.failed_count += 1;

            continue;
        }

        send_response(std::move(protected_packet->protected_packet), *remote_endpoint);
        WEBRTC_LOG_INFO("keyframe request sent stream={} publisher_session={} remote={} feedback={} sender_ssrc={} media_ssrc={}",
                        result.stream_id,
                        result.publisher_session_id,
                        result.publisher_remote_address,
                        feedback_type == keyframe_request_feedback_type::pli ? "pli" : "fir",
                        sender_ssrc,
                        media_ssrc);
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
                self->send_rtcp_bye_for_removed_stream(removed_session.stream_id);
            }
            else if (removed_session.kind == stream_session_kind::subscriber)
            {
                self->send_rtcp_bye_for_removed_session(removed_session);
            }

            self->forget_session(removed_session.session_id);

            if (removed_session.kind == stream_session_kind::publisher)
            {
                self->cleanup_stream_runtime_state(removed_session.stream_id);
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

            self->forget_session(restarted_session.session_id);

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

            self->forget_republished_publisher_runtime_state(republished_session.stream_id, republished_session.old_session_id);

            self->mark_republish_keyframe_request_pending(republished_session.stream_id, republished_session.new_session_id);

            self->schedule_lifecycle_snapshot_log("publisher republish callback", republished_session.stream_id, republished_session.old_session_id);
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

    ice_consent_timer_.expires_after(k_ice_consent_check_interval);

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
        WEBRTC_LOG_WARN("ice consent timer failed: {}", ec.message());

        schedule_ice_consent_check();

        return;
    }

    if (!started_)
    {
        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    std::vector<std::string> expired_session_ids = collect_expired_ice_consent_session_ids(current_time_milliseconds);

    for (const auto& session_id : expired_session_ids)
    {
        WEBRTC_LOG_WARN("ice consent session expired session={} timeout_ms={}", session_id, k_ice_consent_timeout_milliseconds);

        remove_expired_session(session_id, "ice consent");
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

    rtcp_report_timer_.expires_after(k_rtcp_report_interval);

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

    for (const auto& feedback_packet : generation.packets)
    {
        const current_session_endpoint_state current_session = validate_current_session_endpoint(
            feedback_packet.remote_endpoint, feedback_packet.session_id, feedback_packet.stream_id, "rtcp transport cc feedback");

        if (!current_session.allowed)
        {
            current_session_gate_skipped_count += 1;

            rtcp_transport_cc_feedback_service_->forget_session(feedback_packet.session_id);

            continue;
        }

        auto remote_endpoint = find_remote_endpoint(feedback_packet.remote_endpoint);

        if (!remote_endpoint.has_value())
        {
            endpoint_not_found_count += 1;

            rtcp_transport_cc_feedback_service_->forget_peer(feedback_packet.remote_endpoint);

            continue;
        }

        auto protected_packet =
            srtp_transport_->protect_outbound_packet(std::span<const uint8_t>(feedback_packet.packet.data(), feedback_packet.packet.size()),
                                                     feedback_packet.remote_endpoint,
                                                     srtp_packet_kind::rtcp);

        if (!protected_packet)
        {
            protect_failed_count += 1;

            WEBRTC_LOG_DEBUG("rtcp transport cc protect failed stream={} session={} remote={} media_ssrc={} base_seq={} count={} error={}",
                             feedback_packet.stream_id,
                             feedback_packet.session_id,
                             feedback_packet.remote_endpoint,
                             feedback_packet.media_ssrc,
                             feedback_packet.base_sequence_number,
                             feedback_packet.packet_status_count,
                             protected_packet.error());

            continue;
        }

        if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
        {
            protect_ignored_count += 1;

            continue;
        }

        send_response(std::move(protected_packet->protected_packet), *remote_endpoint);

        sent_count += 1;
    }

    WEBRTC_LOG_DEBUG(
        "rtcp transport cc feedback generation sources={} pending={} packets={} sent={} endpoint_not_found={} protect_failed={} protect_ignored={} "
        "current_session_gate_skipped={} stale_expired={}",
        generation.source_count,
        generation.pending_packet_count,
        generation.packets.size(),
        sent_count,
        endpoint_not_found_count,
        protect_failed_count,
        protect_ignored_count,
        current_session_gate_skipped_count,
        generation.stale_sources_expired);
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
void ice_udp_server::handle_stun_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    auto message = parse_stun_message(data);

    if (!message)
    {
        WEBRTC_LOG_WARN("ice stun parse failed remote={} error={}", remote_address, message.error());

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
        suppress_retired_endpoint_packet(remote_address, "stun");

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
            forget_peer_transport_state(selection_result->previous_remote_address);

            WEBRTC_LOG_INFO("ice selected candidate pair replaced stream={} session={} old_remote={} new_remote={}",
                            stream_id,
                            session_id,
                            selection_result->previous_remote_address,
                            remote_address);
        }

        const bool media_peer_refresh_required = selected_media_peer_needs_refresh(remote_address, session_id);
        if (selection_changed || media_peer_refresh_required)
        {
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

            WEBRTC_LOG_INFO("ice candidate pair selected stream={} session={} remote={} priority={} tie_breaker={}",
                            stream_id,
                            session_id,
                            remote_address,
                            remote_priority,
                            remote_tie_breaker);
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

void ice_udp_server::handle_dtls_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    const current_session_endpoint_state current_session = find_current_session_endpoint(remote_address, "dtls");

    if (!current_session.allowed)
    {
        WEBRTC_LOG_DEBUG("dtls packet ignored by current session gate remote={} session={} size={} reason={}",
                         remote_address,
                         current_session.session_id,
                         data.size(),
                         current_session.reject_reason);

        return;
    }

    touch_endpoint_activity(remote_endpoint);
    if (dtls_transport_ == nullptr)
    {
        WEBRTC_LOG_WARN("dtls transport is null remote={} size={}", remote_address, data.size());

        return;
    }

    auto packets = dtls_transport_->handle_udp_packet(data, remote_address);

    if (!packets)
    {
        WEBRTC_LOG_WARN("dtls packet handle failed remote={} error={}", remote_address, packets.error());

        forget_peer_endpoint(remote_address);

        schedule_dtls_timeout();

        return;
    }

    for (auto& packet : *packets)
    {
        WEBRTC_LOG_DEBUG("dtls send packet remote={} size={}", remote_address, packet.size());

        send_response(std::move(packet), remote_endpoint);
    }

    if (dtls_transport_->has_received_close_notify(remote_address))
    {
        handle_dtls_close_notify(remote_address);

        schedule_dtls_timeout();

        return;
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

    if (!track_resolution.has_value() || !track_resolution->resolved || track_resolution->kind != "video")
    {
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
        WEBRTC_LOG_WARN("keyframe request skipped publisher endpoint not found stream={} publisher={} subscriber={} ssrc={}",
                        route.source.stream_id,
                        route.source.remote_endpoint,
                        target_peer.remote_endpoint,
                        packet.ssrc);

        return;
    }

    const uint64_t current_time_milliseconds = now_milliseconds();

    const std::string key = make_keyframe_request_key(route, target_peer, packet.ssrc);

    const bool republish_keyframe_request = consume_republish_keyframe_request_pending_for_subscriber(packet, route, track_resolution, target_peer);
    {
        std::lock_guard lock(endpoint_mutex_);

        const auto iterator = keyframe_request_last_time_milliseconds_by_key_.find(key);

        if (republish_keyframe_request)
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
        else if (iterator != keyframe_request_last_time_milliseconds_by_key_.end())
        {
            const uint64_t elapsed_milliseconds = current_time_milliseconds > iterator->second ? current_time_milliseconds - iterator->second : 0;

            if (elapsed_milliseconds < k_keyframe_request_interval_milliseconds)
            {
                return;
            }

            iterator->second = current_time_milliseconds;
        }
        else
        {
            keyframe_request_last_time_milliseconds_by_key_.emplace(key, current_time_milliseconds);
        }
    }
    const keyframe_request_feedback_type feedback_type = select_keyframe_request_feedback_type(route.source.stream_id);

    if (feedback_type == keyframe_request_feedback_type::none)
    {
        WEBRTC_LOG_DEBUG("keyframe request skipped publisher unsupported stream={} publisher_session={} media_ssrc={}",
                         route.source.stream_id,
                         route.source.session_id,
                         packet.ssrc);

        return;
    }

    const uint32_t sender_ssrc = make_rtcp_report_local_ssrc(route.source, packet.ssrc);
    auto plain_packet = make_keyframe_request_packet(feedback_type, route.source.stream_id, sender_ssrc, packet.ssrc);
    if (!plain_packet.has_value())
    {
        return;
    }
    auto protected_packet = srtp_transport_->protect_outbound_packet(
        std::span<const uint8_t>(plain_packet->data(), plain_packet->size()), route.source.remote_endpoint, srtp_packet_kind::rtcp);

    if (!protected_packet)
    {
        WEBRTC_LOG_WARN("keyframe request protect failed stream={} publisher={} subscriber={} media_ssrc={} error={}",
                        route.source.stream_id,
                        route.source.remote_endpoint,
                        target_peer.remote_endpoint,
                        packet.ssrc,
                        protected_packet.error());

        return;
    }

    if (protected_packet->state == srtp_packet_process_state::ignored)
    {
        WEBRTC_LOG_DEBUG("keyframe request ignored stream={} publisher={} subscriber={} media_ssrc={} reason={}",
                         route.source.stream_id,
                         route.source.remote_endpoint,
                         target_peer.remote_endpoint,
                         packet.ssrc,
                         protected_packet->reason);

        return;
    }

    WEBRTC_LOG_INFO(
        "keyframe request sent stream={} publisher={} publisher_session={} subscriber={} subscriber_session={} sender_ssrc={} media_ssrc={}",
        route.source.stream_id,
        route.source.remote_endpoint,
        route.source.session_id,
        target_peer.remote_endpoint,
        target_peer.session_id,
        sender_ssrc,
        packet.ssrc);

    send_response(std::move(protected_packet->protected_packet), *publisher_endpoint);
}
void ice_udp_server::handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint)
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

        return;
    }

    touch_endpoint_activity(remote_endpoint);

    if (srtp_transport_ == nullptr)
    {
        WEBRTC_LOG_WARN("srtp transport is null remote={} size={}", remote_address, data.size());

        return;
    }

    auto result = srtp_transport_->handle_inbound_packet(data, remote_address);

    if (!result)
    {
        WEBRTC_LOG_WARN("srtp inbound packet handle failed remote={} error={}", remote_address, result.error());

        return;
    }

    if (result->state == srtp_packet_process_state::ignored)
    {
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

    std::optional<media_peer_info> peer = media_router_->get_peer(remote_address);

    std::optional<media_track_resolution> track_resolution;

    if (peer.has_value())
    {
        track_resolution = resolve_media_track(*peer, *result);

        normalize_inbound_rtcp_report_stats(*peer, *result);
    }

    const media_route_result route = media_router_->handle_inbound_packet(remote_address, *result);
    if (!route.known_peer)
    {
        WEBRTC_LOG_WARN(
            "media route ignored unknown peer remote={} kind={} ssrc={}", remote_address, srtp_packet_kind_to_string(result->kind), result->ssrc);

        return;
    }

    if (peer.has_value())
    {
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
    }
    if (track_resolution.has_value() && track_resolution->resolved)
    {
        WEBRTC_LOG_DEBUG(
            "media track resolved remote={} action={} stream={} session={} state={} mid={} kind={} ssrc={} sequence={} payload_type={} "
            "newly_bound={} has_twcc={} twcc={} rtx={} rtx_primary_ssrc={} rtx_repair_ssrc={}",
            remote_address,
            media_route_action_to_string(route.action),
            track_resolution->stream_id,
            track_resolution->session_id,
            media_track_resolution_state_to_string(track_resolution->state),
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
        return;
    }
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

    if (identity_authority_ != nullptr)
    {
        auto identity_result = identity_authority_->remember_track_resolution(*resolution, resolution->rtx);

        if (!identity_result)
        {
            WEBRTC_LOG_WARN("media identity track rejected remote={} stream={} session={} mid={} kind={} ssrc={} payload_type={} rtx={} error={}",
                            peer.remote_endpoint,
                            peer.stream_id,
                            peer.session_id,
                            resolution->mid,
                            resolution->kind,
                            resolution->ssrc,
                            static_cast<unsigned int>(resolution->payload_type),
                            resolution->rtx ? 1 : 0,
                            identity_result.error());

            resolution->resolved = false;
            resolution->newly_bound = false;
            resolution->state = media_track_resolution_state::unresolved;
            resolution->error = identity_result.error();

            return *resolution;
        }
    }
    if (resolution->newly_bound)
    {
        WEBRTC_LOG_INFO(
            "media track binding created remote={} stream={} session={} state={} mid={} kind={} ssrc={} payload_type={} rid={} repaired_rid={}",
            peer.remote_endpoint,
            peer.stream_id,
            peer.session_id,
            media_track_resolution_state_to_string(resolution->state),
            resolution->mid,
            resolution->kind,
            resolution->ssrc,
            static_cast<unsigned int>(resolution->payload_type),
            resolution->rid.has_value() ? *resolution->rid : "",
            resolution->repaired_rid.has_value() ? *resolution->repaired_rid : "");
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
        rtcp_transport_cc_observed_packet transport_cc_packet;

        transport_cc_packet.stream_id = peer.stream_id;

        transport_cc_packet.session_id = peer.session_id;

        transport_cc_packet.remote_endpoint = peer.remote_endpoint;

        transport_cc_packet.sender_ssrc = make_rtcp_report_local_ssrc(peer, header->ssrc);

        transport_cc_packet.media_ssrc = header->ssrc;

        transport_cc_packet.transport_sequence_number = *track_resolution->transport_wide_sequence_number;

        transport_cc_packet.arrival_time_milliseconds = now_milliseconds();

        auto transport_cc_observe_result = rtcp_transport_cc_feedback_service_->observe_received_packet(transport_cc_packet);

        if (!transport_cc_observe_result)
        {
            WEBRTC_LOG_DEBUG("rtcp transport cc observe skipped stream={} session={} remote={} ssrc={} twcc={} error={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             header->ssrc,
                             *track_resolution->transport_wide_sequence_number,
                             transport_cc_observe_result.error());
        }
    }

    auto publisher = registry_->find_publisher_by_session_id(peer.session_id);

    if (publisher == nullptr)
    {
        return;
    }

    std::string mid;
    std::optional<std::string> rid;
    std::optional<std::string> repaired_rid;

    if (track_resolution.has_value() && track_resolution->resolved)
    {
        mid = track_resolution->mid;

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

    if (peer.role != media_peer_role::publisher)
    {
        if (observation->receiver_report_count != 0 || observation->remb_count != 0)
        {
            WEBRTC_LOG_DEBUG("rtcp stats subscriber feedback observed stream={} session={} remote={} rr={} remb={} max_remb_bps={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             observation->receiver_report_count,
                             observation->remb_count,
                             observation->max_remb_bitrate_bps);
        }

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

        const uint32_t local_ssrc = make_rtcp_report_local_ssrc(peer, sender_report_ssrc);

        rtcp_report_source_config source;

        source.stream_id = peer.stream_id;

        source.session_id = peer.session_id;

        source.remote_endpoint = peer.remote_endpoint;

        source.local_ssrc = local_ssrc;

        source.cname = make_rtcp_cname(peer.session_id, local_ssrc);

        source.sender_report_enabled = false;

        source.receiver_report_enabled = true;

        rtcp_report_remember_source_attempts_total_.fetch_add(1, std::memory_order_relaxed);

        auto remember_result = rtcp_report_service_->remember_source(source, current_time_milliseconds);

        if (!remember_result)
        {
            rtcp_report_remember_source_failed_total_.fetch_add(1, std::memory_order_relaxed);

            WEBRTC_LOG_DEBUG("rtcp stats sender report remember source failed stream={} session={} remote={} ssrc={} error={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             sender_report_ssrc,
                             remember_result.error());

            continue;
        }

        rtcp_report_remember_source_success_total_.fetch_add(1, std::memory_order_relaxed);

        remembered_sender_report_source_count += 1;
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

    if (ssrc_mapper_ == nullptr)
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

        const std::optional<media_ssrc_mapping> mapping = ssrc_mapper_->find_by_subscriber_ssrc(peer.session_id, report_block.ssrc);

        if (!mapping.has_value())
        {
            mapping_missing_count += 1;

            WEBRTC_LOG_DEBUG("rtcp report block skipped mapping not found stream={} session={} remote={} subscriber_ssrc={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             report_block.ssrc);

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

    if (outbound_plain_packet.empty())
    {
        return std::nullopt;
    }

    if (ssrc_mapper_ == nullptr)
    {
        return std::nullopt;
    }

    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        return std::nullopt;
    }

    return ssrc_mapper_->find_by_subscriber_ssrc(target_peer.session_id, header->ssrc);
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

    if (outbound_plain_packet.empty())
    {
        return;
    }

    auto header = parse_rtp_packet_header(outbound_plain_packet);

    if (!header)
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp parse skipped remote={} error={}", target_peer.remote_endpoint, header.error());

        return;
    }
    if (mapping.has_value() && media_ssrc_mapping_is_rtx(*mapping))
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp skipped rtx mapping stream={} session={} remote={} subscriber_ssrc={} publisher_ssrc={}",
                         target_peer.stream_id,
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         mapping->subscriber_ssrc,
                         mapping->publisher_ssrc);

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

    std::string mid;

    if (mapping.has_value())
    {
        mid = mapping->subscriber_mid;
    }
    rtcp_sent_rtp_packet observed_packet;

    observed_packet.stream_id = target_peer.stream_id;

    observed_packet.session_id = target_peer.session_id;

    observed_packet.remote_endpoint = target_peer.remote_endpoint;

    observed_packet.mid = mid;

    observed_packet.ssrc = header->ssrc;
    observed_packet.rtp_timestamp = header->timestamp;

    observed_packet.payload_size = *payload_size;

    observed_packet.send_time_milliseconds = now_milliseconds();

    auto observe_result = rtcp_report_service_->observe_sent_rtp(observed_packet);

    if (!observe_result)
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp observe failed stream={} session={} remote={} ssrc={} error={}",
                         target_peer.stream_id,
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         header->ssrc,
                         observe_result.error());

        return;
    }

    rtcp_report_source_config source;

    source.stream_id = target_peer.stream_id;

    source.session_id = target_peer.session_id;

    source.remote_endpoint = target_peer.remote_endpoint;
    source.mid = mid;
    source.local_ssrc = header->ssrc;

    source.cname = make_rtcp_cname(target_peer.session_id, header->ssrc);

    source.sender_report_enabled = true;
    source.receiver_report_enabled = true;

    auto remember_result = rtcp_report_service_->remember_source(source);

    if (!remember_result)
    {
        WEBRTC_LOG_DEBUG("rtcp stats outbound rtp remember source failed stream={} session={} remote={} ssrc={} error={}",
                         target_peer.stream_id,
                         target_peer.session_id,
                         target_peer.remote_endpoint,
                         header->ssrc,
                         remember_result.error());
    }
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
                                                                                    const media_peer_info& target_peer,
                                                                                    const std::optional<media_track_resolution>& track_resolution)
{
    if (!track_resolution.has_value() || !track_resolution->resolved)
    {
        return std::nullopt;
    }

    if (track_resolution->mid.empty())
    {
        WEBRTC_LOG_WARN(
            "payload type mapping skipped resolved track has empty mid stream={} publisher_session={} subscriber_session={} kind={} payload_type={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            track_resolution->kind,
            static_cast<unsigned int>(track_resolution->payload_type));

        return std::nullopt;
    }

    auto table = get_or_create_payload_type_mapping_table(route, target_peer);

    if (!table.has_value())
    {
        return std::nullopt;
    }

    auto mapping = find_media_payload_type_mapping(*table, track_resolution->mid, track_resolution->payload_type);

    if (mapping.has_value())
    {
        return mapping;
    }

    WEBRTC_LOG_DEBUG("payload type mapping not found stream={} publisher_session={} subscriber_session={} mid={} kind={} payload_type={}",
                     route.source.stream_id,
                     route.source.session_id,
                     target_peer.session_id,
                     track_resolution->mid,
                     track_resolution->kind,
                     static_cast<unsigned int>(track_resolution->payload_type));

    return std::nullopt;
}

bool publisher_rtp_rid_is_selected_for_subscriber(const sdp::webrtc_offer_summary& publisher_offer,
                                                  const std::shared_ptr<media_identity_authority>& identity_authority,
                                                  const media_route_result& route,
                                                  const media_peer_info& target_peer,
                                                  const media_track_resolution& track_resolution)
{
    if (identity_authority == nullptr)
    {
        return true;
    }

    if (route.source.role != media_peer_role::publisher || target_peer.role != media_peer_role::subscriber)
    {
        return true;
    }

    if (!track_resolution.resolved || track_resolution.mid.empty() || track_resolution.kind.empty())
    {
        return true;
    }

    if (!is_video_media_kind(track_resolution.kind))
    {
        return true;
    }

    const sdp::media_summary* publisher_media = find_offer_media_by_mid(publisher_offer, track_resolution.mid);

    if (publisher_media == nullptr)
    {
        return true;
    }

    const std::vector<std::string> preferred_rids = make_default_simulcast_rid_preference(*publisher_media);

    if (preferred_rids.empty())
    {
        return true;
    }

    std::optional<std::string> packet_rid;

    if (track_resolution.rtx)
    {
        if (track_resolution.repaired_rid.has_value() && !track_resolution.repaired_rid->empty())
        {
            packet_rid = track_resolution.repaired_rid;
        }
        else if (track_resolution.rtx_primary_ssrc != 0)
        {
            auto primary_layer = identity_authority->find_rid_layer_by_primary_ssrc(route.source.session_id, track_resolution.rtx_primary_ssrc);

            if (primary_layer.has_value())
            {
                packet_rid = primary_layer->rid;
            }
        }
    }
    else if (track_resolution.rid.has_value() && !track_resolution.rid->empty())
    {
        packet_rid = track_resolution.rid;
    }

    if (!packet_rid.has_value() || packet_rid->empty())
    {
        return true;
    }

    auto preferred_layer =
        identity_authority->find_preferred_rid_layer(route.source.stream_id, route.source.session_id, track_resolution.mid, preferred_rids);

    if (!preferred_layer.has_value())
    {
        return true;
    }

    if (preferred_layer->rid == *packet_rid)
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
        preferred_layer->rid,
        track_resolution.ssrc,
        track_resolution.rtx ? 1 : 0);

    return false;
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

    auto mapping_result = ssrc_mapper_->get_or_create_mapping(route.source.stream_id,
                                                              route.source.session_id,
                                                              target_peer.session_id,
                                                              track_resolution->mid,
                                                              subscriber_mid,
                                                              track_resolution->kind,
                                                              track_resolution->ssrc,
                                                              now_milliseconds(),
                                                              track_resolution->rtx,
                                                              track_resolution->rtx_primary_ssrc,
                                                              track_resolution->rtx_repair_ssrc);
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

    if (mapping_result->packet_count == 1)
    {
        WEBRTC_LOG_INFO("media ssrc mapping created {}", media_ssrc_mapping_to_string(*mapping_result));
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

    if (ssrc_mapper_ == nullptr)
    {
        return std::nullopt;
    }

    auto mapping = ssrc_mapper_->find_by_subscriber_ssrc(route.source.session_id, subscriber_ssrc);

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
            "mapping_stream={} mapping_subscriber_session={} mapping_publisher_session={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->stream_id,
            mapping->subscriber_session_id,
            mapping->publisher_session_id);

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
            "publisher_ssrc={} kind={} rtx={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_ssrc,
            mapping->kind,
            media_ssrc_mapping_is_rtx(*mapping) ? 1 : 0);

        return std::nullopt;
    }

    if (!allow_rtx_repair_target)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx repair target is not forwarded stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "publisher_rtx_ssrc={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_ssrc);

        return std::nullopt;
    }

    if (mapping->publisher_rtx_primary_ssrc == 0)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary ssrc missing stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "publisher_rtx_ssrc={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_ssrc);

        return std::nullopt;
    }

    auto primary_mapping = ssrc_mapper_->find_by_publisher_ssrc(mapping->stream_id,
                                                                mapping->publisher_session_id,
                                                                mapping->subscriber_session_id,
                                                                mapping->publisher_mid,
                                                                mapping->publisher_rtx_primary_ssrc);

    if (!primary_mapping.has_value())
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary mapping not found stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "publisher_primary_ssrc={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            mapping->publisher_rtx_primary_ssrc);

        return std::nullopt;
    }

    if (primary_mapping->stream_id != route.source.stream_id || primary_mapping->subscriber_session_id != route.source.session_id ||
        primary_mapping->publisher_session_id != target_peer.session_id)
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary mapping target mismatch stream={} subscriber_session={} publisher_session={} feedback={} subscriber_ssrc={} "
            "primary_stream={} primary_subscriber_session={} primary_publisher_session={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            primary_mapping->stream_id,
            primary_mapping->subscriber_session_id,
            primary_mapping->publisher_session_id);

        return std::nullopt;
    }

    if (!media_ssrc_mapping_is_primary_video(*primary_mapping))
    {
        WEBRTC_LOG_WARN(
            "rtcp feedback rtx primary mapping is not primary video stream={} subscriber_session={} publisher_session={} feedback={} "
            "subscriber_ssrc={} publisher_primary_ssrc={} kind={} rtx={}",
            route.source.stream_id,
            route.source.session_id,
            target_peer.session_id,
            feedback_name,
            subscriber_ssrc,
            primary_mapping->publisher_ssrc,
            primary_mapping->kind,
            media_ssrc_mapping_is_rtx(*primary_mapping) ? 1 : 0);

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

            fci_rewrite.offset = 12 + i * 8;
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
                return std::nullopt;
            }

            rtcp_feedback_block_ssrc_rewrite fci_rewrite;

            fci_rewrite.offset = 20 + i * 4;
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

    auto mapping_result = ssrc_mapper_->get_or_create_mapping(primary_mapping.stream_id,
                                                              primary_mapping.publisher_session_id,
                                                              primary_mapping.subscriber_session_id,
                                                              primary_mapping.publisher_mid,
                                                              rtx_payload_type_mapping.subscriber_mid,
                                                              primary_mapping.kind,
                                                              primary_mapping.publisher_rtx_repair_ssrc,
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
                                                                                     const media_payload_type_mapping& primary_payload_type_mapping)
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

    const uint16_t seed_sequence_number = static_cast<uint16_t>(static_cast<uint32_t>(cached_packet.sequence_number) + 1U);

    const uint16_t rtx_sequence_number = rtx_sequence_allocator_->allocate(
        primary_ssrc_mapping.stream_id, primary_ssrc_mapping.subscriber_session_id, rtx_ssrc_mapping->subscriber_ssrc, seed_sequence_number);

    rtp_rtx_packet_options options;

    options.payload_type = static_cast<uint8_t>(rtx_payload_type_mapping->subscriber_payload_type);

    options.ssrc = rtx_ssrc_mapping->subscriber_ssrc;

    options.sequence_number = rtx_sequence_number;

    options.timestamp = cached_packet.timestamp;

    bool repaired_rid_rewrite_applied = false;

    if (registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(primary_ssrc_mapping.publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(primary_ssrc_mapping.subscriber_session_id);

        if (publisher != nullptr && subscriber != nullptr)
        {
            auto repaired_rid_rewrite = make_rtx_repaired_rid_header_extension_id_rewrite(
                *rtx_payload_type_mapping,
                publisher->remote_offer_summary(),
                subscriber->remote_offer_summary(),
                std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()));

            if (!repaired_rid_rewrite)
            {
                WEBRTC_LOG_WARN("rtx retransmit repaired-rid rewrite failed stream={} subscriber={} sequence={} error={}",
                                event.source.stream_id,
                                event.source.remote_endpoint,
                                cached_packet.sequence_number,
                                repaired_rid_rewrite.error());

                return std::nullopt;
            }

            if (repaired_rid_rewrite->has_value())
            {
                rtp_header_extension_id_rewrite tracked_rewrite;

                tracked_rewrite.source_id = (*repaired_rid_rewrite)->source_id;

                tracked_rewrite.target_id = (*repaired_rid_rewrite)->target_id;

                if (!remember_extmap_header_extension_id_rewrite(event.source.stream_id,
                                                                 primary_ssrc_mapping.publisher_session_id,
                                                                 primary_ssrc_mapping.subscriber_session_id,
                                                                 rtx_payload_type_mapping->subscriber_mid,
                                                                 sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri,
                                                                 tracked_rewrite))
                {
                    return std::nullopt;
                }

                options.header_extension_id_rewrites.push_back(**repaired_rid_rewrite);
            }
        }
    }
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

    if (rtx_payload_type_mapping->mid_rewrite_required && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(primary_ssrc_mapping.publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(primary_ssrc_mapping.subscriber_session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN("rtx retransmit mid rewrite skipped session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                            event.source.stream_id,
                            primary_ssrc_mapping.publisher_session_id,
                            primary_ssrc_mapping.subscriber_session_id,
                            cached_packet.sequence_number);

            return std::nullopt;
        }

        auto mid_rewrite = make_mid_header_extension_rewrite(*rtx_payload_type_mapping,
                                                             publisher->remote_offer_summary(),
                                                             subscriber->remote_offer_summary(),
                                                             std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()));

        if (!mid_rewrite)
        {
            WEBRTC_LOG_WARN("rtx retransmit mid rewrite failed stream={} subscriber={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            mid_rewrite.error());

            return std::nullopt;
        }

        if (mid_rewrite->has_value())
        {
            rtp_packet_rewrite_options rewrite_options;

            rewrite_options.header_extensions.push_back(std::move(**mid_rewrite));

            auto rewrite_result = rewrite_rtp_packet(std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()), rewrite_options);

            if (!rewrite_result)
            {
                WEBRTC_LOG_WARN("rtx retransmit mid rewrite packet failed stream={} subscriber={} sequence={} error={}",
                                event.source.stream_id,
                                event.source.remote_endpoint,
                                cached_packet.sequence_number,
                                rewrite_result.error());

                return std::nullopt;
            }

            rtx_packet = std::move(rewrite_result->packet);
        }
    }
    if (registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(primary_ssrc_mapping.publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(primary_ssrc_mapping.subscriber_session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtx retransmit transport-cc rewrite skipped session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                primary_ssrc_mapping.publisher_session_id,
                primary_ssrc_mapping.subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        auto transport_cc_rewrite =
            make_transport_wide_cc_header_extension_id_rewrite(*rtx_payload_type_mapping,
                                                               publisher->remote_offer_summary(),
                                                               subscriber->remote_offer_summary(),
                                                               std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()));

        if (!transport_cc_rewrite)
        {
            WEBRTC_LOG_WARN("rtx retransmit transport-cc rewrite failed stream={} subscriber={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            transport_cc_rewrite.error());

            return std::nullopt;
        }

        if (transport_cc_rewrite->has_value())
        {
            rtp_packet_rewrite_options rewrite_options;

            rewrite_options.header_extension_id_rewrites.push_back(**transport_cc_rewrite);

            auto rewrite_result = rewrite_rtp_packet(std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()), rewrite_options);

            if (!rewrite_result)
            {
                WEBRTC_LOG_WARN("rtx retransmit transport-cc rewrite packet failed stream={} subscriber={} sequence={} error={}",
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
        validate_rtp_rtx_packet(std::span<const uint8_t>(rtx_packet->data(), rtx_packet->size()), options, cached_packet.sequence_number);
    if (!final_rtx_validation)
    {
        WEBRTC_LOG_WARN(
            "rtx retransmit packet validation failed stream={} subscriber={} primary_ssrc={} rtx_ssrc={} primary_sequence={} rtx_sequence={} "
            "error={}",
            event.source.stream_id,
            event.source.remote_endpoint,
            primary_ssrc_mapping.publisher_ssrc,
            rtx_ssrc_mapping->subscriber_ssrc,
            cached_packet.sequence_number,
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
                                            now_milliseconds());
    }

    WEBRTC_LOG_DEBUG(
        "rtx retransmit packet built stream={} subscriber={} primary_ssrc={} subscriber_primary_ssrc={} rtx_ssrc={} primary_sequence={} "
        "rtx_sequence={} osn={} primary_pt={} rtx_pt={} repaired_rid_rewrite={} rtx_payload_size={} size={}",
        event.source.stream_id,
        event.source.remote_endpoint,
        primary_ssrc_mapping.publisher_ssrc,
        primary_ssrc_mapping.subscriber_ssrc,
        rtx_ssrc_mapping->subscriber_ssrc,
        cached_packet.sequence_number,
        rtx_sequence_number,
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
        if (!publisher_rtp_rid_is_selected_for_subscriber(
                publisher->remote_offer_summary(), identity_authority_, route, target_peer, *track_resolution))
        {
            return std::nullopt;
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

    if (payload_type_mapping.has_value() && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(target_peer.session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN("rtp mid rewrite failed session not found stream={} publisher_session={} subscriber_session={}",
                            route.source.stream_id,
                            route.source.session_id,
                            target_peer.session_id);

            return std::nullopt;
        }

        auto mid_payload_rewrite =
            make_mid_header_extension_rewrite(*payload_type_mapping,
                                              publisher->remote_offer_summary(),
                                              subscriber->remote_offer_summary(),
                                              std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

        if (!mid_payload_rewrite)
        {
            WEBRTC_LOG_WARN(
                "rtp mid payload rewrite failed stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} error={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                mid_payload_rewrite.error());

            return std::nullopt;
        }

        if (mid_payload_rewrite->has_value())
        {
            options.header_extensions.push_back(std::move(**mid_payload_rewrite));

            rewrite_required = true;
        }

        auto mid_id_rewrite = make_mid_header_extension_id_rewrite(*payload_type_mapping,
                                                                   publisher->remote_offer_summary(),
                                                                   subscriber->remote_offer_summary(),
                                                                   std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

        if (!mid_id_rewrite)
        {
            WEBRTC_LOG_WARN(
                "rtp mid id rewrite failed stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} error={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                mid_id_rewrite.error());

            return std::nullopt;
        }

        if (mid_id_rewrite->has_value())
        {
            if (!remember_extmap_header_extension_id_rewrite(route.source.stream_id,
                                                             route.source.session_id,
                                                             target_peer.session_id,
                                                             payload_type_mapping->subscriber_mid,
                                                             k_mid_extension_uri,
                                                             **mid_id_rewrite))
            {
                return std::nullopt;
            }

            options.header_extension_id_rewrites.push_back(**mid_id_rewrite);

            rewrite_required = true;
        }
    }
    if (payload_type_mapping.has_value() && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(target_peer.session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN("rtp transport-cc rewrite failed session not found stream={} publisher_session={} subscriber_session={}",
                            route.source.stream_id,
                            route.source.session_id,
                            target_peer.session_id);

            return std::nullopt;
        }

        auto transport_cc_rewrite =
            make_transport_wide_cc_header_extension_id_rewrite(*payload_type_mapping,
                                                               publisher->remote_offer_summary(),
                                                               subscriber->remote_offer_summary(),
                                                               std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

        if (!transport_cc_rewrite)
        {
            WEBRTC_LOG_WARN(
                "rtp transport-cc rewrite failed stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} error={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                transport_cc_rewrite.error());

            return std::nullopt;
        }

        if (transport_cc_rewrite->has_value())
        {
            options.header_extension_id_rewrites.push_back(**transport_cc_rewrite);

            rewrite_required = true;
        }
    }
    if (payload_type_mapping.has_value() && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(target_peer.session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN("rtp rid rewrite skipped session not found stream={} publisher_session={} subscriber_session={}",
                            route.source.stream_id,
                            route.source.session_id,
                            target_peer.session_id);

            return std::nullopt;
        }

        optional_header_extension_id_rewrite_result rid_rewrite =
            payload_type_mapping->rtx
                ? make_repaired_rid_header_extension_id_rewrite(*payload_type_mapping,
                                                                publisher->remote_offer_summary(),
                                                                subscriber->remote_offer_summary(),
                                                                std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()))
                : make_rid_header_extension_id_rewrite(*payload_type_mapping,
                                                       publisher->remote_offer_summary(),
                                                       subscriber->remote_offer_summary(),
                                                       std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

        if (!rid_rewrite)
        {
            WEBRTC_LOG_WARN(
                "rtp rid rewrite failed stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} rtx={} error={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                payload_type_mapping->rtx ? 1 : 0,
                rid_rewrite.error());

            return std::nullopt;
        }

        if (rid_rewrite->has_value())
        {
            const std::string_view uri = payload_type_mapping->rtx ? sdp::k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri
                                                                   : sdp::k_rtp_header_extension_sdes_rtp_stream_id_uri;

            if (!remember_extmap_header_extension_id_rewrite(route.source.stream_id,
                                                             route.source.session_id,
                                                             target_peer.session_id,
                                                             payload_type_mapping->subscriber_mid,
                                                             uri,
                                                             **rid_rewrite))
            {
                return std::nullopt;
            }

            options.header_extension_id_rewrites.push_back(**rid_rewrite);

            rewrite_required = true;
        }
    }
    if (payload_type_mapping.has_value() && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(target_peer.session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN("rtp abs-send-time rewrite failed session not found stream={} publisher_session={} subscriber_session={}",
                            route.source.stream_id,
                            route.source.session_id,
                            target_peer.session_id);

            return std::nullopt;
        }

        auto absolute_send_time_rewrite =
            make_absolute_send_time_header_extension_id_rewrite(*payload_type_mapping,
                                                                publisher->remote_offer_summary(),
                                                                subscriber->remote_offer_summary(),
                                                                std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

        if (!absolute_send_time_rewrite)
        {
            WEBRTC_LOG_WARN(
                "rtp abs-send-time rewrite failed stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} error={}",
                payload_type_mapping->stream_id,
                route.source.session_id,
                target_peer.session_id,
                payload_type_mapping->publisher_mid,
                payload_type_mapping->subscriber_mid,
                absolute_send_time_rewrite.error());

            return std::nullopt;
        }

        if (absolute_send_time_rewrite->has_value())
        {
            if (!remember_extmap_header_extension_id_rewrite(route.source.stream_id,
                                                             route.source.session_id,
                                                             target_peer.session_id,
                                                             payload_type_mapping->subscriber_mid,
                                                             k_absolute_send_time_extension_uri,
                                                             **absolute_send_time_rewrite))
            {
                return std::nullopt;
            }

            options.header_extension_id_rewrites.push_back(**absolute_send_time_rewrite);

            rewrite_required = true;
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
    const rtcp_feedback_route_event& event, const rtp_packet_cache_entry& cached_packet, const std::optional<media_ssrc_mapping>& ssrc_mapping)
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
        std::optional<std::vector<uint8_t>> rtx_packet = make_rtx_retransmit_plain_packet(event, cached_packet, *ssrc_mapping, *payload_type_mapping);

        if (rtx_packet.has_value())
        {
            return make_rtx_result(std::move(*rtx_packet));
        }
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
                "rtp nack retransmit mid rewrite failed session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        auto mid_payload_rewrite =
            make_mid_header_extension_rewrite(*payload_type_mapping,
                                              publisher->remote_offer_summary(),
                                              subscriber->remote_offer_summary(),
                                              std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()));

        if (!mid_payload_rewrite)
        {
            WEBRTC_LOG_WARN("rtp nack retransmit mid payload rewrite failed stream={} subscriber={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            mid_payload_rewrite.error());

            return std::nullopt;
        }

        if (mid_payload_rewrite->has_value())
        {
            options.header_extensions.push_back(std::move(**mid_payload_rewrite));

            rewrite_required = true;
        }

        auto mid_id_rewrite =
            make_mid_header_extension_id_rewrite(*payload_type_mapping,
                                                 publisher->remote_offer_summary(),
                                                 subscriber->remote_offer_summary(),
                                                 std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()));

        if (!mid_id_rewrite)
        {
            WEBRTC_LOG_WARN("rtp nack retransmit mid id rewrite failed stream={} subscriber={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            mid_id_rewrite.error());

            return std::nullopt;
        }

        if (mid_id_rewrite->has_value())
        {
            if (!remember_extmap_header_extension_id_rewrite(event.source.stream_id,
                                                             ssrc_mapping->publisher_session_id,
                                                             ssrc_mapping->subscriber_session_id,
                                                             payload_type_mapping->subscriber_mid,
                                                             k_mid_extension_uri,
                                                             **mid_id_rewrite))
            {
                return std::nullopt;
            }
            options.header_extension_id_rewrites.push_back(**mid_id_rewrite);
            rewrite_required = true;
        }
    }
    if (registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(ssrc_mapping->publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(ssrc_mapping->subscriber_session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtp nack retransmit transport-cc rewrite failed session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        auto transport_cc_rewrite = make_transport_wide_cc_header_extension_id_rewrite(
            *payload_type_mapping,
            publisher->remote_offer_summary(),
            subscriber->remote_offer_summary(),
            std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()));

        if (!transport_cc_rewrite)
        {
            WEBRTC_LOG_WARN("rtp nack retransmit transport-cc rewrite failed stream={} subscriber={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            transport_cc_rewrite.error());

            return std::nullopt;
        }

        if (transport_cc_rewrite->has_value())
        {
            options.header_extension_id_rewrites.push_back(**transport_cc_rewrite);

            rewrite_required = true;
        }
    }
    if (payload_type_mapping.has_value() && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(ssrc_mapping->publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(ssrc_mapping->subscriber_session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtp nack retransmit rid rewrite failed session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        auto rid_rewrite =
            make_rid_header_extension_id_rewrite(*payload_type_mapping,
                                                 publisher->remote_offer_summary(),
                                                 subscriber->remote_offer_summary(),
                                                 std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()));

        if (!rid_rewrite)
        {
            WEBRTC_LOG_WARN("rtp nack retransmit rid rewrite failed stream={} subscriber={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            rid_rewrite.error());

            return std::nullopt;
        }

        if (rid_rewrite->has_value())
        {
            if (!remember_extmap_header_extension_id_rewrite(event.source.stream_id,
                                                             ssrc_mapping->publisher_session_id,
                                                             ssrc_mapping->subscriber_session_id,
                                                             payload_type_mapping->subscriber_mid,
                                                             sdp::k_rtp_header_extension_sdes_rtp_stream_id_uri,
                                                             **rid_rewrite))
            {
                return std::nullopt;
            }

            options.header_extension_id_rewrites.push_back(**rid_rewrite);

            rewrite_required = true;
        }
    }
    if (registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(ssrc_mapping->publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(ssrc_mapping->subscriber_session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN(
                "rtp nack retransmit abs-send-time rewrite failed session not found stream={} publisher_session={} subscriber_session={} sequence={}",
                event.source.stream_id,
                ssrc_mapping->publisher_session_id,
                ssrc_mapping->subscriber_session_id,
                cached_packet.sequence_number);

            return std::nullopt;
        }

        auto absolute_send_time_rewrite = make_absolute_send_time_header_extension_id_rewrite(
            *payload_type_mapping,
            publisher->remote_offer_summary(),
            subscriber->remote_offer_summary(),
            std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()));

        if (!absolute_send_time_rewrite)
        {
            WEBRTC_LOG_WARN("rtp nack retransmit abs-send-time rewrite failed stream={} subscriber={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            cached_packet.sequence_number,
                            absolute_send_time_rewrite.error());

            return std::nullopt;
        }

        if (absolute_send_time_rewrite->has_value())
        {
            if (!remember_extmap_header_extension_id_rewrite(event.source.stream_id,
                                                             ssrc_mapping->publisher_session_id,
                                                             ssrc_mapping->subscriber_session_id,
                                                             payload_type_mapping->subscriber_mid,
                                                             k_absolute_send_time_extension_uri,
                                                             **absolute_send_time_rewrite))
            {
                return std::nullopt;
            }

            options.header_extension_id_rewrites.push_back(**absolute_send_time_rewrite);

            rewrite_required = true;
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
void ice_udp_server::handle_rtcp_feedback_event(const rtcp_feedback_route_event& event)
{
    if (!event.valid)
    {
        return;
    }

    if (event.has_generic_nack)
    {
        retransmit_cached_rtp_packets(event);
    }
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

    if (media_ssrc_mapping_is_primary_video(*feedback_mapping))
    {
        resolution.ssrc_mapping = feedback_mapping;

        resolution.cache_media_ssrc = feedback_mapping->publisher_ssrc;

        resolution.primary_video = true;
        resolution.rtx_feedback = false;

        resolution.sequences.reserve(feedback_sequence_numbers.size());

        for (uint16_t sequence_number : feedback_sequence_numbers)
        {
            nack_retransmit_sequence sequence;

            sequence.feedback_sequence_number = sequence_number;

            sequence.cache_sequence_number = sequence_number;

            sequence.rtx_feedback = false;

            resolution.sequences.push_back(sequence);
        }

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
                "rtp nack retransmit rtx sequence mapping primary ssrc mismatch stream={} subscriber={} rtx_ssrc={} rtx_sequence={} "
                "indexed_primary_ssrc={} mapping_primary_ssrc={}",
                event.source.stream_id,
                event.source.remote_endpoint,
                feedback_media_ssrc,
                rtx_sequence_number,
                indexed->publisher_primary_ssrc,
                primary_mapping->publisher_ssrc);

            continue;
        }

        nack_retransmit_sequence sequence;

        sequence.feedback_sequence_number = rtx_sequence_number;

        sequence.cache_sequence_number = indexed->primary_sequence_number;

        sequence.rtx_feedback = true;

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

        auto retransmit_plain_packet = make_retransmit_plain_packet(event, *cached, ssrc_mapping);

        if (!retransmit_plain_packet.has_value())
        {
            failed_count += 1;

            continue;
        }

        const bool retransmit_is_rtx = retransmit_plain_packet->kind == retransmit_plain_packet_kind::rtx;

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(retransmit_plain_packet->packet.data(), retransmit_plain_packet->packet.size()),
            event.source.remote_endpoint,
            srtp_packet_kind::rtcp);

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
    std::size_t remaining_packets = 0;

    if (rtp_packet_cache_ != nullptr)
    {
        rtp_packet_cache_->erase_stream(stream_id);

        remaining_packets = rtp_packet_cache_->size();

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

        for (auto iterator = fir_sequence_number_by_key_.begin(); iterator != fir_sequence_number_by_key_.end();)
        {
            if (iterator->first.starts_with(std::string(stream_id) + "|"))
            {
                iterator = fir_sequence_number_by_key_.erase(iterator);
                continue;
            }
            ++iterator;
        }

        publisher_video_ssrc_by_stream_.erase(std::string(stream_id));
        pending_republish_keyframe_state_by_stream_.erase(std::string(stream_id));
    }
    WEBRTC_LOG_INFO(
        "ice udp stream runtime state cleanup stream={} cache_erased={} remaining_cache_packets={} media_router_streams_before={} "
        "media_router_streams_after={} payload_type_mappings_erased={} keyframe_request_states_erased={}",
        stream_id,
        cache_erased ? 1 : 0,
        remaining_packets,
        media_router_stream_count_before,
        media_router_stream_count_after,
        erased_payload_type_mappings,
        erased_keyframe_request_states);
}
void ice_udp_server::mark_republish_keyframe_request_pending(std::string_view stream_id, std::string_view new_publisher_session_id)
{
    if (stream_id.empty() || new_publisher_session_id.empty())
    {
        return;
    }

    {
        std::lock_guard lock(endpoint_mutex_);
        republish_keyframe_request_state state;
        state.publisher_session_id = std::string(new_publisher_session_id);
        pending_republish_keyframe_state_by_stream_[std::string(stream_id)] = std::move(state);
    }

    WEBRTC_LOG_INFO(
        "publisher republish keyframe request pending stream={} publisher_session={} scope=subscribers", stream_id, new_publisher_session_id);
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

    std::lock_guard lock(endpoint_mutex_);

    const auto iterator = pending_republish_keyframe_state_by_stream_.find(route.source.stream_id);

    if (iterator == pending_republish_keyframe_state_by_stream_.end())
    {
        return false;
    }

    republish_keyframe_request_state& state = iterator->second;

    if (state.publisher_session_id != route.source.session_id)
    {
        return false;
    }

    if (state.consumed_subscriber_session_ids.contains(target_peer.session_id))
    {
        return false;
    }

    state.consumed_subscriber_session_ids.insert(target_peer.session_id);

    WEBRTC_LOG_INFO(
        "publisher republish keyframe request consumed stream={} publisher_session={} subscriber_session={} consumed_subscribers={} media_ssrc={}",
        route.source.stream_id,
        route.source.session_id,
        target_peer.session_id,
        state.consumed_subscriber_session_ids.size(),
        packet.ssrc);

    return true;
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
        return;
    }

    if (srtp_transport_ == nullptr)
    {
        WEBRTC_LOG_WARN("media forward skipped srtp transport is null stream={} session={}", route.source.stream_id, route.source.session_id);

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

            continue;
        }

        auto outbound_plain_packet = make_forward_plain_packet(packet, route, track_resolution, feedback_events, *target_peer);
        if (!outbound_plain_packet.has_value())
        {
            WEBRTC_LOG_WARN("media forward skipped rewrite failed stream={} source={} target={} kind={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind));

            continue;
        }

        if (outbound_plain_packet->empty())
        {
            WEBRTC_LOG_WARN("media forward skipped empty rewritten packet stream={} source={} target={} kind={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind));

            continue;
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(outbound_plain_packet->data(), outbound_plain_packet->size()), target_address, packet.kind);
        if (!protected_packet)
        {
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

            const std::optional<media_ssrc_mapping> outbound_mapping = find_outbound_ssrc_mapping(*target_peer, outbound_span);

            observe_outbound_rtp_stats(*target_peer, outbound_span, outbound_mapping);

            observe_outbound_track_stats(*target_peer, outbound_span, outbound_mapping);

            maybe_request_keyframe_from_publisher(packet, route, track_resolution, *target_peer);
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

void ice_udp_server::send_response(std::vector<uint8_t> response, const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    auto response_buffer = std::make_shared<std::vector<uint8_t>>(std::move(response));

    auto self = shared_from_this();

    socket_.async_send_to(boost::asio::buffer(*response_buffer),
                          remote_endpoint,
                          [this, self, response_buffer, remote_address](boost::system::error_code ec, std::size_t bytes_transferred)
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

    pair.nominated = pair.nominated || nominated;
}

std::expected<ice_udp_server::ice_candidate_pair_selection_result, std::string> ice_udp_server::select_candidate_pair(
    std::string_view session_id,
    std::string_view stream_id,
    const udp::endpoint& remote_endpoint,
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

    ice_candidate_pair_selection_result result;

    std::lock_guard lock(endpoint_mutex_);

    const auto endpoint_owner = session_id_by_endpoint_address_.find(remote_address);

    if (endpoint_owner != session_id_by_endpoint_address_.end() && endpoint_owner->second != session_id)
    {
        return make_error("ice endpoint is already selected by another session");
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

            pair.last_binding_at_milliseconds = now_milliseconds();

            pair.nominated = true;
            pair.selected = true;

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

std::vector<std::string> ice_udp_server::collect_expired_ice_consent_session_ids(uint64_t current_time_milliseconds)
{
    std::vector<std::string> expired_session_ids;

    std::lock_guard lock(endpoint_mutex_);

    for (const auto& [key, pair] : candidate_pairs_by_key_)
    {
        (void)key;

        if (!pair.selected || pair.last_binding_at_milliseconds == 0)
        {
            continue;
        }

        const uint64_t age_milliseconds =
            current_time_milliseconds > pair.last_binding_at_milliseconds ? current_time_milliseconds - pair.last_binding_at_milliseconds : 0;

        if (age_milliseconds < k_ice_consent_timeout_milliseconds)
        {
            continue;
        }

        if (!contains_string(expired_session_ids, pair.session_id))
        {
            expired_session_ids.push_back(pair.session_id);
        }
    }

    return expired_session_ids;
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

        if (age_milliseconds < k_unselected_candidate_pair_retention_milliseconds)
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

    {
        std::lock_guard lock(endpoint_mutex_);

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
    send_dtls_close_notify(remote_address);
    forget_peer_transport_state(remote_address);
}
void ice_udp_server::send_dtls_close_notify(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    if (dtls_transport_ == nullptr)
    {
        return;
    }

    auto remote_endpoint = find_remote_endpoint(remote_address);

    if (!remote_endpoint.has_value())
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

        send_response(std::move(packet), *remote_endpoint);
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

    const std::string remote_key(remote_address);

    retired_endpoint_state& state = retired_endpoints_by_address_[remote_key];

    if (state.expires_at_milliseconds != 0 && current_time_milliseconds >= state.expires_at_milliseconds)
    {
        state.suppressed_packets = 0;
    }

    state.expires_at_milliseconds = current_time_milliseconds + k_retired_endpoint_retention_milliseconds;

    state.session_id = std::string(session_id);

    state.reason = std::string(reason);

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

    retired_ice_credential_state& state = retired_ice_credentials_by_local_ufrag_[std::string(local_ice_ufrag)];

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

    expire_retired_ice_credentials_locked(now_milliseconds());

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

std::optional<ice_udp_server::udp::endpoint> ice_udp_server::find_remote_endpoint(std::string_view remote_address) const
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

std::string ice_udp_server::endpoint_ip(const udp::endpoint& endpoint) { return get_endpoint_ip(endpoint); }
}    // namespace webrtc
