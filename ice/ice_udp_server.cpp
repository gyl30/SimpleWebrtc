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
#include "rtp/rtp_packet_rewriter.h"
#include "session/session_state.h"
#include "util/timestamp.h"

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_ice_username_fragment_size = 256;

constexpr std::size_t k_max_ice_username_size = k_max_ice_username_fragment_size * 2 + 1;

constexpr auto k_minimum_dtls_timer_delay = std::chrono::milliseconds(1);

constexpr auto k_ice_consent_check_interval = std::chrono::seconds(5);

constexpr auto k_rtcp_report_interval = std::chrono::milliseconds(200);

constexpr auto k_rtcp_report_empty_generation_log_interval = std::chrono::seconds(60);

constexpr uint64_t k_ice_consent_timeout_milliseconds = 30000;

constexpr uint64_t k_unselected_candidate_pair_retention_milliseconds = 120000;

constexpr std::string_view k_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";

constexpr uint64_t k_fnv_offset_basis = 1469598103934665603ULL;

constexpr uint64_t k_fnv_prime = 1099511628211ULL;

struct ice_username_parts
{
    std::string_view recipient_ufrag;
    std::string_view sender_ufrag;
};

using optional_mid_rewrite_result = std::expected<std::optional<rtp_header_extension_rewrite>, std::string>;

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

uint64_t now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }

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

uint16_t read_network_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_network_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

void write_network_u32(std::vector<uint8_t>& packet, std::size_t offset, uint32_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 24U) & 0xffU);

    packet[offset + 1] = static_cast<uint8_t>((value >> 16U) & 0xffU);

    packet[offset + 2] = static_cast<uint8_t>((value >> 8U) & 0xffU);

    packet[offset + 3] = static_cast<uint8_t>(value & 0xffU);
}

bool is_rtcp_feedback_packet_type(uint8_t packet_type) { return packet_type == 205 || packet_type == 206; }

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

std::expected<std::vector<uint8_t>, std::string> rewrite_rtcp_feedback_media_ssrc(std::span<const uint8_t> packet, uint32_t target_media_ssrc)
{
    if (packet.empty())
    {
        return make_error("rtcp feedback rewrite packet is empty");
    }

    if (target_media_ssrc == 0)
    {
        return make_error("rtcp feedback rewrite target media ssrc is zero");
    }

    if (packet.size() < 4)
    {
        return make_error("rtcp feedback rewrite packet is too small");
    }

    std::vector<uint8_t> rewritten;

    rewritten.assign(packet.begin(), packet.end());

    std::size_t offset = 0;
    bool changed = false;

    while (offset + 4 <= rewritten.size())
    {
        const std::span<const uint8_t> view(rewritten.data(), rewritten.size());

        const uint8_t version = static_cast<uint8_t>(view[offset] >> 6U);

        if (version != 2)
        {
            return make_error("rtcp feedback rewrite version is invalid");
        }

        const uint8_t packet_type = view[offset + 1];

        const uint16_t length = read_network_u16(view, offset + 2);

        const std::size_t packet_size = (static_cast<std::size_t>(length) + 1) * 4;

        if (packet_size == 0 || offset + packet_size > rewritten.size())
        {
            return make_error("rtcp feedback rewrite packet is truncated");
        }

        if (is_rtcp_feedback_packet_type(packet_type))
        {
            if (packet_size < 12)
            {
                return make_error("rtcp feedback rewrite feedback packet is too small");
            }

            const uint32_t current_media_ssrc = read_network_u32(view, offset + 8);

            if (current_media_ssrc != target_media_ssrc)
            {
                write_network_u32(rewritten, offset + 8, target_media_ssrc);

                changed = true;
            }
        }

        offset += packet_size;
    }

    if (offset != rewritten.size())
    {
        return make_error("rtcp feedback rewrite compound packet has trailing bytes");
    }

    (void)changed;

    return rewritten;
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

    WEBRTC_LOG_INFO("rtcp report service config max_report_blocks={} interval_ms={} jitter_ms={} max_packets_per_generation={}",
                    config.max_report_blocks,
                    config.report_interval_milliseconds,
                    config.report_jitter_milliseconds,
                    config.max_packets_per_generation);

    return config;
}

std::shared_ptr<rtcp_report_service> make_rtcp_report_service_from_env()
{
    return std::make_shared<rtcp_report_service>(make_rtcp_report_service_config_from_env());
}
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

    if (*publisher_mid_extension_id != *subscriber_mid_extension_id)
    {
        return make_error("rtp mid extension id rewrite is unsupported");
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

void log_rtcp_feedback_route_event(const rtcp_feedback_route_event& event)
{
    WEBRTC_LOG_INFO(
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

std::vector<uint16_t> expand_nack_sequences(const std::vector<rtcp_nack_item>& nack_items)
{
    std::vector<uint16_t> sequence_numbers;

    sequence_numbers.reserve(nack_items.size() * 17);

    for (const auto& item : nack_items)
    {
        sequence_numbers.push_back(item.packet_id);

        for (uint16_t bit_index = 0; bit_index < 16; ++bit_index)
        {
            const uint16_t mask = static_cast<uint16_t>(1U << bit_index);

            if ((item.lost_packet_bitmask & mask) == 0)
            {
                continue;
            }

            sequence_numbers.push_back(static_cast<uint16_t>(item.packet_id + static_cast<uint16_t>(bit_index + 1)));
        }
    }

    return sequence_numbers;
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
      bind_host_(std::move(bind_host)),
      bind_port_(bind_port),
      registry_(std::move(registry)),
      media_router_(std::move(media_router)),
      track_resolver_(std::make_shared<media_track_resolver>()),
      ssrc_mapper_(std::make_shared<media_ssrc_mapper>()),
      rtcp_report_service_(make_rtcp_report_service_from_env())
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

    if (rtcp_report_service_ == nullptr)
    {
        rtcp_report_service_ = make_rtcp_report_service_from_env();
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

        registry_callback_registered_ = false;
    }

    dtls_timeout_timer_.cancel();

    ice_consent_timer_.cancel();

    rtcp_report_timer_.cancel();

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
    }

    track_resolver_ = std::make_shared<media_track_resolver>();

    ssrc_mapper_ = std::make_shared<media_ssrc_mapper>();

    rtcp_report_service_ = make_rtcp_report_service_from_env();

    last_empty_rtcp_report_log_milliseconds_ = 0;

    reset_rtcp_report_send_counters();

    if (rtp_packet_cache_ != nullptr)
    {
        rtp_packet_cache_->clear();
    }
}

void ice_udp_server::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::string remote_address;

    {
        std::lock_guard lock(endpoint_mutex_);

        erase_candidate_pairs_for_session_locked(session_id);

        erase_payload_type_mappings_for_session_locked(session_id);

        const auto iterator = endpoint_address_by_session_id_.find(std::string(session_id));

        if (iterator != endpoint_address_by_session_id_.end())
        {
            remote_address = iterator->second;

            endpoint_address_by_session_id_.erase(iterator);

            session_id_by_endpoint_address_.erase(remote_address);

            endpoints_by_address_.erase(remote_address);
        }
    }

    if (track_resolver_ != nullptr)
    {
        track_resolver_->forget_session(session_id);
    }

    if (ssrc_mapper_ != nullptr)
    {
        ssrc_mapper_->forget_session(session_id);
    }

    if (rtcp_report_service_ != nullptr)
    {
        rtcp_report_service_->forget_session(session_id);
    }

    if (!remote_address.empty())
    {
        forget_peer_transport_state(remote_address);

        WEBRTC_LOG_INFO("ice udp session transport state removed session={} remote={}", session_id, remote_address);
    }
    else
    {
        WEBRTC_LOG_DEBUG("ice udp session selected endpoint not found session={}", session_id);
    }

    schedule_dtls_timeout();
}

uint16_t ice_udp_server::local_port() const { return bind_port_; }

ice_udp_server_result ice_udp_server::init_dtls_transport()
{
    if (dtls_transport_ != nullptr && srtp_transport_ != nullptr && rtp_packet_cache_ != nullptr)
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

    cache_config.max_packets = 4096;

    rtp_packet_cache_ = std::make_shared<rtp_packet_cache>(cache_config);

    WEBRTC_LOG_INFO("dtls transport initialized handshake_timeout_ms={}", transport_config.handshake_timeout.count());

    WEBRTC_LOG_INFO("srtp transport initialized");

    WEBRTC_LOG_INFO("rtp packet cache initialized max_packets={}", cache_config.max_packets);

    return {};
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

            WEBRTC_LOG_INFO("ice udp registry removal callback kind={} stream={} session={}",
                            stream_session_kind_to_string(removed_session.kind),
                            removed_session.stream_id,
                            removed_session.session_id);

            self->forget_session(removed_session.session_id);

            if (removed_session.kind == stream_session_kind::publisher)
            {
                self->erase_rtp_cache(removed_session.stream_id);
            }
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

    if (is_stun_packet(packet))
    {
        handle_stun_packet(packet, remote_endpoint_);
    }
    else if (is_dtls_packet(packet))
    {
        handle_dtls_packet(packet, remote_endpoint_);
    }
    else if (is_rtp_or_rtcp_packet(packet))
    {
        handle_rtp_or_rtcp_packet(packet, remote_endpoint_);
    }
    else
    {
        const std::string remote_address = endpoint_to_string(remote_endpoint_);

        WEBRTC_LOG_DEBUG("ice udp unknown packet remote={} size={} first_byte={}",
                         remote_address,
                         bytes_transferred,
                         bytes_transferred == 0 ? 0U : static_cast<unsigned int>(receive_buffer_[0]));
    }

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

        auto remote_endpoint = find_remote_endpoint(event.remote_endpoint);

        if (!remote_endpoint.has_value())
        {
            WEBRTC_LOG_WARN("dtls retransmit endpoint not found remote={} packets={}", event.remote_endpoint, event.packets.size());

            forget_peer_transport_state(event.remote_endpoint);

            continue;
        }

        for (auto& packet : event.packets)
        {
            WEBRTC_LOG_DEBUG("dtls retransmit packet remote={} size={}", event.remote_endpoint, packet.size());

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

    const uint64_t current_time = now_milliseconds();

    std::vector<std::string> expired_remotes = expire_ice_candidate_pairs(current_time);

    for (const auto& remote_address : expired_remotes)
    {
        WEBRTC_LOG_WARN("ice consent expired remote={}", remote_address);

        forget_peer_transport_state(remote_address);
    }

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
            WEBRTC_LOG_DEBUG("rtcp active report generation error={}", error);
        }
    }

    const rtcp_report_service_runtime_snapshot snapshot = rtcp_report_runtime_snapshot();

    if (generation.packets.empty())
    {
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

    WEBRTC_LOG_INFO("rtcp active report generation {} runtime={}",
                    rtcp_report_service_generation_to_string(generation),
                    rtcp_report_service_runtime_snapshot_to_string(snapshot));

    for (const auto& report_packet : generation.packets)
    {
        rtcp_report_send_attempts_total_.fetch_add(1, std::memory_order_relaxed);

        auto remote_endpoint = find_remote_endpoint(report_packet.source.remote_endpoint);

        if (!remote_endpoint.has_value())
        {
            rtcp_report_endpoint_not_found_total_.fetch_add(1, std::memory_order_relaxed);

            WEBRTC_LOG_WARN("rtcp active report endpoint not found stream={} session={} remote={} local_ssrc={}",
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
            rtcp_report_protect_ignored_total_.fetch_add(1, std::memory_order_relaxed);

            WEBRTC_LOG_DEBUG("rtcp active report protect ignored stream={} session={} remote={} local_ssrc={} reason={}",
                             report_packet.source.stream_id,
                             report_packet.source.session_id,
                             report_packet.source.remote_endpoint,
                             report_packet.source.local_ssrc,
                             protected_packet->reason);

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

        rtcp_report_send_success_total_.fetch_add(1, std::memory_order_relaxed);
    }
}
void ice_udp_server::reset_rtcp_report_send_counters()
{
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
        WEBRTC_LOG_WARN("ice stun binding request session not found username={} recipient_ufrag={} sender_ufrag={} remote={}",
                        *message->username,
                        username_parts->recipient_ufrag,
                        username_parts->sender_ufrag,
                        remote_address);

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

        if (selection_changed)
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

    send_response(std::move(*response), remote_endpoint);
}

void ice_udp_server::handle_dtls_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    if (!is_selected_endpoint(remote_address))
    {
        WEBRTC_LOG_WARN("dtls packet ignored from unselected ice endpoint remote={} size={}", remote_address, data.size());

        return;
    }

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

    schedule_dtls_timeout();
}

void ice_udp_server::handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    if (!is_selected_endpoint(remote_address))
    {
        WEBRTC_LOG_WARN("srtp packet ignored from unselected ice endpoint remote={} size={}", remote_address, data.size());

        return;
    }

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

        observe_inbound_rtcp_sender_reports(*peer, *result);
    }

    if (track_resolution.has_value() && track_resolution->resolved)
    {
        WEBRTC_LOG_DEBUG(
            "media track resolved remote={} action={} stream={} session={} state={} mid={} kind={} ssrc={} sequence={} payload_type={} "
            "newly_bound={} has_twcc={} twcc={}",
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
                : 0U);
    }

    WEBRTC_LOG_DEBUG("media route resolved remote={} action={} stream={} session={} targets={}",
                     remote_address,
                     media_route_action_to_string(route.action),
                     route.source.stream_id,
                     route.source.session_id,
                     route.target_endpoints.size());

    cache_inbound_rtp_packet(*result, route);

    const auto feedback_event = make_rtcp_feedback_route_event(*result, route);

    if (feedback_event.has_value())
    {
        log_rtcp_feedback_route_event(*feedback_event);

        handle_rtcp_feedback_event(*feedback_event);
    }

    forward_media_packet(*result, route, track_resolution, feedback_event);
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

    auto header = parse_rtp_packet_header(std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

    if (!header)
    {
        WEBRTC_LOG_DEBUG("rtcp stats inbound rtp parse skipped remote={} error={}", peer.remote_endpoint, header.error());

        return;
    }

    auto publisher = registry_->find_publisher_by_session_id(peer.session_id);

    if (publisher == nullptr)
    {
        return;
    }

    std::string mid;

    if (track_resolution.has_value() && track_resolution->resolved)
    {
        mid = track_resolution->mid;
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

void ice_udp_server::observe_inbound_rtcp_sender_reports(const media_peer_info& peer, const srtp_packet_process_result& packet)
{
    if (rtcp_report_service_ == nullptr)
    {
        return;
    }

    if (peer.role != media_peer_role::publisher)
    {
        return;
    }

    if (packet.kind != srtp_packet_kind::rtcp || packet.plain_packet.empty())
    {
        return;
    }

    auto observation =
        rtcp_report_service_->observe_received_rtcp_with_summary(peer.stream_id,
                                                                 peer.session_id,
                                                                 peer.remote_endpoint,
                                                                 std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()),
                                                                 now_milliseconds());

    if (!observation)
    {
        WEBRTC_LOG_DEBUG("rtcp stats sender report observe skipped stream={} session={} remote={} error={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         observation.error());

        return;
    }

    if (observation->sender_report_count == 0)
    {
        return;
    }

    for (uint32_t sender_report_ssrc : observation->sender_report_ssrcs)
    {
        if (sender_report_ssrc == 0)
        {
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

        auto remember_result = rtcp_report_service_->remember_source(source);

        if (!remember_result)
        {
            WEBRTC_LOG_DEBUG("rtcp stats sender report remember source failed stream={} session={} remote={} ssrc={} error={}",
                             peer.stream_id,
                             peer.session_id,
                             peer.remote_endpoint,
                             sender_report_ssrc,
                             remember_result.error());

            continue;
        }

        WEBRTC_LOG_DEBUG("rtcp stats sender report observed stream={} session={} remote={} sender_ssrc={} local_ssrc={}",
                         peer.stream_id,
                         peer.session_id,
                         peer.remote_endpoint,
                         sender_report_ssrc,
                         local_ssrc);
    }
}

void ice_udp_server::observe_outbound_rtp_stats(const media_peer_info& target_peer, std::span<const uint8_t> outbound_plain_packet)
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

    observed_packet.stream_id = target_peer.stream_id;

    observed_packet.session_id = target_peer.session_id;

    observed_packet.remote_endpoint = target_peer.remote_endpoint;

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

    auto table = get_or_create_payload_type_mapping_table(route, target_peer);

    if (!table.has_value())
    {
        return std::nullopt;
    }

    if (!track_resolution->mid.empty())
    {
        auto mapping = find_media_payload_type_mapping(*table, track_resolution->mid, track_resolution->payload_type);

        if (mapping.has_value())
        {
            return mapping;
        }
    }

    if (!track_resolution->kind.empty())
    {
        auto mapping = find_media_payload_type_mapping_by_kind(*table, track_resolution->kind, track_resolution->payload_type);

        if (mapping.has_value())
        {
            return mapping;
        }
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
                                                              now_milliseconds());

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

std::vector<uint8_t> ice_udp_server::make_forward_plain_packet(const srtp_packet_process_result& packet,
                                                               const media_route_result& route,
                                                               const std::optional<media_track_resolution>& track_resolution,
                                                               const std::optional<rtcp_feedback_route_event>& feedback_event,
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
        if (route.source.role != media_peer_role::subscriber || target_peer.role != media_peer_role::publisher || !feedback_event.has_value() ||
            feedback_event->media_ssrc == 0 || ssrc_mapper_ == nullptr)
        {
            return original_packet;
        }

        auto mapping = ssrc_mapper_->find_by_subscriber_ssrc(route.source.session_id, feedback_event->media_ssrc);

        if (!mapping.has_value())
        {
            WEBRTC_LOG_DEBUG("rtcp feedback reverse ssrc mapping not found subscriber_session={} media_ssrc={}",
                             route.source.session_id,
                             feedback_event->media_ssrc);

            return original_packet;
        }

        auto rewrite_result = rewrite_rtcp_feedback_media_ssrc(std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()),
                                                               mapping->publisher_ssrc);

        if (!rewrite_result)
        {
            WEBRTC_LOG_WARN(
                "rtcp feedback reverse ssrc rewrite failed subscriber_session={} publisher_session={} subscriber_ssrc={} publisher_ssrc={} error={}",
                mapping->subscriber_session_id,
                mapping->publisher_session_id,
                mapping->subscriber_ssrc,
                mapping->publisher_ssrc,
                rewrite_result.error());

            return original_packet;
        }

        WEBRTC_LOG_DEBUG("rtcp feedback reverse ssrc rewrite applied subscriber_session={} publisher_session={} subscriber_ssrc={} publisher_ssrc={}",
                         mapping->subscriber_session_id,
                         mapping->publisher_session_id,
                         mapping->subscriber_ssrc,
                         mapping->publisher_ssrc);

        return std::move(*rewrite_result);
    }

    if (packet.kind != srtp_packet_kind::rtp)
    {
        return original_packet;
    }

    auto payload_type_mapping = find_payload_type_mapping(route, target_peer, track_resolution);

    auto ssrc_mapping = get_or_create_ssrc_mapping(route, target_peer, track_resolution, payload_type_mapping);

    if (!payload_type_mapping.has_value() && !ssrc_mapping.has_value())
    {
        return original_packet;
    }

    rtp_packet_rewrite_options options;

    bool rewrite_required = false;

    if (payload_type_mapping.has_value() && payload_type_mapping->payload_type_rewrite_required)
    {
        if (payload_type_mapping->subscriber_payload_type > 127)
        {
            WEBRTC_LOG_WARN("rtp payload type rewrite skipped invalid target payload type stream={} subscriber_session={} payload_type={}",
                            payload_type_mapping->stream_id,
                            target_peer.session_id,
                            payload_type_mapping->subscriber_payload_type);

            return original_packet;
        }

        options.payload_type = static_cast<uint8_t>(payload_type_mapping->subscriber_payload_type);

        rewrite_required = true;
    }

    if (ssrc_mapping.has_value() && media_ssrc_mapping_requires_rewrite(*ssrc_mapping))
    {
        options.ssrc = ssrc_mapping->subscriber_ssrc;

        rewrite_required = true;
    }

    if (payload_type_mapping.has_value() && payload_type_mapping->mid_rewrite_required && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(route.source.session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(target_peer.session_id);

        if (publisher == nullptr || subscriber == nullptr)
        {
            WEBRTC_LOG_WARN("rtp mid rewrite skipped session not found stream={} publisher_session={} subscriber_session={}",
                            route.source.stream_id,
                            route.source.session_id,
                            target_peer.session_id);
        }
        else
        {
            auto mid_rewrite = make_mid_header_extension_rewrite(*payload_type_mapping,
                                                                 publisher->remote_offer_summary(),
                                                                 subscriber->remote_offer_summary(),
                                                                 std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()));

            if (!mid_rewrite)
            {
                WEBRTC_LOG_WARN(
                    "rtp mid rewrite skipped stream={} publisher_session={} subscriber_session={} publisher_mid={} subscriber_mid={} error={}",
                    payload_type_mapping->stream_id,
                    route.source.session_id,
                    target_peer.session_id,
                    payload_type_mapping->publisher_mid,
                    payload_type_mapping->subscriber_mid,
                    mid_rewrite.error());
            }
            else if (mid_rewrite->has_value())
            {
                options.header_extensions.push_back(std::move(**mid_rewrite));

                rewrite_required = true;
            }
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

        return original_packet;
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

std::vector<uint8_t> ice_udp_server::make_retransmit_plain_packet(const rtcp_feedback_route_event& event,
                                                                  const rtp_packet_cache_entry& cached_packet,
                                                                  const std::optional<media_ssrc_mapping>& ssrc_mapping)
{
    std::vector<uint8_t> original_packet;

    original_packet.assign(cached_packet.plain_packet.begin(), cached_packet.plain_packet.end());

    if (!ssrc_mapping.has_value())
    {
        return original_packet;
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

    if (payload_type_mapping.has_value() && payload_type_mapping->payload_type_rewrite_required)
    {
        if (payload_type_mapping->subscriber_payload_type <= 127)
        {
            options.payload_type = static_cast<uint8_t>(payload_type_mapping->subscriber_payload_type);

            rewrite_required = true;
        }
    }

    if (payload_type_mapping.has_value() && payload_type_mapping->mid_rewrite_required && registry_ != nullptr)
    {
        auto publisher = registry_->find_publisher_by_session_id(ssrc_mapping->publisher_session_id);

        auto subscriber = registry_->find_subscriber_by_session_id(ssrc_mapping->subscriber_session_id);

        if (publisher != nullptr && subscriber != nullptr)
        {
            auto mid_rewrite =
                make_mid_header_extension_rewrite(*payload_type_mapping,
                                                  publisher->remote_offer_summary(),
                                                  subscriber->remote_offer_summary(),
                                                  std::span<const uint8_t>(cached_packet.plain_packet.data(), cached_packet.plain_packet.size()));

            if (mid_rewrite && mid_rewrite->has_value())
            {
                options.header_extensions.push_back(std::move(**mid_rewrite));

                rewrite_required = true;
            }
        }
    }

    if (!rewrite_required)
    {
        return original_packet;
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

        return original_packet;
    }

    return std::move(rewrite_result->packet);
}

void ice_udp_server::cache_inbound_rtp_packet(const srtp_packet_process_result& packet, const media_route_result& route)
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

    if (rtp_packet_cache_ == nullptr)
    {
        return;
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

    std::optional<media_ssrc_mapping> ssrc_mapping;

    uint32_t cache_media_ssrc = feedback_media_ssrc;

    if (ssrc_mapper_ != nullptr)
    {
        ssrc_mapping = ssrc_mapper_->find_by_subscriber_ssrc(event.source.session_id, feedback_media_ssrc);

        if (ssrc_mapping.has_value())
        {
            cache_media_ssrc = ssrc_mapping->publisher_ssrc;
        }
    }

    auto target_endpoint = find_remote_endpoint(event.source.remote_endpoint);

    if (!target_endpoint)
    {
        WEBRTC_LOG_WARN(
            "rtp nack retransmit subscriber endpoint not found stream={} subscriber={}", event.source.stream_id, event.source.remote_endpoint);

        return;
    }

    const std::vector<uint16_t> sequence_numbers = expand_nack_sequences(event.nack_items);

    std::size_t hit_count = 0;
    std::size_t miss_count = 0;
    std::size_t sent_count = 0;
    std::size_t ignored_count = 0;
    std::size_t failed_count = 0;

    for (uint16_t sequence_number : sequence_numbers)
    {
        auto cached = rtp_packet_cache_->find(event.source.stream_id, cache_media_ssrc, sequence_number);

        if (!cached)
        {
            miss_count += 1;

            continue;
        }

        hit_count += 1;

        std::vector<uint8_t> retransmit_plain_packet = make_retransmit_plain_packet(event, *cached, ssrc_mapping);

        auto protected_packet =
            srtp_transport_->protect_outbound_packet(std::span<const uint8_t>(retransmit_plain_packet.data(), retransmit_plain_packet.size()),
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

        observe_outbound_rtp_stats(event.source, std::span<const uint8_t>(retransmit_plain_packet.data(), retransmit_plain_packet.size()));

        send_response(std::move(protected_packet->protected_packet), *target_endpoint);

        sent_count += 1;

        WEBRTC_LOG_DEBUG("rtp nack retransmit send stream={} subscriber={} feedback_ssrc={} cache_ssrc={} sequence={}",
                         event.source.stream_id,
                         event.source.remote_endpoint,
                         feedback_media_ssrc,
                         cache_media_ssrc,
                         sequence_number);
    }

    WEBRTC_LOG_INFO(
        "rtp nack retransmit summary stream={} subscriber={} feedback_ssrc={} cache_ssrc={} requested={} hit={} miss={} sent={} ignored={} failed={}",
        event.source.stream_id,
        event.source.remote_endpoint,
        feedback_media_ssrc,
        cache_media_ssrc,
        sequence_numbers.size(),
        hit_count,
        miss_count,
        sent_count,
        ignored_count,
        failed_count);
}

void ice_udp_server::erase_rtp_cache(std::string_view stream_id)
{
    if (rtp_packet_cache_ != nullptr && !stream_id.empty())
    {
        rtp_packet_cache_->erase_stream(stream_id);

        WEBRTC_LOG_INFO("rtp cache stream erased stream={} remaining={}", stream_id, rtp_packet_cache_->size());
    }

    if (ssrc_mapper_ != nullptr && !stream_id.empty())
    {
        ssrc_mapper_->forget_stream(stream_id);
    }

    if (rtcp_report_service_ != nullptr && !stream_id.empty())
    {
        rtcp_report_service_->forget_stream(stream_id);

        WEBRTC_LOG_INFO("rtcp report service stream erased stream={} sources={} stats_sources={}",
                        stream_id,
                        rtcp_report_service_->source_count(),
                        rtcp_report_service_->stats_source_count());
    }
}

void ice_udp_server::forward_media_packet(const srtp_packet_process_result& packet,
                                          const media_route_result& route,
                                          const std::optional<media_track_resolution>& track_resolution,
                                          const std::optional<rtcp_feedback_route_event>& feedback_event)
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

        std::vector<uint8_t> outbound_plain_packet = make_forward_plain_packet(packet, route, track_resolution, feedback_event, *target_peer);

        if (outbound_plain_packet.empty())
        {
            WEBRTC_LOG_WARN("media forward skipped empty rewritten packet stream={} source={} target={} kind={}",
                            route.source.stream_id,
                            route.source.remote_endpoint,
                            target_address,
                            srtp_packet_kind_to_string(packet.kind));

            continue;
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(outbound_plain_packet.data(), outbound_plain_packet.size()), target_address, packet.kind);

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
            observe_outbound_rtp_stats(*target_peer, std::span<const uint8_t>(outbound_plain_packet.data(), outbound_plain_packet.size()));
        }

        WEBRTC_LOG_DEBUG("media forward send stream={} source={} target={} kind={} plain_size={} protected_size={}",
                         route.source.stream_id,
                         route.source.remote_endpoint,
                         target_address,
                         srtp_packet_kind_to_string(packet.kind),
                         outbound_plain_packet.size(),
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

        session_id_by_endpoint_address_.erase(result.previous_remote_address);

        endpoints_by_address_.erase(result.previous_remote_address);

        const std::string previous_key = make_candidate_pair_key(session_id, result.previous_remote_address);

        const auto previous_pair = candidate_pairs_by_key_.find(previous_key);

        if (previous_pair != candidate_pairs_by_key_.end())
        {
            previous_pair->second.selected = false;
        }
    }

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

std::vector<std::string> ice_udp_server::expire_ice_candidate_pairs(uint64_t current_time_milliseconds)
{
    std::vector<std::string> expired_remote_addresses;
    std::vector<std::string> expired_session_ids;

    std::lock_guard lock(endpoint_mutex_);

    for (const auto& [key, pair] : candidate_pairs_by_key_)
    {
        (void)key;

        if (pair.last_binding_at_milliseconds == 0)
        {
            continue;
        }

        const uint64_t age_milliseconds =
            current_time_milliseconds > pair.last_binding_at_milliseconds ? current_time_milliseconds - pair.last_binding_at_milliseconds : 0;

        if (!pair.selected)
        {
            continue;
        }

        if (age_milliseconds < k_ice_consent_timeout_milliseconds)
        {
            continue;
        }

        if (!contains_string(expired_session_ids, pair.session_id))
        {
            expired_session_ids.push_back(pair.session_id);
        }
    }

    for (const auto& session_id : expired_session_ids)
    {
        const auto endpoint_iterator = endpoint_address_by_session_id_.find(session_id);

        if (endpoint_iterator != endpoint_address_by_session_id_.end())
        {
            const std::string remote_address = endpoint_iterator->second;

            if (!contains_string(expired_remote_addresses, remote_address))
            {
                expired_remote_addresses.push_back(remote_address);
            }

            session_id_by_endpoint_address_.erase(remote_address);

            endpoints_by_address_.erase(remote_address);

            endpoint_address_by_session_id_.erase(endpoint_iterator);
        }

        erase_candidate_pairs_for_session_locked(session_id);

        erase_payload_type_mappings_for_session_locked(session_id);

        if (ssrc_mapper_ != nullptr)
        {
            ssrc_mapper_->forget_session(session_id);
        }

        if (rtcp_report_service_ != nullptr)
        {
            rtcp_report_service_->forget_session(session_id);
        }
    }

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

    return expired_remote_addresses;
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

        endpoints_by_address_.erase(std::string(remote_address));

        const auto session_iterator = session_id_by_endpoint_address_.find(std::string(remote_address));

        if (session_iterator != session_id_by_endpoint_address_.end())
        {
            session_id = session_iterator->second;

            session_id_by_endpoint_address_.erase(session_iterator);
        }

        if (!session_id.empty())
        {
            endpoint_address_by_session_id_.erase(session_id);

            erase_payload_type_mappings_for_session_locked(session_id);
        }

        erase_candidate_pairs_for_endpoint_locked(remote_address);
    }

    if (!session_id.empty() && ssrc_mapper_ != nullptr)
    {
        ssrc_mapper_->forget_session(session_id);
    }

    if (!session_id.empty() && rtcp_report_service_ != nullptr)
    {
        rtcp_report_service_->forget_session(session_id);
    }

    forget_peer_transport_state(remote_address);
}

void ice_udp_server::forget_peer_transport_state(std::string_view remote_address)
{
    if (remote_address.empty())
    {
        return;
    }

    forget_transport_peer_if_supported(dtls_transport_, remote_address);

    if (srtp_transport_ != nullptr)
    {
        srtp_transport_->forget_peer(remote_address);
    }

    if (media_router_ != nullptr)
    {
        media_router_->forget_peer(remote_address);
    }

    if (track_resolver_ != nullptr)
    {
        track_resolver_->forget_peer(remote_address);
    }

    if (rtcp_report_service_ != nullptr)
    {
        rtcp_report_service_->forget_peer(remote_address);
    }
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
