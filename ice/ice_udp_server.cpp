#include "ice/ice_udp_server.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <expected>
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
#include "media/media_router.h"
#include "media/rtcp_feedback_router.h"
#include "media/rtp_packet_cache.h"
#include "net/socket.h"
#include "rtp/rtcp_feedback.h"
#include "rtp/rtp_packet.h"
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

constexpr uint64_t k_ice_consent_timeout_milliseconds = 30000;

constexpr uint64_t k_unselected_candidate_pair_retention_milliseconds = 120000;

struct ice_username_parts
{
    std::string_view recipient_ufrag;
    std::string_view sender_ufrag;
};

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

std::string make_candidate_pair_key(std::string_view session_id, std::string_view remote_address)
{
    std::string key;

    key.reserve(session_id.size() + remote_address.size() + 1);

    key.append(session_id);
    key.push_back('\n');
    key.append(remote_address);

    return key;
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
      bind_host_(std::move(bind_host)),
      bind_port_(bind_port),
      registry_(std::move(registry)),
      media_router_(std::move(media_router))
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

    boost::system::error_code consent_timer_ec;

    ice_consent_timer_.cancel();

    if (consent_timer_ec)
    {
        WEBRTC_LOG_WARN("ice consent timer cancel failed: {}", consent_timer_ec.message());
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
    }

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

        const auto iterator = endpoint_address_by_session_id_.find(std::string(session_id));

        if (iterator != endpoint_address_by_session_id_.end())
        {
            remote_address = iterator->second;

            endpoint_address_by_session_id_.erase(iterator);

            session_id_by_endpoint_address_.erase(remote_address);

            endpoints_by_address_.erase(remote_address);
        }
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

    const media_route_result route = media_router_->handle_inbound_packet(remote_address, *result);

    if (!route.known_peer)
    {
        WEBRTC_LOG_WARN(
            "media route ignored unknown peer remote={} kind={} ssrc={}", remote_address, srtp_packet_kind_to_string(result->kind), result->ssrc);

        return;
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

    forward_media_packet(*result, route);
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

    const uint32_t media_ssrc = event.media_ssrc != 0 ? event.media_ssrc : event.ssrc;

    if (media_ssrc == 0)
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

    const std::vector<uint16_t> sequence_numbers = expand_nack_sequences(event.nack_items);

    std::size_t hit_count = 0;
    std::size_t miss_count = 0;
    std::size_t sent_count = 0;
    std::size_t ignored_count = 0;
    std::size_t failed_count = 0;

    for (uint16_t sequence_number : sequence_numbers)
    {
        auto cached = rtp_packet_cache_->find(event.source.stream_id, media_ssrc, sequence_number);

        if (!cached)
        {
            miss_count += 1;

            continue;
        }

        hit_count += 1;

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(cached->plain_packet.data(), cached->plain_packet.size()), event.source.remote_endpoint, srtp_packet_kind::rtp);

        if (!protected_packet)
        {
            failed_count += 1;

            WEBRTC_LOG_WARN("rtp nack retransmit protect failed stream={} subscriber={} ssrc={} sequence={} error={}",
                            event.source.stream_id,
                            event.source.remote_endpoint,
                            media_ssrc,
                            sequence_number,
                            protected_packet.error());

            continue;
        }

        if (protected_packet->state == srtp_packet_process_state::ignored)
        {
            ignored_count += 1;

            WEBRTC_LOG_DEBUG("rtp nack retransmit ignored stream={} subscriber={} ssrc={} sequence={} reason={}",
                             event.source.stream_id,
                             event.source.remote_endpoint,
                             media_ssrc,
                             sequence_number,
                             protected_packet->reason);

            continue;
        }

        send_response(std::move(protected_packet->protected_packet), *target_endpoint);

        sent_count += 1;

        WEBRTC_LOG_DEBUG("rtp nack retransmit send stream={} subscriber={} ssrc={} sequence={}",
                         event.source.stream_id,
                         event.source.remote_endpoint,
                         media_ssrc,
                         sequence_number);
    }

    WEBRTC_LOG_INFO("rtp nack retransmit summary stream={} subscriber={} media_ssrc={} requested={} hit={} miss={} sent={} ignored={} failed={}",
                    event.source.stream_id,
                    event.source.remote_endpoint,
                    media_ssrc,
                    sequence_numbers.size(),
                    hit_count,
                    miss_count,
                    sent_count,
                    ignored_count,
                    failed_count);
}

void ice_udp_server::erase_rtp_cache(std::string_view stream_id)
{
    if (rtp_packet_cache_ == nullptr || stream_id.empty())
    {
        return;
    }

    rtp_packet_cache_->erase_stream(stream_id);

    WEBRTC_LOG_INFO("rtp cache stream erased stream={} remaining={}", stream_id, rtp_packet_cache_->size());
}

void ice_udp_server::forward_media_packet(const srtp_packet_process_result& packet, const media_route_result& route)
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

        auto protected_packet = srtp_transport_->protect_outbound_packet(
            std::span<const uint8_t>(packet.plain_packet.data(), packet.plain_packet.size()), target_address, packet.kind);

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

        WEBRTC_LOG_DEBUG("media forward send stream={} source={} target={} kind={} plain_size={} protected_size={}",
                         route.source.stream_id,
                         route.source.remote_endpoint,
                         target_address,
                         srtp_packet_kind_to_string(packet.kind),
                         packet.plain_packet.size(),
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
        }

        erase_candidate_pairs_for_endpoint_locked(remote_address);
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
