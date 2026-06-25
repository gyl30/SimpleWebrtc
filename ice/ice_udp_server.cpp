#include "ice/ice_udp_server.h"

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
#include "net/socket.h"
#include "rtp/rtp_packet.h"
#include "session/session_state.h"

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

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
    return identity;
}

dtls_peer_identity make_subscriber_dtls_identity(const std::shared_ptr<subscriber_session>& session)
{
    dtls_peer_identity identity;
    identity.role = dtls_peer_role::subscriber;
    identity.session_id = session->session_id();
    identity.stream_id = session->stream_id();
    identity.local_ice_ufrag = session->local_ice().ufrag;
    return identity;
}
}    // namespace

ice_udp_server::ice_udp_server(boost::asio::io_context& io_context,
                               std::string bind_host,
                               uint16_t bind_port,
                               std::shared_ptr<stream_registry> registry)
    : io_context_(io_context), socket_(io_context), bind_host_(std::move(bind_host)), bind_port_(bind_port), registry_(std::move(registry))
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

    boost::system::error_code ec;
    socket_.close(ec);

    if (ec)
    {
        WEBRTC_LOG_WARN("ice udp server close failed: {}", ec.message());
    }

    {
        std::lock_guard lock(endpoint_mutex_);

        endpoints_by_address_.clear();
        endpoint_address_by_session_id_.clear();
        session_id_by_endpoint_address_.clear();
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

        const auto iterator = endpoint_address_by_session_id_.find(std::string(session_id));

        if (iterator == endpoint_address_by_session_id_.end())
        {
            WEBRTC_LOG_DEBUG("ice udp session endpoint not found session={}", session_id);

            return;
        }

        remote_address = iterator->second;

        endpoint_address_by_session_id_.erase(iterator);
        session_id_by_endpoint_address_.erase(remote_address);
        endpoints_by_address_.erase(remote_address);
    }

    forget_peer_transport_state(remote_address);

    WEBRTC_LOG_INFO("ice udp session transport state removed session={} remote={}", session_id, remote_address);
}

uint16_t ice_udp_server::local_port() const { return bind_port_; }

ice_udp_server_result ice_udp_server::init_dtls_transport()
{
    if (dtls_transport_ != nullptr && srtp_transport_ != nullptr && media_router_ != nullptr)
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

    dtls_context_config config;
    config.certificate_file = *certificate_file;
    config.private_key_file = *private_key_file;

    auto context = make_dtls_context(config);

    if (!context)
    {
        return std::unexpected(context.error());
    }

    dtls_transport_ = std::make_shared<dtls_transport>(*context);

    srtp_transport_ = std::make_shared<srtp_transport>(dtls_transport_);

    media_router_ = std::make_shared<media_router>();

    WEBRTC_LOG_INFO("dtls transport initialized");
    WEBRTC_LOG_INFO("srtp transport initialized");
    WEBRTC_LOG_INFO("media router initialized");

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

    auto publisher = find_publisher_for_username(*message->username);

    auto subscriber = find_subscriber_for_username(*message->username);

    std::string integrity_key;

    if (publisher != nullptr)
    {
        integrity_key = publisher->local_ice().pwd;
    }
    else if (subscriber != nullptr)
    {
        integrity_key = subscriber->local_ice().pwd;
    }
    else
    {
        WEBRTC_LOG_WARN("ice stun binding request session not found username={} remote={}", *message->username, remote_address);

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

    remember_remote_endpoint(remote_endpoint);

    if (publisher != nullptr)
    {
        publisher->set_state(session_state::ice_connected);

        remember_session_endpoint(remote_endpoint, publisher->session_id());

        if (dtls_transport_ != nullptr)
        {
            dtls_transport_->remember_peer(remote_address, make_publisher_dtls_identity(publisher));
        }

        if (media_router_ != nullptr)
        {
            media_router_->remember_publisher(remote_address, publisher->stream_id(), publisher->session_id());
        }
    }

    if (subscriber != nullptr)
    {
        subscriber->set_state(session_state::ice_connected);

        remember_session_endpoint(remote_endpoint, subscriber->session_id());

        if (dtls_transport_ != nullptr)
        {
            dtls_transport_->remember_peer(remote_address, make_subscriber_dtls_identity(subscriber));
        }

        if (media_router_ != nullptr)
        {
            media_router_->remember_subscriber(remote_address, subscriber->stream_id(), subscriber->session_id());
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

    WEBRTC_LOG_INFO("ice stun binding success username={} remote={} response_size={}", *message->username, remote_address, response->size());

    send_response(std::move(*response), remote_endpoint);
}

void ice_udp_server::handle_dtls_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    if (dtls_transport_ == nullptr)
    {
        WEBRTC_LOG_WARN("dtls transport is null remote={} size={}", remote_address, data.size());

        return;
    }

    auto packets = dtls_transport_->handle_udp_packet(data, remote_address);

    if (!packets)
    {
        WEBRTC_LOG_WARN("dtls packet handle failed remote={} error={}", remote_address, packets.error());

        return;
    }

    for (auto& packet : *packets)
    {
        WEBRTC_LOG_DEBUG("dtls send packet remote={} size={}", remote_address, packet.size());

        send_response(std::move(packet), remote_endpoint);
    }
}

void ice_udp_server::handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

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

    if (media_router_ == nullptr)
    {
        WEBRTC_LOG_WARN(
            "media router is null remote={} kind={} size={}", remote_address, srtp_packet_kind_to_string(result->kind), result->unprotected_size);

        return;
    }

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

    forward_media_packet(*result, route);
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

        auto protected_packet = srtp_transport_->protect_outbound_packet(packet.plain_packet, target_address, packet.kind);

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

void ice_udp_server::remember_remote_endpoint(const udp::endpoint& remote_endpoint)
{
    const std::string remote_address = endpoint_to_string(remote_endpoint);

    if (remote_address.empty() || remote_address == "<unknown>")
    {
        return;
    }

    std::lock_guard lock(endpoint_mutex_);

    endpoints_by_address_[remote_address] = remote_endpoint;
}

void ice_udp_server::remember_session_endpoint(const udp::endpoint& remote_endpoint, std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    const std::string remote_address = endpoint_to_string(remote_endpoint);

    if (remote_address.empty() || remote_address == "<unknown>")
    {
        return;
    }

    std::vector<std::string> transport_peers_to_forget;

    {
        std::lock_guard lock(endpoint_mutex_);

        const auto existing_session = session_id_by_endpoint_address_.find(remote_address);

        if (existing_session != session_id_by_endpoint_address_.end() && existing_session->second != session_id)
        {
            endpoint_address_by_session_id_.erase(existing_session->second);
            session_id_by_endpoint_address_.erase(existing_session);

            transport_peers_to_forget.push_back(remote_address);
        }

        const auto existing_endpoint = endpoint_address_by_session_id_.find(std::string(session_id));

        if (existing_endpoint != endpoint_address_by_session_id_.end() && existing_endpoint->second != remote_address)
        {
            const std::string old_remote_address = existing_endpoint->second;

            session_id_by_endpoint_address_.erase(old_remote_address);
            endpoints_by_address_.erase(old_remote_address);

            transport_peers_to_forget.push_back(old_remote_address);
        }

        endpoints_by_address_[remote_address] = remote_endpoint;
        endpoint_address_by_session_id_[std::string(session_id)] = remote_address;
        session_id_by_endpoint_address_[remote_address] = std::string(session_id);
    }

    for (const auto& peer_remote_address : transport_peers_to_forget)
    {
        forget_peer_transport_state(peer_remote_address);
    }

    WEBRTC_LOG_DEBUG("ice udp remember session endpoint session={} remote={}", session_id, remote_address);
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
    const std::string local_ufrag = extract_local_ufrag(username);

    if (local_ufrag.empty() || registry_ == nullptr)
    {
        return nullptr;
    }

    return registry_->find_publisher_by_local_ice_ufrag(local_ufrag);
}

std::shared_ptr<subscriber_session> ice_udp_server::find_subscriber_for_username(std::string_view username) const
{
    const std::string local_ufrag = extract_local_ufrag(username);

    if (local_ufrag.empty() || registry_ == nullptr)
    {
        return nullptr;
    }

    return registry_->find_subscriber_by_local_ice_ufrag(local_ufrag);
}

std::string ice_udp_server::extract_local_ufrag(std::string_view username)
{
    const std::size_t separator = username.find(':');

    if (separator == std::string_view::npos)
    {
        return std::string(username);
    }

    return std::string(username.substr(0, separator));
}

std::string ice_udp_server::endpoint_ip(const udp::endpoint& endpoint) { return get_endpoint_ip(endpoint); }
}    // namespace webrtc
