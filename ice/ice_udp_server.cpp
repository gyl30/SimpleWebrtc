#include "ice/ice_udp_server.h"

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/system/error_code.hpp>

#include "ice/stun_message.h"
#include "log/log.h"
#include "net/socket.h"
#include "session/session_state.h"

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::string endpoint_to_string(const boost::asio::ip::udp::endpoint& endpoint)
{
    std::string value = get_endpoint_address(endpoint);

    if (value.empty())
    {
        return "<unknown>";
    }

    return value;
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

    boost::system::error_code ec;
    socket_.close(ec);

    if (ec)
    {
        WEBRTC_LOG_WARN("ice udp server close failed: {}", ec.message());
    }
}

uint16_t ice_udp_server::local_port() const { return bind_port_; }

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
    else
    {
        const std::string remote_address = endpoint_to_string(remote_endpoint_);

        WEBRTC_LOG_DEBUG("ice udp non stun packet remote={} size={}", remote_address, bytes_transferred);
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

    if (publisher != nullptr)
    {
        publisher->set_state(session_state::ice_connected);
    }

    if (subscriber != nullptr)
    {
        subscriber->set_state(session_state::ice_connected);
    }

    WEBRTC_LOG_INFO("ice stun binding success username={} remote={} response_size={}", *message->username, remote_address, response->size());

    send_response(std::move(*response), remote_endpoint);
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
