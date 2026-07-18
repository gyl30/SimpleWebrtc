#include "ice/session_ice_udp_server.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/system/error_code.hpp>

#include "log/log.h"

namespace webrtc
{
namespace
{
std::string endpoint_to_string(const boost::asio::ip::udp::endpoint& endpoint)
{
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}
}    // namespace

session_ice_udp_server::session_ice_udp_server(boost::asio::io_context& io_context, std::string bind_host)
    : socket_(io_context), bind_host_(std::move(bind_host))
{
}

session_ice_udp_server::~session_ice_udp_server() { stop(); }

session_ice_udp_server_result session_ice_udp_server::start(uint16_t local_port, session_ice_udp_packet_handler& handler)
{
    if (started_)
    {
        return {};
    }

    boost::system::error_code ec;

    const auto address = boost::asio::ip::make_address(bind_host_, ec);

    if (ec)
    {
        std::string message = "session ice udp bind address invalid host=";

        message.append(bind_host_);
        message.append(" error=");
        message.append(ec.message());

        return std::unexpected(std::move(message));
    }

    boost::asio::ip::udp::endpoint endpoint(address, local_port);

    socket_.open(endpoint.protocol(), ec);

    if (ec)
    {
        std::string message = "session ice udp socket open failed error=";

        message.append(ec.message());

        return std::unexpected(std::move(message));
    }

    boost::asio::socket_base::reuse_address reuse_address(true);

    socket_.set_option(reuse_address, ec);

    if (ec)
    {
        WEBRTC_LOG_WARN("session ice udp socket set reuse_address failed: {}", ec.message());
    }

    socket_.bind(endpoint, ec);

    if (ec)
    {
        std::string message = "session ice udp bind failed endpoint=";

        message.append(endpoint_to_string(endpoint));
        message.append(" error=");
        message.append(ec.message());

        boost::system::error_code close_ec;

        socket_.close(close_ec);

        return std::unexpected(std::move(message));
    }

    handler_ = &handler;

    local_port_ = socket_.local_endpoint(ec).port();

    if (ec)
    {
        local_port_ = local_port;
    }

    started_ = true;

    WEBRTC_LOG_INFO("session ice udp server listen {}:{}", bind_host_, local_port_);

    do_receive();

    return {};
}

void session_ice_udp_server::stop()
{
    if (!started_)
    {
        return;
    }

    started_ = false;

    handler_ = nullptr;

    boost::system::error_code ec;

    socket_.cancel(ec);

    socket_.close(ec);

    WEBRTC_LOG_INFO("session ice udp server stopped {}:{}", bind_host_, local_port_);
}

void session_ice_udp_server::send(std::vector<uint8_t> packet, const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    if (!started_ || packet.empty())
    {
        return;
    }

    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(packet));

    socket_.async_send_to(boost::asio::buffer(*buffer),
                          remote_endpoint,
                          [buffer, remote_endpoint](boost::system::error_code ec, std::size_t bytes_transferred)
                          {
                              if (ec)
                              {
                                  WEBRTC_LOG_WARN("session ice udp send failed remote={} error={}",
                                                  endpoint_to_string(remote_endpoint),
                                                  ec.message());

                                  return;
                              }

                              WEBRTC_LOG_DEBUG("session ice udp send success remote={} bytes={}",
                                               endpoint_to_string(remote_endpoint),
                                               bytes_transferred);
                          });
}

void session_ice_udp_server::do_receive()
{
    if (!started_)
    {
        return;
    }

    socket_.async_receive_from(boost::asio::buffer(receive_buffer_),
                               remote_endpoint_,
                               [this](boost::system::error_code ec, std::size_t bytes_transferred)
                               {
                                   on_receive(ec, bytes_transferred);
                               });
}

void session_ice_udp_server::on_receive(boost::system::error_code ec, std::size_t bytes_transferred)
{
    if (!started_)
    {
        return;
    }

    if (ec)
    {
        WEBRTC_LOG_WARN("session ice udp receive failed error={}", ec.message());

        do_receive();

        return;
    }

    const std::size_t packet_size = bytes_transferred;

    session_udp_packet packet;

    packet.data.assign(receive_buffer_.begin(), receive_buffer_.begin() + static_cast<std::ptrdiff_t>(packet_size));
    packet.remote_endpoint = remote_endpoint_;

    auto outbound_packets = handler_->handle_udp_packet(packet);

    for (auto& outbound_packet : outbound_packets)
    {
        send(std::move(outbound_packet.data), outbound_packet.remote_endpoint);
    }

    do_receive();
}
}    // namespace webrtc
