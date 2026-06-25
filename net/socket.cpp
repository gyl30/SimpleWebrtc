#include <cerrno>
#include <cstdint>
#include <string>

#include <boost/asio/detail/socket_ops.hpp>
#include <boost/system.hpp>

#include "log/log.h"
#include "net/socket.h"

namespace webrtc
{
namespace
{
std::string safe_address_string(const boost::asio::ip::address& addr)
{
    boost::system::error_code ec;

    if (addr.is_v4())
    {
        auto bytes = addr.to_v4().to_bytes();

        char buffer[boost::asio::detail::max_addr_v4_str_len]{};

        const char* value = boost::asio::detail::socket_ops::inet_ntop(BOOST_ASIO_OS_DEF(AF_INET), bytes.data(), buffer, sizeof(buffer), 0, ec);

        if (value != nullptr)
        {
            return value;
        }

        return {};
    }

    auto bytes = addr.to_v6().to_bytes();

    char buffer[boost::asio::detail::max_addr_v6_str_len]{};

    const char* value =
        boost::asio::detail::socket_ops::inet_ntop(BOOST_ASIO_OS_DEF(AF_INET6), bytes.data(), buffer, sizeof(buffer), addr.to_v6().scope_id(), ec);

    if (value != nullptr)
    {
        return value;
    }

    return {};
}

template <typename Endpoint>
std::string get_endpoint_address_impl(const Endpoint& endpoint)
{
    std::string ip = safe_address_string(endpoint.address());

    if (ip.empty())
    {
        return {};
    }

    const uint16_t port = endpoint.port();

    return ip + ":" + std::to_string(port);
}

template <typename Endpoint>
std::string get_endpoint_ip_impl(const Endpoint& endpoint)
{
    return safe_address_string(endpoint.address());
}

template <typename Socket>
std::string get_socket_local_ip_impl(Socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.local_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return safe_address_string(endpoint.address());
}

template <typename Socket>
uint16_t get_socket_local_port_impl(Socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.local_endpoint(ec);

    if (ec)
    {
        return 0;
    }

    return endpoint.port();
}

template <typename Socket>
std::string get_socket_remote_ip_impl(Socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.remote_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return safe_address_string(endpoint.address());
}

template <typename Socket>
uint16_t get_socket_remote_port_impl(Socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.remote_endpoint(ec);

    if (ec)
    {
        return 0;
    }

    return endpoint.port();
}
}    // namespace

std::string get_socket_local_ip(boost::asio::ip::udp::socket& socket) { return get_socket_local_ip_impl(socket); }

uint16_t get_socket_local_port(boost::asio::ip::udp::socket& socket) { return get_socket_local_port_impl(socket); }

std::string get_socket_remote_ip(boost::asio::ip::udp::socket& socket) { return get_socket_remote_ip_impl(socket); }

uint16_t get_socket_remote_port(boost::asio::ip::udp::socket& socket) { return get_socket_remote_port_impl(socket); }

std::string get_socket_local_ip(boost::asio::ip::tcp::socket& socket) { return get_socket_local_ip_impl(socket); }

uint16_t get_socket_local_port(boost::asio::ip::tcp::socket& socket) { return get_socket_local_port_impl(socket); }

std::string get_socket_remote_ip(boost::asio::ip::tcp::socket& socket) { return get_socket_remote_ip_impl(socket); }

uint16_t get_socket_remote_port(boost::asio::ip::tcp::socket& socket) { return get_socket_remote_port_impl(socket); }

std::string get_endpoint_address(const boost::asio::ip::tcp::endpoint& endpoint) { return get_endpoint_address_impl(endpoint); }

std::string get_endpoint_address(const boost::asio::ip::udp::endpoint& endpoint) { return get_endpoint_address_impl(endpoint); }

std::string get_endpoint_ip(const boost::asio::ip::tcp::endpoint& endpoint) { return get_endpoint_ip_impl(endpoint); }

std::string get_endpoint_ip(const boost::asio::ip::udp::endpoint& endpoint) { return get_endpoint_ip_impl(endpoint); }

std::string get_socket_remote_address(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.remote_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return get_endpoint_address(endpoint);
}

std::string get_socket_local_address(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.local_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return get_endpoint_address(endpoint);
}

std::string get_socket_local_address(boost::asio::ip::udp::socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.local_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return get_endpoint_address(endpoint);
}

std::string get_socket_remote_address(boost::asio::ip::udp::socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.remote_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return get_endpoint_address(endpoint);
}

boost::asio::ip::tcp::socket change_socket_io_context(boost::asio::ip::tcp::socket sock, boost::asio::io_context& io)
{
    std::string local = get_socket_local_address(sock);
    std::string remote = get_socket_remote_address(sock);

    boost::system::error_code ec;

    boost::asio::ip::tcp::socket tmp(io);

    auto fd = sock.release(ec);

    if (ec)
    {
        WEBRTC_LOG_ERROR("{}<-->{} change thread failed {}", local, remote, ec.message());

        return tmp;
    }

    tmp.assign(boost::asio::ip::tcp::v4(), fd);

    return tmp;
}
}    // namespace webrtc
