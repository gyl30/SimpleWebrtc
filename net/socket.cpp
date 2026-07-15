#include <cstdint>
#include <string>

#include <boost/asio/detail/socket_ops.hpp>
#include <boost/system.hpp>

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
}    // namespace

std::string format_udp_endpoint(const boost::asio::ip::udp::endpoint& endpoint)
{
    std::string value = get_endpoint_address_impl(endpoint);

    if (value.empty())
    {
        return "<unknown>";
    }

    return value;
}

std::string get_endpoint_ip(const boost::asio::ip::udp::endpoint& endpoint) { return get_endpoint_ip_impl(endpoint); }

std::string get_socket_remote_address(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.remote_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return get_endpoint_address_impl(endpoint);
}

std::string get_socket_local_address(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;

    auto endpoint = socket.local_endpoint(ec);

    if (ec)
    {
        return {};
    }

    return get_endpoint_address_impl(endpoint);
}
}    // namespace webrtc
