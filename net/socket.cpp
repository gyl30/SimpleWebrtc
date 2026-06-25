#include <boost/system.hpp>
#include <boost/asio/detail/socket_ops.hpp>

#include "log/log.h"
#include "net/socket.h"

namespace webrtc
{

static std::string safe_address_string(const boost::asio::ip::address& addr)
{
    boost::system::error_code ec;
    if (addr.is_v4())
    {
        auto b = addr.to_v4().to_bytes();
        char buf[boost::asio::detail::max_addr_v4_str_len];
        const char* s = boost::asio::detail::socket_ops::inet_ntop(BOOST_ASIO_OS_DEF(AF_INET), b.data(), buf, sizeof(buf), 0, ec);
        if (s != nullptr)
        {
            return s;
        }
        return {};
    }
    auto b = addr.to_v6().to_bytes();
    char buf[boost::asio::detail::max_addr_v6_str_len];
    const char* s = boost::asio::detail::socket_ops::inet_ntop(BOOST_ASIO_OS_DEF(AF_INET6), b.data(), buf, sizeof(buf), addr.to_v6().scope_id(), ec);
    if (s != nullptr)
    {
        return s;
    }

    return {};
}

template <typename Ed>
static std::string get_endpoint_address_(const Ed& ed)
{
    std::string ip = safe_address_string(ed.address());
    if (ip.empty())
    {
        return "";
    }
    const uint16_t port = ed.port();
    return ip + ":" + std::to_string(port);
}

template <typename Socket>
static std::string get_socket_local_ip_(Socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.local_endpoint(ec);
    if (ec)
    {
        return "";
    }
    return safe_address_string(ed.address());
}
template <typename Socket>
static uint16_t get_socket_local_port_(Socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.local_endpoint(ec);
    if (ec)
    {
        return 0;
    }
    return ed.port();
}
//
template <typename Socket>
static std::string get_socket_remote_ip_(Socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.remote_endpoint(ec);
    if (ec)
    {
        return "";
    }
    return safe_address_string(ed.address());
}
template <typename Socket>
static uint16_t get_socket_remote_port_(Socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.remote_endpoint(ec);
    if (ec)
    {
        return 0;
    }
    return ed.port();
}
std::string get_socket_local_ip(boost::asio::ip::udp::socket& socket) { return get_socket_local_ip_(socket); }

uint16_t get_socket_local_port(boost::asio::ip::udp::socket& socket) { return get_socket_local_port_(socket); }

std::string get_socket_remote_ip(boost::asio::ip::udp::socket& socket) { return get_socket_remote_ip_(socket); }
uint16_t get_socket_remote_port(boost::asio::ip::udp::socket& socket) { return get_socket_remote_port_(socket); }
std::string get_socket_local_ip(boost::asio::ip::tcp::socket& socket) { return get_socket_local_ip_(socket); }
uint16_t get_socket_local_port(boost::asio::ip::tcp::socket& socket) { return get_socket_local_port_(socket); }
std::string get_socket_remote_ip(boost::asio::ip::tcp::socket& socket) { return get_socket_remote_ip_(socket); }
uint16_t get_socket_remote_port(boost::asio::ip::tcp::socket& socket) { return get_socket_remote_port_(socket); }
std::string get_endpoint_address(const boost::asio::ip::tcp::endpoint& ed) { return get_endpoint_address_(ed); }
std::string get_endpoint_address(const boost::asio::ip::udp::endpoint& ed) { return get_endpoint_address_(ed); }

std::string get_socket_remote_address(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.remote_endpoint(ec);
    if (ec)
    {
        return "";
    }
    return get_endpoint_address(ed);
}
std::string get_socket_local_address(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.local_endpoint(ec);
    if (ec)
    {
        return "";
    }
    return get_endpoint_address(ed);
}
std::string get_socket_local_address(boost::asio::ip::udp::socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.local_endpoint(ec);
    if (ec)
    {
        return "";
    }
    return get_endpoint_address(ed);
}
std::string get_socket_remote_address(boost::asio::ip::udp::socket& socket)
{
    boost::system::error_code ec;
    auto ed = socket.remote_endpoint(ec);
    if (ec)
    {
        return "";
    }
    return get_endpoint_address(ed);
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
