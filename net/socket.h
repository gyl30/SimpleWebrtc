#ifndef SIMPLE_WEBRTC_NET_SOCKET_H
#define SIMPLE_WEBRTC_NET_SOCKET_H

#include <string>
#include <boost/asio.hpp>

namespace webrtc
{
std::string get_endpoint_address(const boost::asio::ip::tcp::endpoint& ed);
std::string get_endpoint_address(const boost::asio::ip::udp::endpoint& ed);

std::string get_socket_remote_address(boost::asio::ip::tcp::socket& socket);
std::string get_socket_local_address(boost::asio::ip::tcp::socket& socket);

std::string get_socket_remote_address(boost::asio::ip::udp::socket& socket);
std::string get_socket_local_address(boost::asio::ip::udp::socket& socket);
// tcp
std::string get_socket_local_ip(boost::asio::ip::tcp::socket& socket);
uint16_t get_socket_local_port(boost::asio::ip::tcp::socket& socket);
std::string get_socket_remote_ip(boost::asio::ip::tcp::socket& socket);
uint16_t get_socket_remote_port(boost::asio::ip::tcp::socket& socket);
// udp
std::string get_socket_local_ip(boost::asio::ip::udp::socket& socket);
uint16_t get_socket_local_port(boost::asio::ip::udp::socket& socket);
std::string get_socket_remote_ip(boost::asio::ip::udp::socket& socket);
uint16_t get_socket_remote_port(boost::asio::ip::udp::socket& socket);

boost::asio::ip::tcp::socket change_socket_io_context(boost::asio::ip::tcp::socket sock, boost::asio::io_context& io);
}    // namespace webrtc

#endif
