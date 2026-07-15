#ifndef SIMPLE_WEBRTC_NET_SOCKET_H
#define SIMPLE_WEBRTC_NET_SOCKET_H

#include <string>

#include <boost/asio.hpp>

namespace webrtc
{
std::string format_udp_endpoint(const boost::asio::ip::udp::endpoint& endpoint);

std::string get_endpoint_ip(const boost::asio::ip::udp::endpoint& endpoint);

std::string get_socket_remote_address(boost::asio::ip::tcp::socket& socket);

std::string get_socket_local_address(boost::asio::ip::tcp::socket& socket);
}    // namespace webrtc

#endif
