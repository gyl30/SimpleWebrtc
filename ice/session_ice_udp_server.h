#ifndef SIMPLE_WEBRTC_ICE_SESSION_ICE_UDP_SERVER_H
#define SIMPLE_WEBRTC_ICE_SESSION_ICE_UDP_SERVER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include <boost/asio.hpp>

namespace webrtc
{
struct session_udp_packet
{
    std::vector<uint8_t> data;
    boost::asio::ip::udp::endpoint remote_endpoint;
};

struct session_udp_outbound_packet
{
    std::vector<uint8_t> data;
    boost::asio::ip::udp::endpoint remote_endpoint;
};

struct session_udp_dispatch_result
{
    std::vector<session_udp_outbound_packet> outbound_packets;
};

class session_ice_udp_packet_handler
{
   public:
    virtual ~session_ice_udp_packet_handler() = default;

    [[nodiscard]]
    virtual session_udp_dispatch_result handle_udp_packet(const session_udp_packet& packet) = 0;
};

using session_ice_udp_server_result = std::expected<void, std::string>;

class session_ice_udp_server
{
   public:
    session_ice_udp_server(boost::asio::io_context& io_context, std::string bind_host);

    ~session_ice_udp_server();

    session_ice_udp_server(const session_ice_udp_server&) = delete;

    session_ice_udp_server& operator=(const session_ice_udp_server&) = delete;

    session_ice_udp_server(session_ice_udp_server&&) = delete;

    session_ice_udp_server& operator=(session_ice_udp_server&&) = delete;

    [[nodiscard]]
    session_ice_udp_server_result start(uint16_t local_port, session_ice_udp_packet_handler& handler);

    void stop();

    void send(std::vector<uint8_t> packet, const boost::asio::ip::udp::endpoint& remote_endpoint);

   private:
    void do_receive();

    void on_receive(boost::system::error_code ec, std::size_t bytes_transferred);

    void send_outbound_packets(session_udp_dispatch_result result);

   private:
    boost::asio::ip::udp::socket socket_;

    std::string bind_host_;

    uint16_t local_port_ = 0;

    bool started_ = false;

    session_ice_udp_packet_handler* handler_ = nullptr;

    boost::asio::ip::udp::endpoint remote_endpoint_;

    std::array<uint8_t, 65536> receive_buffer_{};
};
}    // namespace webrtc

#endif
