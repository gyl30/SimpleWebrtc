#ifndef SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H
#define SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "dtls/dtls_transport.h"
#include "session/stream_registry.h"

namespace webrtc
{
using ice_udp_server_result = std::expected<void, std::string>;

class ice_udp_server : public std::enable_shared_from_this<ice_udp_server>
{
   public:
    ice_udp_server(boost::asio::io_context& io_context, std::string bind_host, uint16_t bind_port, std::shared_ptr<stream_registry> registry);

    ~ice_udp_server() = default;

    ice_udp_server(const ice_udp_server&) = delete;
    ice_udp_server& operator=(const ice_udp_server&) = delete;

    ice_udp_server(ice_udp_server&&) = delete;
    ice_udp_server& operator=(ice_udp_server&&) = delete;

   public:
    [[nodiscard]] ice_udp_server_result start();
    void stop();

    [[nodiscard]] uint16_t local_port() const;

   private:
    using udp = boost::asio::ip::udp;

    [[nodiscard]] ice_udp_server_result init_dtls_transport();

    void do_receive();

    void on_receive(boost::system::error_code ec, std::size_t bytes_transferred);

    void handle_stun_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    void handle_dtls_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    void handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    void send_response(std::vector<uint8_t> response, const udp::endpoint& remote_endpoint);

    [[nodiscard]] std::shared_ptr<publisher_session> find_publisher_for_username(std::string_view username) const;

    [[nodiscard]] std::shared_ptr<subscriber_session> find_subscriber_for_username(std::string_view username) const;

    [[nodiscard]] static std::string extract_local_ufrag(std::string_view username);

    [[nodiscard]] static std::string endpoint_ip(const udp::endpoint& endpoint);

   private:
    boost::asio::io_context& io_context_;
    udp::socket socket_;

    std::string bind_host_;
    uint16_t bind_port_ = 0;

    std::shared_ptr<stream_registry> registry_;
    std::shared_ptr<dtls_transport> dtls_transport_;

    udp::endpoint remote_endpoint_;
    std::array<uint8_t, 4096> receive_buffer_{};

    bool started_ = false;
};
}    // namespace webrtc

#endif
