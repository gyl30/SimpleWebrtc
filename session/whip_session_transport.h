#ifndef SIMPLE_WEBRTC_SESSION_WHIP_SESSION_TRANSPORT_H
#define SIMPLE_WEBRTC_SESSION_WHIP_SESSION_TRANSPORT_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "dtls/dtls_transport.h"
#include "ice/session_ice_udp_server.h"
#include "media/media_fanout_router.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
using whip_session_transport_result = std::expected<void, std::string>;

class whip_session_transport : public session_ice_udp_packet_handler,
                               public std::enable_shared_from_this<whip_session_transport>
{
   public:
    whip_session_transport(boost::asio::io_context& io_context,
                           std::string bind_host,
                           std::shared_ptr<dtls_context> dtls_context,
                           std::uint16_t dtls_ip_mtu,
                           std::shared_ptr<media_fanout_router> media_fanout_router);

    ~whip_session_transport();

    whip_session_transport(const whip_session_transport&) = delete;
    whip_session_transport& operator=(const whip_session_transport&) = delete;

    whip_session_transport(whip_session_transport&&) = delete;
    whip_session_transport& operator=(whip_session_transport&&) = delete;

    [[nodiscard]] whip_session_transport_result start(uint16_t local_port);

    void set_peer_context(std::string local_ice_pwd, dtls_peer_identity identity);

    void restart_peer_context(std::string local_ice_pwd, dtls_peer_identity identity);

    void send_keyframe_request(uint32_t media_ssrc);

   private:
    enum class peer_nomination_state
    {
        unchanged,
        selected_fresh,
        association_rebound,
    };

    struct pending_ice_restart
    {
        uint64_t generation = 0;
        boost::asio::ip::udp::endpoint association_endpoint;
        dtls_peer_identity association_identity;
    };

    using peer_nomination_result = std::expected<peer_nomination_state, std::string>;

    void clear_peer_state();
    void clear_peer_state_locked();
    void schedule_ice_restart_timeout(uint64_t generation);
    void handle_ice_restart_timeout(uint64_t generation);
    [[nodiscard]] peer_nomination_result nominate_remote_endpoint(
        const boost::asio::ip::udp::endpoint& remote_endpoint);

    session_udp_outbound_packet_list handle_udp_packet(const session_udp_packet& packet) override;

   private:
    session_ice_udp_server udp_server_;
    boost::asio::steady_timer ice_restart_timer_;

    std::shared_ptr<dtls_transport> dtls_transport_;
    std::shared_ptr<srtp_transport> srtp_transport_;
    std::shared_ptr<media_fanout_router> media_fanout_router_;

    std::mutex peer_mutex_;
    std::string stream_id_;
    std::string session_id_;
    std::string local_ice_pwd_;
    std::optional<dtls_peer_identity> dtls_identity_;
    uint64_t ice_generation_ = 0;
    std::optional<pending_ice_restart> pending_ice_restart_;

    std::size_t received_packet_count_ = 0;
    uint32_t rtcp_sender_ssrc_ = 0;

    // 仅由当前 ICE generation 中携带 USE-CANDIDATE 的完整 STUN 校验结果更新。
    std::optional<boost::asio::ip::udp::endpoint> selected_remote_endpoint_;
};
}    // namespace webrtc

#endif
