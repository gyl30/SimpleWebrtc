#ifndef SIMPLE_WEBRTC_SESSION_WHEP_SESSION_TRANSPORT_H
#define SIMPLE_WEBRTC_SESSION_WHEP_SESSION_TRANSPORT_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "dtls/dtls_transport.h"
#include "ice/session_ice_udp_server.h"
#include "media/media_fanout_router.h"
#include "media/whep_rtp_rewriter.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
using whep_session_transport_result = std::expected<void, std::string>;

class whep_session_transport : public session_ice_udp_packet_handler,
                               public std::enable_shared_from_this<whep_session_transport>
{
   public:
    whep_session_transport(boost::asio::io_context& io_context,
                           std::string bind_host,
                           std::shared_ptr<dtls_context> dtls_context,
                           std::uint16_t dtls_ip_mtu,
                           std::shared_ptr<media_fanout_router> media_fanout_router);

    ~whep_session_transport();

    whep_session_transport(const whep_session_transport&) = delete;
    whep_session_transport& operator=(const whep_session_transport&) = delete;

    whep_session_transport(whep_session_transport&&) = delete;
    whep_session_transport& operator=(whep_session_transport&&) = delete;

   public:
    [[nodiscard]] whep_session_transport_result start(uint16_t local_port);

    void set_peer_context(std::string local_ice_pwd,
                          dtls_peer_identity identity,
                          whep_rtp_rewriter_target target);

    void restart_peer_context(std::string local_ice_pwd,
                              dtls_peer_identity identity,
                              whep_rtp_rewriter_target target);

    void send_rtp(uint64_t source_generation, std::span<const uint8_t> plain_rtp);

   private:
    void subscribe_media();
    void unsubscribe_media();
    void handle_publisher_source(media_publisher_source_update update);
    void rebuild_rtp_rewriter_locked();
    void reset_selected_peer();

    session_udp_outbound_packet_list handle_udp_packet(const session_udp_packet& packet) override;

   private:
    session_ice_udp_server udp_server_;

    std::shared_ptr<dtls_transport> dtls_transport_;
    std::shared_ptr<srtp_transport> srtp_transport_;
    std::shared_ptr<media_fanout_router> media_fanout_router_;

    std::string local_ice_pwd_;
    std::optional<dtls_peer_identity> dtls_identity_;

    std::mutex rtp_rewriter_mutex_;
    whep_rtp_rewriter_target rtp_rewriter_target_;
    media_publisher_source_ptr publisher_source_;
    uint64_t publisher_source_generation_ = 0;
    whep_rtp_rewriter rtp_rewriter_;
    std::unordered_set<uint32_t> pending_keyframe_request_ssrcs_;
    std::unordered_set<uint32_t> requested_keyframe_ssrcs_;

    std::size_t received_packet_count_ = 0;
    std::size_t rewritten_rtp_packet_count_ = 0;
    std::size_t dropped_rtp_packet_count_ = 0;

    // 仅由通过完整 STUN 校验的 connectivity check 更新。
    std::optional<boost::asio::ip::udp::endpoint> selected_remote_endpoint_;
};
}    // namespace webrtc

#endif
