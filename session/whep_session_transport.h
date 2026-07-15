#ifndef SIMPLE_WEBRTC_SESSION_WHEP_SESSION_TRANSPORT_H
#define SIMPLE_WEBRTC_SESSION_WHEP_SESSION_TRANSPORT_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include <boost/asio.hpp>

#include "ice/ice_credentials.h"
#include "ice/session_ice_udp_server.h"
#include "dtls/dtls_context.h"
#include "dtls/dtls_transport.h"
#include "media/media_fanout_router.h"
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
                           dtls_transport_config dtls_config);

    ~whep_session_transport();

    whep_session_transport(const whep_session_transport&) = delete;

    whep_session_transport& operator=(const whep_session_transport&) = delete;

    whep_session_transport(whep_session_transport&&) = delete;

    whep_session_transport& operator=(whep_session_transport&&) = delete;

    [[nodiscard]]
    whep_session_transport_result start(uint16_t local_port);

    void set_ice_context(std::string stream_id, std::string session_id, ice_credentials local_ice, std::string remote_ice_ufrag);

    void set_dtls_peer_identity(dtls_peer_identity identity);

    void set_media_fanout_router(std::shared_ptr<media_fanout_router> media_fanout_router);

    void send_rtp(std::span<const uint8_t> plain_rtp);

    void stop();

   private:
    void subscribe_media();

    void unsubscribe_media();

    session_udp_dispatch_result handle_udp_packet(const session_udp_packet& packet) override;

   private:
    session_ice_udp_server udp_server_;

    std::string stream_id_;

    std::string session_id_;

    ice_credentials local_ice_;

    std::string remote_ice_ufrag_;

    std::shared_ptr<dtls_transport> dtls_transport_;

    std::shared_ptr<srtp_transport> srtp_transport_;

    std::shared_ptr<media_fanout_router> media_fanout_router_;

    dtls_peer_identity dtls_identity_;

    bool dtls_identity_ready_ = false;

    bool media_subscribed_ = false;

    std::size_t received_packet_count_ = 0;

    // 仅由通过完整 STUN 校验的 connectivity check 更新。
    std::optional<boost::asio::ip::udp::endpoint> selected_remote_endpoint_;
};
}    // namespace webrtc

#endif
