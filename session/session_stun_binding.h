#ifndef SIMPLE_WEBRTC_SESSION_SESSION_STUN_BINDING_H
#define SIMPLE_WEBRTC_SESSION_SESSION_STUN_BINDING_H

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <boost/asio.hpp>

#include "ice/session_ice_udp_server.h"

namespace webrtc
{
struct session_stun_binding_context
{
    std::string_view log_prefix;
    std::string_view stream_id;
    std::string_view session_id;
    std::string_view local_ice_ufrag;
    std::string_view local_ice_pwd;
    std::string_view remote_ice_ufrag;
};

struct session_stun_binding_result
{
    bool handled = false;

    // 只有完整校验通过且成功生成 Binding Success 响应时才为 true。
    bool accepted = false;

    std::optional<session_udp_outbound_packet> response;
};

[[nodiscard]]
session_stun_binding_result handle_session_stun_binding(std::span<const uint8_t> data,
                                                        const boost::asio::ip::udp::endpoint& remote_endpoint,
                                                        const session_stun_binding_context& context);
}    // namespace webrtc

#endif
