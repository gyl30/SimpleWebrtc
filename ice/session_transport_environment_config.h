#ifndef SIMPLE_WEBRTC_ICE_SESSION_TRANSPORT_ENVIRONMENT_CONFIG_H
#define SIMPLE_WEBRTC_ICE_SESSION_TRANSPORT_ENVIRONMENT_CONFIG_H

#include <cstdint>
#include <expected>
#include <string>

#include "net/udp_port_allocator.h"

namespace webrtc
{
struct session_transport_runtime_config
{
    std::uint16_t dtls_ip_mtu = 0;

    udp_port_range session_udp_port_range;
};

[[nodiscard]] std::expected<session_transport_runtime_config, std::string> load_session_transport_runtime_config();
}    // namespace webrtc

#endif
