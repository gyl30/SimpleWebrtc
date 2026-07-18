#ifndef SIMPLE_WEBRTC_ICE_SESSION_TRANSPORT_ENVIRONMENT_CONFIG_H
#define SIMPLE_WEBRTC_ICE_SESSION_TRANSPORT_ENVIRONMENT_CONFIG_H

#include <cstdint>
#include <expected>
#include <string>

#include "net/udp_port_allocator.h"

namespace webrtc
{
[[nodiscard]] std::expected<udp_port_range, std::string> load_session_udp_port_range();

[[nodiscard]] std::expected<std::uint16_t, std::string> load_dtls_ip_mtu();
}    // namespace webrtc

#endif
