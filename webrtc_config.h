#ifndef SIMPLE_WEBRTC_WEBRTC_CONFIG_H
#define SIMPLE_WEBRTC_WEBRTC_CONFIG_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "net/udp_port_allocator.h"

namespace webrtc
{
enum class webrtc_log_level
{
    trace,
    debug,
    info,
    warn,
    error,
    critical,
    off,
};

struct webrtc_log_config
{
    webrtc_log_level level = webrtc_log_level::info;
    std::size_t file_size_bytes = 0;
    std::size_t file_count = 0;
};

struct webrtc_config
{
    webrtc_log_config log;

    std::string http_certificate_file;
    std::string http_private_key_file;
    std::uint16_t http_port = 0;
    std::string admin_token;

    std::string ice_bind_host;
    std::vector<std::string> ice_public_ips;
    std::string ice_server_link_header;
    udp_port_range session_udp_port_range;

    std::uint16_t dtls_ip_mtu = 0;
    std::uint32_t session_inactivity_timeout_seconds = 0;
    std::uint32_t publisher_recovery_timeout_seconds = 0;
};

using webrtc_config_result = std::expected<webrtc_config, std::string>;

[[nodiscard]] webrtc_config_result load_webrtc_config();
}    // namespace webrtc

#endif
