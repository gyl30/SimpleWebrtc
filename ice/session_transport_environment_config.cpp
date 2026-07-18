#include "ice/session_transport_environment_config.h"

#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <limits>
#include <string_view>
#include <utility>

#include "dtls/dtls_transport.h"
#include "log/log.h"

namespace webrtc
{
namespace
{
constexpr uint16_t k_default_session_udp_port_min = 50000;
constexpr uint16_t k_default_session_udp_port_max = 59999;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint16_t get_env_u16_or_default(const char* name, uint16_t default_value)
{
    const char* value = std::getenv(name);

    if (value == nullptr || value[0] == '\0')
    {
        return default_value;
    }

    errno = 0;

    char* end = nullptr;

    const auto parsed = std::strtoull(value, &end, 10);

    if (errno != 0 || end == value || *end != '\0')
    {
        WEBRTC_LOG_WARN("session transport env value invalid name={} value={} default={}", name, value, default_value);

        return default_value;
    }

    if (parsed > static_cast<unsigned long long>(std::numeric_limits<uint16_t>::max()))
    {
        WEBRTC_LOG_WARN("session udp port env value too large name={} value={} default={}", name, parsed, default_value);

        return default_value;
    }

    return static_cast<uint16_t>(parsed);
}

std::expected<udp_port_range, std::string> make_session_udp_port_range_from_env()
{
    udp_port_range range;

    range.min_port = get_env_u16_or_default("SIMPLE_WEBRTC_UDP_PORT_MIN", k_default_session_udp_port_min);

    range.max_port = get_env_u16_or_default("SIMPLE_WEBRTC_UDP_PORT_MAX", k_default_session_udp_port_max);

    if (!udp_port_range_is_valid(range))
    {
        std::string error = "session udp port range is invalid min=";

        error.append(std::to_string(range.min_port));
        error.append(" max=");
        error.append(std::to_string(range.max_port));

        return std::unexpected(std::move(error));
    }

    WEBRTC_LOG_INFO("session udp port range config min={} max={}", range.min_port, range.max_port);

    return range;
}

std::expected<std::uint16_t, std::string> parse_dtls_ip_mtu_from_env()
{
    const char* value = std::getenv("WEBRTC_DTLS_MTU");

    if (value == nullptr)
    {
        return k_default_dtls_ip_mtu;
    }

    const std::string_view text(value);

    if (text.empty())
    {
        return make_error("WEBRTC_DTLS_MTU is empty");
    }

    std::uint64_t parsed = 0;

    const auto parse_result = std::from_chars(text.data(), text.data() + text.size(), parsed, 10);

    if (parse_result.ec != std::errc{} || parse_result.ptr != text.data() + text.size())
    {
        return make_error("WEBRTC_DTLS_MTU must be an unsigned decimal integer");
    }

    if (parsed < k_min_dtls_ip_mtu || parsed > k_max_dtls_ip_mtu)
    {
        std::string error = "WEBRTC_DTLS_MTU is out of range value=";

        error.append(std::to_string(parsed));
        error.append(" minimum=");
        error.append(std::to_string(k_min_dtls_ip_mtu));
        error.append(" maximum=");
        error.append(std::to_string(k_max_dtls_ip_mtu));

        return std::unexpected(std::move(error));
    }

    return static_cast<std::uint16_t>(parsed);
}

}    // namespace

std::expected<session_transport_runtime_config, std::string> load_session_transport_runtime_config()
{
    auto dtls_ip_mtu = parse_dtls_ip_mtu_from_env();

    auto session_udp_port_range = make_session_udp_port_range_from_env();

    if (!session_udp_port_range)
    {
        return std::unexpected(session_udp_port_range.error());
    }

    if (!dtls_ip_mtu)
    {
        return std::unexpected(dtls_ip_mtu.error());
    }

    session_transport_runtime_config config;
    config.dtls_ip_mtu = *dtls_ip_mtu;
    config.session_udp_port_range = *session_udp_port_range;

    WEBRTC_LOG_INFO("session transport runtime config loaded dtls_ip_mtu={} ipv4_udp_payload_mtu={} ipv6_udp_payload_mtu={} "
                    "session_udp_port_min={} session_udp_port_max={}",
                    config.dtls_ip_mtu,
                    config.dtls_ip_mtu - k_ipv4_udp_overhead,
                    config.dtls_ip_mtu - k_ipv6_udp_overhead,
                    config.session_udp_port_range.min_port,
                    config.session_udp_port_range.max_port);

    return config;
}
}    // namespace webrtc
