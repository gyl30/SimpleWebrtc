#include "webrtc_config.h"

#include <algorithm>
#include <cstddef>
#include <concepts>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include "dtls/dtls_transport.h"
#include "util/number_parse.h"

namespace webrtc
{
namespace
{
constexpr std::uint16_t k_default_http_port = 8811;
constexpr std::uint16_t k_default_session_udp_port_min = 50000;
constexpr std::uint16_t k_default_session_udp_port_max = 59999;
constexpr std::uint32_t k_default_session_inactivity_timeout_seconds = 30;
constexpr std::uint32_t k_default_publisher_recovery_timeout_seconds = 10;
constexpr std::uint32_t k_maximum_session_timeout_seconds = 3600;

constexpr std::uint64_t k_default_log_file_size_bytes = 50ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_minimum_log_file_size_bytes = 1ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t k_maximum_log_file_size_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;

constexpr std::uint32_t k_default_log_file_count = 5;
constexpr std::uint32_t k_minimum_log_file_count = 1;
constexpr std::uint32_t k_maximum_log_file_count = 100;

std::optional<std::string_view> environment_value(const char* name)
{
    const char* value = std::getenv(name);

    if (value == nullptr)
    {
        return std::nullopt;
    }

    return std::string_view(value);
}

std::string environment_string(const char* name)
{
    const auto value = environment_value(name);
    return value.has_value() ? std::string(*value) : std::string();
}

std::unexpected<std::string> make_environment_error(std::string_view name, std::string_view message)
{
    std::string error(name);
    error.append(": ");
    error.append(message);
    return std::unexpected(std::move(error));
}

template <std::integral integer_type>
std::expected<integer_type, std::string> load_integer_environment(const char* name,
                                                                  integer_type default_value,
                                                                  integer_type minimum,
                                                                  integer_type maximum)
{
    const auto value = environment_value(name);

    if (!value.has_value())
    {
        return default_value;
    }

    return parse_integer<integer_type>(*value, minimum, maximum, name);
}

std::expected<std::string, std::string> load_nonempty_environment(const char* name, std::string_view default_value)
{
    const auto value = environment_value(name);

    if (!value.has_value())
    {
        return std::string(default_value);
    }

    if (value->empty())
    {
        return make_environment_error(name, "value is empty");
    }

    return std::string(*value);
}

std::expected<std::string, std::string> load_ip_address_environment(const char* name, std::string_view default_value)
{
    auto value = load_nonempty_environment(name, default_value);

    if (!value)
    {
        return std::unexpected(value.error());
    }

    boost::system::error_code error;
    boost::asio::ip::make_address(*value, error);

    if (error)
    {
        return make_environment_error(name, "must be an IP address");
    }

    return value;
}

std::expected<webrtc_log_level, std::string> parse_log_level(std::string_view value)
{
    if (value == "trace")
    {
        return webrtc_log_level::trace;
    }
    if (value == "debug")
    {
        return webrtc_log_level::debug;
    }
    if (value == "info")
    {
        return webrtc_log_level::info;
    }
    if (value == "warn" || value == "warning")
    {
        return webrtc_log_level::warn;
    }
    if (value == "error" || value == "err")
    {
        return webrtc_log_level::error;
    }
    if (value == "critical")
    {
        return webrtc_log_level::critical;
    }
    if (value == "off")
    {
        return webrtc_log_level::off;
    }

    return make_environment_error("WEBRTC_LOG_LEVEL", "expected trace, debug, info, warn, error, critical, or off");
}

std::expected<webrtc_log_level, std::string> load_log_level_environment()
{
    const auto value = environment_value("WEBRTC_LOG_LEVEL");

    if (!value.has_value())
    {
        return webrtc_log_level::info;
    }

    return parse_log_level(*value);
}

std::expected<std::vector<std::string>, std::string> parse_ice_public_ips(std::string_view value)
{
    std::vector<std::string> items;
    boost::algorithm::split(items, value, boost::algorithm::is_any_of(","));

    std::set<std::string> addresses;

    for (auto& item : items)
    {
        boost::algorithm::trim(item);
        if (item.empty())
        {
            continue;
        }

        boost::system::error_code error;
        boost::asio::ip::make_address(item, error);
        if (error)
        {
            return make_environment_error("WEBRTC_ICE_PUBLIC_IPS", "contains an invalid IP address: " + item);
        }

        addresses.insert(std::move(item));
    }

    if (addresses.empty())
    {
        return make_environment_error("WEBRTC_ICE_PUBLIC_IPS", "must contain at least one IP address");
    }

    return std::vector<std::string>(addresses.begin(), addresses.end());
}

bool contains_line_break(std::string_view value) { return value.find_first_of("\r\n") != std::string_view::npos; }

bool is_ice_server_url(std::string_view url)
{
    return url.starts_with("stun:") || url.starts_with("stuns:") || url.starts_with("turn:") || url.starts_with("turns:");
}

std::expected<std::vector<std::string>, std::string> parse_ice_server_urls(std::string_view value)
{
    if (contains_line_break(value))
    {
        return make_environment_error("WEBRTC_ICE_SERVER_URLS", "must not contain line breaks");
    }

    std::vector<std::string> urls;
    boost::algorithm::split(urls, value, boost::algorithm::is_any_of(", \t"), boost::algorithm::token_compress_on);

    for (auto& url : urls)
    {
        boost::algorithm::trim(url);
        if (url.empty())
        {
            continue;
        }
        if (!is_ice_server_url(url))
        {
            return make_environment_error("WEBRTC_ICE_SERVER_URLS", "contains an unsupported URL: " + url);
        }
        if (url.find_first_of("<>") != std::string::npos)
        {
            return make_environment_error("WEBRTC_ICE_SERVER_URLS", "contains an unsafe URL: " + url);
        }
    }

    std::erase_if(urls, [](const std::string& url) { return url.empty(); });
    return urls;
}

void append_link_parameter(std::string& output, std::string_view name, std::string_view value)
{
    output.append("; ");
    output.append(name);
    output.append("=\"");

    for (const char ch : value)
    {
        if (ch == '"' || ch == '\\')
        {
            output.push_back('\\');
        }
        output.push_back(ch);
    }

    output.push_back('"');
}

std::string make_ice_server_link_header(const std::vector<std::string>& urls, std::string_view username, std::string_view credential)
{
    std::string header;

    for (const auto& url : urls)
    {
        if (!header.empty())
        {
            header.append(", ");
        }
        header.push_back('<');
        header.append(url);
        header.append(">; rel=\"ice-server\"");

        if (!username.empty())
        {
            append_link_parameter(header, "username", username);
            append_link_parameter(header, "credential", credential);
        }
    }

    return header;
}

std::expected<std::string, std::string> load_ice_server_link_header()
{
    const std::string urls_value = environment_string("WEBRTC_ICE_SERVER_URLS");
    const std::string username = environment_string("WEBRTC_ICE_SERVER_USERNAME");
    const std::string credential = environment_string("WEBRTC_ICE_SERVER_CREDENTIAL");

    if (username.empty() != credential.empty())
    {
        return make_environment_error("WEBRTC_ICE_SERVER_USERNAME/WEBRTC_ICE_SERVER_CREDENTIAL", "must be configured together");
    }
    if (urls_value.empty() && !username.empty())
    {
        return make_environment_error("WEBRTC_ICE_SERVER_URLS", "must be configured when ICE server credentials are set");
    }
    if (contains_line_break(username) || contains_line_break(credential))
    {
        return make_environment_error("WEBRTC_ICE_SERVER_USERNAME/WEBRTC_ICE_SERVER_CREDENTIAL", "must not contain line breaks");
    }

    auto urls = parse_ice_server_urls(urls_value);
    if (!urls)
    {
        return std::unexpected(urls.error());
    }
    if (!urls_value.empty() && urls->empty())
    {
        return make_environment_error("WEBRTC_ICE_SERVER_URLS", "must contain at least one URL");
    }

    return make_ice_server_link_header(*urls, username, credential);
}

std::expected<void, std::string> load_log_environment(webrtc_config& config)
{
    auto level = load_log_level_environment();
    if (!level)
    {
        return std::unexpected(level.error());
    }

    auto file_size = load_integer_environment<std::uint64_t>(
        "WEBRTC_LOG_FILE_SIZE_BYTES", k_default_log_file_size_bytes, k_minimum_log_file_size_bytes, k_maximum_log_file_size_bytes);
    if (!file_size)
    {
        return std::unexpected(file_size.error());
    }
    if (*file_size > std::numeric_limits<std::size_t>::max())
    {
        return make_environment_error("WEBRTC_LOG_FILE_SIZE_BYTES", "cannot be represented by std::size_t");
    }

    auto file_count = load_integer_environment<std::uint32_t>(
        "WEBRTC_LOG_FILE_COUNT", k_default_log_file_count, k_minimum_log_file_count, k_maximum_log_file_count);
    if (!file_count)
    {
        return std::unexpected(file_count.error());
    }

    config.log = {*level, static_cast<std::size_t>(*file_size), static_cast<std::size_t>(*file_count)};
    return {};
}

std::expected<void, std::string> load_http_environment(webrtc_config& config)
{
    config.http_certificate_file = environment_string("WEBRTC_HTTP_CERT_FILE");
    config.http_private_key_file = environment_string("WEBRTC_HTTP_KEY_FILE");
    config.admin_token = environment_string("WEBRTC_ADMIN_TOKEN");

    if (config.http_certificate_file.empty() != config.http_private_key_file.empty())
    {
        return make_environment_error("WEBRTC_HTTP_CERT_FILE/WEBRTC_HTTP_KEY_FILE", "must be configured together");
    }

    auto port = load_integer_environment<std::uint16_t>("WEBRTC_HTTP_PORT", k_default_http_port, 1, std::numeric_limits<std::uint16_t>::max());
    if (!port)
    {
        return std::unexpected(port.error());
    }

    config.http_port = *port;
    return {};
}

std::expected<void, std::string> load_ice_environment(webrtc_config& config)
{
    auto bind_host = load_ip_address_environment("WEBRTC_ICE_BIND_HOST", "0.0.0.0");
    if (!bind_host)
    {
        return std::unexpected(bind_host.error());
    }

    auto public_ips_value = load_nonempty_environment("WEBRTC_ICE_PUBLIC_IPS", "127.0.0.1");
    if (!public_ips_value)
    {
        return std::unexpected(public_ips_value.error());
    }
    auto public_ips = parse_ice_public_ips(*public_ips_value);
    if (!public_ips)
    {
        return std::unexpected(public_ips.error());
    }

    auto link_header = load_ice_server_link_header();
    if (!link_header)
    {
        return std::unexpected(link_header.error());
    }

    config.ice_bind_host = std::move(*bind_host);
    config.ice_public_ips = std::move(*public_ips);
    config.ice_server_link_header = std::move(*link_header);
    return {};
}

std::expected<void, std::string> load_transport_environment(webrtc_config& config)
{
    auto min_port = load_integer_environment<std::uint16_t>(
        "SIMPLE_WEBRTC_UDP_PORT_MIN", k_default_session_udp_port_min, 1, std::numeric_limits<std::uint16_t>::max());
    if (!min_port)
    {
        return std::unexpected(min_port.error());
    }

    auto max_port = load_integer_environment<std::uint16_t>(
        "SIMPLE_WEBRTC_UDP_PORT_MAX", k_default_session_udp_port_max, 1, std::numeric_limits<std::uint16_t>::max());
    if (!max_port)
    {
        return std::unexpected(max_port.error());
    }

    config.session_udp_port_range = {*min_port, *max_port};
    if (!udp_port_range_is_valid(config.session_udp_port_range))
    {
        return make_environment_error("SIMPLE_WEBRTC_UDP_PORT_MIN/SIMPLE_WEBRTC_UDP_PORT_MAX", "minimum must not exceed maximum");
    }

    auto dtls_ip_mtu = load_integer_environment<std::uint16_t>("WEBRTC_DTLS_MTU", k_default_dtls_ip_mtu, k_min_dtls_ip_mtu, k_max_dtls_ip_mtu);
    if (!dtls_ip_mtu)
    {
        return std::unexpected(dtls_ip_mtu.error());
    }

    config.dtls_ip_mtu = *dtls_ip_mtu;

    auto inactivity_timeout = load_integer_environment<std::uint32_t>(
        "WEBRTC_SESSION_INACTIVITY_TIMEOUT_SECONDS", k_default_session_inactivity_timeout_seconds, 1, k_maximum_session_timeout_seconds);
    if (!inactivity_timeout)
    {
        return std::unexpected(inactivity_timeout.error());
    }

    auto publisher_recovery_timeout = load_integer_environment<std::uint32_t>(
        "WEBRTC_PUBLISHER_RECOVERY_TIMEOUT_SECONDS", k_default_publisher_recovery_timeout_seconds, 1, k_maximum_session_timeout_seconds);
    if (!publisher_recovery_timeout)
    {
        return std::unexpected(publisher_recovery_timeout.error());
    }

    config.session_inactivity_timeout_seconds = *inactivity_timeout;
    config.publisher_recovery_timeout_seconds = *publisher_recovery_timeout;
    return {};
}
}    // namespace

webrtc_config_result load_webrtc_config()
{
    webrtc_config config;

    auto result = load_log_environment(config);
    if (!result)
    {
        return std::unexpected(result.error());
    }
    result = load_http_environment(config);
    if (!result)
    {
        return std::unexpected(result.error());
    }
    result = load_ice_environment(config);
    if (!result)
    {
        return std::unexpected(result.error());
    }
    result = load_transport_environment(config);
    if (!result)
    {
        return std::unexpected(result.error());
    }

    return config;
}
}    // namespace webrtc
