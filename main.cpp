#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <memory>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/version.hpp>
#include <openssl/opensslv.h>

#include "ice/session_transport_environment_config.h"
#include "log/log.h"
#include "net/detect_ssl_session.h"
#include "net/http.h"
#include "net/socket.h"
#include "net/tcp_server.h"
#include "net/udp_port_allocator.h"
#include "server/router.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"
#include "util/file.h"
#include "util/random.h"
#include "util/scoped_exit.h"
#include "dtls/dtls_certificate.h"
#include "dtls/dtls_context.h"

static std::string get_env_or_default(const char* name, const std::string& default_value)
{
    const char* value = std::getenv(name);

    if (value == nullptr || value[0] == '\0')
    {
        return default_value;
    }

    return value;
}

static uint16_t get_env_uint16_or_default(const char* name, uint16_t default_value)
{
    const char* value = std::getenv(name);

    if (value == nullptr || value[0] == '\0')
    {
        return default_value;
    }

    errno = 0;

    char* end = nullptr;

    const unsigned long parsed = std::strtoul(value, &end, 10);

    if (errno != 0 || end == value || *end != '\0')
    {
        return default_value;
    }

    if (parsed > static_cast<unsigned long>(std::numeric_limits<uint16_t>::max()))
    {
        return default_value;
    }

    return static_cast<uint16_t>(parsed);
}
static std::string_view trim_ascii(std::string_view value)
{
    const std::size_t begin = value.find_first_not_of(" \t\r\n");

    if (begin == std::string_view::npos)
    {
        return {};
    }

    const std::size_t end = value.find_last_not_of(" \t\r\n");

    return value.substr(begin, end - begin + 1);
}

static bool contains_string(const std::vector<std::string>& values, std::string_view value)
{
    for (const auto& current : values)
    {
        if (current == value)
        {
            return true;
        }
    }

    return false;
}

static void append_unique_string(std::vector<std::string>& values, std::string_view value)
{
    value = trim_ascii(value);

    if (value.empty())
    {
        return;
    }

    if (contains_string(values, value))
    {
        return;
    }

    values.emplace_back(value);
}

static std::vector<std::string> split_csv_unique(std::string_view value)
{
    std::vector<std::string> result;

    std::size_t offset = 0;

    while (offset <= value.size())
    {
        const std::size_t comma = value.find(',', offset);

        if (comma == std::string_view::npos)
        {
            append_unique_string(result, value.substr(offset));

            break;
        }

        append_unique_string(result, value.substr(offset, comma - offset));

        offset = comma + 1;
    }

    return result;
}

static std::vector<std::string> make_ice_public_ip_list(std::string_view configured_public_ips)
{
    std::vector<std::string> addresses = split_csv_unique(configured_public_ips);

    if (addresses.empty())
    {
        addresses.emplace_back("127.0.0.1");
    }

    return addresses;
}

static webrtc::sdp::sdp_ice_candidate_options make_ice_host_candidate(std::string address, uint16_t port, std::size_t index)
{
    webrtc::sdp::sdp_ice_candidate_options candidate;

    candidate.foundation = std::to_string(index + 1);

    candidate.component = 1;

    candidate.transport = "udp";

    candidate.priority = static_cast<uint32_t>(2130706431U - static_cast<uint32_t>(index));

    candidate.address = std::move(address);

    candidate.port = port;

    candidate.type = "host";

    return candidate;
}

static bool load_server_certificate(boost::asio::ssl::context& ctx, const std::string& cert_file, const std::string& key_file)
{
    boost::system::error_code ec;

    ec = ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3 |
                             boost::asio::ssl::context::single_dh_use,
                         ec);

    if (ec)
    {
        WEBRTC_LOG_ERROR("ssl context set options failed: {}", ec.message());

        return false;
    }

    ec = ctx.use_certificate_chain_file(cert_file, ec);

    if (ec)
    {
        WEBRTC_LOG_ERROR("load certificate file {} failed: {}", cert_file, ec.message());

        return false;
    }

    ec = ctx.use_private_key_file(key_file, boost::asio::ssl::context::pem, ec);

    if (ec)
    {
        WEBRTC_LOG_ERROR("load private key file {} failed: {}", key_file, ec.message());

        return false;
    }

    return true;
}

static void on_tcp(boost::asio::ip::tcp::socket socket, boost::asio::ssl::context& ssl_ctx, std::shared_ptr<webrtc::router> http_router)
{
    auto local_addr = webrtc::get_socket_local_address(socket);

    auto remote_addr = webrtc::get_socket_remote_address(socket);

    const std::string id = webrtc::random_string(8);

    WEBRTC_LOG_INFO("tcp accept {} <-> {} id {}", local_addr, remote_addr, id);

    webrtc::http_handler http;

    http.http = [http_router](webrtc::http_request_t& req) -> webrtc::http_response_ptr { return http_router->handle(req); };

    std::make_shared<webrtc::detect_ssl_session>(id, std::move(http), std::move(socket), ssl_ctx)->run();
}

int main(int argc, char* argv[])
{
    if (argc <= 0 || argv == nullptr || argv[0] == nullptr || argv[0][0] == '\0')
    {
        std::fprintf(stderr, "resolve executable path failed: argv[0] is empty\n");

        return 1;
    }

    auto app_path_result = webrtc::file_abs_path(argv[0]);

    if (!app_path_result)
    {
        std::fprintf(stderr, "resolve executable path failed: %s\n", app_path_result.error().c_str());

        return 1;
    }

    std::string app_path = std::move(*app_path_result);

    std::string app_dir = webrtc::file_dir(app_path);

    std::string app_name = webrtc::file_name(app_path);

    std::string log_dir = app_dir + "/log";

    std::string abs_log_filename = log_dir + "/" + app_name + ".log";

    auto log_init_result = webrtc::init_log(abs_log_filename);

    if (!log_init_result)
    {
        std::println(stderr, "initialize log failed: {}", log_init_result.error());
        return 1;
    }

    DEFER(webrtc::shutdown_log());

    WEBRTC_LOG_INFO("OpenSSL    version {}", OPENSSL_VERSION_STR);
    WEBRTC_LOG_INFO("Boost      version {}", BOOST_LIB_VERSION);

    WEBRTC_LOG_INFO("spdlog     version {}.{}.{}", SPDLOG_VER_MAJOR, SPDLOG_VER_MINOR, SPDLOG_VER_PATCH);

    boost::asio::ssl::context ssl_ctx_{boost::asio::ssl::context::tls_server};

    const std::string http_certificate_file = get_env_or_default("WEBRTC_HTTP_CERT_FILE", "");
    const std::string http_private_key_file = get_env_or_default("WEBRTC_HTTP_KEY_FILE", "");
    const bool http_tls_enabled = !http_certificate_file.empty();

    if (http_tls_enabled != !http_private_key_file.empty())
    {
        WEBRTC_LOG_ERROR("WEBRTC_HTTP_CERT_FILE and WEBRTC_HTTP_KEY_FILE must be configured together");

        return 1;
    }

    if (http_tls_enabled && !load_server_certificate(ssl_ctx_, http_certificate_file, http_private_key_file))
    {
        WEBRTC_LOG_ERROR("load http tls certificate failed");

        return 1;
    }

    auto dtls_certificate = webrtc::get_process_dtls_certificate();

    if (!dtls_certificate)
    {
        WEBRTC_LOG_ERROR("generate webrtc dtls certificate failed: {}", dtls_certificate.error());

        return 1;
    }

    webrtc::sdp::fingerprint_info local_fingerprint = (*dtls_certificate)->fingerprint;

    WEBRTC_LOG_INFO("flag_webrtc_dtls_certificate_generated fingerprint_algorithm={} fingerprint={}",
                    local_fingerprint.algorithm,
                    local_fingerprint.value);

    auto per_session_dtls_context = webrtc::make_dtls_context(*dtls_certificate);

    if (!per_session_dtls_context)
    {
        WEBRTC_LOG_ERROR("create per-session dtls context failed: {}", per_session_dtls_context.error());

        return 1;
    }

    const uint16_t http_port = get_env_uint16_or_default("WEBRTC_HTTP_PORT", 8811);
    const std::string ice_bind_host = get_env_or_default("WEBRTC_ICE_BIND_HOST", "0.0.0.0");
    const std::string ice_public_ips_config = get_env_or_default("WEBRTC_ICE_PUBLIC_IPS", "127.0.0.1");
    std::string admin_token = get_env_or_default("WEBRTC_ADMIN_TOKEN", "");
    const std::vector<std::string> ice_public_ips = make_ice_public_ip_list(ice_public_ips_config);

    WEBRTC_LOG_INFO(
        "flag_startup_config_summary app_path={} log_file={} http_tls_enabled={} http_cert_file={} http_key_file={} http_port={} "
        "session_ice_bind_host={} ice_public_ip_source={} ice_public_ip_count={} admin_token_configured={}",
        app_path,
        abs_log_filename,
        http_tls_enabled ? 1 : 0,
        http_certificate_file,
        http_private_key_file,
        http_port,
        ice_bind_host,
        ice_public_ips_config,
        ice_public_ips.size(),
        admin_token.empty() ? 0 : 1);

    boost::asio::io_context io_context;
    auto registry = std::make_shared<webrtc::stream_registry>();
    auto session_transport_config_result = webrtc::load_session_transport_runtime_config();

    if (!session_transport_config_result)
    {
        WEBRTC_LOG_ERROR("load session transport runtime config failed: {}", session_transport_config_result.error());

        return 1;
    }

    const webrtc::session_transport_runtime_config session_transport_config = std::move(*session_transport_config_result);

    auto session_udp_port_allocator = std::make_shared<webrtc::udp_port_allocator>(session_transport_config.session_udp_port_range);

    std::vector<webrtc::sdp::sdp_ice_candidate_options> ice_candidates;

    ice_candidates.reserve(ice_public_ips.size());

    for (std::size_t index = 0; index < ice_public_ips.size(); ++index)
    {
        ice_candidates.push_back(make_ice_host_candidate(ice_public_ips[index], session_transport_config.session_udp_port_range.min_port, index));
    }

    for (const auto& candidate : ice_candidates)
    {
        WEBRTC_LOG_INFO("ice host candidate address={} session_port_range={}-{}",
                        candidate.address,
                        session_transport_config.session_udp_port_range.min_port,
                        session_transport_config.session_udp_port_range.max_port);
    }

    auto answer_factory =
        std::make_shared<webrtc::webrtc_answer_factory>(std::move(local_fingerprint), std::move(ice_candidates));
    auto http_router = std::make_shared<webrtc::router>(registry,
                                                        answer_factory,
                                                        session_udp_port_allocator,
                                                        io_context,
                                                        std::move(ice_bind_host),
                                                        *per_session_dtls_context,
                                                        session_transport_config.dtls_ip_mtu,
                                                        std::move(admin_token));

    WEBRTC_LOG_INFO("Webrtc     version {} {}", "SimpleWebrtc", "0.1");

    webrtc::tcp_handler tcp;

    tcp.create_socket = [&io_context]() { return boost::asio::ip::tcp::socket(io_context); };

    tcp.accept_socket = [&ssl_ctx_, http_router](boost::asio::ip::tcp::socket socket) { on_tcp(std::move(socket), ssl_ctx_, http_router); };

    auto http_server = std::make_shared<webrtc::tcp_server>(http_port, "webrtc", io_context, std::move(tcp));

    http_server->run();

    auto shutdown_signals = std::make_shared<boost::asio::signal_set>(io_context, SIGINT, SIGTERM);

    shutdown_signals->async_wait(
        [&io_context, shutdown_signals, http_server](const boost::system::error_code& ec, int signal_number)
        {
            if (ec)
            {
                WEBRTC_LOG_WARN("flag_process_signal_wait_failed error={}", ec.message());
                return;
            }

            WEBRTC_LOG_INFO("flag_process_shutdown_begin signal={}", signal_number);

            http_server->stop();

            shutdown_signals->cancel();

            WEBRTC_LOG_INFO("flag_process_shutdown_end signal={}", signal_number);

            io_context.stop();
        });

    io_context.run();

    WEBRTC_LOG_INFO("flag_process_exit");

    return 0;
}
