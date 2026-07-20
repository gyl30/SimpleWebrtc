#include <cstdio>
#include <memory>
#include <print>
#include <string>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/version.hpp>
#include <openssl/opensslv.h>

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
#include "webrtc_config.h"

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

    auto config_result = webrtc::load_webrtc_config();

    if (!config_result)
    {
        std::println(stderr, "load WebRTC config failed: {}", config_result.error());
        return 1;
    }

    const webrtc::webrtc_config config = std::move(*config_result);

    auto log_init_result = webrtc::init_log(abs_log_filename, config.log);

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

    const bool http_tls_enabled = !config.http_certificate_file.empty();

    if (http_tls_enabled && !load_server_certificate(ssl_ctx_, config.http_certificate_file, config.http_private_key_file))
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

    WEBRTC_LOG_INFO(
        "flag_webrtc_dtls_certificate_generated fingerprint_algorithm={} fingerprint={}", local_fingerprint.algorithm, local_fingerprint.value);

    auto per_session_dtls_context = webrtc::make_dtls_context(*dtls_certificate);

    if (!per_session_dtls_context)
    {
        WEBRTC_LOG_ERROR("create per-session dtls context failed: {}", per_session_dtls_context.error());

        return 1;
    }

    WEBRTC_LOG_INFO(
        "flag_startup_config_summary app_path={} log_file={} http_tls_enabled={} http_cert_file={} http_key_file={} http_port={} "
        "session_ice_bind_host={} ice_public_ip_count={} ice_server_configured={} admin_token_configured={}",
        app_path,
        abs_log_filename,
        http_tls_enabled ? 1 : 0,
        config.http_certificate_file,
        config.http_private_key_file,
        config.http_port,
        config.ice_bind_host,
        config.ice_public_ips.size(),
        config.ice_server_link_header.empty() ? 0 : 1,
        config.admin_token.empty() ? 0 : 1);

    boost::asio::io_context io_context;
    auto registry = std::make_shared<webrtc::stream_registry>();

    WEBRTC_LOG_INFO(
        "session transport runtime config loaded dtls_ip_mtu={} ipv4_udp_payload_mtu={} ipv6_udp_payload_mtu={} "
        "session_udp_port_min={} session_udp_port_max={} inactivity_timeout_seconds={} publisher_recovery_timeout_seconds={}",
        config.dtls_ip_mtu,
        config.dtls_ip_mtu - webrtc::k_ipv4_udp_overhead,
        config.dtls_ip_mtu - webrtc::k_ipv6_udp_overhead,
        config.session_udp_port_range.min_port,
        config.session_udp_port_range.max_port,
        config.session_inactivity_timeout_seconds,
        config.publisher_recovery_timeout_seconds);

    auto session_udp_port_allocator = std::make_shared<webrtc::udp_port_allocator>(config.session_udp_port_range);

    for (const auto& address : config.ice_public_ips)
    {
        WEBRTC_LOG_INFO("ice host candidate address={} session_port_range={}-{}",
                        address,
                        config.session_udp_port_range.min_port,
                        config.session_udp_port_range.max_port);
    }

    auto answer_factory = std::make_shared<webrtc::webrtc_answer_factory>(std::move(local_fingerprint), config.ice_public_ips);
    auto http_router =
        std::make_shared<webrtc::router>(registry, answer_factory, session_udp_port_allocator, io_context, config, *per_session_dtls_context);

    WEBRTC_LOG_INFO("Webrtc     version {} {}", "SimpleWebrtc", "0.1");

    webrtc::tcp_handler tcp;

    tcp.create_socket = [&io_context]() { return boost::asio::ip::tcp::socket(io_context); };

    tcp.accept_socket = [&ssl_ctx_, http_router](boost::asio::ip::tcp::socket socket) { on_tcp(std::move(socket), ssl_ctx_, http_router); };

    auto http_server = std::make_shared<webrtc::tcp_server>(config.http_port, "webrtc", io_context, std::move(tcp));

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
