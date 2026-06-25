#include <cerrno>
#include <cstdlib>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include <boost/asio.hpp>
#include <boost/version.hpp>
#include <openssl/opensslv.h>
#include <spdlog/version.h>

#include "ice/ice_udp_server.h"
#include "log/log.h"
#include "net/detect_ssl_session.h"
#include "net/http.h"
#include "net/socket.h"
#include "net/tcp_server.h"
#include "server/router.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"
#include "util/file.h"
#include "util/random.h"
#include "util/reflect.h"
#include "util/scoped_exit.h"

static std::string get_log_dir(const std::string& app_dir) { return app_dir + "/log"; }

static std::string get_log_fileaname(const std::string& app) { return app + ".log"; }

struct version
{
    std::string name;
    std::string version;
};

REFLECT_STRUCT(version, (name)(version));    // NOLINT

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

static bool load_server_certificate(boost::asio::ssl::context& ctx, const std::string& cert_file, const std::string& key_file)
{
    boost::system::error_code ec;

    ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3 |
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
    (void)argc;

    std::string app_path = webrtc::file_abs_path(argv[0]);
    std::string app_dir = webrtc::file_dir(app_path);
    std::string app_name = webrtc::file_name(app_path);
    std::string log_dir = get_log_dir(app_dir);
    std::string log_name = get_log_fileaname(app_name);
    std::string abs_log_filename = log_dir + "/" + log_name;

    webrtc::init_log(abs_log_filename);
    DEFER(webrtc::shutdown_log());

    WEBRTC_LOG_INFO("OpenSSL    version {}", OPENSSL_VERSION_STR);
    WEBRTC_LOG_INFO("Boost      version {}", BOOST_LIB_VERSION);
    WEBRTC_LOG_INFO("spdlog     version {}.{}.{}", SPDLOG_VER_MAJOR, SPDLOG_VER_MINOR, SPDLOG_VER_PATCH);

    boost::asio::ssl::context ssl_ctx_{boost::asio::ssl::context::tls_server};

    const std::string cert_file = get_env_or_default("WEBRTC_CERT_FILE", "webrtc.pem");

    const std::string key_file = get_env_or_default("WEBRTC_KEY_FILE", "webrtc.key");

    if (!load_server_certificate(ssl_ctx_, cert_file, key_file))
    {
        WEBRTC_LOG_ERROR("load https certificate failed");
        return 1;
    }

    auto answer_factory_config = webrtc::make_webrtc_answer_factory_config_from_certificate(cert_file);

    if (!answer_factory_config)
    {
        WEBRTC_LOG_ERROR("load certificate fingerprint failed: {}", answer_factory_config.error());
        return 1;
    }

    const std::string ice_bind_host = get_env_or_default("WEBRTC_ICE_BIND_HOST", "0.0.0.0");

    const uint16_t ice_port = get_env_uint16_or_default("WEBRTC_ICE_PORT", 8812);

    const std::string ice_public_ip = get_env_or_default("WEBRTC_ICE_PUBLIC_IP", "127.0.0.1");

    boost::asio::io_context io_context;

    auto registry = std::make_shared<webrtc::stream_registry>();

    auto ice_server = std::make_shared<webrtc::ice_udp_server>(io_context, ice_bind_host, ice_port, registry);

    auto ice_start_result = ice_server->start();
    if (!ice_start_result)
    {
        WEBRTC_LOG_ERROR("start ice udp server failed: {}", ice_start_result.error());
        return 1;
    }

    answer_factory_config->media_address = ice_public_ip;
    answer_factory_config->ice_candidate_address = ice_public_ip;
    answer_factory_config->ice_candidate_port = ice_server->local_port();
    answer_factory_config->include_host_candidate = true;
    answer_factory_config->end_of_candidates = true;

    WEBRTC_LOG_INFO(
        "certificate fingerprint {} {}", answer_factory_config->local_fingerprint.algorithm, answer_factory_config->local_fingerprint.value);

    WEBRTC_LOG_INFO("ice host candidate {}:{}", answer_factory_config->ice_candidate_address, answer_factory_config->ice_candidate_port);

    auto answer_factory = std::make_shared<webrtc::webrtc_answer_factory>(std::move(*answer_factory_config));

    auto http_router = std::make_shared<webrtc::router>(registry, answer_factory);

    version v;
    static const std::string version_str = R"({"name": "SimpleWebrtc", "version": "0.1"})";

    webrtc::deserialize_struct(v, version_str);

    WEBRTC_LOG_INFO("Webrtc     version {} {}", v.name, v.version);

    webrtc::tcp_handler tcp;
    tcp.create_socket = [&io_context]() { return boost::asio::ip::tcp::socket(io_context); };

    tcp.accept_socket = [&ssl_ctx_, http_router](boost::asio::ip::tcp::socket socket) { on_tcp(std::move(socket), ssl_ctx_, http_router); };

    std::make_shared<webrtc::tcp_server>(8811, "webrtc", io_context, std::move(tcp))->run();

    io_context.run();

    return 0;
}
