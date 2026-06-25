#include <openssl/opensslv.h>
#include <rapidjson/document.h>

#include "log/log.h"

#include "net/http.h"
#include "net/socket.h"
#include "net/detect_ssl_session.h"

#include "util/file.h"
#include "util/random.h"
#include "util/reflect.h"
#include "util/scoped_exit.h"

#include "net/tcp_server.h"

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
static bool load_server_certificate(boost::asio::ssl::context& ctx, const std::string& cert_file, const std::string& key_file)
{
    boost::system::error_code ec;

    ec = ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3 |
                             boost::asio::ssl::context::no_tlsv1 | boost::asio::ssl::context::no_tlsv1_1 | boost::asio::ssl::context::single_dh_use,
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
static webrtc::http_response_ptr on_http(webrtc::http_request_t& request)
{
    std::string target = request.req.target();
    auto now = webrtc::timestamp::now().milliseconds();
    auto response = webrtc::create_response(request, 200, "SimpleWebrtc HTTPS OK\n");
    response->set(boost::beast::http::field::content_type, "text/plain; charset=utf-8");
    auto diff = webrtc::timestamp::now().milliseconds() - now;
    WEBRTC_LOG_DEBUG("http request {} cost {} ms", target, diff);
    return response;
}
static void on_tcp(boost::asio::ip::tcp::socket socket, boost::asio::ssl::context& ssl_ctx)
{
    auto local_addr = webrtc::get_socket_local_address(socket);
    auto remote_addr = webrtc::get_socket_remote_address(socket);

    const std::string id = webrtc::random_string(8);
    WEBRTC_LOG_INFO("tcp accept {} <-> {} id {}", local_addr, remote_addr, id);
    webrtc::http_handler http;
    http.http = [](webrtc::http_request_t& req) -> webrtc::http_response_ptr { return on_http(req); };
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
    boost::asio::ssl::context server_ssl_ctx_{boost::asio::ssl::context::tls_server};

    const std::string cert_file = get_env_or_default("WEBRTC_CERT_FILE", "webrtc.pem");
    const std::string key_file = get_env_or_default("WEBRTC_KEY_FILE", "webrtc.key");

    if (!load_server_certificate(server_ssl_ctx_, cert_file, key_file))
    {
        WEBRTC_LOG_ERROR("load https certificate failed");
        return 1;
    }
    version v;
    static const std::string version_str = R"({"name": "SimpleWebrtc", "version": "0.1"})";
    webrtc::deserialize_struct(v, version_str);
    WEBRTC_LOG_INFO("Webrtc     version {} {}", v.name, v.version);
    boost::asio::io_context io_context;
    webrtc::tcp_handler tcp;
    tcp.create_socket = [&io_context]() { return boost::asio::ip::tcp::socket(io_context); };
    tcp.accept_socket = [&server_ssl_ctx_](boost::asio::ip::tcp::socket socket) { on_tcp(std::move(socket), server_ssl_ctx_); };
    std::make_shared<webrtc::tcp_server>(8811, "webrtc", io_context, std::move(tcp))->run();
    io_context.run();
    return 0;
}
