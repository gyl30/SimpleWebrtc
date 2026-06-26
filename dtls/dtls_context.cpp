#include "dtls/dtls_context.h"

#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::string make_openssl_error(std::string_view prefix)
{
    const unsigned long error_code = ERR_get_error();

    if (error_code == 0)
    {
        return std::string(prefix);
    }

    char buffer[256]{};

    ERR_error_string_n(error_code, buffer, sizeof(buffer));

    std::string message(prefix);

    message.append(": ");
    message.append(buffer);

    return message;
}

std::expected<void, std::string> validate_config(const dtls_context_config& config)
{
    if (config.certificate_file.empty())
    {
        return make_error("dtls certificate file is empty");
    }

    if (config.private_key_file.empty())
    {
        return make_error("dtls private key file is empty");
    }

    if (config.srtp_profiles.empty())
    {
        return make_error("dtls srtp profiles is empty");
    }

    return {};
}

int accept_peer_certificate_for_fingerprint_verification(int preverify_ok, X509_STORE_CTX* store_context)
{
    (void)preverify_ok;
    (void)store_context;

    /*
     * WebRTC peers normally use self-signed certificates.
     * The certificate is authenticated later by comparing its
     * digest with the fingerprint carried in the authenticated SDP.
     */
    return 1;
}
}    // namespace

dtls_context::dtls_context(SSL_CTX* native_handle) : native_handle_(native_handle) {}

dtls_context::~dtls_context()
{
    if (native_handle_ != nullptr)
    {
        SSL_CTX_free(native_handle_);

        native_handle_ = nullptr;
    }
}

SSL_CTX* dtls_context::native_handle() const { return native_handle_; }

dtls_context_result make_dtls_context(const dtls_context_config& config)
{
    auto config_result = validate_config(config);

    if (!config_result)
    {
        return std::unexpected(config_result.error());
    }

    OPENSSL_init_ssl(0, nullptr);

    SSL_CTX* native_context = SSL_CTX_new(DTLS_server_method());

    if (native_context == nullptr)
    {
        return std::unexpected(make_openssl_error("dtls ssl context create failed"));
    }

    std::shared_ptr<dtls_context> context = std::make_shared<dtls_context>(native_context);

    SSL_CTX_set_read_ahead(native_context, 1);

    SSL_CTX_set_verify(native_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, accept_peer_certificate_for_fingerprint_verification);

    SSL_CTX_set_verify_depth(native_context, 4);

    if (SSL_CTX_set_min_proto_version(native_context, DTLS1_2_VERSION) != 1)
    {
        return std::unexpected(make_openssl_error("dtls set min protocol version failed"));
    }

    if (SSL_CTX_use_certificate_chain_file(native_context, config.certificate_file.c_str()) != 1)
    {
        return std::unexpected(make_openssl_error("dtls load certificate failed"));
    }

    if (SSL_CTX_use_PrivateKey_file(native_context, config.private_key_file.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        return std::unexpected(make_openssl_error("dtls load private key failed"));
    }

    if (SSL_CTX_check_private_key(native_context) != 1)
    {
        return std::unexpected(make_openssl_error("dtls private key check failed"));
    }

    if (SSL_CTX_set_tlsext_use_srtp(native_context, config.srtp_profiles.c_str()) != 0)
    {
        return std::unexpected(make_openssl_error("dtls set srtp profiles failed"));
    }

    return context;
}
}    // namespace webrtc
