#ifndef SIMPLE_WEBRTC_DTLS_DTLS_CONTEXT_H
#define SIMPLE_WEBRTC_DTLS_DTLS_CONTEXT_H

#include <expected>
#include <memory>
#include <string>

#include <openssl/ssl.h>

#include "dtls/dtls_certificate.h"

namespace webrtc
{

struct dtls_context_config
{
    std::shared_ptr<dtls_certificate> certificate;
    std::string srtp_profiles = "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32";
};
class dtls_context
{
   public:
    explicit dtls_context(SSL_CTX* native_handle);
    ~dtls_context();

    dtls_context(const dtls_context&) = delete;
    dtls_context& operator=(const dtls_context&) = delete;

    dtls_context(dtls_context&&) = delete;
    dtls_context& operator=(dtls_context&&) = delete;

   public:
    [[nodiscard]] SSL_CTX* native_handle() const;

   private:
    SSL_CTX* native_handle_ = nullptr;
};

using dtls_context_result = std::expected<std::shared_ptr<dtls_context>, std::string>;

[[nodiscard]] dtls_context_result make_dtls_context(const dtls_context_config& config);
}    // namespace webrtc

#endif
