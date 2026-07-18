#ifndef SIMPLE_WEBRTC_DTLS_DTLS_CERTIFICATE_H
#define SIMPLE_WEBRTC_DTLS_DTLS_CERTIFICATE_H

#include <expected>
#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
struct dtls_certificate
{
    std::shared_ptr<X509> certificate;
    std::shared_ptr<EVP_PKEY> private_key;
    sdp::fingerprint_info fingerprint;
};

using dtls_certificate_result = std::expected<std::shared_ptr<dtls_certificate>, std::string>;

[[nodiscard]] dtls_certificate_result get_process_dtls_certificate();
}    // namespace webrtc

#endif
