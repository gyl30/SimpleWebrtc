#ifndef SIMPLE_WEBRTC_SECURITY_CERTIFICATE_FINGERPRINT_H
#define SIMPLE_WEBRTC_SECURITY_CERTIFICATE_FINGERPRINT_H

#include <expected>
#include <string>

#include <openssl/x509.h>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
using certificate_fingerprint_result = std::expected<sdp::fingerprint_info, std::string>;

[[nodiscard]] certificate_fingerprint_result verify_certificate_fingerprint(X509* certificate, const sdp::fingerprint_info& expected_fingerprint);
}    // namespace webrtc

#endif
