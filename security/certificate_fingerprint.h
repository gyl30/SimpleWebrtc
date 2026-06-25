#ifndef SIMPLE_WEBRTC_SECURITY_CERTIFICATE_FINGERPRINT_H
#define SIMPLE_WEBRTC_SECURITY_CERTIFICATE_FINGERPRINT_H

#include <expected>
#include <string>
#include <string_view>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
using certificate_fingerprint_result = std::expected<sdp::fingerprint_info, std::string>;

[[nodiscard]] certificate_fingerprint_result load_certificate_fingerprint(std::string_view certificate_file);
}    // namespace webrtc

#endif
