#ifndef SIMPLE_WEBRTC_RTP_RTP_HEADER_EXTENSION_H
#define SIMPLE_WEBRTC_RTP_RTP_HEADER_EXTENSION_H

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

namespace webrtc
{
using rtp_header_extension_result = std::expected<std::optional<std::span<const uint8_t>>, std::string>;

[[nodiscard]] rtp_header_extension_result find_rtp_header_extension(std::span<const uint8_t> packet, uint8_t extension_id);
}    // namespace webrtc

#endif
