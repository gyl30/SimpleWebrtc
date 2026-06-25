#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_CODEC_NEGOTIATOR_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_CODEC_NEGOTIATOR_H

#include <expected>
#include <string>
#include <vector>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc::sdp
{
using codec_negotiation_result = std::expected<std::vector<codec_info>, std::string>;

[[nodiscard]] codec_negotiation_result negotiate_codecs(const media_summary& offer_media);
}    // namespace webrtc::sdp

#endif
