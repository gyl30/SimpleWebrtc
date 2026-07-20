#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_CODEC_NEGOTIATOR_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_CODEC_NEGOTIATOR_H

#include <expected>
#include <optional>
#include <string>
#include <vector>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc::sdp
{
using codec_negotiation_result = std::expected<std::vector<codec_info>, std::string>;

struct codec_payload_type_mapping
{
    uint16_t publisher_payload_type = 0;
    uint16_t subscriber_payload_type = 0;

    std::optional<uint16_t> publisher_associated_payload_type;
    std::optional<uint16_t> subscriber_associated_payload_type;
};

using codec_payload_type_mapping_result = std::expected<std::vector<codec_payload_type_mapping>, std::string>;

[[nodiscard]] codec_negotiation_result negotiate_codecs(const media_summary& offer_media);

[[nodiscard]]
codec_negotiation_result negotiate_codecs(const media_summary& subscriber_media, const media_summary& publisher_media);

[[nodiscard]]
codec_payload_type_mapping_result negotiate_codec_payload_type_mappings(const media_summary& subscriber_media, const media_summary& publisher_media);
}    // namespace webrtc::sdp

#endif
