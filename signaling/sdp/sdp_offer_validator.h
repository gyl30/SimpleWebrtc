#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_OFFER_VALIDATOR_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_OFFER_VALIDATOR_H

#include <expected>
#include <string>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc::sdp
{
using offer_validation_result = std::expected<void, std::string>;

[[nodiscard]] offer_validation_result validate_whip_offer(const webrtc_offer_summary& offer);

[[nodiscard]] offer_validation_result validate_whep_offer(const webrtc_offer_summary& offer);
}    // namespace webrtc::sdp

#endif
