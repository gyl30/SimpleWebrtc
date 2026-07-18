#ifndef SIMPLE_WEBRTC_SERVER_RUNTIME_OFFER_FILTER_H
#define SIMPLE_WEBRTC_SERVER_RUNTIME_OFFER_FILTER_H

#include <expected>
#include <span>
#include <string>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
[[nodiscard]]
std::expected<sdp::webrtc_offer_summary, std::string> make_runtime_offer_summary(
    const sdp::webrtc_offer_summary& original_offer, std::span<const int> accepted_mline_indexes);
}    // namespace webrtc

#endif
