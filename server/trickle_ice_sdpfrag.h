#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_SDPFRAG_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_SDPFRAG_H

#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "ice/ice_candidate.h"

namespace webrtc
{
struct trickle_ice_sdpfrag_parse_result
{
    std::vector<remote_ice_candidate> candidates;
    std::string ice_ufrag;
    std::string ice_pwd;
};

using trickle_ice_sdpfrag_parse_result_type = std::expected<trickle_ice_sdpfrag_parse_result, std::string>;

[[nodiscard]]
trickle_ice_sdpfrag_parse_result_type parse_trickle_ice_sdpfrag(std::string_view body);
}    // namespace webrtc

#endif
