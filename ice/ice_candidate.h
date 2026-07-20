#ifndef SIMPLE_WEBRTC_ICE_ICE_CANDIDATE_H
#define SIMPLE_WEBRTC_ICE_ICE_CANDIDATE_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace webrtc
{
struct remote_ice_candidate
{
    std::string candidate;
    std::string sdp_mid;

    int sdp_mline_index = -1;

    std::string address;
    uint16_t port = 0;
    bool address_is_hostname = false;
    bool address_is_mdns_hostname = false;

    bool end_of_candidates = false;
};

using remote_ice_candidate_result = std::expected<remote_ice_candidate, std::string>;

[[nodiscard]] remote_ice_candidate_result make_remote_ice_candidate(std::string_view candidate, std::string_view sdp_mid, int sdp_mline_index);
}    // namespace webrtc

#endif
