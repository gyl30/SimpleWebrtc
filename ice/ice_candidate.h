#ifndef SIMPLE_WEBRTC_ICE_ICE_CANDIDATE_H
#define SIMPLE_WEBRTC_ICE_ICE_CANDIDATE_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc
{
enum class ice_candidate_transport
{
    unknown,
    udp,
    tcp,
};

enum class ice_candidate_type
{
    unknown,
    host,
    server_reflexive,
    peer_reflexive,
    relay,
};

enum class ice_tcp_candidate_type
{
    none,
    active,
    passive,
    simultaneous_open,
};

struct ice_candidate_extension
{
    std::string name;
    std::string value;
};

struct remote_ice_candidate
{
    std::string candidate;
    std::string sdp_mid;

    int sdp_mline_index = -1;

    std::string foundation;
    uint32_t component = 0;

    ice_candidate_transport transport = ice_candidate_transport::unknown;

    uint32_t priority = 0;

    std::string address;
    uint16_t port = 0;
    bool address_is_hostname = false;
    bool address_is_mdns_hostname = false;

    ice_candidate_type type = ice_candidate_type::unknown;

    std::string related_address;
    uint16_t related_port = 0;

    ice_tcp_candidate_type tcp_type = ice_tcp_candidate_type::none;

    uint32_t generation = 0;
    uint32_t network_id = 0;
    uint32_t network_cost = 0;

    bool has_generation = false;
    bool has_network_id = false;
    bool has_network_cost = false;

    std::vector<ice_candidate_extension> extensions;

    uint64_t received_at_milliseconds = 0;

    bool end_of_candidates = false;
};

using remote_ice_candidate_result = std::expected<remote_ice_candidate, std::string>;

[[nodiscard]] remote_ice_candidate_result make_remote_ice_candidate(std::string_view candidate,
                                                                    std::string_view sdp_mid,
                                                                    int sdp_mline_index,
                                                                    uint64_t received_at_milliseconds);

[[nodiscard]] std::string_view ice_candidate_transport_to_string(ice_candidate_transport transport);

[[nodiscard]] std::string_view ice_candidate_type_to_string(ice_candidate_type type);

[[nodiscard]] std::string_view ice_tcp_candidate_type_to_string(ice_tcp_candidate_type type);
}    // namespace webrtc

#endif
