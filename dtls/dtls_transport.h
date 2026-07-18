#ifndef SIMPLE_WEBRTC_DTLS_DTLS_TRANSPORT_H
#define SIMPLE_WEBRTC_DTLS_DTLS_TRANSPORT_H

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dtls/dtls_context.h"
#include "dtls/dtls_srtp_keying_material.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
enum class dtls_peer_role
{
    unknown,
    publisher,
    subscriber,
};

struct dtls_peer_identity
{
    dtls_peer_role role = dtls_peer_role::unknown;

    std::string session_id;
    std::string stream_id;

    std::string local_ice_ufrag;
    std::string remote_ice_ufrag;

    std::string generation;

    sdp::dtls_connection_role local_setup = sdp::dtls_connection_role::unknown;
    sdp::dtls_connection_role remote_setup = sdp::dtls_connection_role::unknown;

    sdp::fingerprint_info remote_fingerprint;
};

enum class dtls_network_family
{
    unknown,
    ipv4,
    ipv6,
};

inline constexpr std::uint16_t k_min_dtls_ip_mtu = 576;
inline constexpr std::uint16_t k_max_dtls_ip_mtu = 9000;
inline constexpr std::uint16_t k_default_dtls_ip_mtu = 1200;

inline constexpr std::uint16_t k_ipv4_udp_overhead = 20 + 8;
inline constexpr std::uint16_t k_ipv6_udp_overhead = 40 + 8;

using dtls_transport_packet_list = std::vector<std::vector<uint8_t>>;

using dtls_transport_packet_result = std::expected<dtls_transport_packet_list, std::string>;

class dtls_transport
{
   public:
    explicit dtls_transport(std::shared_ptr<dtls_context> context, std::uint16_t ip_mtu);

    ~dtls_transport();

    dtls_transport(const dtls_transport&) = delete;
    dtls_transport& operator=(const dtls_transport&) = delete;

    dtls_transport(dtls_transport&&) = delete;
    dtls_transport& operator=(dtls_transport&&) = delete;

   public:
    void remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity);

    [[nodiscard]] dtls_transport_packet_result handle_udp_packet(std::span<const uint8_t> data,
                                                                 std::string_view remote_endpoint,
                                                                 dtls_network_family network_family);

    [[nodiscard]]
    std::optional<srtp_keying_material> get_srtp_keying_material(std::string_view remote_endpoint) const;

    [[nodiscard]]
    std::optional<dtls_peer_identity> get_peer_identity(std::string_view remote_endpoint) const;

   private:
    struct impl;

   private:
    std::unique_ptr<impl> impl_;
};

}    // namespace webrtc

#endif
