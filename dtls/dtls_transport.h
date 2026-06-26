#ifndef SIMPLE_WEBRTC_DTLS_DTLS_TRANSPORT_H
#define SIMPLE_WEBRTC_DTLS_DTLS_TRANSPORT_H

#include <cstddef>
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

    sdp::fingerprint_info remote_fingerprint;
};

using dtls_transport_packet_list = std::vector<std::vector<uint8_t>>;

using dtls_transport_packet_result = std::expected<dtls_transport_packet_list, std::string>;

class dtls_transport
{
   public:
    explicit dtls_transport(std::shared_ptr<dtls_context> context);

    ~dtls_transport();

    dtls_transport(const dtls_transport&) = delete;

    dtls_transport& operator=(const dtls_transport&) = delete;

    dtls_transport(dtls_transport&&) = delete;

    dtls_transport& operator=(dtls_transport&&) = delete;

   public:
    void remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity);

    void forget_peer(std::string_view remote_endpoint);

    [[nodiscard]] dtls_transport_packet_result handle_udp_packet(std::span<const uint8_t> data, std::string_view remote_endpoint);

    [[nodiscard]]
    std::optional<srtp_keying_material> get_srtp_keying_material(std::string_view remote_endpoint) const;

    [[nodiscard]] bool is_handshake_done(std::string_view remote_endpoint) const;

    [[nodiscard]] std::size_t peer_count() const;

   private:
    struct impl;

   private:
    std::unique_ptr<impl> impl_;
};

[[nodiscard]] std::string dtls_peer_role_to_string(dtls_peer_role role);
}    // namespace webrtc

#endif
