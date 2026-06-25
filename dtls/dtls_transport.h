#ifndef SIMPLE_WEBRTC_DTLS_DTLS_TRANSPORT_H
#define SIMPLE_WEBRTC_DTLS_DTLS_TRANSPORT_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

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
};

class dtls_transport
{
   public:
    dtls_transport() = default;
    ~dtls_transport() = default;

    dtls_transport(const dtls_transport&) = delete;
    dtls_transport& operator=(const dtls_transport&) = delete;

    dtls_transport(dtls_transport&&) = delete;
    dtls_transport& operator=(dtls_transport&&) = delete;

   public:
    void remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity);

    void forget_peer(std::string_view remote_endpoint);

    void handle_udp_packet(std::span<const uint8_t> data, std::string_view remote_endpoint);

    [[nodiscard]] std::size_t peer_count() const;

   private:
    struct dtls_peer_context
    {
        dtls_peer_identity identity;

        uint64_t packet_count = 0;
        uint64_t byte_count = 0;

        bool saw_client_hello = false;
        bool saw_dtls_packet = false;
    };

   private:
    [[nodiscard]] dtls_peer_context* find_peer_locked(std::string_view remote_endpoint);

    void handle_known_peer_packet_locked(dtls_peer_context& context, std::span<const uint8_t> data, std::string_view remote_endpoint);

   private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, dtls_peer_context> peers_by_endpoint_;
};

[[nodiscard]] std::string dtls_peer_role_to_string(dtls_peer_role role);
}    // namespace webrtc

#endif
