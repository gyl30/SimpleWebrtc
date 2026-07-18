#ifndef SIMPLE_WEBRTC_SRTP_SRTP_TRANSPORT_H
#define SIMPLE_WEBRTC_SRTP_SRTP_TRANSPORT_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dtls/dtls_transport.h"

namespace webrtc
{
enum class srtp_packet_kind
{
    unknown,
    rtp,
    rtcp,
};

enum class srtp_packet_process_state
{
    ignored,
    unprotected,
    protected_packet,
};

struct srtp_packet_process_result
{
    srtp_packet_process_state state = srtp_packet_process_state::ignored;

    srtp_packet_kind kind = srtp_packet_kind::unknown;

    uint32_t ssrc = 0;
    uint8_t payload_type = 0;

    uint16_t sequence_number = 0;
    uint32_t timestamp = 0;

    std::vector<uint8_t> plain_packet;
    std::vector<uint8_t> protected_packet;

    std::string reason;
};

using srtp_transport_result = std::expected<srtp_packet_process_result, std::string>;

class srtp_transport
{
   public:
    explicit srtp_transport(std::shared_ptr<dtls_transport> dtls_transport);

    ~srtp_transport();

    srtp_transport(const srtp_transport&) = delete;
    srtp_transport& operator=(const srtp_transport&) = delete;

    srtp_transport(srtp_transport&&) = delete;
    srtp_transport& operator=(srtp_transport&&) = delete;

   public:
    void forget_peer(std::string_view remote_endpoint);

    [[nodiscard]] srtp_transport_result handle_inbound_packet(std::span<const uint8_t> data, std::string_view remote_endpoint);

    [[nodiscard]] srtp_transport_result protect_outbound_packet(std::span<const uint8_t> plain_packet,
                                                                std::string_view remote_endpoint,
                                                                srtp_packet_kind kind);

   private:
    struct impl;

   private:
    std::unique_ptr<impl> impl_;
};

[[nodiscard]] std::string srtp_packet_process_state_to_string(srtp_packet_process_state state);
}    // namespace webrtc

#endif
