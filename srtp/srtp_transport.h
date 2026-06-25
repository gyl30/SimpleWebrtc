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

    std::size_t packet_size = 0;
    std::size_t unprotected_size = 0;
    std::size_t protected_size = 0;

    uint32_t ssrc = 0;
    uint8_t payload_type = 0;

    bool marker = false;
    uint16_t sequence_number = 0;
    uint32_t timestamp = 0;

    uint8_t rtcp_count = 0;
    uint16_t rtcp_length = 0;
    std::string packet_type_name;

    std::size_t rtcp_block_count = 0;
    std::size_t rtcp_feedback_block_count = 0;

    bool rtcp_is_feedback = false;
    uint8_t rtcp_feedback_format = 0;
    std::string rtcp_feedback_name;
    uint32_t rtcp_sender_ssrc = 0;
    uint32_t rtcp_media_ssrc = 0;
    std::size_t rtcp_nack_count = 0;
    std::size_t rtcp_fir_count = 0;
    bool rtcp_has_generic_nack = false;
    bool rtcp_has_keyframe_request = false;
    bool rtcp_has_transport_cc = false;
    bool rtcp_has_remb = false;
    uint64_t rtcp_remb_bitrate_bps = 0;

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
    [[nodiscard]] srtp_transport_result handle_inbound_packet(std::span<const uint8_t> data, std::string_view remote_endpoint);

    [[nodiscard]] srtp_transport_result protect_outbound_packet(std::span<const uint8_t> plain_packet,
                                                                std::string_view remote_endpoint,
                                                                srtp_packet_kind kind);

    void forget_peer(std::string_view remote_endpoint);

    [[nodiscard]] std::size_t peer_count() const;

   private:
    struct impl;

   private:
    std::unique_ptr<impl> impl_;
};

[[nodiscard]] std::string srtp_packet_kind_to_string(srtp_packet_kind kind);

[[nodiscard]] std::string srtp_packet_process_state_to_string(srtp_packet_process_state state);
}    // namespace webrtc

#endif
