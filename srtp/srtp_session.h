#ifndef SIMPLE_WEBRTC_SRTP_SRTP_SESSION_H
#define SIMPLE_WEBRTC_SRTP_SRTP_SESSION_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include <srtp2/srtp.h>

#include "dtls/dtls_srtp_keying_material.h"

namespace webrtc
{
enum class srtp_direction
{
    inbound,
    outbound,
};

using srtp_packet_result = std::expected<std::size_t, std::string>;

class srtp_session
{
   public:
    ~srtp_session();

    srtp_session(const srtp_session&) = delete;
    srtp_session& operator=(const srtp_session&) = delete;

    srtp_session(srtp_session&& other) noexcept;
    srtp_session& operator=(srtp_session&& other) noexcept;

   public:
    [[nodiscard]] srtp_packet_result protect_rtp(std::span<uint8_t> buffer, std::size_t packet_size);

    [[nodiscard]] srtp_packet_result unprotect_rtp(std::span<uint8_t> buffer, std::size_t packet_size);

    [[nodiscard]] srtp_packet_result protect_rtcp(std::span<uint8_t> buffer, std::size_t packet_size);

    [[nodiscard]] srtp_packet_result unprotect_rtcp(std::span<uint8_t> buffer, std::size_t packet_size);

   private:
    explicit srtp_session(srtp_t native_handle);

    void reset();

   private:
    friend std::expected<srtp_session, std::string> make_inbound_srtp_session(const srtp_keying_material& material);
    friend std::expected<srtp_session, std::string> make_outbound_srtp_session(const srtp_keying_material& material);

   private:
    srtp_t native_handle_ = nullptr;
};

using srtp_session_result = std::expected<srtp_session, std::string>;

[[nodiscard]] srtp_session_result make_inbound_srtp_session(const srtp_keying_material& material);

[[nodiscard]] srtp_session_result make_outbound_srtp_session(const srtp_keying_material& material);

[[nodiscard]] std::string srtp_direction_to_string(srtp_direction direction);

[[nodiscard]] bool is_srtp_replay_error(std::string_view error);
}    // namespace webrtc

#endif
