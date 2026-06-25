#ifndef SIMPLE_WEBRTC_SRTP_SRTP_SESSION_H
#define SIMPLE_WEBRTC_SRTP_SRTP_SESSION_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

#include <srtp2/srtp.h>

#include "dtls/dtls_srtp_keying_material.h"

namespace webrtc
{
enum class srtp_direction
{
    inbound,
    outbound,
};

struct srtp_session_config
{
    srtp_direction direction = srtp_direction::inbound;
    srtp_profile_id profile = srtp_profile_id::unknown;

    std::array<uint8_t, k_srtp_aes128_master_key_size> master_key{};
    std::array<uint8_t, k_srtp_aes128_master_salt_size> master_salt{};
};

using srtp_packet_result = std::expected<std::size_t, std::string>;

class srtp_session
{
   public:
    srtp_session() = default;
    ~srtp_session();

    srtp_session(const srtp_session&) = delete;
    srtp_session& operator=(const srtp_session&) = delete;

    srtp_session(srtp_session&& other) noexcept;
    srtp_session& operator=(srtp_session&& other) noexcept;

   public:
    [[nodiscard]] bool valid() const;

    [[nodiscard]] srtp_packet_result protect_rtp(std::span<uint8_t> buffer, std::size_t packet_size);

    [[nodiscard]] srtp_packet_result unprotect_rtp(std::span<uint8_t> buffer, std::size_t packet_size);

    [[nodiscard]] srtp_packet_result protect_rtcp(std::span<uint8_t> buffer, std::size_t packet_size);

    [[nodiscard]] srtp_packet_result unprotect_rtcp(std::span<uint8_t> buffer, std::size_t packet_size);

   private:
    explicit srtp_session(srtp_t native_handle);

    void reset();

   private:
    friend std::expected<srtp_session, std::string> make_srtp_session(const srtp_session_config& config);

   private:
    srtp_t native_handle_ = nullptr;
};

using srtp_session_result = std::expected<srtp_session, std::string>;

[[nodiscard]] srtp_session_result make_srtp_session(const srtp_session_config& config);

[[nodiscard]] srtp_session_config make_inbound_srtp_session_config(const srtp_keying_material& material);

[[nodiscard]] srtp_session_config make_outbound_srtp_session_config(const srtp_keying_material& material);

[[nodiscard]] std::string srtp_direction_to_string(srtp_direction direction);

[[nodiscard]] std::string srtp_error_to_string(srtp_err_status_t status);
}    // namespace webrtc

#endif
