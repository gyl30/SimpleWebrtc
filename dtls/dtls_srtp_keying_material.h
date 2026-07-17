#ifndef SIMPLE_WEBRTC_DTLS_DTLS_SRTP_KEYING_MATERIAL_H
#define SIMPLE_WEBRTC_DTLS_DTLS_SRTP_KEYING_MATERIAL_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>

#include <openssl/ssl.h>

namespace webrtc
{
inline constexpr std::size_t k_srtp_aes128_master_key_size = 16;
inline constexpr std::size_t k_srtp_aes128_master_salt_size = 14;
inline constexpr std::size_t k_srtp_aes128_exporter_size = 2 * (k_srtp_aes128_master_key_size + k_srtp_aes128_master_salt_size);

enum class srtp_profile_id
{
    unknown,
    aes128_cm_sha1_80,
    aes128_cm_sha1_32,
};

struct srtp_keying_material
{
    srtp_profile_id profile = srtp_profile_id::unknown;
    std::array<uint8_t, k_srtp_aes128_master_key_size> client_write_master_key{};

    std::array<uint8_t, k_srtp_aes128_master_key_size> server_write_master_key{};

    std::array<uint8_t, k_srtp_aes128_master_salt_size> client_write_master_salt{};

    std::array<uint8_t, k_srtp_aes128_master_salt_size> server_write_master_salt{};
};

using srtp_keying_material_result = std::expected<srtp_keying_material, std::string>;

[[nodiscard]] srtp_keying_material_result export_srtp_keying_material(SSL* ssl);

[[nodiscard]] std::string srtp_profile_id_to_string(srtp_profile_id profile);
}    // namespace webrtc

#endif
