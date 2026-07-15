#ifndef SIMPLE_WEBRTC_DTLS_DTLS_PACKET_H
#define SIMPLE_WEBRTC_DTLS_DTLS_PACKET_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace webrtc
{
inline constexpr std::size_t k_dtls_record_header_size = 13;

enum class dtls_record_content_type
{
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    unknown = 0,
};

enum class dtls_handshake_type
{
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    unknown = 255,
};

struct dtls_record_header
{
    dtls_record_content_type content_type = dtls_record_content_type::unknown;

    uint16_t version = 0;
    uint16_t epoch = 0;
    std::array<uint8_t, 6> sequence_number{};
    uint16_t length = 0;
    std::size_t record_size = 0;
};

using dtls_record_header_result = std::expected<dtls_record_header, std::string>;

[[nodiscard]] bool is_dtls_packet(std::span<const uint8_t> data);

[[nodiscard]] dtls_record_header_result parse_dtls_record_header(std::span<const uint8_t> data);

[[nodiscard]] dtls_handshake_type get_dtls_handshake_type(std::span<const uint8_t> data);

[[nodiscard]] std::string dtls_record_content_type_to_string(dtls_record_content_type value);

[[nodiscard]] std::string dtls_handshake_type_to_string(dtls_handshake_type value);

[[nodiscard]] std::string dtls_version_to_string(uint16_t version);
}    // namespace webrtc

#endif
