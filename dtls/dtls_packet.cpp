#include "dtls/dtls_packet.h"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

bool is_dtls_content_type_byte(uint8_t value) { return value >= 20U && value <= 63U; }

bool is_known_dtls_content_type(uint8_t value) { return value == 20U || value == 21U || value == 22U || value == 23U; }

bool is_dtls_version(uint16_t version) { return (version & 0xFF00U) == 0xFE00U; }

dtls_record_content_type make_content_type(uint8_t value)
{
    switch (value)
    {
        case 20:
            return dtls_record_content_type::change_cipher_spec;

        case 21:
            return dtls_record_content_type::alert;

        case 22:
            return dtls_record_content_type::handshake;

        case 23:
            return dtls_record_content_type::application_data;

        default:
            return dtls_record_content_type::unknown;
    }
}

dtls_handshake_type make_handshake_type(uint8_t value)
{
    switch (value)
    {
        case 0:
            return dtls_handshake_type::hello_request;

        case 1:
            return dtls_handshake_type::client_hello;

        case 2:
            return dtls_handshake_type::server_hello;

        case 3:
            return dtls_handshake_type::hello_verify_request;

        case 11:
            return dtls_handshake_type::certificate;

        case 12:
            return dtls_handshake_type::server_key_exchange;

        case 13:
            return dtls_handshake_type::certificate_request;

        case 14:
            return dtls_handshake_type::server_hello_done;

        case 15:
            return dtls_handshake_type::certificate_verify;

        case 16:
            return dtls_handshake_type::client_key_exchange;

        case 20:
            return dtls_handshake_type::finished;

        default:
            return dtls_handshake_type::unknown;
    }
}
}    // namespace

bool is_dtls_packet(std::span<const uint8_t> data)
{
    if (data.size() < k_dtls_record_header_size)
    {
        return false;
    }

    if (!is_dtls_content_type_byte(data[0]))
    {
        return false;
    }

    const uint16_t version = read_u16(data, 1);

    if (!is_dtls_version(version))
    {
        return false;
    }

    const uint16_t length = read_u16(data, 11);

    const std::size_t record_size = k_dtls_record_header_size + static_cast<std::size_t>(length);

    if (record_size > data.size())
    {
        return false;
    }

    return true;
}

dtls_record_header_result parse_dtls_record_header(std::span<const uint8_t> data)
{
    if (data.size() < k_dtls_record_header_size)
    {
        return make_error("dtls packet is shorter than record header");
    }

    if (!is_dtls_content_type_byte(data[0]))
    {
        return make_error("dtls content type byte is invalid");
    }

    if (!is_known_dtls_content_type(data[0]))
    {
        return make_error("dtls content type is unsupported");
    }

    const uint16_t version = read_u16(data, 1);

    if (!is_dtls_version(version))
    {
        return make_error("dtls version is invalid");
    }

    const uint16_t length = read_u16(data, 11);

    const std::size_t record_size = k_dtls_record_header_size + static_cast<std::size_t>(length);

    if (record_size > data.size())
    {
        return make_error("dtls record is truncated");
    }

    dtls_record_header header;
    header.content_type = make_content_type(data[0]);
    header.version = version;
    header.epoch = read_u16(data, 3);

    header.length = length;
    header.record_size = record_size;

    return header;
}

dtls_handshake_type get_dtls_handshake_type(std::span<const uint8_t> data, const dtls_record_header& header)
{
    if (header.content_type != dtls_record_content_type::handshake || header.length == 0 || data.size() <= k_dtls_record_header_size)
    {
        return dtls_handshake_type::unknown;
    }

    return make_handshake_type(data[k_dtls_record_header_size]);
}

std::string dtls_record_content_type_to_string(dtls_record_content_type value)
{
    switch (value)
    {
        case dtls_record_content_type::change_cipher_spec:
            return "change_cipher_spec";

        case dtls_record_content_type::alert:
            return "alert";

        case dtls_record_content_type::handshake:
            return "handshake";

        case dtls_record_content_type::application_data:
            return "application_data";

        case dtls_record_content_type::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string dtls_handshake_type_to_string(dtls_handshake_type value)
{
    switch (value)
    {
        case dtls_handshake_type::hello_request:
            return "hello_request";

        case dtls_handshake_type::client_hello:
            return "client_hello";

        case dtls_handshake_type::server_hello:
            return "server_hello";

        case dtls_handshake_type::hello_verify_request:
            return "hello_verify_request";

        case dtls_handshake_type::certificate:
            return "certificate";

        case dtls_handshake_type::server_key_exchange:
            return "server_key_exchange";

        case dtls_handshake_type::certificate_request:
            return "certificate_request";

        case dtls_handshake_type::server_hello_done:
            return "server_hello_done";

        case dtls_handshake_type::certificate_verify:
            return "certificate_verify";

        case dtls_handshake_type::client_key_exchange:
            return "client_key_exchange";

        case dtls_handshake_type::finished:
            return "finished";

        case dtls_handshake_type::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string dtls_version_to_string(uint16_t version)
{
    switch (version)
    {
        case 0xFEFFU:
            return "dtls1.0";

        case 0xFEFDU:
            return "dtls1.2";

        case 0xFEFCU:
            return "dtls1.3";

        default:
            return "unknown";
    }
}
}    // namespace webrtc
