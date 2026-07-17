#include "dtls/dtls_srtp_keying_material.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace webrtc
{
namespace
{
inline constexpr std::string_view k_dtls_srtp_exporter_label = "EXTRACTOR-dtls_srtp";

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::string make_openssl_error(std::string_view prefix)
{
    unsigned long error_code = ERR_get_error();

    if (error_code == 0)
    {
        return std::string(prefix);
    }

    char buffer[256]{};

    ERR_error_string_n(error_code, buffer, sizeof(buffer));

    std::string message(prefix);
    message.append(": ");
    message.append(buffer);

    return message;
}

srtp_profile_id profile_id_from_name(std::string_view name)
{
    if (name == "SRTP_AES128_CM_SHA1_80")
    {
        return srtp_profile_id::aes128_cm_sha1_80;
    }

    if (name == "SRTP_AES128_CM_SHA1_32")
    {
        return srtp_profile_id::aes128_cm_sha1_32;
    }

    return srtp_profile_id::unknown;
}

std::string selected_srtp_profile_name(SSL* ssl)
{
    if (ssl == nullptr)
    {
        return {};
    }

    const SRTP_PROTECTION_PROFILE* profile = SSL_get_selected_srtp_profile(ssl);

    if (profile == nullptr || profile->name == nullptr)
    {
        return {};
    }

    return profile->name;
}
}    // namespace

srtp_keying_material_result export_srtp_keying_material(SSL* ssl)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    if (SSL_is_init_finished(ssl) != 1)
    {
        return make_error("dtls handshake is not complete");
    }

    const std::string profile_name = selected_srtp_profile_name(ssl);

    if (profile_name.empty())
    {
        return make_error("dtls selected srtp profile is empty");
    }

    const srtp_profile_id profile = profile_id_from_name(profile_name);

    if (profile == srtp_profile_id::unknown)
    {
        std::string message = "dtls selected srtp profile is unsupported: ";

        message.append(profile_name);

        return std::unexpected(std::move(message));
    }

    std::array<uint8_t, k_srtp_aes128_exporter_size> exporter{};

    const int export_result = SSL_export_keying_material(
        ssl, exporter.data(), exporter.size(), k_dtls_srtp_exporter_label.data(), k_dtls_srtp_exporter_label.size(), nullptr, 0, 0);

    if (export_result != 1)
    {
        return std::unexpected(make_openssl_error("dtls export srtp keying material failed"));
    }

    srtp_keying_material material;
    material.profile = profile;

    std::size_t offset = 0;

    std::copy_n(
        exporter.begin() + static_cast<std::ptrdiff_t>(offset), material.client_write_master_key.size(), material.client_write_master_key.begin());

    offset += material.client_write_master_key.size();

    std::copy_n(
        exporter.begin() + static_cast<std::ptrdiff_t>(offset), material.server_write_master_key.size(), material.server_write_master_key.begin());

    offset += material.server_write_master_key.size();

    std::copy_n(
        exporter.begin() + static_cast<std::ptrdiff_t>(offset), material.client_write_master_salt.size(), material.client_write_master_salt.begin());

    offset += material.client_write_master_salt.size();

    std::copy_n(
        exporter.begin() + static_cast<std::ptrdiff_t>(offset), material.server_write_master_salt.size(), material.server_write_master_salt.begin());

    return material;
}

std::string srtp_profile_id_to_string(srtp_profile_id profile)
{
    switch (profile)
    {
        case srtp_profile_id::aes128_cm_sha1_80:
            return "SRTP_AES128_CM_SHA1_80";

        case srtp_profile_id::aes128_cm_sha1_32:
            return "SRTP_AES128_CM_SHA1_32";

        case srtp_profile_id::unknown:
            return "unknown";
    }

    return "unknown";
}
}    // namespace webrtc
