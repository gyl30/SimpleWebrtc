#include "security/certificate_fingerprint.h"

#include <array>
#include <cstdio>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool contains_null_char(std::string_view value)
{
    for (const auto ch : value)
    {
        if (ch == '\0')
        {
            return true;
        }
    }

    return false;
}

std::string make_openssl_error(std::string_view prefix)
{
    std::string message(prefix);

    const unsigned long error_code = ERR_get_error();
    if (error_code == 0)
    {
        return message;
    }

    std::array<char, 256> buffer{};
    ERR_error_string_n(error_code, buffer.data(), buffer.size());

    message.append(": ");
    message.append(buffer.data());

    return message;
}

std::expected<std::string, std::string> make_certificate_path(std::string_view certificate_file)
{
    if (certificate_file.empty())
    {
        return make_error("certificate file is empty");
    }

    if (contains_null_char(certificate_file))
    {
        return make_error("certificate file contains null character");
    }

    return std::string(certificate_file);
}

std::expected<std::string, std::string> format_fingerprint_value(const unsigned char* digest, unsigned int digest_size)
{
    if (digest == nullptr)
    {
        return make_error("certificate digest is null");
    }

    if (digest_size == 0)
    {
        return make_error("certificate digest is empty");
    }

    constexpr char k_hex_digits[] = "0123456789ABCDEF";

    std::string value;
    value.reserve(static_cast<std::size_t>(digest_size) * 3);

    for (unsigned int i = 0; i < digest_size; ++i)
    {
        if (i != 0)
        {
            value.push_back(':');
        }

        const auto byte = static_cast<unsigned int>(digest[i]);

        value.push_back(k_hex_digits[(byte >> 4U) & 0x0FU]);
        value.push_back(k_hex_digits[byte & 0x0FU]);
    }

    return value;
}
}    // namespace

certificate_fingerprint_result load_certificate_fingerprint(std::string_view certificate_file)
{
    auto path = make_certificate_path(certificate_file);
    if (!path)
    {
        return std::unexpected(path.error());
    }

    using file_ptr = std::unique_ptr<FILE, decltype(&std::fclose)>;
    using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

    file_ptr file(std::fopen(path->c_str(), "rb"), &std::fclose);

    if (file == nullptr)
    {
        std::string message = "open certificate file failed: ";
        message.append(*path);
        return std::unexpected(std::move(message));
    }

    x509_ptr certificate(PEM_read_X509(file.get(), nullptr, nullptr, nullptr), &X509_free);

    if (certificate == nullptr)
    {
        return make_error(make_openssl_error("read x509 certificate failed"));
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;

    const int result = X509_digest(certificate.get(), EVP_sha256(), digest.data(), &digest_size);

    if (result != 1)
    {
        return make_error(make_openssl_error("calculate certificate sha-256 fingerprint failed"));
    }

    auto value = format_fingerprint_value(digest.data(), digest_size);

    if (!value)
    {
        return std::unexpected(value.error());
    }

    sdp::fingerprint_info fingerprint;
    fingerprint.algorithm = "sha-256";
    fingerprint.value = std::move(*value);

    return fingerprint;
}
}    // namespace webrtc
