#include "security/certificate_fingerprint.h"

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
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
    for (const char character : value)
    {
        if (character == '\0')
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

std::string to_lower_ascii(std::string_view value)
{
    std::string result;

    result.reserve(value.size());

    for (const char character : value)
    {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }

    return result;
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

std::expected<const EVP_MD*, std::string> find_digest_algorithm(std::string_view algorithm)
{
    const std::string normalized_algorithm = to_lower_ascii(algorithm);

    if (normalized_algorithm == "sha-256")
    {
        return EVP_sha256();
    }

    if (normalized_algorithm == "sha-384")
    {
        return EVP_sha384();
    }

    if (normalized_algorithm == "sha-512")
    {
        return EVP_sha512();
    }

    std::string message = "certificate fingerprint algorithm is unsupported: ";

    message.append(algorithm);

    return std::unexpected(std::move(message));
}

std::expected<std::size_t, std::string> get_digest_size(std::string_view algorithm)
{
    const std::string normalized_algorithm = to_lower_ascii(algorithm);

    if (normalized_algorithm == "sha-256")
    {
        return 32;
    }

    if (normalized_algorithm == "sha-384")
    {
        return 48;
    }

    if (normalized_algorithm == "sha-512")
    {
        return 64;
    }

    std::string message = "certificate fingerprint algorithm is unsupported: ";

    message.append(algorithm);

    return std::unexpected(std::move(message));
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

    for (unsigned int index = 0; index < digest_size; ++index)
    {
        if (index != 0)
        {
            value.push_back(':');
        }

        const auto byte = static_cast<unsigned int>(digest[index]);

        value.push_back(k_hex_digits[(byte >> 4U) & 0x0FU]);

        value.push_back(k_hex_digits[byte & 0x0FU]);
    }

    return value;
}

int hex_digit_value(char character)
{
    if (character >= '0' && character <= '9')
    {
        return character - '0';
    }

    if (character >= 'a' && character <= 'f')
    {
        return 10 + character - 'a';
    }

    if (character >= 'A' && character <= 'F')
    {
        return 10 + character - 'A';
    }

    return -1;
}

std::expected<std::vector<unsigned char>, std::string> parse_fingerprint_value(std::string_view value, std::size_t digest_size)
{
    if (digest_size == 0)
    {
        return make_error("certificate fingerprint digest size is zero");
    }

    const std::size_t expected_value_size = digest_size * 3 - 1;

    if (value.size() != expected_value_size)
    {
        return make_error("certificate fingerprint value length is invalid");
    }

    std::vector<unsigned char> digest;

    digest.reserve(digest_size);

    for (std::size_t byte_index = 0; byte_index < digest_size; ++byte_index)
    {
        const std::size_t character_index = byte_index * 3;

        const int high = hex_digit_value(value[character_index]);

        const int low = hex_digit_value(value[character_index + 1]);

        if (high < 0 || low < 0)
        {
            return make_error("certificate fingerprint contains invalid hexadecimal byte");
        }

        const auto byte = static_cast<unsigned char>((high << 4) | low);

        digest.push_back(byte);

        if (byte_index + 1 < digest_size)
        {
            if (value[character_index + 2] != ':')
            {
                return make_error("certificate fingerprint must use colon separators");
            }
        }
    }

    return digest;
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

    return calculate_certificate_fingerprint(certificate.get(), "sha-256");
}

certificate_fingerprint_result calculate_certificate_fingerprint(X509* certificate, std::string_view algorithm)
{
    if (certificate == nullptr)
    {
        return make_error("certificate is null");
    }

    if (algorithm.empty())
    {
        return make_error("certificate fingerprint algorithm is empty");
    }

    auto digest_algorithm = find_digest_algorithm(algorithm);

    if (!digest_algorithm)
    {
        return std::unexpected(digest_algorithm.error());
    }

    auto expected_digest_size = get_digest_size(algorithm);

    if (!expected_digest_size)
    {
        return std::unexpected(expected_digest_size.error());
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};

    unsigned int digest_size = 0;

    const int result = X509_digest(certificate, *digest_algorithm, digest.data(), &digest_size);

    if (result != 1)
    {
        return make_error(make_openssl_error("calculate certificate fingerprint failed"));
    }

    if (static_cast<std::size_t>(digest_size) != *expected_digest_size)
    {
        return make_error("certificate fingerprint digest size is invalid");
    }

    auto value = format_fingerprint_value(digest.data(), digest_size);

    if (!value)
    {
        return std::unexpected(value.error());
    }

    sdp::fingerprint_info fingerprint;

    fingerprint.algorithm = to_lower_ascii(algorithm);

    fingerprint.value = std::move(*value);

    return fingerprint;
}

certificate_fingerprint_result verify_certificate_fingerprint(X509* certificate, const sdp::fingerprint_info& expected_fingerprint)
{
    if (certificate == nullptr)
    {
        return make_error("remote dtls certificate is null");
    }

    if (expected_fingerprint.algorithm.empty())
    {
        return make_error("expected remote dtls fingerprint algorithm is empty");
    }

    if (expected_fingerprint.value.empty())
    {
        return make_error("expected remote dtls fingerprint value is empty");
    }

    auto digest_size = get_digest_size(expected_fingerprint.algorithm);

    if (!digest_size)
    {
        return std::unexpected(digest_size.error());
    }

    auto actual_fingerprint = calculate_certificate_fingerprint(certificate, expected_fingerprint.algorithm);

    if (!actual_fingerprint)
    {
        return std::unexpected(actual_fingerprint.error());
    }

    auto expected_digest = parse_fingerprint_value(expected_fingerprint.value, *digest_size);

    if (!expected_digest)
    {
        return std::unexpected(expected_digest.error());
    }

    auto actual_digest = parse_fingerprint_value(actual_fingerprint->value, *digest_size);

    if (!actual_digest)
    {
        return std::unexpected(actual_digest.error());
    }

    if (expected_digest->size() != actual_digest->size())
    {
        return make_error("remote dtls certificate fingerprint size mismatch");
    }

    const int compare_result = CRYPTO_memcmp(expected_digest->data(), actual_digest->data(), expected_digest->size());

    if (compare_result != 0)
    {
        std::string message = "remote dtls certificate fingerprint mismatch expected=";

        message.append(expected_fingerprint.value);

        message.append(" actual=");

        message.append(actual_fingerprint->value);

        return std::unexpected(std::move(message));
    }

    return *actual_fingerprint;
}
}    // namespace webrtc
