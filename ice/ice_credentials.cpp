#include "ice/ice_credentials.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include <openssl/err.h>
#include <openssl/rand.h>

namespace webrtc
{
namespace
{
constexpr std::size_t k_ice_ufrag_length = 16;
constexpr std::size_t k_ice_pwd_length = 32;

constexpr std::string_view k_ice_credential_alphabet =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789";

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

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

std::expected<void, std::string> append_random_credential_char(std::string& value)
{
    constexpr auto alphabet_size = static_cast<unsigned int>(k_ice_credential_alphabet.size());

    constexpr unsigned int k_byte_value_count = 256U;
    constexpr unsigned int k_rejection_threshold = k_byte_value_count - (k_byte_value_count % alphabet_size);

    while (true)
    {
        unsigned char random_byte = 0;

        const int result = RAND_bytes(&random_byte, 1);

        if (result != 1)
        {
            return make_error(make_openssl_error("generate secure random bytes failed"));
        }

        const auto random_value = static_cast<unsigned int>(random_byte);

        if (random_value >= k_rejection_threshold)
        {
            continue;
        }

        const auto index = static_cast<std::size_t>(random_value % alphabet_size);

        value.push_back(k_ice_credential_alphabet[index]);
        return {};
    }
}

std::expected<std::string, std::string> generate_random_text(std::size_t length)
{
    if (length == 0)
    {
        return make_error("random text length is zero");
    }

    std::string value;
    value.reserve(length);

    while (value.size() < length)
    {
        auto result = append_random_credential_char(value);
        if (!result)
        {
            return std::unexpected(result.error());
        }
    }

    return value;
}
}    // namespace

ice_credentials_result generate_ice_credentials()
{
    auto ufrag = generate_random_text(k_ice_ufrag_length);
    if (!ufrag)
    {
        return std::unexpected(ufrag.error());
    }

    auto pwd = generate_random_text(k_ice_pwd_length);
    if (!pwd)
    {
        return std::unexpected(pwd.error());
    }

    ice_credentials credentials;
    credentials.ufrag = std::move(*ufrag);
    credentials.pwd = std::move(*pwd);

    return credentials;
}
}    // namespace webrtc
