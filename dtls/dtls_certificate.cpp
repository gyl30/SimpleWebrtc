#include "dtls/dtls_certificate.h"

#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::string make_openssl_error(std::string_view prefix)
{
    const unsigned long error_code = ERR_get_error();

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

struct evp_pkey_ctx_deleter
{
    void operator()(EVP_PKEY_CTX* context) const
    {
        if (context != nullptr)
        {
            EVP_PKEY_CTX_free(context);
        }
    }
};

struct evp_pkey_deleter
{
    void operator()(EVP_PKEY* key) const
    {
        if (key != nullptr)
        {
            EVP_PKEY_free(key);
        }
    }
};

struct x509_deleter
{
    void operator()(X509* certificate) const
    {
        if (certificate != nullptr)
        {
            X509_free(certificate);
        }
    }
};

using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
using x509_ptr = std::unique_ptr<X509, x509_deleter>;

std::expected<evp_pkey_ptr, std::string> generate_private_key()
{
    evp_pkey_ctx_ptr context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));

    if (context == nullptr)
    {
        return std::unexpected(make_openssl_error("dtls private key context create failed"));
    }

    if (EVP_PKEY_keygen_init(context.get()) <= 0)
    {
        return std::unexpected(make_openssl_error("dtls private keygen init failed"));
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0)
    {
        return std::unexpected(make_openssl_error("dtls private keygen bits failed"));
    }

    EVP_PKEY* raw_key = nullptr;

    if (EVP_PKEY_keygen(context.get(), &raw_key) <= 0 || raw_key == nullptr)
    {
        return std::unexpected(make_openssl_error("dtls private key generate failed"));
    }

    return evp_pkey_ptr(raw_key);
}

std::expected<x509_ptr, std::string> generate_self_signed_certificate(EVP_PKEY* private_key)
{
    if (private_key == nullptr)
    {
        return make_error("dtls private key is null");
    }

    x509_ptr certificate(X509_new());

    if (certificate == nullptr)
    {
        return std::unexpected(make_openssl_error("dtls certificate create failed"));
    }

    if (X509_set_version(certificate.get(), 2) != 1)
    {
        return std::unexpected(make_openssl_error("dtls certificate set version failed"));
    }

    ASN1_INTEGER* serial_number = X509_get_serialNumber(certificate.get());

    if (serial_number == nullptr || ASN1_INTEGER_set(serial_number, 1) != 1)
    {
        return std::unexpected(make_openssl_error("dtls certificate set serial failed"));
    }

    if (X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) == nullptr)
    {
        return std::unexpected(make_openssl_error("dtls certificate set notBefore failed"));
    }

    if (X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 31536000L) == nullptr)
    {
        return std::unexpected(make_openssl_error("dtls certificate set notAfter failed"));
    }

    if (X509_set_pubkey(certificate.get(), private_key) != 1)
    {
        return std::unexpected(make_openssl_error("dtls certificate set public key failed"));
    }

    X509_NAME* subject_name = X509_get_subject_name(certificate.get());

    if (subject_name == nullptr)
    {
        return std::unexpected(make_openssl_error("dtls certificate get subject failed"));
    }

    const char common_name[] = "SimpleWebrtc";

    if (X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) != 1)
    {
        return std::unexpected(make_openssl_error("dtls certificate set common name failed"));
    }

    if (X509_set_issuer_name(certificate.get(), subject_name) != 1)
    {
        return std::unexpected(make_openssl_error("dtls certificate set issuer failed"));
    }

    if (X509_sign(certificate.get(), private_key, EVP_sha256()) <= 0)
    {
        return std::unexpected(make_openssl_error("dtls certificate sign failed"));
    }

    return certificate;
}

std::string format_fingerprint(const unsigned char* digest, unsigned int digest_size)
{
    static constexpr char k_hex[] = "0123456789ABCDEF";

    std::string value;

    value.reserve(static_cast<std::size_t>(digest_size) * 3U);

    for (unsigned int i = 0; i < digest_size; ++i)
    {
        if (i != 0)
        {
            value.push_back(':');
        }

        const unsigned char byte = digest[i];

        value.push_back(k_hex[(byte >> 4U) & 0x0FU]);
        value.push_back(k_hex[byte & 0x0FU]);
    }

    return value;
}

std::expected<sdp::fingerprint_info, std::string> make_certificate_fingerprint(X509* certificate)
{
    if (certificate == nullptr)
    {
        return make_error("dtls certificate is null");
    }

    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_size = 0;

    if (X509_digest(certificate, EVP_sha256(), digest, &digest_size) != 1)
    {
        return std::unexpected(make_openssl_error("dtls certificate fingerprint digest failed"));
    }

    sdp::fingerprint_info fingerprint;
    fingerprint.algorithm = "sha-256";
    fingerprint.value = format_fingerprint(digest, digest_size);

    return fingerprint;
}
}    // namespace

dtls_certificate_result generate_dtls_certificate()
{
    ERR_clear_error();

    auto private_key = generate_private_key();

    if (!private_key)
    {
        return std::unexpected(private_key.error());
    }

    auto certificate = generate_self_signed_certificate(private_key->get());

    if (!certificate)
    {
        return std::unexpected(certificate.error());
    }

    auto fingerprint = make_certificate_fingerprint(certificate->get());

    if (!fingerprint)
    {
        return std::unexpected(fingerprint.error());
    }

    auto result = std::make_shared<dtls_certificate>();

    result->private_key = std::shared_ptr<EVP_PKEY>(private_key->release(), EVP_PKEY_free);
    result->certificate = std::shared_ptr<X509>(certificate->release(), X509_free);
    result->fingerprint = std::move(*fingerprint);

    return result;
}

dtls_certificate_result get_process_dtls_certificate()
{
    static std::mutex mutex;
    static std::shared_ptr<dtls_certificate> certificate;

    std::lock_guard lock(mutex);

    if (certificate != nullptr)
    {
        return certificate;
    }

    auto generated = generate_dtls_certificate();

    if (!generated)
    {
        return std::unexpected(generated.error());
    }

    certificate = std::move(*generated);

    return certificate;
}
}    // namespace webrtc
