#include "dtls/dtls_transport.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "dtls/dtls_packet.h"
#include "dtls/dtls_srtp_keying_material.h"
#include "log/log.h"
#include "security/certificate_fingerprint.h"

#if OPENSSL_VERSION_NUMBER < 0x30200000L
#error "SimpleWebrtc requires OpenSSL 3.2 or newer"
#endif

namespace webrtc
{
namespace
{
using steady_clock = std::chrono::steady_clock;
using milliseconds = std::chrono::milliseconds;

std::string dtls_peer_role_to_string(dtls_peer_role role)
{
    switch (role)
    {
        case dtls_peer_role::publisher:
            return "publisher";

        case dtls_peer_role::subscriber:
            return "subscriber";

        case dtls_peer_role::unknown:
            return "unknown";
    }

    return "unknown";
}

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

std::string make_openssl_error(int ssl_error, std::string_view prefix)
{
    if (ssl_error == SSL_ERROR_WANT_READ)
    {
        return "want_read";
    }

    if (ssl_error == SSL_ERROR_WANT_WRITE)
    {
        return "want_write";
    }

    const unsigned long error_code = ERR_get_error();

    if (error_code == 0)
    {
        std::string message(prefix);

        message.append(": ssl_error=");
        message.append(std::to_string(ssl_error));

        return message;
    }

    char buffer[256]{};

    ERR_error_string_n(error_code, buffer, sizeof(buffer));

    std::string message(prefix);

    message.append(": ");
    message.append(buffer);

    return message;
}

struct ssl_deleter
{
    void operator()(SSL* ssl) const
    {
        if (ssl != nullptr)
        {
            SSL_free(ssl);
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

using ssl_ptr = std::unique_ptr<SSL, ssl_deleter>;

using x509_ptr = std::unique_ptr<X509, x509_deleter>;

bool fingerprints_equal(const sdp::fingerprint_info& left, const sdp::fingerprint_info& right)
{
    return left.algorithm == right.algorithm && left.value == right.value;
}

std::string_view dtls_setup_role_to_string(sdp::dtls_connection_role role)
{
    switch (role)
    {
        case sdp::dtls_connection_role::active:
            return "active";

        case sdp::dtls_connection_role::passive:
            return "passive";

        case sdp::dtls_connection_role::actpass:
            return "actpass";

        case sdp::dtls_connection_role::holdconn:
            return "holdconn";

        case sdp::dtls_connection_role::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string_view dtls_network_family_to_string(dtls_network_family family)
{
    switch (family)
    {
        case dtls_network_family::ipv4:
            return "ipv4";

        case dtls_network_family::ipv6:
            return "ipv6";

        case dtls_network_family::unknown:
            return "unknown";
    }

    return "unknown";
}

std::expected<std::uint16_t, std::string> make_dtls_udp_payload_mtu(std::uint16_t ip_mtu, dtls_network_family family)
{
    std::uint16_t overhead = 0;

    switch (family)
    {
        case dtls_network_family::ipv4:
            overhead = k_ipv4_udp_overhead;
            break;

        case dtls_network_family::ipv6:
            overhead = k_ipv6_udp_overhead;
            break;

        case dtls_network_family::unknown:
            return make_error("dtls network family is unknown");
    }

    if (ip_mtu <= overhead)
    {
        std::string message("dtls ip mtu is too small for network headers ip_mtu=");

        message.append(std::to_string(ip_mtu));
        message.append(" overhead=");
        message.append(std::to_string(overhead));

        return make_error(message);
    }

    return static_cast<std::uint16_t>(ip_mtu - overhead);
}

std::string make_expected_dtls_generation(std::string_view session_id, std::string_view local_ice_ufrag, std::string_view remote_ice_ufrag)
{
    std::string generation;

    generation.reserve(session_id.size() + local_ice_ufrag.size() + remote_ice_ufrag.size() + 2);

    generation.append(session_id);

    generation.push_back('|');

    generation.append(local_ice_ufrag);

    generation.push_back('|');

    generation.append(remote_ice_ufrag);

    return generation;
}

std::expected<void, std::string> validate_dtls_peer_identity(const dtls_peer_identity& identity)
{
    if (identity.role == dtls_peer_role::unknown)
    {
        return make_error("dtls peer role is unknown");
    }

    if (identity.session_id.empty())
    {
        return make_error("dtls peer session id is empty");
    }

    if (identity.stream_id.empty())
    {
        return make_error("dtls peer stream id is empty");
    }

    if (identity.local_ice_ufrag.empty())
    {
        return make_error("dtls peer local ice ufrag is empty");
    }

    if (identity.remote_ice_ufrag.empty())
    {
        return make_error("dtls peer remote ice ufrag is empty");
    }

    if (identity.generation.empty())
    {
        return make_error("dtls peer generation is empty");
    }

    const std::string expected_generation = make_expected_dtls_generation(identity.session_id, identity.local_ice_ufrag, identity.remote_ice_ufrag);

    if (identity.generation != expected_generation)
    {
        return make_error("dtls peer generation does not match ice credentials");
    }

    if (identity.local_setup != sdp::dtls_connection_role::passive)
    {
        return make_error("dtls local setup must be passive");
    }

    if (identity.remote_setup != sdp::dtls_connection_role::actpass)
    {
        return make_error("dtls remote setup must be actpass");
    }

    if (identity.remote_fingerprint.algorithm.empty())
    {
        return make_error("remote dtls fingerprint algorithm is empty");
    }

    if (identity.remote_fingerprint.value.empty())
    {
        return make_error("remote dtls fingerprint value is empty");
    }

    return {};
}

bool identities_equal(const dtls_peer_identity& left, const dtls_peer_identity& right)
{
    return left.role == right.role && left.session_id == right.session_id && left.stream_id == right.stream_id &&
           left.local_ice_ufrag == right.local_ice_ufrag && left.remote_ice_ufrag == right.remote_ice_ufrag && left.generation == right.generation &&
           left.local_setup == right.local_setup && left.remote_setup == right.remote_setup &&
           fingerprints_equal(left.remote_fingerprint, right.remote_fingerprint);
}

std::expected<void, std::string> configure_datagram_bio_mtu(BIO* bio, std::uint16_t udp_payload_mtu, std::string_view bio_name)
{
    if (bio == nullptr)
    {
        std::string message("dtls ");

        message.append(bio_name);
        message.append(" datagram bio is null");

        return make_error(message);
    }

    ERR_clear_error();

    const int set_mtu_result = BIO_dgram_set_mtu(bio, static_cast<long>(udp_payload_mtu));

    if (set_mtu_result != 1)
    {
        std::string prefix("dtls ");

        prefix.append(bio_name);
        prefix.append(" datagram bio set mtu failed");

        return std::unexpected(make_openssl_error(prefix));
    }

    const unsigned int configured_mtu = BIO_dgram_get_mtu(bio);

    if (configured_mtu != static_cast<unsigned int>(udp_payload_mtu))
    {
        std::string message("dtls ");

        message.append(bio_name);
        message.append(" datagram bio mtu mismatch requested=");
        message.append(std::to_string(udp_payload_mtu));
        message.append(" configured=");
        message.append(std::to_string(configured_mtu));

        return make_error(message);
    }

    return {};
}

std::expected<ssl_ptr, std::string> make_ssl(const std::shared_ptr<dtls_context>& context, std::uint16_t udp_payload_mtu)
{
    if (context == nullptr || context->native_handle() == nullptr)
    {
        return make_error("dtls context is null");
    }

    if (udp_payload_mtu == 0)
    {
        return make_error("dtls udp payload mtu is zero");
    }

    SSL* ssl = SSL_new(context->native_handle());

    if (ssl == nullptr)
    {
        return make_error("dtls ssl create failed");
    }

    ssl_ptr ssl_owner(ssl);

    BIO* read_bio = BIO_new(BIO_s_dgram_mem());

    if (read_bio == nullptr)
    {
        return make_error("dtls read datagram bio create failed");
    }

    BIO* write_bio = BIO_new(BIO_s_dgram_mem());

    if (write_bio == nullptr)
    {
        BIO_free(read_bio);

        return make_error("dtls write datagram bio create failed");
    }
    auto write_bio_mtu_result = configure_datagram_bio_mtu(write_bio, udp_payload_mtu, "write");

    if (!write_bio_mtu_result)
    {
        BIO_free(read_bio);
        BIO_free(write_bio);

        return std::unexpected(write_bio_mtu_result.error());
    }

    SSL_set_bio(ssl, read_bio, write_bio);

    SSL_set_accept_state(ssl);

    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);

    ERR_clear_error();

    /*
     * BIO_s_dgram_mem does not report IP/UDP overhead to OpenSSL. The caller
     * therefore converts the configured IP MTU to a UDP payload ceiling
     * before calling SSL_set_mtu().
     */
    const long set_mtu_result = SSL_set_mtu(ssl, static_cast<long>(udp_payload_mtu));

    if (set_mtu_result != static_cast<long>(udp_payload_mtu))
    {
        return std::unexpected(make_openssl_error("dtls set udp payload mtu failed"));
    }

    const unsigned int configured_write_bio_mtu = BIO_dgram_get_mtu(SSL_get_wbio(ssl));

    if (configured_write_bio_mtu != static_cast<unsigned int>(udp_payload_mtu))
    {
        std::string message("dtls write datagram bio mtu changed after ssl ownership transfer requested=");

        message.append(std::to_string(udp_payload_mtu));
        message.append(" configured=");
        message.append(std::to_string(configured_write_bio_mtu));

        return make_error(message);
    }

    return ssl_owner;
}

std::expected<x509_ptr, std::string> get_peer_certificate(SSL* ssl)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    X509* certificate = SSL_get1_peer_certificate(ssl);

    if (certificate == nullptr)
    {
        return make_error("remote dtls certificate is missing");
    }

    return x509_ptr(certificate);
}

std::expected<void, std::string> write_packet_to_ssl(SSL* ssl, std::span<const uint8_t> data)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    if (data.empty())
    {
        return {};
    }

    BIO* read_bio = SSL_get_rbio(ssl);

    if (read_bio == nullptr)
    {
        return make_error("dtls read bio is null");
    }

    std::size_t written = 0;

    const int write_result = BIO_write_ex(read_bio, data.data(), data.size(), &written);

    if (write_result != 1)
    {
        return make_error("dtls write datagram to read bio failed");
    }

    if (written != data.size())
    {
        return make_error("dtls write datagram to read bio incomplete");
    }

    return {};
}

std::expected<void, std::string> drain_ssl_write_bio(SSL* ssl,
                                                     std::uint16_t ip_mtu,
                                                     std::uint16_t udp_payload_mtu,
                                                     dtls_transport_packet_list& packets)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    BIO* write_bio = SSL_get_wbio(ssl);

    if (write_bio == nullptr)
    {
        return make_error("dtls write bio is null");
    }

    for (;;)
    {
        const std::size_t pending = static_cast<std::size_t>(BIO_pending(write_bio));

        if (pending == 0)
        {
            break;
        }

        if (pending > static_cast<std::size_t>(udp_payload_mtu))
        {
            std::string message("dtls output datagram exceeds configured ip mtu datagram_size=");

            message.append(std::to_string(pending));
            message.append(" udp_payload_mtu=");
            message.append(std::to_string(udp_payload_mtu));
            message.append(" ip_mtu=");
            message.append(std::to_string(ip_mtu));

            return make_error(message);
        }

        std::vector<uint8_t> packet(pending);

        std::size_t read_size = 0;

        const int read_result = BIO_read_ex(write_bio, packet.data(), packet.size(), &read_size);

        if (read_result != 1)
        {
            return make_error("dtls read datagram from write bio failed");
        }

        if (read_size != packet.size())
        {
            return make_error("dtls read datagram from write bio incomplete");
        }

        if (read_size > static_cast<std::size_t>(udp_payload_mtu))
        {
            std::string message("dtls output datagram exceeds configured ip mtu after read datagram_size=");

            message.append(std::to_string(read_size));
            message.append(" udp_payload_mtu=");
            message.append(std::to_string(udp_payload_mtu));
            message.append(" ip_mtu=");
            message.append(std::to_string(ip_mtu));

            return make_error(message);
        }

        packets.push_back(std::move(packet));
    }

    return {};
}

std::expected<void, std::string> run_dtls_handshake(SSL* ssl,
                                                    std::uint16_t ip_mtu,
                                                    std::uint16_t udp_payload_mtu,
                                                    dtls_transport_packet_list& packets)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    if (SSL_is_init_finished(ssl) == 1)
    {
        return {};
    }

    ERR_clear_error();

    const int result = SSL_do_handshake(ssl);

    const int ssl_error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl, result);

    std::string fatal_error;

    if (result != 1 && ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
    {
        fatal_error = make_openssl_error(ssl_error, "dtls handshake failed");
    }

    auto drain_result = drain_ssl_write_bio(ssl, ip_mtu, udp_payload_mtu, packets);

    if (!drain_result)
    {
        return std::unexpected(drain_result.error());
    }

    if (result == 1 || ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
    {
        return {};
    }

    return std::unexpected(std::move(fatal_error));
}

std::expected<void, std::string> consume_dtls_application_data_and_alerts(
    SSL* ssl, std::uint16_t ip_mtu, std::uint16_t udp_payload_mtu, dtls_transport_packet_list& packets, bool& received_close_notify)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    std::array<uint8_t, 2048> buffer{};

    for (int loop_count = 0; loop_count < 8; ++loop_count)
    {
        ERR_clear_error();

        const int read_result = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));

        const int ssl_error = read_result > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl, read_result);

        std::string fatal_error;

        if (read_result <= 0 && ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
        {
            fatal_error = make_openssl_error(ssl_error, "dtls read failed");
        }

        auto drain_result = drain_ssl_write_bio(ssl, ip_mtu, udp_payload_mtu, packets);

        if (!drain_result)
        {
            return std::unexpected(drain_result.error());
        }

        if (read_result > 0)
        {
            continue;
        }

        if (ssl_error == SSL_ERROR_ZERO_RETURN)
        {
            received_close_notify = true;

            return {};
        }

        if ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != 0)
        {
            received_close_notify = true;

            return {};
        }

        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            return {};
        }

        return std::unexpected(std::move(fatal_error));
    }

    return {};
}

struct dtls_peer_state
{
    dtls_peer_identity identity;

    uint64_t packet_count = 0;
    uint64_t byte_count = 0;

    dtls_network_family network_family = dtls_network_family::unknown;

    std::uint16_t udp_payload_mtu = 0;

    steady_clock::time_point handshake_started_at;

    std::string handshake_error;

    ssl_ptr ssl;

    std::optional<srtp_keying_material> keying_material;
};
}    // namespace

struct dtls_transport::impl
{
    explicit impl(std::shared_ptr<dtls_context> context, std::uint16_t ip_mtu) : context_(std::move(context)), ip_mtu_(ip_mtu)
    {
        if (ip_mtu_ < k_min_dtls_ip_mtu || ip_mtu_ > k_max_dtls_ip_mtu)
        {
            ip_mtu_ = k_default_dtls_ip_mtu;
        }
    }

    void remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity)
    {
        if (remote_endpoint.empty())
        {
            return;
        }

        const auto validation_result = validate_dtls_peer_identity(identity);

        std::lock_guard lock(mutex_);

        const std::string endpoint_key(remote_endpoint);

        if (!validation_result)
        {
            peers_by_endpoint_.erase(endpoint_key);

            WEBRTC_LOG_WARN("dtls peer identity rejected remote={} session={} stream={} generation={} local_setup={} remote_setup={} error={}",
                            remote_endpoint,
                            identity.session_id,
                            identity.stream_id,
                            identity.generation,
                            dtls_setup_role_to_string(identity.local_setup),
                            dtls_setup_role_to_string(identity.remote_setup),
                            validation_result.error());

            return;
        }

        auto [iterator, inserted] = peers_by_endpoint_.try_emplace(endpoint_key);

        auto& peer = iterator->second;

        if (!inserted && identities_equal(peer.identity, identity))
        {
            return;
        }

        if (!inserted)
        {
            WEBRTC_LOG_INFO(
                "dtls peer identity changed reset transport remote={} old_session={} new_session={} old_generation={} new_generation={} "
                "old_local_ufrag={} new_local_ufrag={} old_remote_ufrag={} new_remote_ufrag={} old_local_setup={} new_local_setup={} "
                "old_remote_setup={} new_remote_setup={}",
                remote_endpoint,
                peer.identity.session_id,
                identity.session_id,
                peer.identity.generation,
                identity.generation,
                peer.identity.local_ice_ufrag,
                identity.local_ice_ufrag,
                peer.identity.remote_ice_ufrag,
                identity.remote_ice_ufrag,
                dtls_setup_role_to_string(peer.identity.local_setup),
                dtls_setup_role_to_string(identity.local_setup),
                dtls_setup_role_to_string(peer.identity.remote_setup),
                dtls_setup_role_to_string(identity.remote_setup));

            peer = dtls_peer_state{};
        }

        peer.identity = std::move(identity);

        WEBRTC_LOG_INFO(
            "dtls remember peer remote={} role={} stream={} session={} generation={} local_ufrag={} remote_ufrag={} local_setup={} remote_setup={} "
            "fingerprint_algorithm={}",
            remote_endpoint,
            dtls_peer_role_to_string(peer.identity.role),
            peer.identity.stream_id,
            peer.identity.session_id,
            peer.identity.generation,
            peer.identity.local_ice_ufrag,
            peer.identity.remote_ice_ufrag,
            dtls_setup_role_to_string(peer.identity.local_setup),
            dtls_setup_role_to_string(peer.identity.remote_setup),
            peer.identity.remote_fingerprint.algorithm);
    }
    dtls_transport_packet_result handle_udp_packet(std::span<const uint8_t> data,
                                                   std::string_view remote_endpoint,
                                                   dtls_network_family network_family)
    {
        dtls_transport_packet_list packets;

        auto header = parse_dtls_record_header(data);

        if (!header)
        {
            WEBRTC_LOG_WARN("dtls packet parse failed remote={} error={}", remote_endpoint, header.error());

            return packets;
        }

        std::lock_guard lock(mutex_);

        auto* peer = find_peer_locked(remote_endpoint);

        if (peer == nullptr)
        {
            WEBRTC_LOG_WARN("dtls packet from unknown peer remote={} content_type={} version={} size={}",
                            remote_endpoint,
                            dtls_record_content_type_to_string(header->content_type),
                            dtls_version_to_string(header->version),
                            data.size());

            return packets;
        }

        if (!peer->handshake_error.empty())
        {
            return std::unexpected(peer->handshake_error);
        }

        peer->packet_count += 1;

        peer->byte_count += static_cast<uint64_t>(data.size());

        if (peer->network_family != dtls_network_family::unknown && peer->network_family != network_family)
        {
            std::string error("dtls peer network family changed old=");

            error.append(dtls_network_family_to_string(peer->network_family));
            error.append(" new=");
            error.append(dtls_network_family_to_string(network_family));

            mark_handshake_failed_locked(*peer, error, remote_endpoint);

            return std::unexpected(std::move(error));
        }

        if (peer->ssl == nullptr)
        {
            auto udp_payload_mtu_result = make_dtls_udp_payload_mtu(ip_mtu_, network_family);

            if (!udp_payload_mtu_result)
            {
                const std::string error = udp_payload_mtu_result.error();

                mark_handshake_failed_locked(*peer, error, remote_endpoint);

                return std::unexpected(error);
            }

            peer->network_family = network_family;
            peer->udp_payload_mtu = *udp_payload_mtu_result;

            auto ssl_result = make_ssl(context_, peer->udp_payload_mtu);

            if (!ssl_result)
            {
                const std::string error = ssl_result.error();

                mark_handshake_failed_locked(*peer, error, remote_endpoint);

                return std::unexpected(error);
            }

            peer->ssl = std::move(*ssl_result);

            peer->handshake_started_at = steady_clock::now();

            WEBRTC_LOG_INFO("dtls handshake started remote={} stream={} session={} network_family={} ip_mtu={} udp_payload_mtu={}",
                            remote_endpoint,
                            peer->identity.stream_id,
                            peer->identity.session_id,
                            dtls_network_family_to_string(peer->network_family),
                            ip_mtu_,
                            peer->udp_payload_mtu);
        }

        auto write_result = write_packet_to_ssl(peer->ssl.get(), data);

        if (!write_result)
        {
            const std::string error = write_result.error();

            mark_handshake_failed_locked(*peer, error, remote_endpoint);

            return std::unexpected(error);
        }

        log_packet_locked(*peer, data, remote_endpoint, *header);

        auto handshake_result = run_dtls_handshake(peer->ssl.get(), ip_mtu_, peer->udp_payload_mtu, packets);

        if (!handshake_result)
        {
            const std::string error = handshake_result.error();

            mark_handshake_failed_locked(*peer, error, remote_endpoint);

            return std::unexpected(error);
        }

        auto complete_result = complete_handshake_if_ready_locked(*peer, remote_endpoint);

        if (!complete_result)
        {
            return std::unexpected(complete_result.error());
        }

        if (peer->keying_material.has_value())
        {
            bool received_close_notify = false;

            auto consume_result =
                consume_dtls_application_data_and_alerts(peer->ssl.get(), ip_mtu_, peer->udp_payload_mtu, packets, received_close_notify);

            if (!consume_result)
            {
                const std::string error = consume_result.error();

                WEBRTC_LOG_WARN(
                    "dtls application data consume failed remote={} session={} error={}", remote_endpoint, peer->identity.session_id, error);

                return std::unexpected(error);
            }

            if (received_close_notify)
            {
                WEBRTC_LOG_INFO("dtls close notify received remote={} role={} stream={} session={}",
                                remote_endpoint,
                                dtls_peer_role_to_string(peer->identity.role),
                                peer->identity.stream_id,
                                peer->identity.session_id);
            }
        }

        return packets;
    }

    std::optional<srtp_keying_material> get_srtp_keying_material(std::string_view remote_endpoint) const
    {
        std::lock_guard lock(mutex_);

        const auto* peer = find_peer_locked_const(remote_endpoint);

        if (peer == nullptr)
        {
            return std::nullopt;
        }

        return peer->keying_material;
    }
    std::optional<dtls_peer_identity> get_peer_identity(std::string_view remote_endpoint) const
    {
        std::lock_guard lock(mutex_);

        const auto* peer = find_peer_locked_const(remote_endpoint);

        if (peer == nullptr)
        {
            return std::nullopt;
        }

        return peer->identity;
    }

    dtls_peer_state* find_peer_locked(std::string_view remote_endpoint)
    {
        const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

        if (iterator == peers_by_endpoint_.end())
        {
            return nullptr;
        }

        return &iterator->second;
    }

    const dtls_peer_state* find_peer_locked_const(std::string_view remote_endpoint) const
    {
        const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

        if (iterator == peers_by_endpoint_.end())
        {
            return nullptr;
        }

        return &iterator->second;
    }

    void mark_handshake_failed_locked(dtls_peer_state& peer, std::string error, std::string_view remote_endpoint)
    {
        if (error.empty())
        {
            error = "dtls peer handshake previously failed";
        }

        peer.handshake_error = std::move(error);

        peer.keying_material.reset();

        WEBRTC_LOG_ERROR("dtls peer handshake failed remote={} role={} stream={} session={} error={}",
                         remote_endpoint,
                         dtls_peer_role_to_string(peer.identity.role),
                         peer.identity.stream_id,
                         peer.identity.session_id,
                         peer.handshake_error);

        peer.ssl.reset();
    }

    std::expected<void, std::string> verify_remote_certificate_locked(dtls_peer_state& peer, std::string_view remote_endpoint)
    {
        auto identity_result = validate_dtls_peer_identity(peer.identity);

        if (!identity_result)
        {
            WEBRTC_LOG_WARN("dtls remote certificate verify rejected identity remote={} session={} stream={} generation={} error={}",
                            remote_endpoint,
                            peer.identity.session_id,
                            peer.identity.stream_id,
                            peer.identity.generation,
                            identity_result.error());

            return std::unexpected(identity_result.error());
        }

        if (peer.ssl == nullptr)
        {
            return make_error("dtls ssl is null");
        }
        auto certificate = get_peer_certificate(peer.ssl.get());
        if (!certificate)
        {
            return std::unexpected(certificate.error());
        }

        auto fingerprint = verify_certificate_fingerprint(certificate->get(), peer.identity.remote_fingerprint);

        if (!fingerprint)
        {
            return std::unexpected(fingerprint.error());
        }

        WEBRTC_LOG_INFO("dtls remote certificate fingerprint verified remote={} role={} stream={} session={} algorithm={} fingerprint={}",
                        remote_endpoint,
                        dtls_peer_role_to_string(peer.identity.role),
                        peer.identity.stream_id,
                        peer.identity.session_id,
                        fingerprint->algorithm,
                        fingerprint->value);

        return {};
    }

    std::expected<void, std::string> complete_handshake_if_ready_locked(dtls_peer_state& peer, std::string_view remote_endpoint)
    {
        if (peer.ssl == nullptr)
        {
            return {};
        }

        if (peer.keying_material.has_value())
        {
            return {};
        }

        if (SSL_is_init_finished(peer.ssl.get()) != 1)
        {
            return {};
        }

        auto fingerprint_result = verify_remote_certificate_locked(peer, remote_endpoint);

        if (!fingerprint_result)
        {
            const std::string error = fingerprint_result.error();

            mark_handshake_failed_locked(peer, error, remote_endpoint);

            return std::unexpected(error);
        }

        auto material = export_srtp_keying_material(peer.ssl.get());

        if (!material)
        {
            const std::string error = material.error();

            mark_handshake_failed_locked(peer, error, remote_endpoint);

            return std::unexpected(error);
        }

        peer.keying_material = std::move(*material);

        const auto elapsed = std::chrono::duration_cast<milliseconds>(steady_clock::now() - peer.handshake_started_at);

        WEBRTC_LOG_INFO(
            "dtls handshake complete remote={} role={} stream={} session={} profile={} key_size={} salt_size={} packets={} bytes={} "
            "duration_ms={}",
            remote_endpoint,
            dtls_peer_role_to_string(peer.identity.role),
            peer.identity.stream_id,
            peer.identity.session_id,
            srtp_profile_id_to_string(peer.keying_material->profile),
            peer.keying_material->client_write_master_key.size(),
            peer.keying_material->client_write_master_salt.size(),
            peer.packet_count,
            peer.byte_count,
            elapsed.count());

        return {};
    }

    void log_packet_locked(dtls_peer_state& peer, std::span<const uint8_t> data, std::string_view remote_endpoint, const dtls_record_header& header)
    {
        if (header.content_type == dtls_record_content_type::handshake)
        {
            const dtls_handshake_type handshake_type = get_dtls_handshake_type(data);

            if (handshake_type == dtls_handshake_type::client_hello)
            {
                WEBRTC_LOG_INFO(
                    "dtls client hello received remote={} role={} stream={} session={} version={} epoch={} record_size={} packet_count={}",
                    remote_endpoint,
                    dtls_peer_role_to_string(peer.identity.role),
                    peer.identity.stream_id,
                    peer.identity.session_id,
                    dtls_version_to_string(header.version),
                    header.epoch,
                    header.record_size,
                    peer.packet_count);

                return;
            }

            WEBRTC_LOG_INFO("dtls handshake packet received remote={} session={} type={} version={} epoch={} record_size={}",
                            remote_endpoint,
                            peer.identity.session_id,
                            dtls_handshake_type_to_string(handshake_type),
                            dtls_version_to_string(header.version),
                            header.epoch,
                            header.record_size);

            return;
        }

        WEBRTC_LOG_DEBUG("dtls packet received remote={} session={} content_type={} version={} epoch={} record_size={} packet_count={} byte_count={}",
                         remote_endpoint,
                         peer.identity.session_id,
                         dtls_record_content_type_to_string(header.content_type),
                         dtls_version_to_string(header.version),
                         header.epoch,
                         header.record_size,
                         peer.packet_count,
                         peer.byte_count);
    }

    std::shared_ptr<dtls_context> context_;

    std::uint16_t ip_mtu_ = k_default_dtls_ip_mtu;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, dtls_peer_state> peers_by_endpoint_;
};

dtls_transport::dtls_transport(std::shared_ptr<dtls_context> context, std::uint16_t ip_mtu)
    : impl_(std::make_unique<impl>(std::move(context), ip_mtu))
{
}

dtls_transport::~dtls_transport() = default;

void dtls_transport::remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity)
{
    impl_->remember_peer(remote_endpoint, std::move(identity));
}

dtls_transport_packet_result dtls_transport::handle_udp_packet(std::span<const uint8_t> data,
                                                               std::string_view remote_endpoint,
                                                               dtls_network_family network_family)
{
    return impl_->handle_udp_packet(data, remote_endpoint, network_family);
}

std::optional<srtp_keying_material> dtls_transport::get_srtp_keying_material(std::string_view remote_endpoint) const
{
    return impl_->get_srtp_keying_material(remote_endpoint);
}

std::optional<dtls_peer_identity> dtls_transport::get_peer_identity(std::string_view remote_endpoint) const
{
    return impl_->get_peer_identity(remote_endpoint);
}

}    // namespace webrtc
