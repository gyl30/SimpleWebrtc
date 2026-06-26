#include "dtls/dtls_transport.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/time.h>
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
using microseconds = std::chrono::microseconds;

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

std::string make_openssl_error(SSL* ssl, int ssl_result, std::string_view prefix)
{
    const int ssl_error = SSL_get_error(ssl, ssl_result);

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

using ssl_event_timeout_result = std::expected<std::optional<milliseconds>, std::string>;

bool fingerprints_equal(const sdp::fingerprint_info& left, const sdp::fingerprint_info& right)
{
    return left.algorithm == right.algorithm && left.value == right.value;
}

bool identities_equal(const dtls_peer_identity& left, const dtls_peer_identity& right)
{
    return left.role == right.role && left.session_id == right.session_id && left.stream_id == right.stream_id &&
           left.local_ice_ufrag == right.local_ice_ufrag && fingerprints_equal(left.remote_fingerprint, right.remote_fingerprint);
}

std::expected<ssl_ptr, std::string> make_ssl(const std::shared_ptr<dtls_context>& context)
{
    if (context == nullptr || context->native_handle() == nullptr)
    {
        return make_error("dtls context is null");
    }

    SSL* ssl = SSL_new(context->native_handle());

    if (ssl == nullptr)
    {
        return make_error("dtls ssl create failed");
    }

    ssl_ptr ssl_owner(ssl);

    BIO* read_bio = BIO_new(BIO_s_mem());

    if (read_bio == nullptr)
    {
        return make_error("dtls read bio create failed");
    }

    BIO* write_bio = BIO_new(BIO_s_mem());

    if (write_bio == nullptr)
    {
        BIO_free(read_bio);

        return make_error("dtls write bio create failed");
    }

    BIO_set_mem_eof_return(read_bio, -1);

    BIO_set_mem_eof_return(write_bio, -1);

    SSL_set_bio(ssl, read_bio, write_bio);

    SSL_set_accept_state(ssl);

    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);

    SSL_set_mtu(ssl, 1200);

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

    if (data.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return make_error("dtls input packet is too large");
    }

    BIO* read_bio = SSL_get_rbio(ssl);

    if (read_bio == nullptr)
    {
        return make_error("dtls read bio is null");
    }

    const int write_result = BIO_write(read_bio, data.data(), static_cast<int>(data.size()));

    if (write_result <= 0)
    {
        return make_error("dtls write packet to read bio failed");
    }

    if (static_cast<std::size_t>(write_result) != data.size())
    {
        return make_error("dtls write packet to read bio incomplete");
    }

    return {};
}

std::expected<void, std::string> drain_ssl_write_bio(SSL* ssl, dtls_transport_packet_list& packets)
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
        const int pending = BIO_pending(write_bio);

        if (pending <= 0)
        {
            break;
        }

        std::vector<uint8_t> packet(static_cast<std::size_t>(pending));

        const int read_result = BIO_read(write_bio, packet.data(), pending);

        if (read_result <= 0)
        {
            return make_error("dtls read packet from write bio failed");
        }

        packet.resize(static_cast<std::size_t>(read_result));

        packets.push_back(std::move(packet));
    }

    return {};
}

std::expected<void, std::string> run_dtls_handshake(SSL* ssl, dtls_transport_packet_list& packets)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    for (int loop_count = 0; loop_count < 8; ++loop_count)
    {
        if (SSL_is_init_finished(ssl) == 1)
        {
            return {};
        }

        ERR_clear_error();

        const int result = SSL_do_handshake(ssl);

        auto drain_result = drain_ssl_write_bio(ssl, packets);

        if (!drain_result)
        {
            return std::unexpected(drain_result.error());
        }

        if (result == 1)
        {
            return {};
        }

        const int ssl_error = SSL_get_error(ssl, result);

        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            return {};
        }

        return std::unexpected(make_openssl_error(ssl, result, "dtls handshake failed"));
    }

    return {};
}

milliseconds timeval_to_milliseconds(const timeval& timeout)
{
    const auto seconds_value = std::chrono::seconds(static_cast<int64_t>(timeout.tv_sec));

    const auto microseconds_value = microseconds(static_cast<int64_t>(timeout.tv_usec));

    const auto duration = std::chrono::duration_cast<microseconds>(seconds_value) + microseconds_value;

    if (duration <= microseconds::zero())
    {
        return milliseconds::zero();
    }

    return std::chrono::ceil<milliseconds>(duration);
}

ssl_event_timeout_result get_ssl_event_timeout(SSL* ssl)
{
    if (ssl == nullptr)
    {
        return make_error("dtls ssl is null");
    }

    timeval timeout{};
    int is_infinite = 0;

    ERR_clear_error();

    const int result = SSL_get_event_timeout(ssl, &timeout, &is_infinite);

    if (result != 1)
    {
        return std::unexpected(make_openssl_error("dtls get event timeout failed"));
    }

    if (is_infinite != 0)
    {
        return std::optional<milliseconds>{};
    }

    return std::optional<milliseconds>{timeval_to_milliseconds(timeout)};
}

void update_minimum_timeout(std::optional<milliseconds>& current, milliseconds candidate)
{
    if (!current.has_value() || candidate < *current)
    {
        current = candidate;
    }
}

milliseconds remaining_duration(steady_clock::time_point now, steady_clock::time_point deadline)
{
    if (now >= deadline)
    {
        return milliseconds::zero();
    }

    return std::chrono::ceil<milliseconds>(deadline - now);
}
}    // namespace

struct dtls_transport::impl
{
    explicit impl(std::shared_ptr<dtls_context> context, dtls_transport_config config) : context_(std::move(context)), config_(std::move(config))
    {
        if (config_.handshake_timeout <= milliseconds::zero())
        {
            config_.handshake_timeout = std::chrono::seconds(30);
        }
    }

    struct dtls_peer_context
    {
        dtls_peer_identity identity;

        uint64_t packet_count = 0;
        uint64_t byte_count = 0;
        uint64_t timeout_event_count = 0;
        uint64_t retransmission_packet_count = 0;

        bool saw_client_hello = false;
        bool saw_dtls_packet = false;
        bool handshake_started = false;
        bool fingerprint_verified = false;
        bool handshake_done = false;
        bool handshake_failed = false;

        steady_clock::time_point handshake_started_at{};

        std::string handshake_error;

        ssl_ptr ssl;

        std::optional<sdp::fingerprint_info> verified_remote_fingerprint;

        std::optional<srtp_keying_material> keying_material;
    };

    void remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity)
    {
        if (remote_endpoint.empty())
        {
            return;
        }

        std::lock_guard lock(mutex_);

        const std::string endpoint_key(remote_endpoint);

        auto [iterator, inserted] = peers_by_endpoint_.try_emplace(endpoint_key);

        auto& peer = iterator->second;

        if (!inserted && !identities_equal(peer.identity, identity))
        {
            WEBRTC_LOG_INFO("dtls peer identity changed reset transport remote={} old_session={} new_session={}",
                            remote_endpoint,
                            peer.identity.session_id,
                            identity.session_id);

            peer = dtls_peer_context{};
        }

        peer.identity = std::move(identity);

        WEBRTC_LOG_INFO("dtls remember peer remote={} role={} stream={} session={} local_ufrag={} fingerprint_algorithm={}",
                        remote_endpoint,
                        dtls_peer_role_to_string(peer.identity.role),
                        peer.identity.stream_id,
                        peer.identity.session_id,
                        peer.identity.local_ice_ufrag,
                        peer.identity.remote_fingerprint.algorithm);
    }

    dtls_transport_packet_result close_peer(std::string_view remote_endpoint)
    {
        dtls_transport_packet_list packets;

        if (remote_endpoint.empty())
        {
            return packets;
        }

        std::lock_guard lock(mutex_);

        auto* peer = find_peer_locked(remote_endpoint);

        if (peer == nullptr)
        {
            return packets;
        }

        if (peer->ssl == nullptr)
        {
            return packets;
        }

        ERR_clear_error();

        const int result = SSL_shutdown(peer->ssl.get());

        auto drain_result = drain_ssl_write_bio(peer->ssl.get(), packets);

        if (!drain_result)
        {
            return std::unexpected(drain_result.error());
        }

        if (result >= 0)
        {
            return packets;
        }

        const int ssl_error = SSL_get_error(peer->ssl.get(), result);

        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            return packets;
        }

        return std::unexpected(make_openssl_error(peer->ssl.get(), result, "dtls shutdown failed"));
    }

    void forget_peer(std::string_view remote_endpoint)
    {
        if (remote_endpoint.empty())
        {
            return;
        }

        std::lock_guard lock(mutex_);

        peers_by_endpoint_.erase(std::string(remote_endpoint));
    }

    dtls_transport_packet_result handle_udp_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
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

        if (peer->handshake_failed)
        {
            if (peer->handshake_error.empty())
            {
                return make_error("dtls peer handshake previously failed");
            }

            return std::unexpected(peer->handshake_error);
        }

        peer->packet_count += 1;

        peer->byte_count += static_cast<uint64_t>(data.size());

        peer->saw_dtls_packet = true;

        if (peer->ssl == nullptr)
        {
            auto ssl_result = make_ssl(context_);

            if (!ssl_result)
            {
                const std::string error = ssl_result.error();

                mark_handshake_failed_locked(*peer, error, remote_endpoint);

                return std::unexpected(error);
            }

            peer->ssl = std::move(*ssl_result);

            peer->handshake_started = true;

            peer->handshake_started_at = steady_clock::now();

            WEBRTC_LOG_INFO("dtls handshake timer started remote={} stream={} session={} timeout_ms={}",
                            remote_endpoint,
                            peer->identity.stream_id,
                            peer->identity.session_id,
                            config_.handshake_timeout.count());
        }

        auto write_result = write_packet_to_ssl(peer->ssl.get(), data);

        if (!write_result)
        {
            const std::string error = write_result.error();

            mark_handshake_failed_locked(*peer, error, remote_endpoint);

            return std::unexpected(error);
        }

        log_packet_locked(*peer, data, remote_endpoint, *header);

        auto handshake_result = run_dtls_handshake(peer->ssl.get(), packets);

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

        return packets;
    }

    dtls_timeout_event_list handle_timeouts()
    {
        dtls_timeout_event_list events;

        const auto now = steady_clock::now();

        std::lock_guard lock(mutex_);

        for (auto& [remote_endpoint, peer] : peers_by_endpoint_)
        {
            if (peer.ssl == nullptr || peer.handshake_done || peer.handshake_failed)
            {
                continue;
            }

            if (handshake_deadline_reached_locked(peer, now))
            {
                dtls_timeout_event event;

                event.remote_endpoint = remote_endpoint;

                event.peer_failed = true;

                event.error = "dtls handshake timeout";

                mark_handshake_failed_locked(peer, event.error, remote_endpoint);

                events.push_back(std::move(event));

                continue;
            }

            auto timeout_result = get_ssl_event_timeout(peer.ssl.get());

            if (!timeout_result)
            {
                dtls_timeout_event event;

                event.remote_endpoint = remote_endpoint;

                event.peer_failed = true;

                event.error = timeout_result.error();

                mark_handshake_failed_locked(peer, event.error, remote_endpoint);

                events.push_back(std::move(event));

                continue;
            }

            if (!timeout_result->has_value() || **timeout_result > milliseconds::zero())
            {
                continue;
            }

            dtls_timeout_event event;

            event.remote_endpoint = remote_endpoint;

            ERR_clear_error();

            const int handle_result = SSL_handle_events(peer.ssl.get());

            if (handle_result != 1)
            {
                event.peer_failed = true;

                event.error = make_openssl_error("dtls handle events failed");

                mark_handshake_failed_locked(peer, event.error, remote_endpoint);

                events.push_back(std::move(event));

                continue;
            }

            peer.timeout_event_count += 1;

            auto drain_result = drain_ssl_write_bio(peer.ssl.get(), event.packets);

            if (!drain_result)
            {
                event.peer_failed = true;

                event.error = drain_result.error();

                mark_handshake_failed_locked(peer, event.error, remote_endpoint);

                events.push_back(std::move(event));

                continue;
            }

            auto complete_result = complete_handshake_if_ready_locked(peer, remote_endpoint);

            if (!complete_result)
            {
                event.peer_failed = true;

                event.error = complete_result.error();

                events.push_back(std::move(event));

                continue;
            }

            if (!event.packets.empty())
            {
                peer.retransmission_packet_count += static_cast<uint64_t>(event.packets.size());

                WEBRTC_LOG_INFO("dtls handshake retransmit remote={} stream={} session={} timeout_events={} retransmission_packets={} packets={}",
                                remote_endpoint,
                                peer.identity.stream_id,
                                peer.identity.session_id,
                                peer.timeout_event_count,
                                peer.retransmission_packet_count,
                                event.packets.size());

                events.push_back(std::move(event));
            }
        }

        return events;
    }

    std::optional<milliseconds> next_timeout() const
    {
        const auto now = steady_clock::now();

        std::optional<milliseconds> minimum_timeout;

        std::lock_guard lock(mutex_);

        for (const auto& [remote_endpoint, peer] : peers_by_endpoint_)
        {
            if (peer.ssl == nullptr || peer.handshake_done || peer.handshake_failed)
            {
                continue;
            }

            if (peer.handshake_started)
            {
                const auto deadline = peer.handshake_started_at + config_.handshake_timeout;

                update_minimum_timeout(minimum_timeout, remaining_duration(now, deadline));
            }

            auto timeout_result = get_ssl_event_timeout(peer.ssl.get());

            if (!timeout_result)
            {
                WEBRTC_LOG_WARN("dtls next timeout query failed remote={} session={} error={}",
                                remote_endpoint,
                                peer.identity.session_id,
                                timeout_result.error());

                update_minimum_timeout(minimum_timeout, milliseconds::zero());

                continue;
            }

            if (timeout_result->has_value())
            {
                update_minimum_timeout(minimum_timeout, **timeout_result);
            }
        }

        return minimum_timeout;
    }

    std::optional<srtp_keying_material> get_srtp_keying_material(std::string_view remote_endpoint) const
    {
        std::lock_guard lock(mutex_);

        const auto* peer = find_peer_locked_const(remote_endpoint);

        if (peer == nullptr)
        {
            return std::nullopt;
        }

        if (!peer->handshake_done || !peer->fingerprint_verified || peer->handshake_failed)
        {
            return std::nullopt;
        }

        return peer->keying_material;
    }

    bool is_handshake_done(std::string_view remote_endpoint) const
    {
        std::lock_guard lock(mutex_);

        const auto* peer = find_peer_locked_const(remote_endpoint);

        if (peer == nullptr)
        {
            return false;
        }

        return peer->handshake_done && peer->fingerprint_verified && !peer->handshake_failed;
    }

    std::size_t peer_count() const
    {
        std::lock_guard lock(mutex_);

        return peers_by_endpoint_.size();
    }

    dtls_peer_context* find_peer_locked(std::string_view remote_endpoint)
    {
        const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

        if (iterator == peers_by_endpoint_.end())
        {
            return nullptr;
        }

        return &iterator->second;
    }

    const dtls_peer_context* find_peer_locked_const(std::string_view remote_endpoint) const
    {
        const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

        if (iterator == peers_by_endpoint_.end())
        {
            return nullptr;
        }

        return &iterator->second;
    }

    bool handshake_deadline_reached_locked(const dtls_peer_context& peer, steady_clock::time_point now) const
    {
        if (!peer.handshake_started)
        {
            return false;
        }

        return now - peer.handshake_started_at >= config_.handshake_timeout;
    }

    void mark_handshake_failed_locked(dtls_peer_context& peer, std::string error, std::string_view remote_endpoint)
    {
        peer.handshake_failed = true;
        peer.handshake_done = false;
        peer.fingerprint_verified = false;

        peer.handshake_error = std::move(error);

        peer.keying_material.reset();
        peer.verified_remote_fingerprint.reset();

        WEBRTC_LOG_ERROR("dtls peer handshake failed remote={} role={} stream={} session={} timeout_events={} retransmission_packets={} error={}",
                         remote_endpoint,
                         dtls_peer_role_to_string(peer.identity.role),
                         peer.identity.stream_id,
                         peer.identity.session_id,
                         peer.timeout_event_count,
                         peer.retransmission_packet_count,
                         peer.handshake_error);

        peer.ssl.reset();
    }

    std::expected<void, std::string> verify_remote_certificate_locked(dtls_peer_context& peer, std::string_view remote_endpoint)
    {
        if (peer.fingerprint_verified)
        {
            return {};
        }

        if (peer.ssl == nullptr)
        {
            return make_error("dtls ssl is null");
        }

        if (peer.identity.remote_fingerprint.algorithm.empty())
        {
            return make_error("remote dtls fingerprint algorithm is empty");
        }

        if (peer.identity.remote_fingerprint.value.empty())
        {
            return make_error("remote dtls fingerprint value is empty");
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

        peer.verified_remote_fingerprint = std::move(*fingerprint);

        peer.fingerprint_verified = true;

        WEBRTC_LOG_INFO("dtls remote certificate fingerprint verified remote={} role={} stream={} session={} algorithm={} fingerprint={}",
                        remote_endpoint,
                        dtls_peer_role_to_string(peer.identity.role),
                        peer.identity.stream_id,
                        peer.identity.session_id,
                        peer.verified_remote_fingerprint->algorithm,
                        peer.verified_remote_fingerprint->value);

        return {};
    }

    std::expected<void, std::string> complete_handshake_if_ready_locked(dtls_peer_context& peer, std::string_view remote_endpoint)
    {
        if (peer.ssl == nullptr)
        {
            return {};
        }

        if (peer.handshake_done)
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

        peer.handshake_done = true;

        const auto elapsed =
            peer.handshake_started ? std::chrono::duration_cast<milliseconds>(steady_clock::now() - peer.handshake_started_at) : milliseconds::zero();

        WEBRTC_LOG_INFO(
            "dtls handshake complete remote={} role={} stream={} session={} profile={} key_size={} salt_size={} packets={} bytes={} "
            "timeout_events={} retransmission_packets={} duration_ms={} fingerprint_verified={}",
            remote_endpoint,
            dtls_peer_role_to_string(peer.identity.role),
            peer.identity.stream_id,
            peer.identity.session_id,
            srtp_profile_id_to_string(peer.keying_material->profile),
            peer.keying_material->master_key_size,
            peer.keying_material->master_salt_size,
            peer.packet_count,
            peer.byte_count,
            peer.timeout_event_count,
            peer.retransmission_packet_count,
            elapsed.count(),
            peer.fingerprint_verified ? 1 : 0);

        return {};
    }

    void log_packet_locked(dtls_peer_context& peer, std::span<const uint8_t> data, std::string_view remote_endpoint, const dtls_record_header& header)
    {
        if (header.content_type == dtls_record_content_type::handshake)
        {
            const dtls_handshake_type handshake_type = get_dtls_handshake_type(data);

            if (handshake_type == dtls_handshake_type::client_hello)
            {
                peer.saw_client_hello = true;

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

    dtls_transport_config config_;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, dtls_peer_context> peers_by_endpoint_;
};

dtls_transport::dtls_transport(std::shared_ptr<dtls_context> context, dtls_transport_config config)
    : impl_(std::make_unique<impl>(std::move(context), std::move(config)))
{
}

dtls_transport::~dtls_transport() = default;

void dtls_transport::remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity)
{
    impl_->remember_peer(remote_endpoint, std::move(identity));
}

dtls_transport_packet_result dtls_transport::close_peer(std::string_view remote_endpoint) { return impl_->close_peer(remote_endpoint); }

void dtls_transport::forget_peer(std::string_view remote_endpoint) { impl_->forget_peer(remote_endpoint); }

dtls_transport_packet_result dtls_transport::handle_udp_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
{
    return impl_->handle_udp_packet(data, remote_endpoint);
}

dtls_timeout_event_list dtls_transport::handle_timeouts() { return impl_->handle_timeouts(); }

std::optional<std::chrono::milliseconds> dtls_transport::next_timeout() const { return impl_->next_timeout(); }

std::optional<srtp_keying_material> dtls_transport::get_srtp_keying_material(std::string_view remote_endpoint) const
{
    return impl_->get_srtp_keying_material(remote_endpoint);
}

bool dtls_transport::is_handshake_done(std::string_view remote_endpoint) const { return impl_->is_handshake_done(remote_endpoint); }

std::size_t dtls_transport::peer_count() const { return impl_->peer_count(); }

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
}    // namespace webrtc
