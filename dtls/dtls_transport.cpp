#include "dtls/dtls_transport.h"

#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "dtls/dtls_packet.h"
#include "log/log.h"

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

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

    unsigned long error_code = ERR_get_error();

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

using ssl_ptr = std::unique_ptr<SSL, ssl_deleter>;

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
    SSL_set_mtu(ssl, 1200);

    return ssl_owner;
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
}    // namespace

struct dtls_transport::impl
{
    explicit impl(std::shared_ptr<dtls_context> context) : context_(std::move(context)) {}

    struct dtls_peer_context
    {
        dtls_peer_identity identity;

        uint64_t packet_count = 0;
        uint64_t byte_count = 0;

        bool saw_client_hello = false;
        bool saw_dtls_packet = false;
        bool handshake_done = false;

        ssl_ptr ssl;
    };

    void remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity)
    {
        if (remote_endpoint.empty())
        {
            return;
        }

        std::lock_guard lock(mutex_);

        auto& context = peers_by_endpoint_[std::string(remote_endpoint)];

        context.identity = std::move(identity);

        WEBRTC_LOG_INFO("dtls remember peer remote={} role={} stream={} session={} local_ufrag={}",
                        remote_endpoint,
                        dtls_peer_role_to_string(context.identity.role),
                        context.identity.stream_id,
                        context.identity.session_id,
                        context.identity.local_ice_ufrag);
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

        peer->packet_count += 1;
        peer->byte_count += static_cast<uint64_t>(data.size());
        peer->saw_dtls_packet = true;

        if (peer->ssl == nullptr)
        {
            auto ssl_result = make_ssl(context_);

            if (!ssl_result)
            {
                return std::unexpected(ssl_result.error());
            }

            peer->ssl = std::move(*ssl_result);
        }

        auto write_result = write_packet_to_ssl(peer->ssl.get(), data);

        if (!write_result)
        {
            return std::unexpected(write_result.error());
        }

        log_packet_locked(*peer, data, remote_endpoint, *header);

        auto handshake_result = run_dtls_handshake(peer->ssl.get(), packets);

        if (!handshake_result)
        {
            WEBRTC_LOG_WARN(
                "dtls handshake step failed remote={} session={} error={}", remote_endpoint, peer->identity.session_id, handshake_result.error());

            return std::unexpected(handshake_result.error());
        }

        if (!peer->handshake_done && SSL_is_init_finished(peer->ssl.get()) == 1)
        {
            peer->handshake_done = true;

            WEBRTC_LOG_INFO("dtls handshake complete remote={} role={} stream={} session={} packets={} bytes={}",
                            remote_endpoint,
                            dtls_peer_role_to_string(peer->identity.role),
                            peer->identity.stream_id,
                            peer->identity.session_id,
                            peer->packet_count,
                            peer->byte_count);
        }

        return packets;
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
    mutable std::mutex mutex_;
    std::unordered_map<std::string, dtls_peer_context> peers_by_endpoint_;
};

dtls_transport::dtls_transport(std::shared_ptr<dtls_context> context) : impl_(std::make_unique<impl>(std::move(context))) {}

dtls_transport::~dtls_transport() = default;

void dtls_transport::remember_peer(std::string_view remote_endpoint, dtls_peer_identity identity)
{
    impl_->remember_peer(remote_endpoint, std::move(identity));
}

void dtls_transport::forget_peer(std::string_view remote_endpoint) { impl_->forget_peer(remote_endpoint); }

dtls_transport_packet_result dtls_transport::handle_udp_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
{
    return impl_->handle_udp_packet(data, remote_endpoint);
}

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
