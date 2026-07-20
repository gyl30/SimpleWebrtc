#include "session/session_transport_peer_rebind.h"

#include <expected>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "dtls/dtls_transport.h"
#include "net/socket.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
session_transport_peer_rebind_result rebind_session_transport_peer(const std::shared_ptr<dtls_transport>& dtls_transport,
                                                                   const std::shared_ptr<srtp_transport>& srtp_transport,
                                                                   const boost::asio::ip::udp::endpoint& previous_endpoint,
                                                                   const boost::asio::ip::udp::endpoint& next_endpoint,
                                                                   const dtls_peer_identity& previous_identity,
                                                                   const dtls_peer_identity& next_identity)
{
    if (dtls_transport == nullptr || srtp_transport == nullptr)
    {
        return std::unexpected(std::string("session transport peer rebind dependency is null"));
    }

    const std::string previous_remote = format_udp_endpoint(previous_endpoint);
    const std::string next_remote = format_udp_endpoint(next_endpoint);

    auto srtp_rebind = srtp_transport->rebind_peer(previous_remote, next_remote, next_identity);

    if (!srtp_rebind)
    {
        return std::unexpected(srtp_rebind.error());
    }

    const dtls_network_family network_family = next_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

    auto dtls_rebind = dtls_transport->rebind_peer(previous_remote, next_remote, next_identity, network_family);

    if (!dtls_rebind)
    {
        if (*srtp_rebind)
        {
            auto rollback = srtp_transport->rebind_peer(next_remote, previous_remote, previous_identity);

            if (!rollback || !*rollback)
            {
                srtp_transport->forget_peer(next_remote);
                srtp_transport->forget_peer(previous_remote);
            }
        }

        return std::unexpected(dtls_rebind.error());
    }

    if (!*dtls_rebind)
    {
        if (*srtp_rebind)
        {
            auto rollback = srtp_transport->rebind_peer(next_remote, previous_remote, previous_identity);

            if (!rollback || !*rollback)
            {
                srtp_transport->forget_peer(next_remote);
                srtp_transport->forget_peer(previous_remote);
            }
        }

        srtp_transport->forget_peer(previous_remote);
        dtls_transport->forget_peer(previous_remote);
        return false;
    }

    return true;
}
}    // namespace webrtc
