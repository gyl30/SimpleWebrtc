#ifndef SIMPLE_WEBRTC_SESSION_SESSION_TRANSPORT_PEER_REBIND_H
#define SIMPLE_WEBRTC_SESSION_SESSION_TRANSPORT_PEER_REBIND_H

#include <expected>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "dtls/dtls_transport.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
using session_transport_peer_rebind_result = std::expected<bool, std::string>;

[[nodiscard]]
session_transport_peer_rebind_result rebind_session_transport_peer(
    const std::shared_ptr<dtls_transport>& dtls_transport,
    const std::shared_ptr<srtp_transport>& srtp_transport,
    const boost::asio::ip::udp::endpoint& previous_endpoint,
    const boost::asio::ip::udp::endpoint& next_endpoint,
    const dtls_peer_identity& previous_identity,
    const dtls_peer_identity& next_identity);
}    // namespace webrtc

#endif
