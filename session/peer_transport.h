#ifndef SIMPLE_WEBRTC_SESSION_PEER_TRANSPORT_H
#define SIMPLE_WEBRTC_SESSION_PEER_TRANSPORT_H

#include "dtls/dtls_transport.h"
#include "session/publisher_session.h"
#include "session/subscriber_session.h"

namespace webrtc
{
[[nodiscard]] dtls_peer_identity make_dtls_peer_identity(const publisher_session& session);

[[nodiscard]] dtls_peer_identity make_dtls_peer_identity(const subscriber_session& session);
}    // namespace webrtc

#endif
