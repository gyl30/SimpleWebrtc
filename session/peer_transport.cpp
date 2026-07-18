#include "session/peer_transport.h"

#include <string>

namespace webrtc
{
namespace
{
dtls_peer_identity make_dtls_peer_identity(dtls_peer_role role,
                                           const std::string& session_id,
                                           const std::string& stream_id,
                                           const ice_credentials& local_ice,
                                           const sdp::webrtc_offer_summary& remote_offer)
{
    dtls_peer_identity identity;

    identity.role = role;
    identity.session_id = session_id;
    identity.stream_id = stream_id;
    identity.local_ice_ufrag = local_ice.ufrag;
    identity.remote_ice_ufrag = remote_offer.ice_ufrag;
    identity.remote_fingerprint = remote_offer.fingerprint;

    return identity;
}
}    // namespace

dtls_peer_identity make_dtls_peer_identity(const publisher_session& session)
{
    return make_dtls_peer_identity(
        dtls_peer_role::publisher, session.session_id(), session.stream_id(), session.local_ice(), session.remote_offer_summary());
}

dtls_peer_identity make_dtls_peer_identity(const subscriber_session& session)
{
    return make_dtls_peer_identity(
        dtls_peer_role::subscriber, session.session_id(), session.stream_id(), session.local_ice(), session.remote_offer_summary());
}
}    // namespace webrtc
