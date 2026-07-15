#include "session/peer_transport.h"

#include <string>
#include <string_view>

namespace webrtc
{
namespace
{
std::string make_dtls_session_generation_id(std::string_view session_id, std::string_view local_ice_ufrag, std::string_view remote_ice_ufrag)
{
    std::string generation;

    generation.reserve(session_id.size() + local_ice_ufrag.size() + remote_ice_ufrag.size() + 3);

    generation.append(session_id);
    generation.push_back('|');
    generation.append(local_ice_ufrag);
    generation.push_back('|');
    generation.append(remote_ice_ufrag);

    return generation;
}

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
    identity.generation = make_dtls_session_generation_id(identity.session_id, identity.local_ice_ufrag, identity.remote_ice_ufrag);
    identity.local_setup = sdp::dtls_connection_role::passive;
    identity.remote_setup = remote_offer.setup;
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
