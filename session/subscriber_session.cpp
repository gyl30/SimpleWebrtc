#include "session/subscriber_session.h"

#include <utility>

#include "util/timestamp.h"

namespace webrtc
{
namespace
{
uint64_t now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }
}    // namespace

subscriber_session::subscriber_session(std::string session_id,
                                       std::string stream_id,
                                       std::string remote_sdp_offer,
                                       sdp::webrtc_offer_summary remote_offer_summary,
                                       uint64_t created_at_milliseconds)
    : session_id_(std::move(session_id)),
      stream_id_(std::move(stream_id)),
      remote_sdp_offer_(std::move(remote_sdp_offer)),
      remote_offer_summary_(std::move(remote_offer_summary)),
      state_(session_state::sdp_received),
      created_at_milliseconds_(created_at_milliseconds),
      updated_at_milliseconds_(created_at_milliseconds)
{
}

const std::string& subscriber_session::session_id() const { return session_id_; }

const std::string& subscriber_session::stream_id() const { return stream_id_; }

const std::string& subscriber_session::remote_sdp_offer() const { return remote_sdp_offer_; }

const sdp::webrtc_offer_summary& subscriber_session::remote_offer_summary() const { return remote_offer_summary_; }

const std::string& subscriber_session::local_sdp_answer() const { return local_sdp_answer_; }

const ice_credentials& subscriber_session::local_ice() const { return local_ice_; }

const sdp::fingerprint_info& subscriber_session::local_fingerprint() const { return local_fingerprint_; }

uint64_t subscriber_session::sdp_session_id() const { return sdp_session_id_; }

uint64_t subscriber_session::sdp_session_version() const { return sdp_session_version_; }

session_state subscriber_session::state() const { return state_; }

std::string subscriber_session::state_string() const { return std::string(session_state_to_string(state_)); }

uint64_t subscriber_session::created_at_milliseconds() const { return created_at_milliseconds_; }

uint64_t subscriber_session::updated_at_milliseconds() const { return updated_at_milliseconds_; }

void subscriber_session::set_state(session_state state)
{
    state_ = state;
    updated_at_milliseconds_ = now_milliseconds();
}

void subscriber_session::set_local_sdp_answer(std::string local_sdp_answer)
{
    local_sdp_answer_ = std::move(local_sdp_answer);
    state_ = session_state::sdp_answered;
    updated_at_milliseconds_ = now_milliseconds();
}

void subscriber_session::set_local_answer(std::string local_sdp_answer,
                                          ice_credentials local_ice,
                                          sdp::fingerprint_info local_fingerprint,
                                          uint64_t sdp_session_id,
                                          uint64_t sdp_session_version)
{
    local_sdp_answer_ = std::move(local_sdp_answer);
    local_ice_ = std::move(local_ice);
    local_fingerprint_ = std::move(local_fingerprint);
    sdp_session_id_ = sdp_session_id;
    sdp_session_version_ = sdp_session_version;
    state_ = session_state::sdp_answered;
    updated_at_milliseconds_ = now_milliseconds();
}
}    // namespace webrtc
