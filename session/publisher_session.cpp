#include "session/publisher_session.h"

#include <utility>

namespace webrtc
{
publisher_session::publisher_session(std::string session_id, std::string stream_id, std::string remote_sdp_offer, uint64_t created_at_milliseconds)
    : session_id_(std::move(session_id)),
      stream_id_(std::move(stream_id)),
      remote_sdp_offer_(std::move(remote_sdp_offer)),
      state_(session_state::sdp_received),
      created_at_milliseconds_(created_at_milliseconds),
      updated_at_milliseconds_(created_at_milliseconds)
{
}

const std::string& publisher_session::session_id() const { return session_id_; }

const std::string& publisher_session::stream_id() const { return stream_id_; }

const std::string& publisher_session::remote_sdp_offer() const { return remote_sdp_offer_; }

session_state publisher_session::state() const { return state_; }

std::string_view publisher_session::state_string() const { return session_state_to_string(state_); }

uint64_t publisher_session::created_at_milliseconds() const { return created_at_milliseconds_; }

uint64_t publisher_session::updated_at_milliseconds() const { return updated_at_milliseconds_; }

void publisher_session::set_state(session_state state, uint64_t updated_at_milliseconds)
{
    state_ = state;
    updated_at_milliseconds_ = updated_at_milliseconds;
}

void publisher_session::set_local_sdp_answer(std::string local_sdp_answer, uint64_t updated_at_milliseconds)
{
    local_sdp_answer_ = std::move(local_sdp_answer);
    state_ = session_state::sdp_answered;
    updated_at_milliseconds_ = updated_at_milliseconds;
}

const std::string& publisher_session::local_sdp_answer() const { return local_sdp_answer_; }
}    // namespace webrtc
