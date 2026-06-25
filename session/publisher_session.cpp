#include "session/publisher_session.h"

#include <utility>

#include "util/timestamp.h"

namespace webrtc
{
namespace
{
uint64_t now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }
}    // namespace

publisher_session::publisher_session(std::string session_id,
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

const std::string& publisher_session::session_id() const { return session_id_; }

const std::string& publisher_session::stream_id() const { return stream_id_; }

const std::string& publisher_session::remote_sdp_offer() const { return remote_sdp_offer_; }

const sdp::webrtc_offer_summary& publisher_session::remote_offer_summary() const { return remote_offer_summary_; }

const std::string& publisher_session::local_sdp_answer() const { return local_sdp_answer_; }

session_state publisher_session::state() const { return state_; }

std::string publisher_session::state_string() const { return std::string(session_state_to_string(state_)); }

uint64_t publisher_session::created_at_milliseconds() const { return created_at_milliseconds_; }

uint64_t publisher_session::updated_at_milliseconds() const { return updated_at_milliseconds_; }

void publisher_session::set_state(session_state state)
{
    state_ = state;
    updated_at_milliseconds_ = now_milliseconds();
}

void publisher_session::set_local_sdp_answer(std::string local_sdp_answer)
{
    local_sdp_answer_ = std::move(local_sdp_answer);
    state_ = session_state::sdp_answered;
    updated_at_milliseconds_ = now_milliseconds();
}
}    // namespace webrtc
