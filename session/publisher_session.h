#ifndef SIMPLE_WEBRTC_SESSION_PUBLISHER_SESSION_H
#define SIMPLE_WEBRTC_SESSION_PUBLISHER_SESSION_H

#include <cstdint>
#include <string>
#include <string_view>

#include "session/session_state.h"

namespace webrtc
{
class publisher_session
{
   public:
    publisher_session(std::string session_id, std::string stream_id, std::string remote_sdp_offer, uint64_t created_at_milliseconds);

   public:
    const std::string& session_id() const;
    const std::string& stream_id() const;
    const std::string& remote_sdp_offer() const;

    session_state state() const;
    std::string_view state_string() const;

    uint64_t created_at_milliseconds() const;
    uint64_t updated_at_milliseconds() const;

   public:
    void set_state(session_state state, uint64_t updated_at_milliseconds);
    void set_local_sdp_answer(std::string local_sdp_answer, uint64_t updated_at_milliseconds);

    const std::string& local_sdp_answer() const;

   private:
    std::string session_id_;
    std::string stream_id_;
    std::string remote_sdp_offer_;
    std::string local_sdp_answer_;
    session_state state_ = session_state::created;
    uint64_t created_at_milliseconds_ = 0;
    uint64_t updated_at_milliseconds_ = 0;
};
}    // namespace webrtc

#endif
