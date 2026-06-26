#ifndef SIMPLE_WEBRTC_SESSION_PUBLISHER_SESSION_H
#define SIMPLE_WEBRTC_SESSION_PUBLISHER_SESSION_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "ice/ice_candidate.h"
#include "ice/ice_credentials.h"
#include "session/session_state.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
class publisher_session
{
   public:
    publisher_session(std::string session_id,
                      std::string stream_id,
                      std::string remote_sdp_offer,
                      sdp::webrtc_offer_summary remote_offer_summary,
                      uint64_t created_at_milliseconds);

    ~publisher_session() = default;

    publisher_session(const publisher_session&) = delete;

    publisher_session& operator=(const publisher_session&) = delete;

    publisher_session(publisher_session&&) = delete;

    publisher_session& operator=(publisher_session&&) = delete;

   public:
    [[nodiscard]] const std::string& session_id() const;

    [[nodiscard]] const std::string& stream_id() const;

    [[nodiscard]] const std::string& remote_sdp_offer() const;

    [[nodiscard]] const sdp::webrtc_offer_summary& remote_offer_summary() const;

    [[nodiscard]] const std::string& local_sdp_answer() const;

    [[nodiscard]] const ice_credentials& local_ice() const;

    [[nodiscard]] const sdp::fingerprint_info& local_fingerprint() const;

    [[nodiscard]] uint64_t sdp_session_id() const;

    [[nodiscard]] uint64_t sdp_session_version() const;

    [[nodiscard]] const std::vector<remote_ice_candidate>& remote_ice_candidates() const;

    [[nodiscard]] bool remote_ice_completed() const;

    [[nodiscard]] session_state state() const;

    [[nodiscard]] std::string state_string() const;

    [[nodiscard]] uint64_t created_at_milliseconds() const;

    [[nodiscard]] uint64_t updated_at_milliseconds() const;

   public:
    void set_state(session_state state);

    void set_local_sdp_answer(std::string local_sdp_answer);

    void set_local_answer(std::string local_sdp_answer,
                          ice_credentials local_ice,
                          sdp::fingerprint_info local_fingerprint,
                          uint64_t sdp_session_id,
                          uint64_t sdp_session_version);

    [[nodiscard]] std::expected<void, std::string> add_remote_ice_candidate(remote_ice_candidate candidate);

   private:
    std::string session_id_;
    std::string stream_id_;

    std::string remote_sdp_offer_;
    sdp::webrtc_offer_summary remote_offer_summary_;

    std::string local_sdp_answer_;
    ice_credentials local_ice_;
    sdp::fingerprint_info local_fingerprint_;

    uint64_t sdp_session_id_ = 0;
    uint64_t sdp_session_version_ = 0;

    std::vector<remote_ice_candidate> remote_ice_candidates_;

    bool remote_ice_completed_ = false;

    session_state state_ = session_state::created;

    uint64_t created_at_milliseconds_ = 0;
    uint64_t updated_at_milliseconds_ = 0;
};
}    // namespace webrtc

#endif
