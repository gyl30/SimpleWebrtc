#ifndef SIMPLE_WEBRTC_SESSION_SUBSCRIBER_SESSION_H
#define SIMPLE_WEBRTC_SESSION_SUBSCRIBER_SESSION_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "ice/ice_candidate.h"
#include "ice/ice_credentials.h"
#include "net/udp_port_allocator.h"
#include "session/whep_session_transport.h"
#include "signaling/sdp/sdp_summary.h"
#include "signaling/sdp/sdp_answer_builder.h"

namespace webrtc
{
class subscriber_session
{
   public:
    subscriber_session(std::string session_id,
                       std::string stream_id,
                       sdp::webrtc_offer_summary remote_offer_summary,
                       uint64_t created_at_milliseconds);

    ~subscriber_session() = default;

    subscriber_session(const subscriber_session&) = delete;

    subscriber_session& operator=(const subscriber_session&) = delete;

    subscriber_session(subscriber_session&&) = delete;

    subscriber_session& operator=(subscriber_session&&) = delete;

   public:
    [[nodiscard]] const std::string& session_id() const;

    [[nodiscard]] const std::string& stream_id() const;

    [[nodiscard]] const sdp::webrtc_offer_summary& remote_offer_summary() const;

    [[nodiscard]] const ice_credentials& local_ice() const;

    [[nodiscard]] uint16_t local_udp_port() const;

    [[nodiscard]] uint64_t sdp_session_id() const;

    [[nodiscard]] uint64_t sdp_session_version() const;

    [[nodiscard]] const std::vector<remote_ice_candidate>& remote_ice_candidates() const;

    [[nodiscard]] bool remote_ice_completed() const;

    [[nodiscard]] const std::vector<int>& accepted_remote_media_mline_indexes() const;

    [[nodiscard]] const std::vector<sdp::sdp_answer_media_source>& outbound_media_sources() const;

    [[nodiscard]] uint64_t created_at_milliseconds() const;

    [[nodiscard]] uint64_t updated_at_milliseconds() const;

   public:
    void complete_initial_setup(ice_credentials local_ice,
                                uint64_t sdp_session_id,
                                uint64_t sdp_session_version,
                                std::vector<int> accepted_remote_media_mline_indexes,
                                std::vector<sdp::sdp_answer_media_source> outbound_media_sources,
                                udp_port_reservation_ptr local_udp_port,
                                std::shared_ptr<whep_session_transport> transport);

    void apply_remote_ice_restart(sdp::webrtc_offer_summary remote_offer_summary,
                                  std::vector<int> accepted_remote_media_mline_indexes,
                                  ice_credentials local_ice,
                                  uint64_t sdp_session_id,
                                  uint64_t sdp_session_version);

    [[nodiscard]] std::expected<void, std::string> add_remote_ice_candidate(remote_ice_candidate candidate);

   private:
    std::string session_id_;
    std::string stream_id_;

    sdp::webrtc_offer_summary remote_offer_summary_;

    ice_credentials local_ice_;
    udp_port_reservation_ptr local_udp_port_;
    std::shared_ptr<whep_session_transport> transport_;

    uint64_t sdp_session_id_ = 0;
    uint64_t sdp_session_version_ = 0;

    std::vector<remote_ice_candidate> remote_ice_candidates_;
    std::vector<int> accepted_remote_media_mline_indexes_;
    std::vector<sdp::sdp_answer_media_source> outbound_media_sources_;

    uint64_t created_at_milliseconds_ = 0;
    uint64_t updated_at_milliseconds_ = 0;
};
}    // namespace webrtc

#endif
