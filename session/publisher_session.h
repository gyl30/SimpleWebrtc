#ifndef SIMPLE_WEBRTC_SESSION_PUBLISHER_SESSION_H
#define SIMPLE_WEBRTC_SESSION_PUBLISHER_SESSION_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "ice/ice_candidate.h"
#include "ice/ice_credentials.h"
#include "net/udp_port_allocator.h"
#include "session/whip_session_transport.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
class publisher_session
{
   public:
    publisher_session(std::string session_id,
                      std::string stream_id,
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

    [[nodiscard]] const sdp::webrtc_offer_summary& remote_offer_summary() const;

    [[nodiscard]] const ice_credentials& local_ice() const;

    [[nodiscard]] uint16_t local_udp_port() const;

    [[nodiscard]] uint64_t sdp_session_id() const;

    [[nodiscard]] uint64_t sdp_session_version() const;

    [[nodiscard]] const std::vector<remote_ice_candidate>& remote_ice_candidates() const;

    [[nodiscard]] bool remote_ice_completed() const;

    [[nodiscard]] const std::vector<int>& accepted_remote_media_mline_indexes() const;

    [[nodiscard]] uint64_t created_at_milliseconds() const;

    [[nodiscard]] uint64_t updated_at_milliseconds() const;

   public:
    void complete_initial_setup(ice_credentials local_ice,
                                uint64_t sdp_session_id,
                                uint64_t sdp_session_version,
                                std::vector<int> accepted_remote_media_mline_indexes,
                                udp_port_reservation_ptr local_udp_port,
                                std::shared_ptr<whip_session_transport> transport);

    void request_keyframe(uint32_t media_ssrc);

    void set_publisher_source_generation(uint64_t source_generation);

    void close(std::string_view reason);

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
    std::shared_ptr<whip_session_transport> transport_;

    uint64_t sdp_session_id_ = 0;
    uint64_t sdp_session_version_ = 0;

    std::vector<remote_ice_candidate> remote_ice_candidates_;

    std::vector<int> accepted_remote_media_mline_indexes_;

    uint64_t created_at_milliseconds_ = 0;
    uint64_t updated_at_milliseconds_ = 0;
};
}    // namespace webrtc

#endif
