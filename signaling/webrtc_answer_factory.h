#ifndef SIMPLE_WEBRTC_SIGNALING_WEBRTC_ANSWER_FACTORY_H
#define SIMPLE_WEBRTC_SIGNALING_WEBRTC_ANSWER_FACTORY_H

#include <atomic>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "ice/ice_credentials.h"
#include "signaling/sdp/sdp_answer_builder.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
struct webrtc_answer_factory_config
{
    sdp::fingerprint_info local_fingerprint;

    std::string origin_username = "-";
    std::string network_type = "IN";
    std::string address_type = "IP4";
    std::string unicast_address = "0.0.0.0";
    std::string media_address = "0.0.0.0";

    sdp::dtls_connection_role local_setup = sdp::dtls_connection_role::passive;

    bool ice_lite = true;
    bool enable_trickle = true;

    bool include_host_candidate = false;

    std::string ice_candidate_address = "127.0.0.1";
    uint16_t ice_candidate_port = 0;
    std::string ice_candidate_foundation = "1";
    uint32_t ice_candidate_component = 1;
    std::string ice_candidate_transport = "udp";
    uint32_t ice_candidate_priority = 2130706431;
    std::string ice_candidate_type = "host";

    std::vector<sdp::sdp_ice_candidate_options> ice_candidates;

    bool end_of_candidates = true;

    std::string local_stream_id_prefix = "webrtc";
};

struct generated_sdp_answer
{
    std::string sdp;

    ice_credentials local_ice;

    uint64_t sdp_session_id = 0;
    uint64_t sdp_session_version = 0;

    std::vector<sdp::sdp_answer_media_source> media_sources;
};

using generated_sdp_answer_result = std::expected<generated_sdp_answer, std::string>;

class webrtc_answer_factory
{
   public:
    explicit webrtc_answer_factory(webrtc_answer_factory_config config);

    webrtc_answer_factory(const webrtc_answer_factory&) = delete;

    webrtc_answer_factory& operator=(const webrtc_answer_factory&) = delete;

    webrtc_answer_factory(webrtc_answer_factory&&) = delete;

    webrtc_answer_factory& operator=(webrtc_answer_factory&&) = delete;

    ~webrtc_answer_factory() = default;

   public:
    [[nodiscard]]
    generated_sdp_answer_result build_whip_answer(std::string_view stream_id,
                                                  const sdp::webrtc_offer_summary& offer,
                                                  uint16_t local_candidate_port);

    [[nodiscard]]
    generated_sdp_answer_result build_whep_answer(std::string_view stream_id,
                                                  const sdp::webrtc_offer_summary& subscriber_offer,
                                                  const sdp::webrtc_offer_summary& publisher_offer,
                                                  std::vector<sdp::sdp_answer_media_source> media_sources,
                                                  uint16_t local_candidate_port);

    [[nodiscard]]
    generated_sdp_answer_result build_whip_restart_answer(std::string_view stream_id,
                                                          const sdp::webrtc_offer_summary& offer,
                                                          uint64_t sdp_session_id,
                                                          uint64_t sdp_session_version,
                                                          uint16_t local_candidate_port);

    [[nodiscard]]
    generated_sdp_answer_result build_whep_restart_answer(std::string_view stream_id,
                                                          const sdp::webrtc_offer_summary& subscriber_offer,
                                                          const sdp::webrtc_offer_summary& publisher_offer,
                                                          uint64_t sdp_session_id,
                                                          uint64_t sdp_session_version,
                                                          std::vector<sdp::sdp_answer_media_source> media_sources,
                                                          uint16_t local_candidate_port);

   private:
    [[nodiscard]]
    std::expected<void, std::string> validate_config() const;

    [[nodiscard]]
    sdp::sdp_answer_options make_answer_options(std::string_view stream_id,
                                                const ice_credentials& local_ice,
                                                uint64_t session_id,
                                                uint64_t session_version,
                                                uint16_t local_candidate_port) const;

    [[nodiscard]]
    generated_sdp_answer_result build_answer(bool is_whip,
                                             std::string_view stream_id,
                                             const sdp::webrtc_offer_summary& offer,
                                             const sdp::webrtc_offer_summary* whep_publisher_offer,
                                             std::vector<sdp::sdp_answer_media_source> media_sources,
                                             uint16_t local_candidate_port);

    [[nodiscard]]
    generated_sdp_answer_result build_answer_with_origin(bool is_whip,
                                                         std::string_view stream_id,
                                                         const sdp::webrtc_offer_summary& offer,
                                                         const sdp::webrtc_offer_summary* whep_publisher_offer,
                                                         uint64_t sdp_session_id,
                                                         uint64_t sdp_session_version,
                                                         std::vector<sdp::sdp_answer_media_source> media_sources,
                                                         uint16_t local_candidate_port);
    [[nodiscard]]
    static uint64_t make_initial_session_id();

   private:
    webrtc_answer_factory_config config_;

    std::atomic<uint64_t> next_session_id_;
};
}    // namespace webrtc

#endif
