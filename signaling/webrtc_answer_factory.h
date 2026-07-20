#ifndef SIMPLE_WEBRTC_SIGNALING_WEBRTC_ANSWER_FACTORY_H
#define SIMPLE_WEBRTC_SIGNALING_WEBRTC_ANSWER_FACTORY_H

#include <atomic>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ice/ice_credentials.h"
#include "signaling/sdp/sdp_answer_builder.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
struct generated_sdp_answer
{
    std::string sdp;

    ice_credentials local_ice;

    std::vector<int> accepted_mline_indexes;
};

using generated_sdp_answer_result = std::expected<generated_sdp_answer, std::string>;

class webrtc_answer_factory
{
   public:
    explicit webrtc_answer_factory(sdp::fingerprint_info local_fingerprint, std::vector<std::string> ice_candidate_addresses);

    webrtc_answer_factory(const webrtc_answer_factory&) = delete;

    webrtc_answer_factory& operator=(const webrtc_answer_factory&) = delete;

    webrtc_answer_factory(webrtc_answer_factory&&) = delete;

    webrtc_answer_factory& operator=(webrtc_answer_factory&&) = delete;

    ~webrtc_answer_factory() = default;

   public:
    [[nodiscard]]
    generated_sdp_answer_result build_whip_answer(std::string_view stream_id, const sdp::webrtc_offer_summary& offer, uint16_t local_candidate_port);

    [[nodiscard]]
    generated_sdp_answer_result build_whep_answer(std::string_view stream_id,
                                                  const sdp::webrtc_offer_summary& subscriber_offer,
                                                  const sdp::webrtc_offer_summary& publisher_offer,
                                                  std::span<const sdp::sdp_answer_media_source> media_sources,
                                                  uint16_t local_candidate_port);

   private:
    [[nodiscard]]
    generated_sdp_answer_result build_answer(std::string_view stream_id,
                                             const sdp::webrtc_offer_summary& offer,
                                             const sdp::webrtc_offer_summary* whep_publisher_offer,
                                             std::span<const sdp::sdp_answer_media_source> media_sources,
                                             uint16_t local_candidate_port);

    [[nodiscard]]
    static uint64_t make_initial_session_id();

   private:
    sdp::fingerprint_info local_fingerprint_;

    std::vector<std::string> ice_candidate_addresses_;

    std::atomic<uint64_t> next_session_id_;
};
}    // namespace webrtc

#endif
