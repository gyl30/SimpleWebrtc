#ifndef SIMPLE_WEBRTC_MEDIA_WHEP_RTP_REWRITER_H
#define SIMPLE_WEBRTC_MEDIA_WHEP_RTP_REWRITER_H

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "signaling/sdp/sdp_answer_builder.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
struct whep_rtp_payload_type_mapping
{
    uint8_t source_payload_type = 0;
    uint8_t target_payload_type = 0;
    uint32_t clock_rate = 0;

    bool rtx = false;

    uint8_t source_associated_payload_type = 0;
    uint8_t target_associated_payload_type = 0;
};

struct whep_rtp_header_extension_mapping
{
    uint8_t source_id = 0;
    uint8_t target_id = 0;
    std::string uri;
};

struct whep_rtp_media_mapping
{
    std::string kind;
    std::string source_mid;
    std::string target_mid;

    uint32_t target_ssrc = 0;
    uint32_t target_rtx_ssrc = 0;

    bool target_extmap_allow_mixed = false;

    std::vector<whep_rtp_payload_type_mapping> payload_types;
    std::vector<whep_rtp_header_extension_mapping> header_extensions;
};

struct whep_rtp_rewriter_target
{
    sdp::webrtc_offer_summary subscriber_offer;
    std::vector<int> accepted_mline_indexes;
    std::vector<sdp::sdp_answer_media_source> accepted_media_sources;
};

struct whep_rtp_rewriter_config
{
    std::string source_session_id;
    std::vector<whep_rtp_media_mapping> media;
};

using whep_rtp_rewriter_config_result = std::expected<whep_rtp_rewriter_config, std::string>;

[[nodiscard]]
whep_rtp_rewriter_config_result make_whep_rtp_rewriter_config(
    std::string_view publisher_session_id,
    const sdp::webrtc_offer_summary& publisher_offer,
    const whep_rtp_rewriter_target& target);

enum class whep_rtp_rewrite_state
{
    rewritten,
    dropped,
};

struct whep_rtp_rewrite_result
{
    whep_rtp_rewrite_state state = whep_rtp_rewrite_state::dropped;

    std::vector<uint8_t> packet;
    std::string reason;
    std::string kind;

    bool rtx = false;
    bool keyframe_request_needed = false;

    uint32_t source_ssrc = 0;
    uint32_t target_ssrc = 0;

    uint8_t source_payload_type = 0;
    uint8_t target_payload_type = 0;

    uint16_t source_sequence_number = 0;
    uint16_t target_sequence_number = 0;

    uint32_t source_timestamp = 0;
    uint32_t target_timestamp = 0;
};

using whep_rtp_rewrite_packet_result = std::expected<whep_rtp_rewrite_result, std::string>;

class whep_rtp_rewriter
{
   public:
    whep_rtp_rewriter();
    ~whep_rtp_rewriter();

    whep_rtp_rewriter(const whep_rtp_rewriter&) = delete;
    whep_rtp_rewriter& operator=(const whep_rtp_rewriter&) = delete;

    whep_rtp_rewriter(whep_rtp_rewriter&&) = delete;
    whep_rtp_rewriter& operator=(whep_rtp_rewriter&&) = delete;

   public:
    void set_config(whep_rtp_rewriter_config config);

    void clear_source();

    [[nodiscard]] whep_rtp_rewrite_packet_result rewrite(std::span<const uint8_t> packet);

   private:
    struct impl;

    std::unique_ptr<impl> impl_;
};

[[nodiscard]] std::string_view whep_rtp_rewrite_state_to_string(whep_rtp_rewrite_state state);
}    // namespace webrtc

#endif
