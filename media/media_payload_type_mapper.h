#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_PAYLOAD_TYPE_MAPPER_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_PAYLOAD_TYPE_MAPPER_H

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
struct media_payload_type_mapping
{
    std::string stream_id;

    std::string kind;

    std::string publisher_mid;
    std::string subscriber_mid;

    uint16_t publisher_payload_type = 0;
    uint16_t subscriber_payload_type = 0;

    std::string codec_name;
    uint32_t clock_rate = 0;
    std::string encoding_parameters;

    bool rtx = false;
    uint16_t publisher_apt_payload_type = 0;
    uint16_t subscriber_apt_payload_type = 0;

    bool payload_type_rewrite_required = false;
    bool mid_rewrite_required = false;
};

struct media_payload_type_mapping_table
{
    std::string stream_id;

    std::vector<media_payload_type_mapping> mappings;
};

using media_payload_type_mapping_table_result = std::expected<media_payload_type_mapping_table, std::string>;

[[nodiscard]]
media_payload_type_mapping_table_result build_media_payload_type_mapping_table(std::string_view stream_id,
                                                                               const sdp::webrtc_offer_summary& publisher_offer,
                                                                               const sdp::webrtc_offer_summary& subscriber_offer);

[[nodiscard]]
std::optional<media_payload_type_mapping> find_media_payload_type_mapping(const media_payload_type_mapping_table& table,
                                                                          std::string_view publisher_mid,
                                                                          uint16_t publisher_payload_type);

[[nodiscard]]
std::optional<media_payload_type_mapping> find_media_payload_type_mapping_by_kind(const media_payload_type_mapping_table& table,
                                                                                  std::string_view kind,
                                                                                  uint16_t publisher_payload_type);

[[nodiscard]]
bool media_payload_type_mapping_requires_packet_rewrite(const media_payload_type_mapping& mapping);

[[nodiscard]]
bool media_payload_type_mapping_is_rtx(const media_payload_type_mapping& mapping);

[[nodiscard]]
bool media_payload_type_is_rtx(const sdp::media_summary& media, uint16_t payload_type);

[[nodiscard]]
bool media_offer_payload_type_is_rtx(const sdp::webrtc_offer_summary& offer, std::string_view mid, uint16_t payload_type);

[[nodiscard]]
bool media_payload_type_is_unsupported_repair_codec(const sdp::media_summary& media, uint16_t payload_type);

[[nodiscard]]
bool media_offer_payload_type_is_unsupported_repair_codec(const sdp::webrtc_offer_summary& offer, std::string_view mid, uint16_t payload_type);

[[nodiscard]]
bool media_payload_type_is_forwardable_media(const sdp::media_summary& media, uint16_t payload_type);

[[nodiscard]]
bool media_offer_payload_type_is_forwardable_media(const sdp::webrtc_offer_summary& offer, std::string_view mid, uint16_t payload_type);

[[nodiscard]]
std::string media_payload_type_mapping_to_string(const media_payload_type_mapping& mapping);
}    // namespace webrtc

#endif
