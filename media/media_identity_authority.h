#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_IDENTITY_AUTHORITY_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_IDENTITY_AUTHORITY_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "media/media_payload_type_mapper.h"
#include "media/media_ssrc_mapper.h"
#include "media/media_track_resolver.h"

namespace webrtc
{
struct media_identity_track_binding
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    std::string mid;
    std::string kind;

    std::optional<std::string> rid;
    std::optional<std::string> repaired_rid;

    uint32_t ssrc = 0;
    uint8_t payload_type = 0;

    bool rtx = false;

    uint64_t packet_count = 0;
};
struct media_identity_rid_layer_binding
{
    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    std::string mid;
    std::string kind;
    std::string rid;

    uint32_t primary_ssrc = 0;
    uint32_t repair_ssrc = 0;

    uint16_t primary_payload_type = 0;
    uint16_t repair_payload_type = 0;

    uint64_t packet_count = 0;
};
struct media_identity_forward_binding
{
    std::string stream_id;

    std::string publisher_session_id;
    std::string subscriber_session_id;

    std::string publisher_mid;
    std::string subscriber_mid;
    std::string kind;

    uint32_t publisher_ssrc = 0;
    uint32_t subscriber_ssrc = 0;

    uint16_t publisher_payload_type = 0;
    uint16_t subscriber_payload_type = 0;

    bool rtx = false;
    uint16_t publisher_apt_payload_type = 0;
    uint16_t subscriber_apt_payload_type = 0;

    uint32_t publisher_rtx_primary_ssrc = 0;
    uint32_t publisher_rtx_repair_ssrc = 0;

    bool payload_type_rewrite_required = false;
    bool mid_rewrite_required = false;
    bool ssrc_rewrite_required = false;

    uint64_t packet_count = 0;
};

using media_identity_result = std::expected<void, std::string>;

class media_identity_authority
{
   public:
    media_identity_authority() = default;
    ~media_identity_authority() = default;

    media_identity_authority(const media_identity_authority&) = delete;
    media_identity_authority& operator=(const media_identity_authority&) = delete;

    media_identity_authority(media_identity_authority&&) = delete;
    media_identity_authority& operator=(media_identity_authority&&) = delete;

   public:
    [[nodiscard]]
    media_identity_result remember_track_resolution(const media_track_resolution& resolution, bool rtx);

    [[nodiscard]]
    media_identity_result remember_forward_mapping(const media_ssrc_mapping& ssrc_mapping, const media_payload_type_mapping& payload_mapping);

    [[nodiscard]]
    std::optional<media_identity_track_binding> find_track_by_peer_ssrc(std::string_view remote_endpoint, uint32_t ssrc) const;

    [[nodiscard]]
    std::optional<media_identity_rid_layer_binding> find_rid_layer_by_rid(std::string_view stream_id,
                                                                          std::string_view session_id,
                                                                          std::string_view mid,
                                                                          std::string_view rid) const;

    [[nodiscard]]
    std::optional<media_identity_rid_layer_binding> find_rid_layer_by_primary_ssrc(std::string_view session_id, uint32_t primary_ssrc) const;

    [[nodiscard]]
    std::optional<media_identity_rid_layer_binding> find_rid_layer_by_repair_ssrc(std::string_view session_id, uint32_t repair_ssrc) const;

    [[nodiscard]]
    std::optional<media_identity_forward_binding> find_forward_by_publisher_ssrc(std::string_view stream_id,
                                                                                 std::string_view publisher_session_id,
                                                                                 std::string_view subscriber_session_id,
                                                                                 std::string_view publisher_mid,
                                                                                 uint32_t publisher_ssrc) const;

    [[nodiscard]]
    std::optional<media_identity_forward_binding> find_forward_by_subscriber_ssrc(std::string_view subscriber_session_id,
                                                                                  uint32_t subscriber_ssrc) const;

    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_ssrc_mapping_by_publisher_ssrc(std::string_view stream_id,
                                                                          std::string_view publisher_session_id,
                                                                          std::string_view subscriber_session_id,
                                                                          std::string_view publisher_mid,
                                                                          uint32_t publisher_ssrc) const;

    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_ssrc_mapping_by_subscriber_ssrc(std::string_view subscriber_session_id, uint32_t subscriber_ssrc) const;

    void forget_peer(std::string_view remote_endpoint);

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    void clear();

    [[nodiscard]]
    std::size_t track_binding_count() const;

    [[nodiscard]]
    std::size_t forward_binding_count() const;

    [[nodiscard]]
    std::size_t rid_layer_binding_count() const;

   private:
    [[nodiscard]]
    static std::string make_peer_ssrc_key(std::string_view remote_endpoint, uint32_t ssrc);

    [[nodiscard]]
    static std::string make_publisher_forward_key(std::string_view stream_id,
                                                  std::string_view publisher_session_id,
                                                  std::string_view subscriber_session_id,
                                                  std::string_view publisher_mid,
                                                  uint32_t publisher_ssrc);

    [[nodiscard]]
    static std::string make_subscriber_forward_key(std::string_view subscriber_session_id, uint32_t subscriber_ssrc);

    [[nodiscard]]
    static std::string make_rid_layer_key(std::string_view stream_id, std::string_view session_id, std::string_view mid, std::string_view rid);

    [[nodiscard]]
    static std::string make_session_ssrc_key(std::string_view session_id, uint32_t ssrc);

    [[nodiscard]]
    static media_identity_result validate_track_binding(const media_identity_track_binding& binding);

    [[nodiscard]]
    static media_identity_result validate_forward_binding(const media_identity_forward_binding& binding);

    [[nodiscard]]
    static media_identity_result validate_rid_layer_binding(const media_identity_rid_layer_binding& binding);

    [[nodiscard]]
    media_identity_result remember_rid_layer_binding_locked(const media_track_resolution& resolution,
                                                            const media_identity_track_binding& track_binding);

    void erase_rid_layer_indexes_locked(const media_identity_rid_layer_binding& binding);

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, media_identity_track_binding> tracks_by_peer_ssrc_;
    std::unordered_map<std::string, media_identity_rid_layer_binding> rid_layers_by_key_;
    std::unordered_map<std::string, std::string> rid_layer_key_by_primary_ssrc_key_;
    std::unordered_map<std::string, std::string> rid_layer_key_by_repair_ssrc_key_;
    std::unordered_map<std::string, media_identity_forward_binding> forwards_by_publisher_key_;
    std::unordered_map<std::string, std::string> publisher_key_by_subscriber_key_;
};

[[nodiscard]]
std::string media_identity_track_binding_to_string(const media_identity_track_binding& binding);

[[nodiscard]]
std::string media_identity_forward_binding_to_string(const media_identity_forward_binding& binding);
}    // namespace webrtc

#endif
