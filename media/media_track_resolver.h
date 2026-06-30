#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_TRACK_RESOLVER_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_TRACK_RESOLVER_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include "rtp/rtp_packet.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
enum class media_track_resolution_state
{
    unresolved,
    resolved_by_ssrc,
    resolved_by_mid,
    resolved_by_payload_type,
    resolved_by_single_media,
};

struct media_track_resolution
{
    media_track_resolution_state state = media_track_resolution_state::unresolved;

    bool resolved = false;
    bool newly_bound = false;

    std::string stream_id;
    std::string session_id;
    std::string remote_endpoint;

    std::string mid;
    std::string kind;

    std::optional<std::string> rid;
    std::optional<std::string> repaired_rid;

    std::optional<uint16_t> transport_wide_sequence_number;

    std::optional<uint32_t> absolute_send_time;

    std::optional<uint8_t> audio_level;
    std::optional<bool> voice_activity;

    bool rtx = false;
    uint32_t rtx_primary_ssrc = 0;
    uint32_t rtx_repair_ssrc = 0;

    uint32_t ssrc = 0;
    uint8_t payload_type = 0;
    uint16_t sequence_number = 0;
    uint32_t timestamp = 0;

    std::string error;
};

using media_track_resolution_result = std::expected<media_track_resolution, std::string>;

class media_track_resolver
{
   public:
    media_track_resolver() = default;
    ~media_track_resolver() = default;

    media_track_resolver(const media_track_resolver&) = delete;

    media_track_resolver& operator=(const media_track_resolver&) = delete;

    media_track_resolver(media_track_resolver&&) = delete;

    media_track_resolver& operator=(media_track_resolver&&) = delete;

   public:
    [[nodiscard]]
    media_track_resolution_result resolve_inbound_rtp(std::string_view remote_endpoint,
                                                      std::string_view stream_id,
                                                      std::string_view session_id,
                                                      const sdp::webrtc_offer_summary& offer,
                                                      const std::vector<int>& accepted_mline_indexes,
                                                      std::span<const uint8_t> plain_packet);
    void forget_peer(std::string_view remote_endpoint);

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    [[nodiscard]]
    std::size_t binding_count() const;

   public:
    struct media_track_binding
    {
        std::string remote_endpoint;
        std::string stream_id;
        std::string session_id;
        std::string mid;
        std::string kind;

        std::optional<std::string> rid;
        std::optional<std::string> repaired_rid;

        std::optional<uint8_t> audio_level;
        std::optional<bool> voice_activity;

        bool rtx = false;
        uint32_t rtx_primary_ssrc = 0;
        uint32_t rtx_repair_ssrc = 0;

        uint32_t ssrc = 0;
        uint8_t payload_type = 0;

        uint64_t packet_count = 0;
    };

   private:
    [[nodiscard]]
    std::optional<media_track_binding> find_binding_locked(std::string_view remote_endpoint, uint32_t ssrc) const;

    void remember_binding_locked(const media_track_binding& binding);

    void erase_binding_by_peer_ssrc_locked(std::string_view remote_endpoint, uint32_t ssrc);

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, media_track_binding> bindings_by_peer_ssrc_;
};

[[nodiscard]]
std::string media_track_resolution_state_to_string(media_track_resolution_state state);
}    // namespace webrtc

#endif
