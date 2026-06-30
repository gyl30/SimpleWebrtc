#include "media/media_track_resolver.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "log/log.h"
#include "rtp/rtp_packet.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
namespace
{
constexpr std::string_view k_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::string make_peer_ssrc_key(std::string_view remote_endpoint, uint32_t ssrc)
{
    std::string key;

    key.reserve(remote_endpoint.size() + 16);

    key.append(remote_endpoint);
    key.push_back('\n');
    key.append(std::to_string(ssrc));

    return key;
}

bool is_active_media(const sdp::media_summary& media)
{
    return media.direction != sdp::media_direction::inactive && media.direction != sdp::media_direction::unknown;
}
bool accepted_mline_indexes_contains(const std::vector<int>& accepted_mline_indexes, std::size_t media_index)
{
    if (media_index > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }

    const int expected_index = static_cast<int>(media_index);

    return std::find(accepted_mline_indexes.begin(), accepted_mline_indexes.end(), expected_index) != accepted_mline_indexes.end();
}

bool media_index_is_accepted(const std::vector<int>& accepted_mline_indexes, std::size_t media_index)
{
    if (accepted_mline_indexes.empty())
    {
        return false;
    }

    return accepted_mline_indexes_contains(accepted_mline_indexes, media_index);
}

const sdp::media_summary* find_media_by_mid(const sdp::webrtc_offer_summary& offer,
                                            const std::vector<int>& accepted_mline_indexes,
                                            std::string_view mid)
{
    if (mid.empty())
    {
        return nullptr;
    }

    for (std::size_t index = 0; index < offer.media.size(); ++index)
    {
        if (!media_index_is_accepted(accepted_mline_indexes, index))
        {
            continue;
        }

        const auto& media = offer.media[index];

        if (media.mid == mid)
        {
            return &media;
        }
    }

    return nullptr;
}

bool media_has_payload_type(const sdp::media_summary& media, uint8_t payload_type)
{
    const uint16_t expected_payload_type = static_cast<uint16_t>(payload_type);

    for (uint16_t current_payload_type : media.payload_types)
    {
        if (current_payload_type == expected_payload_type)
        {
            return true;
        }
    }

    for (const auto& codec : media.codecs)
    {
        if (codec.payload_type == expected_payload_type)
        {
            return true;
        }
    }

    return false;
}
const sdp::media_summary* find_unique_media_by_payload_type(const sdp::webrtc_offer_summary& offer,
                                                            const std::vector<int>& accepted_mline_indexes,
                                                            uint8_t payload_type)
{
    const sdp::media_summary* matched_media = nullptr;

    for (std::size_t index = 0; index < offer.media.size(); ++index)
    {
        if (!media_index_is_accepted(accepted_mline_indexes, index))
        {
            continue;
        }

        const auto& media = offer.media[index];

        if (!is_active_media(media))
        {
            continue;
        }

        if (!media_has_payload_type(media, payload_type))
        {
            continue;
        }

        if (matched_media != nullptr)
        {
            return nullptr;
        }

        matched_media = &media;
    }

    return matched_media;
}

const sdp::media_summary* find_single_active_media_with_payload_type(const sdp::webrtc_offer_summary& offer,
                                                                     const std::vector<int>& accepted_mline_indexes,
                                                                     uint8_t payload_type)
{
    const sdp::media_summary* selected_media = nullptr;

    for (std::size_t index = 0; index < offer.media.size(); ++index)
    {
        if (!media_index_is_accepted(accepted_mline_indexes, index))
        {
            continue;
        }

        const auto& media = offer.media[index];

        if (!is_active_media(media))
        {
            continue;
        }

        if (!media_has_payload_type(media, payload_type))
        {
            continue;
        }

        if (selected_media != nullptr)
        {
            return nullptr;
        }

        selected_media = &media;
    }

    return selected_media;
}

bool contains_forbidden_mid_character(uint8_t value) { return value == 0 || value == '\r' || value == '\n'; }

std::expected<std::string, std::string> parse_mid_payload(std::span<const uint8_t> payload)
{
    if (payload.empty())
    {
        return make_error("rtp mid extension is empty");
    }

    if (payload.size() > 255)
    {
        return make_error("rtp mid extension is too large");
    }

    std::string value;

    value.reserve(payload.size());

    for (uint8_t byte : payload)
    {
        if (contains_forbidden_mid_character(byte))
        {
            return make_error("rtp mid extension contains invalid characters");
        }

        value.push_back(static_cast<char>(byte));
    }

    return value;
}

std::optional<std::string> extract_mid_for_media(std::span<const uint8_t> packet, const rtp_packet_header& header, const sdp::media_summary& media)
{
    auto mid_extension_id = find_rtp_header_extension_id(media, k_mid_extension_uri);

    if (!mid_extension_id.has_value())
    {
        return std::nullopt;
    }

    auto mid_payload = find_rtp_header_extension(packet, header, *mid_extension_id);

    if (!mid_payload.has_value())
    {
        return std::nullopt;
    }

    auto parsed_mid = parse_mid_payload(*mid_payload);

    if (!parsed_mid)
    {
        return std::nullopt;
    }

    return *parsed_mid;
}

struct media_extension_match
{
    const sdp::media_summary* media = nullptr;
    rtp_header_extension_values values;
};
rtp_header_extension_values parse_optional_extension_values(std::span<const uint8_t> packet,
                                                            const rtp_packet_header& header,
                                                            const sdp::media_summary& media)
{
    auto values = parse_rtp_header_extension_values(packet, header, media);

    if (!values)
    {
        return {};
    }

    return std::move(*values);
}

void fill_resolution_from_header(media_track_resolution& resolution, const rtp_packet_header& header)
{
    resolution.ssrc = header.ssrc;

    resolution.payload_type = header.payload_type;

    resolution.sequence_number = header.sequence_number;

    resolution.timestamp = header.timestamp;
}

void fill_resolution_rtx_from_media(media_track_resolution& resolution, const sdp::media_summary& media)
{
    resolution.rtx = false;
    resolution.rtx_primary_ssrc = 0;
    resolution.rtx_repair_ssrc = 0;

    const std::optional<uint32_t> primary_ssrc = sdp::find_rtx_primary_ssrc(media, resolution.ssrc);

    if (primary_ssrc.has_value())
    {
        resolution.rtx = true;
        resolution.rtx_primary_ssrc = *primary_ssrc;
        resolution.rtx_repair_ssrc = resolution.ssrc;

        return;
    }

    const std::optional<uint32_t> repair_ssrc = sdp::find_rtx_repair_ssrc(media, resolution.ssrc);

    if (repair_ssrc.has_value())
    {
        resolution.rtx = false;
        resolution.rtx_primary_ssrc = resolution.ssrc;
        resolution.rtx_repair_ssrc = *repair_ssrc;
    }
}

void fill_binding_rtx_from_media(media_track_resolver::media_track_binding& binding, const sdp::media_summary& media)
{
    binding.rtx = false;
    binding.rtx_primary_ssrc = 0;
    binding.rtx_repair_ssrc = 0;

    const std::optional<uint32_t> primary_ssrc = sdp::find_rtx_primary_ssrc(media, binding.ssrc);

    if (primary_ssrc.has_value())
    {
        binding.rtx = true;
        binding.rtx_primary_ssrc = *primary_ssrc;
        binding.rtx_repair_ssrc = binding.ssrc;

        return;
    }

    const std::optional<uint32_t> repair_ssrc = sdp::find_rtx_repair_ssrc(media, binding.ssrc);

    if (repair_ssrc.has_value())
    {
        binding.rtx = false;
        binding.rtx_primary_ssrc = binding.ssrc;
        binding.rtx_repair_ssrc = *repair_ssrc;
    }
}

void fill_resolution_from_media(media_track_resolution& resolution, const sdp::media_summary& media)
{
    resolution.mid = media.mid;

    resolution.kind = media.kind;

    fill_resolution_rtx_from_media(resolution, media);
}

void fill_resolution_from_values(media_track_resolution& resolution, const rtp_header_extension_values& values)
{
    resolution.rid = values.rid;

    resolution.repaired_rid = values.repaired_rid;

    resolution.transport_wide_sequence_number = values.transport_wide_sequence_number;

    resolution.absolute_send_time = values.absolute_send_time;

    resolution.audio_level = values.audio_level;

    resolution.voice_activity = values.voice_activity;
}
std::optional<media_track_resolution> make_identity_rejected_resolution(media_track_resolution resolution, std::string_view error)
{
    resolution.resolved = false;

    resolution.newly_bound = false;

    resolution.state = media_track_resolution_state::unresolved;

    resolution.error = std::string(error);

    return resolution;
}

std::optional<media_track_resolution> validate_resolved_track_identity(const sdp::media_summary& media,
                                                                       const rtp_header_extension_values& values,
                                                                       const rtp_packet_header& header,
                                                                       media_track_resolution resolution)
{
    auto identity_result = sdp::validate_rtp_track_identity(media, values.rid, values.repaired_rid, header.payload_type, header.ssrc);

    if (identity_result)
    {
        return std::nullopt;
    }

    std::string message = "media track identity rejected: ";

    message.append(identity_result.error());

    return make_identity_rejected_resolution(std::move(resolution), message);
}
void fill_binding_from_values(media_track_resolver::media_track_binding& binding, const rtp_header_extension_values& values)
{
    if (values.rid.has_value())
    {
        binding.rid = values.rid;
    }

    if (values.repaired_rid.has_value())
    {
        binding.repaired_rid = values.repaired_rid;
    }

    binding.audio_level = values.audio_level;
    binding.voice_activity = values.voice_activity;
}

std::expected<media_extension_match, std::string> find_media_by_mid_extension(std::span<const uint8_t> packet,
                                                                              const rtp_packet_header& header,
                                                                              const sdp::webrtc_offer_summary& offer,
                                                                              const std::vector<int>& accepted_mline_indexes)
{
    for (std::size_t index = 0; index < offer.media.size(); ++index)
    {
        if (!media_index_is_accepted(accepted_mline_indexes, index))
        {
            continue;
        }

        const auto& media = offer.media[index];

        if (!is_active_media(media))
        {
            continue;
        }

        if (!media_has_payload_type(media, header.payload_type))
        {
            continue;
        }

        auto mid = extract_mid_for_media(packet, header, media);

        if (!mid.has_value())
        {
            continue;
        }

        if (*mid != media.mid)
        {
            continue;
        }

        const rtp_header_extension_values values = parse_optional_extension_values(packet, header, media);

        media_track_resolution resolution;

        fill_resolution_from_header(resolution, header);

        resolution.mid = media.mid;

        resolution.kind = media.kind;

        fill_resolution_from_values(resolution, values);

        fill_resolution_rtx_from_media(resolution, media);

        auto identity_rejection = validate_resolved_track_identity(media, values, header, resolution);

        if (identity_rejection.has_value())
        {
            return make_error(identity_rejection->error);
        }

        media_extension_match match;

        match.media = &media;

        match.values = values;

        return match;
    }

    return make_error("media track mid extension did not match accepted media");
}

bool optional_string_conflicts(const std::optional<std::string>& expected, const std::optional<std::string>& actual)
{
    return expected.has_value() && actual.has_value() && *expected != *actual;
}

bool binding_rid_values_conflict(const media_track_resolver::media_track_binding& binding, const rtp_header_extension_values& values)
{
    if (optional_string_conflicts(binding.rid, values.rid))
    {
        return true;
    }

    if (optional_string_conflicts(binding.repaired_rid, values.repaired_rid))
    {
        return true;
    }

    if (binding.rid.has_value() && values.repaired_rid.has_value() && *binding.rid != *values.repaired_rid)
    {
        return true;
    }

    if (binding.repaired_rid.has_value() && values.rid.has_value() && *binding.repaired_rid != *values.rid)
    {
        return true;
    }

    return false;
}

bool binding_mid_extension_conflicts(std::span<const uint8_t> packet,
                                     const rtp_packet_header& header,
                                     const sdp::media_summary& media,
                                     const media_track_resolver::media_track_binding& binding)
{
    auto packet_mid = extract_mid_for_media(packet, header, media);

    if (!packet_mid.has_value())
    {
        return false;
    }

    return *packet_mid != binding.mid;
}
}    // namespace

media_track_resolution_result media_track_resolver::resolve_inbound_rtp(std::string_view remote_endpoint,
                                                                        std::string_view stream_id,
                                                                        std::string_view session_id,
                                                                        const sdp::webrtc_offer_summary& offer,
                                                                        const std::vector<int>& accepted_mline_indexes,
                                                                        std::span<const uint8_t> plain_packet)
{
    if (remote_endpoint.empty())
    {
        return make_error("media track remote endpoint is empty");
    }

    if (stream_id.empty())
    {
        return make_error("media track stream id is empty");
    }

    if (session_id.empty())
    {
        return make_error("media track session id is empty");
    }

    if (plain_packet.empty())
    {
        return make_error("media track rtp packet is empty");
    }

    if (offer.media.empty())
    {
        return make_error("media track offer has no media sections");
    }

    if (accepted_mline_indexes.empty())
    {
        return make_error("media track accepted mline indexes is empty");
    }
    auto header = parse_rtp_packet_header(plain_packet);

    if (!header)
    {
        std::string message = "media track rtp header parse failed: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    media_track_resolution resolution;

    resolution.remote_endpoint = std::string(remote_endpoint);

    resolution.stream_id = std::string(stream_id);

    resolution.session_id = std::string(session_id);

    fill_resolution_from_header(resolution, *header);

    {
        std::lock_guard lock(mutex_);

        auto binding = find_binding_locked(remote_endpoint, header->ssrc);

        if (binding.has_value())
        {
            const sdp::media_summary* media = find_media_by_mid(offer, accepted_mline_indexes, binding->mid);
            if (media != nullptr && is_active_media(*media) && media_has_payload_type(*media, header->payload_type))
            {
                const rtp_header_extension_values values = parse_optional_extension_values(plain_packet, *header, *media);

                if (!binding_mid_extension_conflicts(plain_packet, *header, *media, *binding) && !binding_rid_values_conflict(*binding, values))
                {
                    resolution.state = media_track_resolution_state::resolved_by_ssrc;

                    resolution.resolved = true;
                    resolution.newly_bound = false;

                    fill_resolution_from_media(resolution, *media);

                    fill_resolution_from_values(resolution, values);

                    media_track_binding updated_binding = *binding;

                    updated_binding.payload_type = header->payload_type;

                    fill_binding_from_values(updated_binding, values);

                    fill_binding_rtx_from_media(updated_binding, *media);

                    updated_binding.packet_count += 1;

                    remember_binding_locked(updated_binding);
                    auto identity_rejection = validate_resolved_track_identity(*media, values, *header, resolution);

                    if (identity_rejection.has_value())
                    {
                        erase_binding_by_peer_ssrc_locked(remote_endpoint, header->ssrc);

                        return *identity_rejection;
                    }
                    return resolution;
                }
            }

            erase_binding_by_peer_ssrc_locked(remote_endpoint, header->ssrc);
        }
    }

    if (header->extension)
    {
        auto match = find_media_by_mid_extension(plain_packet, *header, offer, accepted_mline_indexes);
        if (match)
        {
            media_track_binding binding;

            binding.remote_endpoint = std::string(remote_endpoint);

            binding.stream_id = std::string(stream_id);

            binding.session_id = std::string(session_id);

            binding.mid = match->media->mid;

            binding.kind = match->media->kind;

            binding.ssrc = header->ssrc;

            binding.payload_type = header->payload_type;

            fill_binding_from_values(binding, match->values);

            fill_binding_rtx_from_media(binding, *match->media);

            binding.packet_count = 1;

            {
                std::lock_guard lock(mutex_);

                remember_binding_locked(binding);
            }

            resolution.state = media_track_resolution_state::resolved_by_mid;

            resolution.resolved = true;
            resolution.newly_bound = true;

            fill_resolution_from_media(resolution, *match->media);

            fill_resolution_from_values(resolution, match->values);

            WEBRTC_LOG_INFO(
                "media track bound by mid remote={} stream={} session={} mid={} kind={} ssrc={} payload_type={} rtx={} rtx_primary_ssrc={} "
                "rtx_repair_ssrc={}",
                remote_endpoint,
                stream_id,
                session_id,
                resolution.mid,
                resolution.kind,
                resolution.ssrc,
                static_cast<unsigned int>(resolution.payload_type),
                resolution.rtx ? 1 : 0,
                resolution.rtx_primary_ssrc,
                resolution.rtx_repair_ssrc);

            return resolution;
        }
    }

    const sdp::media_summary* payload_media = find_unique_media_by_payload_type(offer, accepted_mline_indexes, header->payload_type);
    if (payload_media != nullptr)
    {
        const rtp_header_extension_values values = parse_optional_extension_values(plain_packet, *header, *payload_media);

        media_track_binding binding;

        binding.remote_endpoint = std::string(remote_endpoint);

        binding.stream_id = std::string(stream_id);

        binding.session_id = std::string(session_id);

        binding.mid = payload_media->mid;

        binding.kind = payload_media->kind;

        binding.ssrc = header->ssrc;

        binding.payload_type = header->payload_type;

        fill_binding_from_values(binding, values);

        fill_binding_rtx_from_media(binding, *payload_media);

        binding.packet_count = 1;

        {
            std::lock_guard lock(mutex_);

            remember_binding_locked(binding);
        }
        resolution.state = media_track_resolution_state::resolved_by_payload_type;

        resolution.resolved = true;

        resolution.newly_bound = true;

        fill_resolution_from_media(resolution, *payload_media);

        fill_resolution_from_values(resolution, values);

        WEBRTC_LOG_INFO(
            "media track bound by mid remote={} stream={} session={} mid={} kind={} ssrc={} payload_type={} rtx={} rtx_primary_ssrc={} "
            "rtx_repair_ssrc={}",
            remote_endpoint,
            stream_id,
            session_id,
            resolution.mid,
            resolution.kind,
            resolution.ssrc,
            static_cast<unsigned int>(resolution.payload_type),
            resolution.rtx ? 1 : 0,
            resolution.rtx_primary_ssrc,
            resolution.rtx_repair_ssrc);

        return resolution;
    }
    const sdp::media_summary* single_media = find_single_active_media_with_payload_type(offer, accepted_mline_indexes, header->payload_type);
    if (single_media != nullptr)
    {
        const rtp_header_extension_values values = parse_optional_extension_values(plain_packet, *header, *single_media);

        fill_resolution_from_media(resolution, *single_media);

        fill_resolution_from_values(resolution, values);

        auto identity_rejection = validate_resolved_track_identity(*single_media, values, *header, resolution);

        if (identity_rejection.has_value())
        {
            return *identity_rejection;
        }

        media_track_binding binding;

        binding.remote_endpoint = std::string(remote_endpoint);

        binding.stream_id = std::string(stream_id);

        binding.session_id = std::string(session_id);

        binding.mid = single_media->mid;

        binding.kind = single_media->kind;

        binding.ssrc = header->ssrc;

        binding.payload_type = header->payload_type;

        fill_binding_from_values(binding, values);

        fill_binding_rtx_from_media(binding, *single_media);

        binding.packet_count = 1;

        {
            std::lock_guard lock(mutex_);

            remember_binding_locked(binding);
        }
        resolution.state = media_track_resolution_state::resolved_by_single_media;

        resolution.resolved = true;
        resolution.newly_bound = true;

        WEBRTC_LOG_INFO(
            "media track bound by mid remote={} stream={} session={} mid={} kind={} ssrc={} payload_type={} rtx={} rtx_primary_ssrc={} "
            "rtx_repair_ssrc={}",
            remote_endpoint,
            stream_id,
            session_id,
            resolution.mid,
            resolution.kind,
            resolution.ssrc,
            static_cast<unsigned int>(resolution.payload_type),
            resolution.rtx ? 1 : 0,
            resolution.rtx_primary_ssrc,
            resolution.rtx_repair_ssrc);

        return resolution;
    }

    resolution.error = "media track could not resolve rtp packet";

    return resolution;
}

void media_track_resolver::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = bindings_by_peer_ssrc_.begin(); iterator != bindings_by_peer_ssrc_.end();)
    {
        if (iterator->second.remote_endpoint == remote_endpoint)
        {
            iterator = bindings_by_peer_ssrc_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void media_track_resolver::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = bindings_by_peer_ssrc_.begin(); iterator != bindings_by_peer_ssrc_.end();)
    {
        if (iterator->second.session_id == session_id)
        {
            iterator = bindings_by_peer_ssrc_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void media_track_resolver::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = bindings_by_peer_ssrc_.begin(); iterator != bindings_by_peer_ssrc_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = bindings_by_peer_ssrc_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

std::size_t media_track_resolver::binding_count() const
{
    std::lock_guard lock(mutex_);

    return bindings_by_peer_ssrc_.size();
}

std::optional<media_track_resolver::media_track_binding> media_track_resolver::find_binding_locked(std::string_view remote_endpoint,
                                                                                                   uint32_t ssrc) const
{
    const std::string key = make_peer_ssrc_key(remote_endpoint, ssrc);

    const auto iterator = bindings_by_peer_ssrc_.find(key);

    if (iterator == bindings_by_peer_ssrc_.end())
    {
        return std::nullopt;
    }

    return iterator->second;
}

void media_track_resolver::remember_binding_locked(const media_track_binding& binding)
{
    if (binding.remote_endpoint.empty() || binding.mid.empty() || binding.ssrc == 0)
    {
        return;
    }

    const std::string key = make_peer_ssrc_key(binding.remote_endpoint, binding.ssrc);

    bindings_by_peer_ssrc_[key] = binding;
}

void media_track_resolver::erase_binding_by_peer_ssrc_locked(std::string_view remote_endpoint, uint32_t ssrc)
{
    bindings_by_peer_ssrc_.erase(make_peer_ssrc_key(remote_endpoint, ssrc));
}

std::string media_track_resolution_state_to_string(media_track_resolution_state state)
{
    switch (state)
    {
        case media_track_resolution_state::resolved_by_ssrc:
            return "resolved_by_ssrc";

        case media_track_resolution_state::resolved_by_mid:
            return "resolved_by_mid";

        case media_track_resolution_state::resolved_by_single_media:
            return "resolved_by_single_media";

        case media_track_resolution_state::unresolved:
            return "unresolved";
        case media_track_resolution_state::resolved_by_payload_type:
            return "resolved_by_payload_type";
    }

    return "unresolved";
}
}    // namespace webrtc
