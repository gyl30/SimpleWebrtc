#include "media/video_keyframe_detector.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include <boost/algorithm/string.hpp>

namespace webrtc
{
namespace
{
constexpr std::size_t k_rtp_fixed_header_size = 12;
constexpr std::size_t k_rtp_csrc_size = 4;
constexpr std::size_t k_rtp_extension_header_size = 4;

struct rtp_payload_view
{
    bool marker = false;
    uint16_t sequence_number = 0;
    uint32_t timestamp = 0;
    uint32_t ssrc = 0;
    std::span<const uint8_t> payload;
};

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

std::expected<rtp_payload_view, std::string> parse_rtp_payload_view(std::span<const uint8_t> packet)
{
    if (packet.size() < k_rtp_fixed_header_size)
    {
        return make_error("rtp packet is shorter than fixed header");
    }

    if ((packet[0] >> 6U) != 2U)
    {
        return make_error("rtp version is invalid");
    }

    const bool padding = (packet[0] & 0x20U) != 0;
    const bool extension = (packet[0] & 0x10U) != 0;
    const uint8_t csrc_count = static_cast<uint8_t>(packet[0] & 0x0FU);

    std::size_t payload_offset = k_rtp_fixed_header_size + static_cast<std::size_t>(csrc_count) * k_rtp_csrc_size;

    if (payload_offset > packet.size())
    {
        return make_error("rtp csrc list is truncated");
    }

    if (extension)
    {
        if (payload_offset + k_rtp_extension_header_size > packet.size())
        {
            return make_error("rtp extension header is truncated");
        }

        const uint16_t extension_length_words = read_u16(packet, payload_offset + 2);
        const std::size_t extension_size = k_rtp_extension_header_size + static_cast<std::size_t>(extension_length_words) * 4U;

        if (payload_offset + extension_size > packet.size())
        {
            return make_error("rtp extension payload is truncated");
        }

        payload_offset += extension_size;
    }

    std::size_t payload_end = packet.size();

    if (padding)
    {
        if (payload_end <= payload_offset)
        {
            return make_error("rtp padding packet has no payload");
        }

        const std::size_t padding_size = packet[payload_end - 1];

        if (padding_size == 0 || padding_size > payload_end - payload_offset)
        {
            return make_error("rtp padding size is invalid");
        }

        payload_end -= padding_size;
    }

    if (payload_offset >= payload_end)
    {
        return make_error("rtp payload is empty");
    }

    return rtp_payload_view{
        .marker = (packet[1] & 0x80U) != 0,
        .sequence_number = read_u16(packet, 2),
        .timestamp = read_u32(packet, 4),
        .ssrc = read_u32(packet, 8),
        .payload = packet.subspan(payload_offset, payload_end - payload_offset),
    };
}

std::expected<bool, std::string> is_vp8_keyframe_start(std::span<const uint8_t> payload)
{
    if (payload.empty())
    {
        return make_error("vp8 payload descriptor is empty");
    }

    std::size_t offset = 0;
    const uint8_t descriptor = payload[offset++];
    const bool extension = (descriptor & 0x80U) != 0;
    const bool start_of_partition = (descriptor & 0x10U) != 0;
    const uint8_t partition_id = static_cast<uint8_t>(descriptor & 0x0FU);

    if (extension)
    {
        if (offset >= payload.size())
        {
            return make_error("vp8 extension bits are truncated");
        }

        const uint8_t extension_bits = payload[offset++];
        const bool has_picture_id = (extension_bits & 0x80U) != 0;
        const bool has_tl0picidx = (extension_bits & 0x40U) != 0;
        const bool has_tid = (extension_bits & 0x20U) != 0;
        const bool has_keyidx = (extension_bits & 0x10U) != 0;

        if (has_picture_id)
        {
            if (offset >= payload.size())
            {
                return make_error("vp8 picture id is truncated");
            }

            const bool extended_picture_id = (payload[offset] & 0x80U) != 0;
            offset += extended_picture_id ? 2U : 1U;

            if (offset > payload.size())
            {
                return make_error("vp8 extended picture id is truncated");
            }
        }

        if (has_tl0picidx)
        {
            offset += 1;
        }

        if (has_tid || has_keyidx)
        {
            offset += 1;
        }

        if (offset > payload.size())
        {
            return make_error("vp8 payload descriptor extension is truncated");
        }
    }

    if (offset >= payload.size())
    {
        return make_error("vp8 frame payload is empty");
    }

    const bool inter_frame = (payload[offset] & 0x01U) != 0;
    return start_of_partition && partition_id == 0 && !inter_frame;
}
}    // namespace

video_keyframe_observation_result video_keyframe_tracker::observe(std::string_view codec, std::span<const uint8_t> rtp_packet)
{
    auto view = parse_rtp_payload_view(rtp_packet);

    if (!view)
    {
        return std::unexpected(view.error());
    }

    video_keyframe_observation observation;
    observation.ssrc = view->ssrc;
    observation.timestamp = view->timestamp;
    observation.codec = std::string(codec);

    if (!boost::algorithm::iequals(codec, "VP8"))
    {
        active_frames_by_ssrc_.erase(view->ssrc);
        observation.state = video_keyframe_observation_state::unsupported_codec;
        return observation;
    }

    auto keyframe_start = is_vp8_keyframe_start(view->payload);

    if (!keyframe_start)
    {
        return std::unexpected(keyframe_start.error());
    }

    auto active = active_frames_by_ssrc_.find(view->ssrc);

    if (active != active_frames_by_ssrc_.end())
    {
        if (active->second.timestamp != view->timestamp || active->second.next_sequence_number != view->sequence_number)
        {
            active_frames_by_ssrc_.erase(active);
            observation.state = video_keyframe_observation_state::aborted;
        }
        else
        {
            active->second.next_sequence_number = static_cast<uint16_t>(view->sequence_number + 1U);

            if (view->marker)
            {
                active_frames_by_ssrc_.erase(active);
                observation.state = video_keyframe_observation_state::completed;
            }

            return observation;
        }
    }

    if (!*keyframe_start)
    {
        return observation;
    }

    if (view->marker)
    {
        observation.state = video_keyframe_observation_state::completed;
        return observation;
    }

    active_frames_by_ssrc_.insert_or_assign(view->ssrc,
                                            frame_state{
                                                .timestamp = view->timestamp,
                                                .next_sequence_number = static_cast<uint16_t>(view->sequence_number + 1U),
                                            });
    observation.state = video_keyframe_observation_state::started;
    return observation;
}

void video_keyframe_tracker::reset() { active_frames_by_ssrc_.clear(); }

void video_keyframe_tracker::reset(uint32_t ssrc) { active_frames_by_ssrc_.erase(ssrc); }

std::string_view video_keyframe_observation_state_to_string(video_keyframe_observation_state state)
{
    switch (state)
    {
        case video_keyframe_observation_state::none:
            return "none";

        case video_keyframe_observation_state::started:
            return "started";

        case video_keyframe_observation_state::completed:
            return "completed";

        case video_keyframe_observation_state::aborted:
            return "aborted";

        case video_keyframe_observation_state::unsupported_codec:
            return "unsupported_codec";
    }

    return "unknown";
}
}    // namespace webrtc
