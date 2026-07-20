#ifndef SIMPLE_WEBRTC_MEDIA_VIDEO_KEYFRAME_DETECTOR_H
#define SIMPLE_WEBRTC_MEDIA_VIDEO_KEYFRAME_DETECTOR_H

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
enum class video_keyframe_observation_state
{
    none,
    started,
    completed,
    aborted,
    unsupported_codec,
};

struct video_keyframe_observation
{
    video_keyframe_observation_state state = video_keyframe_observation_state::none;
    uint32_t ssrc = 0;
    uint32_t timestamp = 0;
    std::string codec;
};

using video_keyframe_observation_result = std::expected<video_keyframe_observation, std::string>;

class video_keyframe_tracker
{
   public:
    [[nodiscard]] video_keyframe_observation_result observe(std::string_view codec, std::span<const uint8_t> rtp_packet);

    void reset();
    void reset(uint32_t ssrc);

   private:
    struct frame_state
    {
        uint32_t timestamp = 0;
        uint16_t next_sequence_number = 0;
    };

    std::unordered_map<uint32_t, frame_state> active_frames_by_ssrc_;
};

[[nodiscard]] std::string_view video_keyframe_observation_state_to_string(video_keyframe_observation_state state);
}    // namespace webrtc

#endif
