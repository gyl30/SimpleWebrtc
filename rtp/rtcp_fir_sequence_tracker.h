#ifndef SIMPLE_WEBRTC_RTP_RTCP_FIR_SEQUENCE_TRACKER_H
#define SIMPLE_WEBRTC_RTP_RTCP_FIR_SEQUENCE_TRACKER_H

#include <cstdint>
#include <unordered_map>

namespace webrtc
{
class rtcp_fir_sequence_tracker
{
   public:
    [[nodiscard]] bool accept(uint32_t sender_ssrc,
                              uint32_t media_ssrc,
                              uint8_t sequence_number);

    void clear();

   private:
    std::unordered_map<uint64_t, uint8_t> last_sequence_by_sender_and_media_;
};
}    // namespace webrtc

#endif
