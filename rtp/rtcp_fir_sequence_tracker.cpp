#include "rtp/rtcp_fir_sequence_tracker.h"

#include <cstdint>

namespace webrtc
{
namespace
{
uint64_t make_sequence_key(uint32_t sender_ssrc, uint32_t media_ssrc)
{
    return (static_cast<uint64_t>(sender_ssrc) << 32U) | static_cast<uint64_t>(media_ssrc);
}
}    // namespace

bool rtcp_fir_sequence_tracker::accept(uint32_t sender_ssrc,
                                       uint32_t media_ssrc,
                                       uint8_t sequence_number)
{
    const uint64_t key = make_sequence_key(sender_ssrc, media_ssrc);
    const auto previous = last_sequence_by_sender_and_media_.find(key);

    if (previous != last_sequence_by_sender_and_media_.end() &&
        previous->second == sequence_number)
    {
        return false;
    }

    last_sequence_by_sender_and_media_.insert_or_assign(key, sequence_number);
    return true;
}

void rtcp_fir_sequence_tracker::clear()
{
    last_sequence_by_sender_and_media_.clear();
}
}    // namespace webrtc
