#include <sys/time.h>

#include "util/timestamp.h"

using webrtc::timestamp;

namespace
{
constexpr uint64_t kMicrosecondsPerSecond = 1000ULL * 1000ULL;
constexpr uint64_t kNanosecondsPerMicrosecond = 1000ULL;
constexpr uint64_t kNanosecondsPerMillisecond = 1000ULL * 1000ULL;
}    // namespace

uint64_t timestamp::milliseconds() const { return nanoseconds_ / kNanosecondsPerMillisecond; }

timestamp timestamp::now()
{
    timeval value{};
    gettimeofday(&value, nullptr);

    timestamp result;
    const auto seconds = static_cast<uint64_t>(value.tv_sec);
    const auto microseconds = static_cast<uint64_t>(value.tv_usec);
    result.nanoseconds_ = (seconds * kMicrosecondsPerSecond + microseconds) * kNanosecondsPerMicrosecond;
    return result;
}
