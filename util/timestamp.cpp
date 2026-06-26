#include <ctime>         // gmtime_r
#include <sys/time.h>    // gettimeofday
#include "util/timestamp.h"

using webrtc::timestamp;

static const int kNanosecondsPerSecond = 1000 * 1000 * 1000;
static const int kMicroSecondsPerSecond = 1000 * 1000;
static const int kMicroSecondsPerMilli = 1000;
static const int kNanoSecondsPerMicro = 1000;

// 纳秒转微秒
uint64_t nano_to_micro(uint64_t nano) { return nano / 1000; }
// 毫秒转微秒
uint64_t mill_to_micro(uint64_t mill) { return mill * 1000; }
// 秒转微秒
uint64_t second_to_micro(uint64_t second) { return second * kMicroSecondsPerSecond; }

// 纳秒转微秒
// nano_to_micro
// 纳秒转毫秒
uint64_t nano_to_mill(uint64_t nano) { return nano / 1000 / 1000; }
// 纳秒转秒
uint64_t nano_to_second(uint64_t nano) { return nano / 1000 / 1000 / 1000; }

// 微秒转秒
uint64_t micro_to_second(uint64_t micro) { return micro / kMicroSecondsPerSecond; }
// 微秒转毫秒
uint64_t micro_to_mill(uint64_t micro) { return micro / kMicroSecondsPerMilli; }
// 微妙转纳秒
uint64_t micro_to_nano(uint64_t micro) { return micro * kNanoSecondsPerMicro; }

// 格式化时全部转换为微秒
uint64_t timestamp::nanoseconds() const { return nanoseconds_; }

uint64_t timestamp::microseconds() const { return nano_to_micro(nanoseconds_); }

uint64_t timestamp::milliseconds() const { return nano_to_mill(nanoseconds_); }

uint64_t timestamp::seconds() const { return nano_to_second(nanoseconds_); }

// 创建 timestamp
timestamp timestamp::now()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    uint64_t const seconds = tv.tv_sec;
    uint64_t micro = seconds * kMicroSecondsPerSecond + tv.tv_usec;
    return from_microseconds(micro);
}

timestamp timestamp::from_nanoseconds(uint64_t nanoseconds)
{
    timestamp tm;
    tm.nanoseconds_ = nanoseconds;
    return tm;
}

timestamp timestamp::from_timeval(timeval val)
{
    timestamp tm;
    tm.nanoseconds_ = val.tv_sec;
    tm.nanoseconds_ = tm.nanoseconds_ * kNanosecondsPerSecond + micro_to_nano(val.tv_usec);
    return tm;
}

timestamp timestamp::from_timespec(timespec spec)
{
    timestamp tm;
    tm.nanoseconds_ = spec.tv_sec;
    tm.nanoseconds_ = tm.nanoseconds_ * kNanosecondsPerSecond + spec.tv_nsec;
    return tm;
}

timestamp timestamp::from_microseconds(uint64_t microseconds) { return from_nanoseconds(micro_to_nano(microseconds)); }
timestamp timestamp::from_milliseconds(uint64_t milliseconds) { return from_microseconds(mill_to_micro(milliseconds)); }
timestamp timestamp::from_seconds(uint64_t seconds) { return from_microseconds(second_to_micro(seconds)); }

// 格式化
static std::string format_time(uint64_t microseconds, bool mill, bool micro)
{
    char buf[64] = {0};
    auto seconds = static_cast<time_t>(micro_to_second(microseconds));
    struct tm tm_time;
    gmtime_r(&seconds, &tm_time);
    if (micro)
    {
        int const micro_seconds = static_cast<int>(microseconds % kMicroSecondsPerSecond);
        snprintf(buf,
                 sizeof(buf),
                 "%4d%02d%02d %02d:%02d:%02d.%06d",
                 tm_time.tm_year + 1900,
                 tm_time.tm_mon + 1,
                 tm_time.tm_mday,
                 tm_time.tm_hour,
                 tm_time.tm_min,
                 tm_time.tm_sec,
                 micro_seconds);
    }
    else if (mill)
    {
        const int microseconds1 = static_cast<int>(microseconds % static_cast<uint64_t>(kMicroSecondsPerSecond));
        const int milliseconds = microseconds1 / kMicroSecondsPerMilli;

        snprintf(buf,
                 sizeof(buf),
                 "%4d%02d%02d %02d:%02d:%02d.%03d",
                 tm_time.tm_year + 1900,
                 tm_time.tm_mon + 1,
                 tm_time.tm_mday,
                 tm_time.tm_hour,
                 tm_time.tm_min,
                 tm_time.tm_sec,
                 milliseconds);
    }
    else
    {
        snprintf(buf,
                 sizeof(buf),
                 "%4d%02d%02d %02d:%02d:%02d",
                 tm_time.tm_year + 1900,
                 tm_time.tm_mon + 1,
                 tm_time.tm_mday,
                 tm_time.tm_hour,
                 tm_time.tm_min,
                 tm_time.tm_sec);
    }
    return buf;
}

std::string timestamp::fmt_micro_string() const
{
    constexpr bool mill = false;
    constexpr bool micro = true;
    return format_time(nano_to_micro(nanoseconds_), mill, micro);
}
std::string timestamp::fmt_milli_string() const
{
    constexpr bool mill = true;
    constexpr bool micro = false;
    return format_time(nano_to_micro(nanoseconds_), mill, micro);
}
std::string timestamp::fmt_second_string() const
{
    constexpr bool mill = false;
    constexpr bool micro = false;

    return format_time(nano_to_micro(nanoseconds_), mill, micro);
}
