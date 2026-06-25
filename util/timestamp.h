#ifndef SIMPLE_WEBRTC_UTIL_TIMESTAMP_H
#define SIMPLE_WEBRTC_UTIL_TIMESTAMP_H

#include <cstdint>
#include <string>
#include <ctime>

namespace webrtc
{
class timestamp
{
   private:
    timestamp() = default;

   public:
    uint64_t nanoseconds() const;
    uint64_t milliseconds() const;
    uint64_t microseconds() const;
    uint64_t seconds() const;
    std::string fmt_micro_string() const;
    std::string fmt_milli_string() const;
    std::string fmt_second_string() const;

   public:
    static timestamp now();
    static timestamp from_timespec(timespec spec);
    static timestamp from_timeval(timeval val);
    static timestamp from_nanoseconds(uint64_t nanoseconds);
    static timestamp from_microseconds(uint64_t microseconds);
    static timestamp from_milliseconds(uint64_t milliseconds);
    static timestamp from_seconds(uint64_t seconds);

   private:
    uint64_t nanoseconds_;
};
}    // namespace webrtc

#endif
