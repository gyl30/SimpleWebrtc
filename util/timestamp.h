#ifndef SIMPLE_WEBRTC_UTIL_TIMESTAMP_H
#define SIMPLE_WEBRTC_UTIL_TIMESTAMP_H

#include <cstdint>

namespace webrtc
{
class timestamp
{
   private:
    timestamp() = default;

   public:
    uint64_t milliseconds() const;

    static timestamp now();

   private:
    uint64_t nanoseconds_ = 0;
};
}    // namespace webrtc

#endif
