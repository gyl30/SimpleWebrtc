#include <string>
#include <random>
#include "util/random.h"

namespace webrtc
{
std::string random_string(std::size_t length)
{
    static const char str[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<std::size_t> dist(0, sizeof(str) - 2);

    std::string result(length, 0);
    for (std::size_t i = 0; i < length; ++i)
    {
        result[i] = str[dist(generator)];
    }
    return result;
}
}    // namespace webrtc
