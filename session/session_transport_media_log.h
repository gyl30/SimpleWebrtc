#ifndef SIMPLE_WEBRTC_SESSION_SESSION_TRANSPORT_MEDIA_LOG_H
#define SIMPLE_WEBRTC_SESSION_SESSION_TRANSPORT_MEDIA_LOG_H

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace webrtc
{
class session_transport_log_interval
{
   public:
    [[nodiscard]] bool try_begin(std::chrono::steady_clock::duration interval, int64_t& interval_ms)
    {
        const int64_t now_tick = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        const int64_t interval_ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(interval).count();
        const int64_t next_summary_tick = next_summary_tick_;

        if (next_summary_tick == 0)
        {
            next_summary_tick_ = now_tick + interval_ticks;
            return false;
        }

        if (now_tick < next_summary_tick)
        {
            return false;
        }

        next_summary_tick_ = now_tick + interval_ticks;
        interval_ms = (now_tick - (next_summary_tick - interval_ticks)) / 1'000'000;
        return true;
    }

   private:
    int64_t next_summary_tick_ = 0;
};

template <typename Counter>
class session_transport_log_counters
{
   public:
    void add(Counter counter, uint64_t value = 1) { counters_[static_cast<std::size_t>(counter)] += value; }

    [[nodiscard]] uint64_t take(Counter counter)
    {
        auto& value = counters_[static_cast<std::size_t>(counter)];
        const uint64_t result = value;
        value = 0;
        return result;
    }

   private:
    static constexpr std::size_t k_counter_count = static_cast<std::size_t>(Counter::count);
    std::array<uint64_t, k_counter_count> counters_{};
};

template <std::size_t SlotCount>
[[nodiscard]] bool mark_session_transport_value_once(std::array<uint32_t, SlotCount>& slots, uint32_t value)
{
    static_assert(SlotCount > 0);

    if (value == 0)
    {
        return false;
    }

    const std::size_t first_slot = static_cast<std::size_t>(value) % SlotCount;

    for (std::size_t offset = 0; offset < SlotCount; ++offset)
    {
        auto& slot = slots[(first_slot + offset) % SlotCount];
        if (slot == value)
        {
            return false;
        }

        if (slot == 0)
        {
            slot = value;
            return true;
        }
    }

    return false;
}
}    // namespace webrtc

#endif
