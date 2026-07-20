#ifndef SIMPLE_WEBRTC_SESSION_SESSION_TRANSPORT_MEDIA_LOG_H
#define SIMPLE_WEBRTC_SESSION_SESSION_TRANSPORT_MEDIA_LOG_H

#include <array>
#include <atomic>
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
        int64_t next_summary_tick = next_summary_tick_.load(std::memory_order_relaxed);

        if (next_summary_tick == 0)
        {
            const int64_t first_summary_tick = now_tick + interval_ticks;

            if (next_summary_tick_.compare_exchange_strong(next_summary_tick, first_summary_tick, std::memory_order_relaxed))
            {
                return false;
            }
        }

        if (now_tick < next_summary_tick ||
            !next_summary_tick_.compare_exchange_strong(next_summary_tick, now_tick + interval_ticks, std::memory_order_relaxed))
        {
            return false;
        }

        interval_ms = (now_tick - (next_summary_tick - interval_ticks)) / 1'000'000;
        return true;
    }

   private:
    std::atomic<int64_t> next_summary_tick_{0};
};

template <typename Counter>
class session_transport_log_counters
{
   public:
    void add(Counter counter, uint64_t value = 1) { counters_[static_cast<std::size_t>(counter)].fetch_add(value, std::memory_order_relaxed); }

    [[nodiscard]] uint64_t take(Counter counter) { return counters_[static_cast<std::size_t>(counter)].exchange(0, std::memory_order_relaxed); }

   private:
    static constexpr std::size_t k_counter_count = static_cast<std::size_t>(Counter::count);
    std::array<std::atomic<uint64_t>, k_counter_count> counters_{};
};

template <std::size_t SlotCount>
[[nodiscard]] bool mark_session_transport_value_once(std::array<std::atomic<uint32_t>, SlotCount>& slots, uint32_t value)
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
        uint32_t current = slot.load(std::memory_order_relaxed);

        if (current == value)
        {
            return false;
        }

        if (current == 0 && slot.compare_exchange_strong(current, value, std::memory_order_relaxed))
        {
            return true;
        }

        if (current == value)
        {
            return false;
        }
    }

    return false;
}
}    // namespace webrtc

#endif
