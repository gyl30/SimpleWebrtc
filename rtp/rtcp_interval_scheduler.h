#ifndef SIMPLE_WEBRTC_RTP_RTCP_INTERVAL_SCHEDULER_H
#define SIMPLE_WEBRTC_RTP_RTCP_INTERVAL_SCHEDULER_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>

namespace webrtc
{
enum class rtcp_interval_role
{
    sender,
    receiver,
};

struct rtcp_interval_config
{
    // 默认按每个 RTP/RTCP 会话 64 kbit/s 的 RTCP 预算计算。
    double bandwidth_bytes_per_second = 8'000.0;
    double sender_bandwidth_fraction = 0.25;
    std::chrono::milliseconds minimum_interval{1'250};
    std::chrono::milliseconds initial_minimum_interval{625};
    std::size_t initial_average_packet_size = 128;
};

struct rtcp_interval_input
{
    std::size_t member_count = 1;
    std::size_t sender_count = 0;
    rtcp_interval_role local_role = rtcp_interval_role::receiver;
};

struct rtcp_interval_snapshot
{
    bool initial = true;
    std::size_t member_count = 1;
    std::size_t sender_count = 0;
    std::size_t average_packet_size = 0;
    std::chrono::milliseconds last_interval{0};
    std::optional<std::chrono::steady_clock::time_point> next_deadline;
};

class rtcp_interval_scheduler
{
   public:
    using clock = std::chrono::steady_clock;

    explicit rtcp_interval_scheduler(rtcp_interval_config config = {}, std::uint64_t random_seed = 0);

    [[nodiscard]] clock::time_point schedule_initial(clock::time_point now, rtcp_interval_input input);

    [[nodiscard]] clock::time_point schedule_after_fire(clock::time_point now, rtcp_interval_input input, bool packet_sent);

    void note_transmission(std::size_t wire_bytes);

    void reset();

    [[nodiscard]] rtcp_interval_snapshot snapshot() const;

    [[nodiscard]] static std::chrono::microseconds calculate_nominal_interval(const rtcp_interval_config& config,
                                                                              const rtcp_interval_input& input,
                                                                              std::size_t average_packet_size,
                                                                              bool initial);

   private:
    [[nodiscard]] std::chrono::microseconds make_randomized_interval(rtcp_interval_input input) const;
    [[nodiscard]] clock::time_point make_next_deadline(clock::time_point now, std::chrono::microseconds interval, bool preserve_previous_deadline);

    rtcp_interval_config config_;
    mutable std::mt19937_64 random_generator_;
    mutable std::uniform_real_distribution<double> random_factor_{0.5, 1.5};

    bool initial_ = true;
    std::size_t average_packet_size_ = 0;
    rtcp_interval_input last_input_;
    std::chrono::milliseconds last_interval_{0};
    std::optional<clock::time_point> next_deadline_;
};
}    // namespace webrtc

#endif
