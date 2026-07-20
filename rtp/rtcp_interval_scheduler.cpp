#include "rtp/rtcp_interval_scheduler.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <random>

namespace webrtc
{
namespace
{
constexpr double k_rtcp_interval_compensation = 1.21828;
constexpr auto k_minimum_timer_delay = std::chrono::milliseconds(100);

std::uint64_t make_random_seed()
{
    std::random_device device;
    const std::uint64_t high = static_cast<std::uint64_t>(device());
    const std::uint64_t low = static_cast<std::uint64_t>(device());
    return (high << 32U) ^ low;
}

rtcp_interval_input normalize_input(rtcp_interval_input input)
{
    input.member_count = std::max<std::size_t>(input.member_count, 1);
    input.sender_count = std::min(input.sender_count, input.member_count);
    return input;
}

std::chrono::microseconds seconds_to_microseconds(double seconds)
{
    if (!std::isfinite(seconds) || seconds <= 0.0)
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(k_minimum_timer_delay);
    }

    constexpr double k_microseconds_per_second = 1'000'000.0;
    const double microseconds = seconds * k_microseconds_per_second;
    const double maximum = static_cast<double>(std::numeric_limits<std::int64_t>::max());

    return std::chrono::microseconds(static_cast<std::int64_t>(std::min(microseconds, maximum)));
}
}    // namespace

rtcp_interval_scheduler::rtcp_interval_scheduler(rtcp_interval_config config, std::uint64_t random_seed)
    : config_(std::move(config)),
      random_generator_(random_seed == 0 ? make_random_seed() : random_seed),
      average_packet_size_(std::max<std::size_t>(config_.initial_average_packet_size, 1))
{
    if (!std::isfinite(config_.bandwidth_bytes_per_second) || config_.bandwidth_bytes_per_second <= 0.0)
    {
        config_.bandwidth_bytes_per_second = 8'000.0;
    }

    if (!std::isfinite(config_.sender_bandwidth_fraction) || config_.sender_bandwidth_fraction <= 0.0 || config_.sender_bandwidth_fraction >= 1.0)
    {
        config_.sender_bandwidth_fraction = 0.25;
    }

    if (config_.minimum_interval <= std::chrono::milliseconds::zero())
    {
        config_.minimum_interval = std::chrono::milliseconds(1'250);
    }

    if (config_.initial_minimum_interval <= std::chrono::milliseconds::zero())
    {
        config_.initial_minimum_interval = config_.minimum_interval / 2;
    }
}

rtcp_interval_scheduler::clock::time_point rtcp_interval_scheduler::schedule_initial(clock::time_point now, rtcp_interval_input input)
{
    input = normalize_input(input);
    last_input_ = input;
    const auto interval = make_randomized_interval(input);
    return make_next_deadline(now, interval, false);
}

rtcp_interval_scheduler::clock::time_point rtcp_interval_scheduler::schedule_after_fire(clock::time_point now,
                                                                                        rtcp_interval_input input,
                                                                                        bool packet_sent)
{
    input = normalize_input(input);

    if (packet_sent)
    {
        initial_ = false;
    }

    last_input_ = input;
    const auto interval = make_randomized_interval(input);
    return make_next_deadline(now, interval, true);
}

void rtcp_interval_scheduler::note_transmission(std::size_t wire_bytes)
{
    if (wire_bytes == 0)
    {
        return;
    }

    // RFC 3550 使用 1/16 的新样本权重平滑平均 RTCP packet size。
    average_packet_size_ = ((average_packet_size_ * 15U) + wire_bytes + 8U) / 16U;
    average_packet_size_ = std::max<std::size_t>(average_packet_size_, 1);
}

void rtcp_interval_scheduler::reset()
{
    initial_ = true;
    average_packet_size_ = std::max<std::size_t>(config_.initial_average_packet_size, 1);
    last_input_ = {};
    last_interval_ = std::chrono::milliseconds::zero();
    next_deadline_.reset();
}

rtcp_interval_snapshot rtcp_interval_scheduler::snapshot() const
{
    return rtcp_interval_snapshot{
        .initial = initial_,
        .member_count = last_input_.member_count,
        .sender_count = last_input_.sender_count,
        .average_packet_size = average_packet_size_,
        .last_interval = last_interval_,
        .next_deadline = next_deadline_,
    };
}

std::chrono::microseconds rtcp_interval_scheduler::calculate_nominal_interval(const rtcp_interval_config& config,
                                                                              const rtcp_interval_input& raw_input,
                                                                              std::size_t average_packet_size,
                                                                              bool initial)
{
    const auto input = normalize_input(raw_input);
    double bandwidth = config.bandwidth_bytes_per_second;
    std::size_t participants = input.member_count;

    const double sender_threshold = static_cast<double>(input.member_count) * config.sender_bandwidth_fraction;

    if (input.sender_count > 0 && static_cast<double>(input.sender_count) <= sender_threshold)
    {
        if (input.local_role == rtcp_interval_role::sender)
        {
            bandwidth *= config.sender_bandwidth_fraction;
            participants = std::max<std::size_t>(input.sender_count, 1);
        }
        else
        {
            bandwidth *= 1.0 - config.sender_bandwidth_fraction;
            participants = std::max<std::size_t>(input.member_count - input.sender_count, 1);
        }
    }

    const double calculated_seconds =
        (static_cast<double>(std::max<std::size_t>(average_packet_size, 1)) * static_cast<double>(participants)) / std::max(bandwidth, 1.0);

    const auto minimum = initial ? config.initial_minimum_interval : config.minimum_interval;
    const double minimum_seconds = std::chrono::duration<double>(minimum).count();
    return seconds_to_microseconds(std::max(calculated_seconds, minimum_seconds));
}

std::chrono::microseconds rtcp_interval_scheduler::make_randomized_interval(rtcp_interval_input input) const
{
    const auto nominal = calculate_nominal_interval(config_, input, average_packet_size_, initial_);
    const double randomized_seconds =
        std::chrono::duration<double>(nominal).count() * random_factor_(random_generator_) / k_rtcp_interval_compensation;
    return std::max(seconds_to_microseconds(randomized_seconds), std::chrono::duration_cast<std::chrono::microseconds>(k_minimum_timer_delay));
}

rtcp_interval_scheduler::clock::time_point rtcp_interval_scheduler::make_next_deadline(clock::time_point now,
                                                                                       std::chrono::microseconds interval,
                                                                                       bool preserve_previous_deadline)
{
    clock::time_point base = now;

    if (preserve_previous_deadline && next_deadline_.has_value())
    {
        base = *next_deadline_;
    }

    auto deadline = base + interval;

    // Timer 被调度线程延迟时跳过已经错过的周期，避免连续补发形成 RTCP burst。
    if (deadline <= now)
    {
        deadline = now + interval;
    }

    next_deadline_ = deadline;
    last_interval_ = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    return deadline;
}
}    // namespace webrtc
