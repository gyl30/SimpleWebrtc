#include "rtp/rtp_receive_statistics.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstdint>
#include <limits>

namespace webrtc
{
namespace
{
constexpr uint32_t k_sequence_number_modulus = 1U << 16U;
constexpr uint16_t k_maximum_dropout = 3000;
constexpr uint16_t k_maximum_misorder = 100;
constexpr int32_t k_minimum_cumulative_lost = -8388608;
constexpr int32_t k_maximum_cumulative_lost = 8388607;

int32_t wrapping_difference(uint32_t left, uint32_t right)
{
    return std::bit_cast<int32_t>(left - right);
}

int32_t clamp_cumulative_lost(int64_t value)
{
    return static_cast<int32_t>(std::clamp<int64_t>(value,
                                                    k_minimum_cumulative_lost,
                                                    k_maximum_cumulative_lost));
}
}    // namespace

void rtp_receive_statistics::reset()
{
    sequence_initialized_ = false;
    base_sequence_number_ = 0;
    maximum_sequence_number_ = 0;
    bad_sequence_number_ = k_sequence_number_modulus + 1U;
    sequence_cycles_ = 0;
    received_packet_count_ = 0;
    expected_packet_count_prior_ = 0;
    received_packet_count_prior_ = 0;

    clock_rate_ = 0;
    jitter_initialized_ = false;
    arrival_anchor_ = {};
    rtp_timestamp_anchor_ = 0;
    previous_transit_ = 0;
    jitter_ = 0.0;
}

void rtp_receive_statistics::initialize_sequence(uint16_t sequence_number)
{
    sequence_initialized_ = true;
    base_sequence_number_ = sequence_number;
    maximum_sequence_number_ = sequence_number;
    bad_sequence_number_ = k_sequence_number_modulus + 1U;
    sequence_cycles_ = 0;
    received_packet_count_ = 0;
    expected_packet_count_prior_ = 0;
    received_packet_count_prior_ = 0;
}

bool rtp_receive_statistics::update_sequence(uint16_t sequence_number)
{
    if (!sequence_initialized_)
    {
        initialize_sequence(sequence_number);
        received_packet_count_ = 1;
        return true;
    }

    const uint16_t delta = static_cast<uint16_t>(sequence_number - maximum_sequence_number_);

    if (delta < k_maximum_dropout)
    {
        if (sequence_number < maximum_sequence_number_)
        {
            sequence_cycles_ += k_sequence_number_modulus;
        }

        maximum_sequence_number_ = sequence_number;
    }
    else if (delta <= static_cast<uint16_t>(k_sequence_number_modulus - k_maximum_misorder))
    {
        if (static_cast<uint32_t>(sequence_number) == bad_sequence_number_)
        {
            initialize_sequence(sequence_number);
            clock_rate_ = 0;
            jitter_initialized_ = false;
            arrival_anchor_ = {};
            rtp_timestamp_anchor_ = 0;
            previous_transit_ = 0;
            jitter_ = 0.0;
        }
        else
        {
            bad_sequence_number_ = static_cast<uint16_t>(sequence_number + 1U);
            return false;
        }
    }

    ++received_packet_count_;
    return true;
}

void rtp_receive_statistics::update_jitter(uint32_t rtp_timestamp,
                                           uint32_t clock_rate,
                                           std::chrono::steady_clock::time_point arrival_time)
{
    if (!jitter_initialized_ || clock_rate_ != clock_rate)
    {
        clock_rate_ = clock_rate;
        jitter_initialized_ = true;
        arrival_anchor_ = arrival_time;
        rtp_timestamp_anchor_ = rtp_timestamp;
        previous_transit_ = 0;
        jitter_ = 0.0;
        return;
    }

    const auto elapsed_microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(arrival_time - arrival_anchor_).count();
    const uint64_t elapsed_timestamp_units =
        static_cast<uint64_t>(std::max<int64_t>(0, elapsed_microseconds)) * clock_rate_ / 1000000U;
    const uint32_t arrival_timestamp =
        rtp_timestamp_anchor_ + static_cast<uint32_t>(elapsed_timestamp_units);
    const int32_t transit = wrapping_difference(arrival_timestamp, rtp_timestamp);
    const int64_t transit_delta = static_cast<int64_t>(transit) - previous_transit_;
    const double absolute_delta = static_cast<double>(transit_delta < 0 ? -transit_delta : transit_delta);

    jitter_ += (absolute_delta - jitter_) / 16.0;
    previous_transit_ = transit;
}

bool rtp_receive_statistics::observe(uint16_t sequence_number,
                                     uint32_t rtp_timestamp,
                                     uint32_t clock_rate,
                                     std::chrono::steady_clock::time_point arrival_time)
{
    if (clock_rate == 0 || !update_sequence(sequence_number))
    {
        return false;
    }

    update_jitter(rtp_timestamp, clock_rate, arrival_time);
    return true;
}

bool rtp_receive_statistics::initialized() const { return sequence_initialized_; }

uint64_t rtp_receive_statistics::expected_packet_count() const
{
    if (!sequence_initialized_)
    {
        return 0;
    }

    const uint64_t extended_maximum =
        static_cast<uint64_t>(sequence_cycles_) + maximum_sequence_number_;
    return extended_maximum - base_sequence_number_ + 1U;
}

rtp_receive_report_snapshot rtp_receive_statistics::preview_report() const
{
    rtp_receive_report_snapshot result;

    if (!sequence_initialized_)
    {
        return result;
    }

    const uint64_t expected = expected_packet_count();
    const int64_t cumulative_lost =
        static_cast<int64_t>(expected) - static_cast<int64_t>(received_packet_count_);
    const uint64_t expected_interval = expected - expected_packet_count_prior_;
    const uint64_t received_interval = received_packet_count_ - received_packet_count_prior_;
    const int64_t lost_interval =
        static_cast<int64_t>(expected_interval) - static_cast<int64_t>(received_interval);

    uint8_t fraction_lost = 0;

    if (expected_interval != 0 && lost_interval > 0)
    {
        const uint64_t fraction =
            (static_cast<uint64_t>(lost_interval) << 8U) / expected_interval;
        fraction_lost = static_cast<uint8_t>(std::min<uint64_t>(fraction, 255U));
    }

    result.fraction_lost = fraction_lost;
    result.cumulative_lost = clamp_cumulative_lost(cumulative_lost);
    result.extended_highest_sequence_number = sequence_cycles_ + maximum_sequence_number_;
    result.jitter = static_cast<uint32_t>(std::clamp<double>(jitter_,
                                                             0.0,
                                                             std::numeric_limits<uint32_t>::max()));
    result.expected_packet_count = expected;
    result.received_packet_count = received_packet_count_;
    return result;
}

void rtp_receive_statistics::commit_report()
{
    expected_packet_count_prior_ = expected_packet_count();
    received_packet_count_prior_ = received_packet_count_;
}
}    // namespace webrtc
