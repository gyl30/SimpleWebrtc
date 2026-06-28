#include "rtp/rtcp_session_stats.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rtp/rtcp_packet_writer.h"
#include "rtp/rtcp_report.h"

namespace webrtc
{
namespace
{
constexpr uint32_t k_rtp_sequence_modulus = 65536;
constexpr uint32_t k_rtp_max_dropout = 3000;
constexpr uint32_t k_rtp_max_misorder = 100;

constexpr int64_t k_rtcp_cumulative_lost_min = -8388608;
constexpr int64_t k_rtcp_cumulative_lost_max = 8388607;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void append_key_part(std::string& key, std::string_view value)
{
    key.append(value);
    key.push_back('\n');
}

uint32_t low_u32(uint64_t value) { return static_cast<uint32_t>(value & 0xffffffffULL); }

uint32_t clamp_jitter(double value)
{
    if (value <= 0.0)
    {
        return 0;
    }

    if (value >= static_cast<double>(std::numeric_limits<uint32_t>::max()))
    {
        return std::numeric_limits<uint32_t>::max();
    }

    return static_cast<uint32_t>(value + 0.5);
}

int32_t clamp_cumulative_lost(int64_t value)
{
    if (value < k_rtcp_cumulative_lost_min)
    {
        return static_cast<int32_t>(k_rtcp_cumulative_lost_min);
    }

    if (value > k_rtcp_cumulative_lost_max)
    {
        return static_cast<int32_t>(k_rtcp_cumulative_lost_max);
    }

    return static_cast<int32_t>(value);
}

uint64_t elapsed_milliseconds(uint64_t now_milliseconds, uint64_t past_milliseconds)
{
    if (now_milliseconds <= past_milliseconds)
    {
        return 0;
    }

    return now_milliseconds - past_milliseconds;
}

uint8_t make_fraction_lost(uint32_t expected_interval, uint64_t received_interval)
{
    if (expected_interval == 0)
    {
        return 0;
    }

    if (received_interval >= expected_interval)
    {
        return 0;
    }

    const uint64_t lost_interval = static_cast<uint64_t>(expected_interval) - received_interval;

    const uint64_t fraction = (lost_interval << 8U) / static_cast<uint64_t>(expected_interval);

    if (fraction > std::numeric_limits<uint8_t>::max())
    {
        return std::numeric_limits<uint8_t>::max();
    }

    return static_cast<uint8_t>(fraction);
}
bool optional_string_filter_matches(const std::optional<std::string>& expected, const std::optional<std::string>& actual)
{
    if (!expected.has_value())
    {
        return true;
    }

    return actual.has_value() && *actual == *expected;
}
}    // namespace

rtcp_session_stats_result rtcp_session_stats::observe_received_rtp(const rtcp_received_rtp_packet& packet)
{
    auto validation_result = validate_received_rtp(packet);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    std::lock_guard lock(mutex_);

    const std::string key = make_source_key(packet.session_id, packet.remote_endpoint, packet.ssrc);

    auto& state = sources_by_key_[key];

    if (state.ssrc == 0)
    {
        state.stream_id = packet.stream_id;

        state.session_id = packet.session_id;

        state.remote_endpoint = packet.remote_endpoint;

        state.ssrc = packet.ssrc;
    }

    if (!packet.mid.empty())
    {
        state.mid = packet.mid;
    }

    if (packet.rid.has_value())
    {
        state.rid = packet.rid;
    }

    if (packet.repaired_rid.has_value())
    {
        state.repaired_rid = packet.repaired_rid;
    }

    state.clock_rate = packet.clock_rate;
    const bool accepted = update_sequence_state(state, packet.sequence_number);

    if (!accepted)
    {
        return {};
    }

    state.received_packets += 1;

    state.last_received_time_milliseconds = packet.arrival_time_milliseconds;

    update_jitter(state, packet.rtp_timestamp, packet.arrival_time_milliseconds);

    return {};
}

rtcp_session_stats_result rtcp_session_stats::observe_sent_rtp(const rtcp_sent_rtp_packet& packet)
{
    auto validation_result = validate_sent_rtp(packet);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    std::lock_guard lock(mutex_);

    const std::string key = make_source_key(packet.session_id, packet.remote_endpoint, packet.ssrc);

    auto& state = sources_by_key_[key];

    if (state.ssrc == 0)
    {
        state.stream_id = packet.stream_id;

        state.session_id = packet.session_id;

        state.remote_endpoint = packet.remote_endpoint;

        state.ssrc = packet.ssrc;
    }

    if (!packet.mid.empty())
    {
        state.mid = packet.mid;
    }

    if (packet.rid.has_value())
    {
        state.rid = packet.rid;
    }

    if (packet.repaired_rid.has_value())
    {
        state.repaired_rid = packet.repaired_rid;
    }

    state.sender_packet_count += 1;
    state.sender_octet_count += static_cast<uint64_t>(packet.payload_size);

    state.last_sent_rtp_timestamp = packet.rtp_timestamp;

    state.last_send_time_milliseconds = packet.send_time_milliseconds;

    state.has_sent_rtp = true;

    return {};
}

rtcp_session_stats_result rtcp_session_stats::observe_sender_report(const rtcp_received_sender_report& report)
{
    auto validation_result = validate_sender_report(report);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    std::lock_guard lock(mutex_);

    const std::string key = make_source_key(report.session_id, report.remote_endpoint, report.ssrc);

    auto& state = sources_by_key_[key];

    if (state.ssrc == 0)
    {
        state.stream_id = report.stream_id;

        state.session_id = report.session_id;

        state.remote_endpoint = report.remote_endpoint;

        state.ssrc = report.ssrc;
    }

    state.last_sender_report = make_rtcp_last_sender_report(report.ntp_msw, report.ntp_lsw);

    state.last_sender_report_arrival_milliseconds = report.arrival_time_milliseconds;

    state.has_sender_report = true;

    return {};
}

rtcp_report_block_result rtcp_session_stats::make_report_block(std::string_view session_id,
                                                               std::string_view remote_endpoint,
                                                               uint32_t ssrc,
                                                               uint64_t now_milliseconds)
{
    if (session_id.empty())
    {
        return make_error("rtcp stats session id is empty");
    }

    if (remote_endpoint.empty())
    {
        return make_error("rtcp stats remote endpoint is empty");
    }

    if (ssrc == 0)
    {
        return make_error("rtcp stats ssrc is zero");
    }

    std::lock_guard lock(mutex_);

    const auto iterator = sources_by_key_.find(make_source_key(session_id, remote_endpoint, ssrc));

    if (iterator == sources_by_key_.end())
    {
        return make_error("rtcp stats source not found");
    }

    rtcp_session_report_snapshot snapshot = make_snapshot_from_state(iterator->second, now_milliseconds, true, &iterator->second);

    return snapshot.report_block;
}

std::vector<rtcp_report_block> rtcp_session_stats::make_report_blocks(std::string_view session_id,
                                                                      std::string_view remote_endpoint,
                                                                      uint64_t now_milliseconds,
                                                                      std::size_t max_report_blocks)
{
    return make_report_blocks(session_id, remote_endpoint, std::string_view{}, std::nullopt, std::nullopt, now_milliseconds, max_report_blocks);
}

std::vector<rtcp_report_block> rtcp_session_stats::make_report_blocks(std::string_view session_id,
                                                                      std::string_view remote_endpoint,
                                                                      std::string_view mid,
                                                                      const std::optional<std::string>& rid,
                                                                      const std::optional<std::string>& repaired_rid,
                                                                      uint64_t now_milliseconds,
                                                                      std::size_t max_report_blocks)
{
    std::vector<rtcp_report_block> blocks;

    if (session_id.empty() || remote_endpoint.empty() || max_report_blocks == 0)
    {
        return blocks;
    }

    std::lock_guard lock(mutex_);

    blocks.reserve(std::min(max_report_blocks, sources_by_key_.size()));

    for (auto& [key, state] : sources_by_key_)
    {
        (void)key;

        if (state.session_id != session_id || state.remote_endpoint != remote_endpoint || !state.sequence_initialized)
        {
            continue;
        }

        if (!mid.empty() && state.mid != mid)
        {
            continue;
        }

        if (!optional_string_filter_matches(rid, state.rid))
        {
            continue;
        }

        if (!optional_string_filter_matches(repaired_rid, state.repaired_rid))
        {
            continue;
        }

        rtcp_session_report_snapshot snapshot = make_snapshot_from_state(state, now_milliseconds, true, &state);

        blocks.push_back(snapshot.report_block);

        if (blocks.size() >= max_report_blocks)
        {
            break;
        }
    }

    return blocks;
}
rtcp_sender_info_result rtcp_session_stats::make_sender_info(std::string_view session_id,
                                                             std::string_view remote_endpoint,
                                                             uint32_t ssrc,
                                                             uint64_t now_milliseconds) const
{
    if (session_id.empty())
    {
        return make_error("rtcp sender stats session id is empty");
    }

    if (remote_endpoint.empty())
    {
        return make_error("rtcp sender stats remote endpoint is empty");
    }

    if (ssrc == 0)
    {
        return make_error("rtcp sender stats ssrc is zero");
    }

    std::lock_guard lock(mutex_);

    const auto iterator = sources_by_key_.find(make_source_key(session_id, remote_endpoint, ssrc));

    if (iterator == sources_by_key_.end())
    {
        return make_error("rtcp sender stats source not found");
    }

    if (!iterator->second.has_sent_rtp)
    {
        return make_error("rtcp sender stats has no sent rtp");
    }

    return make_sender_snapshot_from_state(iterator->second, now_milliseconds).sender_info;
}

std::optional<rtcp_session_report_snapshot> rtcp_session_stats::find_report_snapshot(std::string_view session_id,
                                                                                     std::string_view remote_endpoint,
                                                                                     uint32_t ssrc,
                                                                                     uint64_t now_milliseconds) const
{
    if (session_id.empty() || remote_endpoint.empty() || ssrc == 0)
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const auto iterator = sources_by_key_.find(make_source_key(session_id, remote_endpoint, ssrc));

    if (iterator == sources_by_key_.end())
    {
        return std::nullopt;
    }

    return make_snapshot_from_state(iterator->second, now_milliseconds, false, nullptr);
}

std::optional<rtcp_sender_stats_snapshot> rtcp_session_stats::find_sender_snapshot(std::string_view session_id,
                                                                                   std::string_view remote_endpoint,
                                                                                   uint32_t ssrc,
                                                                                   uint64_t now_milliseconds) const
{
    if (session_id.empty() || remote_endpoint.empty() || ssrc == 0)
    {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    const auto iterator = sources_by_key_.find(make_source_key(session_id, remote_endpoint, ssrc));

    if (iterator == sources_by_key_.end())
    {
        return std::nullopt;
    }

    if (!iterator->second.has_sent_rtp)
    {
        return std::nullopt;
    }

    return make_sender_snapshot_from_state(iterator->second, now_milliseconds);
}

void rtcp_session_stats::forget_ssrc(std::string_view session_id, std::string_view remote_endpoint, uint32_t ssrc)
{
    if (session_id.empty() || remote_endpoint.empty() || ssrc == 0)
    {
        return;
    }

    std::lock_guard lock(mutex_);

    sources_by_key_.erase(make_source_key(session_id, remote_endpoint, ssrc));
}

void rtcp_session_stats::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
    {
        if (iterator->second.session_id == session_id)
        {
            iterator = sources_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void rtcp_session_stats::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
    {
        if (iterator->second.stream_id == stream_id)
        {
            iterator = sources_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void rtcp_session_stats::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::lock_guard lock(mutex_);

    for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
    {
        if (iterator->second.remote_endpoint == remote_endpoint)
        {
            iterator = sources_by_key_.erase(iterator);

            continue;
        }

        ++iterator;
    }
}

void rtcp_session_stats::clear()
{
    std::lock_guard lock(mutex_);

    sources_by_key_.clear();
}

std::size_t rtcp_session_stats::source_count() const
{
    std::lock_guard lock(mutex_);

    return sources_by_key_.size();
}

std::string rtcp_session_stats::make_source_key(std::string_view session_id, std::string_view remote_endpoint, uint32_t ssrc)
{
    std::string key;

    key.reserve(session_id.size() + remote_endpoint.size() + 16);

    append_key_part(key, session_id);

    append_key_part(key, remote_endpoint);

    key.append(std::to_string(ssrc));

    return key;
}

rtcp_session_stats_result rtcp_session_stats::validate_received_rtp(const rtcp_received_rtp_packet& packet)
{
    if (packet.session_id.empty())
    {
        return make_error("rtcp received rtp session id is empty");
    }

    if (packet.remote_endpoint.empty())
    {
        return make_error("rtcp received rtp remote endpoint is empty");
    }

    if (packet.ssrc == 0)
    {
        return make_error("rtcp received rtp ssrc is zero");
    }

    if (packet.clock_rate == 0)
    {
        return make_error("rtcp received rtp clock rate is zero");
    }

    return {};
}

rtcp_session_stats_result rtcp_session_stats::validate_sent_rtp(const rtcp_sent_rtp_packet& packet)
{
    if (packet.session_id.empty())
    {
        return make_error("rtcp sent rtp session id is empty");
    }

    if (packet.remote_endpoint.empty())
    {
        return make_error("rtcp sent rtp remote endpoint is empty");
    }

    if (packet.ssrc == 0)
    {
        return make_error("rtcp sent rtp ssrc is zero");
    }

    return {};
}

rtcp_session_stats_result rtcp_session_stats::validate_sender_report(const rtcp_received_sender_report& report)
{
    if (report.session_id.empty())
    {
        return make_error("rtcp sender report session id is empty");
    }

    if (report.remote_endpoint.empty())
    {
        return make_error("rtcp sender report remote endpoint is empty");
    }

    if (report.ssrc == 0)
    {
        return make_error("rtcp sender report ssrc is zero");
    }

    return {};
}

uint32_t rtcp_session_stats::make_extended_highest_sequence_number(const source_state& state)
{
    return state.sequence_cycles + static_cast<uint32_t>(state.max_sequence_number);
}

uint64_t rtcp_session_stats::make_expected_packet_count(const source_state& state)
{
    if (!state.sequence_initialized)
    {
        return 0;
    }

    const uint32_t extended_highest = make_extended_highest_sequence_number(state);

    const uint32_t base = static_cast<uint32_t>(state.base_sequence_number);

    if (extended_highest < base)
    {
        return 0;
    }

    return static_cast<uint64_t>(extended_highest - base + 1);
}

void rtcp_session_stats::fill_report_block(
    rtcp_report_block& block, const source_state& state, uint64_t expected_packets, uint8_t fraction_lost, uint32_t jitter, uint64_t now_milliseconds)
{
    block.ssrc = state.ssrc;

    block.fraction_lost = fraction_lost;

    block.cumulative_lost = clamp_cumulative_lost(static_cast<int64_t>(expected_packets) - static_cast<int64_t>(state.received_packets));

    block.extended_highest_sequence_number = make_extended_highest_sequence_number(state);

    block.jitter = jitter;

    if (state.has_sender_report)
    {
        block.last_sender_report = state.last_sender_report;

        block.delay_since_last_sender_report =
            make_rtcp_delay_since_last_sender_report(elapsed_milliseconds(now_milliseconds, state.last_sender_report_arrival_milliseconds));
    }
    else
    {
        block.last_sender_report = 0;
        block.delay_since_last_sender_report = 0;
    }
}

rtcp_session_report_snapshot rtcp_session_stats::make_snapshot_from_state(const source_state& state,
                                                                          uint64_t now_milliseconds,
                                                                          bool update_interval,
                                                                          source_state* mutable_state)
{
    rtcp_session_report_snapshot snapshot;

    snapshot.stream_id = state.stream_id;

    snapshot.session_id = state.session_id;

    snapshot.remote_endpoint = state.remote_endpoint;

    snapshot.ssrc = state.ssrc;

    snapshot.clock_rate = state.clock_rate;

    snapshot.initialized = state.sequence_initialized;

    snapshot.base_sequence_number = state.base_sequence_number;

    snapshot.max_sequence_number = state.max_sequence_number;

    snapshot.sequence_cycles = state.sequence_cycles;

    snapshot.extended_highest_sequence_number = make_extended_highest_sequence_number(state);

    snapshot.received_packets = state.received_packets;

    snapshot.expected_packets = make_expected_packet_count(state);

    snapshot.cumulative_lost = static_cast<int64_t>(snapshot.expected_packets) - static_cast<int64_t>(state.received_packets);

    const uint32_t expected = snapshot.expected_packets > std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max()
                                                                                               : static_cast<uint32_t>(snapshot.expected_packets);

    const uint32_t expected_interval = expected >= state.expected_prior ? expected - state.expected_prior : 0;

    const uint64_t received_interval = state.received_packets >= state.received_prior ? state.received_packets - state.received_prior : 0;

    snapshot.fraction_lost = make_fraction_lost(expected_interval, received_interval);

    snapshot.jitter = clamp_jitter(state.jitter);

    snapshot.has_sender_report = state.has_sender_report;

    snapshot.last_sender_report = state.has_sender_report ? state.last_sender_report : 0;

    snapshot.delay_since_last_sender_report =
        state.has_sender_report
            ? make_rtcp_delay_since_last_sender_report(elapsed_milliseconds(now_milliseconds, state.last_sender_report_arrival_milliseconds))
            : 0;

    snapshot.last_packet_time_milliseconds = state.last_received_time_milliseconds;

    fill_report_block(snapshot.report_block, state, snapshot.expected_packets, snapshot.fraction_lost, snapshot.jitter, now_milliseconds);

    if (update_interval && mutable_state != nullptr)
    {
        mutable_state->expected_prior = expected;

        mutable_state->received_prior = state.received_packets;
    }

    return snapshot;
}

rtcp_sender_stats_snapshot rtcp_session_stats::make_sender_snapshot_from_state(const source_state& state, uint64_t now_milliseconds)
{
    rtcp_sender_stats_snapshot snapshot;

    snapshot.stream_id = state.stream_id;

    snapshot.session_id = state.session_id;

    snapshot.remote_endpoint = state.remote_endpoint;

    snapshot.ssrc = state.ssrc;

    snapshot.last_rtp_timestamp = state.last_sent_rtp_timestamp;

    snapshot.sender_packet_count = state.sender_packet_count;

    snapshot.sender_octet_count = state.sender_octet_count;

    snapshot.last_send_time_milliseconds = state.last_send_time_milliseconds;

    snapshot.sender_info = make_rtcp_sender_info_from_clock(
        now_milliseconds, state.last_sent_rtp_timestamp, low_u32(state.sender_packet_count), low_u32(state.sender_octet_count));

    return snapshot;
}

void rtcp_session_stats::reset_sequence_state(source_state& state, uint16_t sequence_number)
{
    state.sequence_initialized = true;

    state.base_sequence_number = sequence_number;

    state.max_sequence_number = sequence_number;

    state.bad_sequence_number = static_cast<uint16_t>((static_cast<uint32_t>(sequence_number) + 1U) % k_rtp_sequence_modulus);

    state.sequence_cycles = 0;

    state.received_packets = 0;
    state.received_prior = 0;
    state.expected_prior = 0;
}

bool rtcp_session_stats::update_sequence_state(source_state& state, uint16_t sequence_number)
{
    if (!state.sequence_initialized)
    {
        reset_sequence_state(state, sequence_number);

        return true;
    }

    const uint32_t delta = static_cast<uint16_t>(sequence_number - state.max_sequence_number);

    if (delta < k_rtp_max_dropout)
    {
        if (sequence_number < state.max_sequence_number)
        {
            state.sequence_cycles += k_rtp_sequence_modulus;
        }

        state.max_sequence_number = sequence_number;

        return true;
    }

    if (delta <= k_rtp_sequence_modulus - k_rtp_max_misorder)
    {
        if (sequence_number == state.bad_sequence_number)
        {
            reset_sequence_state(state, sequence_number);

            return true;
        }

        state.bad_sequence_number = static_cast<uint16_t>((static_cast<uint32_t>(sequence_number) + 1U) % k_rtp_sequence_modulus);

        return false;
    }

    return true;
}

void rtcp_session_stats::update_jitter(source_state& state, uint32_t rtp_timestamp, uint64_t arrival_time_milliseconds)
{
    if (state.clock_rate == 0)
    {
        return;
    }

    const uint64_t arrival_rtp_units = (arrival_time_milliseconds * static_cast<uint64_t>(state.clock_rate)) / 1000ULL;

    const int64_t transit = static_cast<int64_t>(arrival_rtp_units) - static_cast<int64_t>(rtp_timestamp);

    if (!state.transit_initialized)
    {
        state.previous_transit = transit;

        state.transit_initialized = true;

        return;
    }

    int64_t delta = transit - state.previous_transit;

    if (delta < 0)
    {
        delta = -delta;
    }

    state.previous_transit = transit;

    state.jitter += (static_cast<double>(delta) - state.jitter) / 16.0;
}

std::string rtcp_session_report_snapshot_to_string(const rtcp_session_report_snapshot& snapshot)
{
    std::string result;

    result.reserve(192);

    result.append("stream=");
    result.append(snapshot.stream_id);

    result.append(" session=");
    result.append(snapshot.session_id);

    result.append(" remote=");
    result.append(snapshot.remote_endpoint);

    result.append(" ssrc=");
    result.append(std::to_string(snapshot.ssrc));

    result.append(" expected=");
    result.append(std::to_string(snapshot.expected_packets));

    result.append(" received=");
    result.append(std::to_string(snapshot.received_packets));

    result.append(" lost=");
    result.append(std::to_string(snapshot.cumulative_lost));

    result.append(" fraction_lost=");
    result.append(std::to_string(static_cast<unsigned int>(snapshot.fraction_lost)));

    result.append(" jitter=");
    result.append(std::to_string(snapshot.jitter));

    return result;
}

std::string rtcp_sender_stats_snapshot_to_string(const rtcp_sender_stats_snapshot& snapshot)
{
    std::string result;

    result.reserve(192);

    result.append("stream=");
    result.append(snapshot.stream_id);

    result.append(" session=");
    result.append(snapshot.session_id);

    result.append(" remote=");
    result.append(snapshot.remote_endpoint);

    result.append(" ssrc=");
    result.append(std::to_string(snapshot.ssrc));

    result.append(" packets=");
    result.append(std::to_string(snapshot.sender_packet_count));

    result.append(" octets=");
    result.append(std::to_string(snapshot.sender_octet_count));

    result.append(" rtp_timestamp=");
    result.append(std::to_string(snapshot.last_rtp_timestamp));

    return result;
}
}    // namespace webrtc
