#include "media/rtcp_report_service.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rtp/rtcp_compound_packet.h"
#include "rtp/rtcp_report_generator.h"
#include "rtp/rtcp_session_stats.h"

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_rtcp_report_blocks = 31;

constexpr uint64_t k_fnv_offset_basis = 1469598103934665603ULL;

constexpr uint64_t k_fnv_prime = 1099511628211ULL;

struct pending_rtcp_report_source
{
    std::string key;

    rtcp_report_source_config source;
};

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void append_key_part(std::string& key, std::string_view value)
{
    key.append(value);
    key.push_back('\n');
}

bool contains_invalid_cname_character(char value) { return value == '\0' || value == '\r' || value == '\n'; }

std::string make_source_error(const rtcp_report_source_config& source, std::string_view message)
{
    std::string error;

    error.reserve(source.session_id.size() + source.remote_endpoint.size() + message.size() + 64);

    error.append("rtcp report source session=");
    error.append(source.session_id);
    error.append(" remote=");
    error.append(source.remote_endpoint);
    error.append(" local_ssrc=");
    error.append(std::to_string(source.local_ssrc));
    error.push_back(' ');
    error.append(message);

    return error;
}

void hash_byte(uint64_t& hash, uint8_t value)
{
    hash ^= static_cast<uint64_t>(value);

    hash *= k_fnv_prime;
}

void hash_string(uint64_t& hash, std::string_view value)
{
    for (char item : value)
    {
        hash_byte(hash, static_cast<uint8_t>(item));
    }

    hash_byte(hash, 0xffU);
}

void hash_u64(uint64_t& hash, uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index)
    {
        const uint8_t byte = static_cast<uint8_t>((value >> ((7U - index) * 8U)) & 0xffU);

        hash_byte(hash, byte);
    }
}

uint64_t make_schedule_hash(std::string_view key, uint64_t generation_round)
{
    uint64_t hash = k_fnv_offset_basis;

    hash_string(hash, "simplewebrtc-rtcp-report-schedule");

    hash_string(hash, key);

    hash_u64(hash, generation_round);

    return hash;
}

void append_json_uint64(std::string& output, std::string_view name, uint64_t value, bool& first)
{
    if (!first)
    {
        output.push_back(',');
    }

    first = false;

    output.push_back('"');
    output.append(name);
    output.append("\":");
    output.append(std::to_string(value));
}

void append_json_size(std::string& output, std::string_view name, std::size_t value, bool& first)
{
    append_json_uint64(output, name, static_cast<uint64_t>(value), first);
}

void append_metric_header(std::string& output, std::string_view name, std::string_view help, std::string_view type)
{
    output.append("# HELP ");
    output.append(name);
    output.push_back(' ');
    output.append(help);
    output.push_back('\n');

    output.append("# TYPE ");
    output.append(name);
    output.push_back(' ');
    output.append(type);
    output.push_back('\n');
}

void append_metric_value(std::string& output, std::string_view name, uint64_t value)
{
    output.append(name);
    output.push_back(' ');
    output.append(std::to_string(value));
    output.push_back('\n');
}
}    // namespace

rtcp_report_service::rtcp_report_service() : config_() {}

rtcp_report_service::rtcp_report_service(rtcp_report_service_config config) : config_(std::move(config))
{
    auto validation_result = validate_config(config_);

    if (!validation_result)
    {
        config_ = rtcp_report_service_config{};
    }
}

rtcp_report_service_result rtcp_report_service::remember_source(const rtcp_report_source_config& source) { return remember_source(source, 0); }

rtcp_report_service_result rtcp_report_service::remember_source(const rtcp_report_source_config& source, uint64_t now_milliseconds)
{
    auto validation_result = validate_source(source);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    rtcp_report_source_config normalized_source = normalize_source(source);

    const std::string key = make_source_key(normalized_source.session_id, normalized_source.remote_endpoint, normalized_source.local_ssrc);

    std::lock_guard lock(mutex_);

    auto [iterator, inserted] = sources_by_key_.try_emplace(key);

    iterator->second.source = std::move(normalized_source);

    if (inserted)
    {
        iterator->second.next_due_milliseconds = 0;
        iterator->second.last_active_milliseconds = now_milliseconds;
    }
    else if (now_milliseconds != 0)
    {
        iterator->second.last_active_milliseconds = now_milliseconds;
    }

    return {};
}
rtcp_report_service_result rtcp_report_service::observe_received_rtp(const rtcp_received_rtp_packet& packet)
{
    return stats_.observe_received_rtp(packet);
}

rtcp_report_service_result rtcp_report_service::observe_sent_rtp(const rtcp_sent_rtp_packet& packet) { return stats_.observe_sent_rtp(packet); }

rtcp_report_service_result rtcp_report_service::observe_sender_report(const rtcp_received_sender_report& report)
{
    auto result = stats_.observe_sender_report(report);

    if (!result)
    {
        return std::unexpected(result.error());
    }

    {
        std::lock_guard lock(mutex_);

        observed_sender_reports_ += 1;
    }

    return {};
}
rtcp_report_service_result rtcp_report_service::observe_receiver_report(const rtcp_received_receiver_report& report)
{
    auto result = stats_.observe_receiver_report(report);

    if (!result)
    {
        return std::unexpected(result.error());
    }

    return {};
}

rtcp_report_service_result rtcp_report_service::observe_remb(const rtcp_received_remb& report)
{
    auto result = stats_.observe_remb(report);

    if (!result)
    {
        return std::unexpected(result.error());
    }

    return {};
}

rtcp_report_service_result rtcp_report_service::observe_received_rtcp(std::string_view stream_id,
                                                                      std::string_view session_id,
                                                                      std::string_view remote_endpoint,
                                                                      std::span<const uint8_t> plain_packet,
                                                                      uint64_t arrival_time_milliseconds)
{
    auto observation = observe_received_rtcp_with_summary(stream_id, session_id, remote_endpoint, plain_packet, arrival_time_milliseconds);

    if (!observation)
    {
        return std::unexpected(observation.error());
    }

    return {};
}

rtcp_report_service_rtcp_observation_result rtcp_report_service::observe_received_rtcp_with_summary(std::string_view stream_id,
                                                                                                    std::string_view session_id,
                                                                                                    std::string_view remote_endpoint,
                                                                                                    std::span<const uint8_t> plain_packet,
                                                                                                    uint64_t arrival_time_milliseconds)
{
    auto validation_result = validate_rtcp_observation(session_id, remote_endpoint, plain_packet);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    auto compound = parse_rtcp_compound_packet(plain_packet);

    if (!compound)
    {
        std::string message = "rtcp report service compound parse failed: ";

        message.append(compound.error());

        return std::unexpected(std::move(message));
    }

    rtcp_report_service_rtcp_observation observation;

    observation.stream_id = std::string(stream_id);

    observation.session_id = std::string(session_id);

    observation.remote_endpoint = std::string(remote_endpoint);

    for (const auto& block : compound->blocks)
    {
        if (block.is_sender_report && block.has_sender_info && block.report_sender_ssrc != 0)
        {
            rtcp_received_sender_report report;

            report.stream_id = std::string(stream_id);

            report.session_id = std::string(session_id);

            report.remote_endpoint = std::string(remote_endpoint);

            report.ssrc = block.report_sender_ssrc;

            report.ntp_msw = block.sender_info.ntp_msw;

            report.ntp_lsw = block.sender_info.ntp_lsw;

            report.arrival_time_milliseconds = arrival_time_milliseconds;

            auto observe_result = observe_sender_report(report);

            if (!observe_result)
            {
                return std::unexpected(observe_result.error());
            }

            observation.sender_report_ssrcs.push_back(block.report_sender_ssrc);

            continue;
        }

        if (block.is_receiver_report && block.report_sender_ssrc != 0 && !block.report_blocks.empty())
        {
            rtcp_received_receiver_report report;

            report.stream_id = std::string(stream_id);

            report.session_id = std::string(session_id);

            report.remote_endpoint = std::string(remote_endpoint);

            report.reporter_ssrc = block.report_sender_ssrc;

            report.report_blocks = block.report_blocks;

            report.arrival_time_milliseconds = arrival_time_milliseconds;

            auto observe_result = observe_receiver_report(report);

            if (!observe_result)
            {
                return std::unexpected(observe_result.error());
            }

            for (const auto& report_block : block.report_blocks)
            {
                observation.receiver_report_ssrcs.push_back(report_block.ssrc);
            }

            continue;
        }

        if (block.has_remb && block.feedback_sender_ssrc != 0 && block.remb_bitrate_bps != 0)
        {
            rtcp_received_remb report;

            report.stream_id = std::string(stream_id);

            report.session_id = std::string(session_id);

            report.remote_endpoint = std::string(remote_endpoint);

            report.sender_ssrc = block.feedback_sender_ssrc;

            report.media_ssrc = block.feedback_media_ssrc;

            report.bitrate_bps = block.remb_bitrate_bps;

            report.ssrcs = block.remb_ssrcs;

            report.arrival_time_milliseconds = arrival_time_milliseconds;

            auto observe_result = observe_remb(report);

            if (!observe_result)
            {
                return std::unexpected(observe_result.error());
            }

            if (!block.remb_ssrcs.empty())
            {
                observation.remb_ssrcs.insert(observation.remb_ssrcs.end(), block.remb_ssrcs.begin(), block.remb_ssrcs.end());
            }
            else if (block.feedback_media_ssrc != 0)
            {
                observation.remb_ssrcs.push_back(block.feedback_media_ssrc);
            }

            if (block.remb_bitrate_bps > observation.max_remb_bitrate_bps)
            {
                observation.max_remb_bitrate_bps = block.remb_bitrate_bps;
            }
        }
    }

    observation.sender_report_count = observation.sender_report_ssrcs.size();

    observation.receiver_report_count = observation.receiver_report_ssrcs.size();

    observation.remb_count = observation.remb_ssrcs.size();

    return observation;
}

rtcp_report_service_generation rtcp_report_service::generate_reports(uint64_t now_milliseconds)
{
    rtcp_report_service_generation generation;

    std::vector<pending_rtcp_report_source> pending_sources;

    {
        std::lock_guard lock(mutex_);
        generation.stale_sources_expired = expire_stale_sources_locked(now_milliseconds);

        pending_sources.reserve(sources_by_key_.size());

        const uint64_t next_generation_round = generated_report_rounds_ + 1;

        for (auto& [key, record] : sources_by_key_)
        {
            if (record.last_active_milliseconds == 0)
            {
                record.last_active_milliseconds = now_milliseconds;
            }

            if (record.next_due_milliseconds == 0)
            {
                record.next_due_milliseconds = add_milliseconds_saturated(now_milliseconds, make_initial_delay_milliseconds(key, config_));
            }

            if (record.next_due_milliseconds > now_milliseconds)
            {
                continue;
            }

            generation.due_sources += 1;

            if (config_.max_packets_per_generation != 0 && pending_sources.size() >= config_.max_packets_per_generation)
            {
                generation.throttled_sources += 1;

                continue;
            }

            pending_rtcp_report_source pending_source;

            pending_source.key = key;

            pending_source.source = record.source;

            pending_sources.push_back(std::move(pending_source));

            const uint64_t next_delay_milliseconds = make_next_delay_milliseconds(key, next_generation_round, config_);

            record.next_due_milliseconds = add_milliseconds_saturated(now_milliseconds, next_delay_milliseconds);
        }
    }

    generation.packets.reserve(pending_sources.size());

    for (const auto& pending_source : pending_sources)
    {
        auto packet = generate_report_for_source(pending_source.source, now_milliseconds);

        if (!packet)
        {
            generation.failed += 1;

            generation.errors.push_back(packet.error());

            continue;
        }

        if (packet->report.packet.empty())
        {
            generation.skipped += 1;

            continue;
        }

        generation.packets.push_back(std::move(*packet));
    }

    {
        std::lock_guard lock(mutex_);

        generated_report_rounds_ += 1;

        generated_packets_ += generation.packets.size();

        skipped_packets_ += generation.skipped;

        failed_packets_ += generation.failed;

        throttled_sources_ += generation.throttled_sources;

        last_generation_time_milliseconds_ = now_milliseconds;

        last_generation_packets_ = generation.packets.size();

        last_generation_skipped_ = generation.skipped;

        last_generation_failed_ = generation.failed;

        last_generation_due_sources_ = generation.due_sources;

        last_generation_throttled_sources_ = generation.throttled_sources;
    }

    return generation;
}
rtcp_report_service_packet_result rtcp_report_service::generate_report_for_source(const rtcp_report_source_config& source, uint64_t now_milliseconds)
{
    auto validation_result = validate_source(source);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    rtcp_report_source_config normalized_source = normalize_source(source);

    auto report = generate_report_packet(normalized_source, now_milliseconds);

    if (!report)
    {
        return std::unexpected(report.error());
    }

    rtcp_report_service_packet packet;

    packet.source = std::move(normalized_source);

    packet.report = std::move(*report);

    return packet;
}
void rtcp_report_service::forget_source(std::string_view session_id, std::string_view remote_endpoint, uint32_t local_ssrc)
{
    if (session_id.empty() || remote_endpoint.empty() || local_ssrc == 0)
    {
        return;
    }

    const std::string key = make_source_key(session_id, remote_endpoint, local_ssrc);

    std::lock_guard lock(mutex_);

    const std::size_t erased = sources_by_key_.erase(key);

    if (erased != 0)
    {
        forgot_sources_ += erased;
    }
}

void rtcp_report_service::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    std::size_t erased_sources = 0;

    {
        std::lock_guard lock(mutex_);

        for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
        {
            if (iterator->second.source.session_id == session_id)
            {
                iterator = sources_by_key_.erase(iterator);

                erased_sources += 1;

                continue;
            }

            ++iterator;
        }

        forgot_sessions_ += 1;
        forgot_sources_ += erased_sources;
    }

    stats_.forget_session(session_id);
}
void rtcp_report_service::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    std::size_t erased_sources = 0;

    {
        std::lock_guard lock(mutex_);

        for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
        {
            if (iterator->second.source.stream_id == stream_id)
            {
                iterator = sources_by_key_.erase(iterator);

                erased_sources += 1;

                continue;
            }

            ++iterator;
        }

        forgot_streams_ += 1;
        forgot_sources_ += erased_sources;
    }

    stats_.forget_stream(stream_id);
}
void rtcp_report_service::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    std::size_t erased_sources = 0;

    {
        std::lock_guard lock(mutex_);

        for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
        {
            if (iterator->second.source.remote_endpoint == remote_endpoint)
            {
                iterator = sources_by_key_.erase(iterator);

                erased_sources += 1;

                continue;
            }

            ++iterator;
        }

        forgot_peers_ += 1;
        forgot_sources_ += erased_sources;
    }

    stats_.forget_peer(remote_endpoint);
}
void rtcp_report_service::clear()
{
    {
        std::lock_guard lock(mutex_);

        sources_by_key_.clear();

        reset_runtime_counters_locked();
    }

    stats_.clear();
}

std::size_t rtcp_report_service::source_count() const
{
    std::lock_guard lock(mutex_);

    return sources_by_key_.size();
}

std::size_t rtcp_report_service::stats_source_count() const { return stats_.source_count(); }

rtcp_report_service_runtime_snapshot rtcp_report_service::runtime_snapshot() const
{
    rtcp_report_service_runtime_snapshot snapshot;

    {
        std::lock_guard lock(mutex_);

        snapshot.configured_sources = sources_by_key_.size();

        snapshot.max_report_blocks = config_.max_report_blocks == 0 ? k_max_rtcp_report_blocks : config_.max_report_blocks;

        snapshot.report_interval_milliseconds = config_.report_interval_milliseconds;

        snapshot.report_jitter_milliseconds = config_.report_jitter_milliseconds;

        snapshot.max_packets_per_generation = config_.max_packets_per_generation;

        snapshot.stale_source_timeout_milliseconds = config_.stale_source_timeout_milliseconds;

        snapshot.forgot_sources = forgot_sources_;

        snapshot.forgot_sessions = forgot_sessions_;

        snapshot.forgot_streams = forgot_streams_;

        snapshot.forgot_peers = forgot_peers_;

        snapshot.stale_sources_expired = stale_sources_expired_;

        snapshot.last_cleanup_time_milliseconds = last_cleanup_time_milliseconds_;

        snapshot.last_cleanup_expired_sources = last_cleanup_expired_sources_;

        snapshot.generated_report_rounds = generated_report_rounds_;

        snapshot.generated_packets = generated_packets_;

        snapshot.skipped_packets = skipped_packets_;

        snapshot.failed_packets = failed_packets_;

        snapshot.throttled_sources = throttled_sources_;

        snapshot.observed_sender_reports = observed_sender_reports_;

        snapshot.last_generation_time_milliseconds = last_generation_time_milliseconds_;

        snapshot.last_generation_packets = last_generation_packets_;

        snapshot.last_generation_skipped = last_generation_skipped_;

        snapshot.last_generation_failed = last_generation_failed_;

        snapshot.last_generation_due_sources = last_generation_due_sources_;

        snapshot.last_generation_throttled_sources = last_generation_throttled_sources_;
    }

    snapshot.stats_sources = stats_.source_count();

    return snapshot;
}
rtcp_session_stats& rtcp_report_service::stats() { return stats_; }

const rtcp_session_stats& rtcp_report_service::stats() const { return stats_; }

std::string rtcp_report_service::make_source_key(std::string_view session_id, std::string_view remote_endpoint, uint32_t local_ssrc)
{
    std::string key;

    key.reserve(session_id.size() + remote_endpoint.size() + 16);

    append_key_part(key, session_id);

    append_key_part(key, remote_endpoint);

    key.append(std::to_string(local_ssrc));

    return key;
}

rtcp_report_service_result rtcp_report_service::validate_config(const rtcp_report_service_config& config)
{
    if (config.max_report_blocks > k_max_rtcp_report_blocks)
    {
        return make_error("rtcp report service max report blocks is too large");
    }

    if (config.report_interval_milliseconds == 0)
    {
        return make_error("rtcp report service interval is zero");
    }

    if (config.report_jitter_milliseconds > config.report_interval_milliseconds)
    {
        return make_error("rtcp report service jitter is greater than interval");
    }

    return {};
}

rtcp_report_service_result rtcp_report_service::validate_source(const rtcp_report_source_config& source)
{
    if (source.session_id.empty())
    {
        return make_error("rtcp report source session id is empty");
    }

    if (source.remote_endpoint.empty())
    {
        return make_error("rtcp report source remote endpoint is empty");
    }

    if (source.local_ssrc == 0)
    {
        return make_error("rtcp report source local ssrc is zero");
    }

    if (source.cname.empty())
    {
        return make_error("rtcp report source cname is empty");
    }

    if (source.cname.size() > std::numeric_limits<uint8_t>::max())
    {
        return make_error("rtcp report source cname is too large");
    }

    for (char value : source.cname)
    {
        if (contains_invalid_cname_character(value))
        {
            return make_error("rtcp report source cname contains invalid characters");
        }
    }

    if (!source.sender_report_enabled && !source.receiver_report_enabled)
    {
        return make_error("rtcp report source has no enabled report type");
    }

    if (source.max_report_blocks > k_max_rtcp_report_blocks)
    {
        return make_error("rtcp report source max report blocks is too large");
    }

    return {};
}

rtcp_report_service_result rtcp_report_service::validate_rtcp_observation(std::string_view session_id,
                                                                          std::string_view remote_endpoint,
                                                                          std::span<const uint8_t> plain_packet)
{
    if (session_id.empty())
    {
        return make_error("rtcp observation session id is empty");
    }

    if (remote_endpoint.empty())
    {
        return make_error("rtcp observation remote endpoint is empty");
    }

    if (plain_packet.empty())
    {
        return make_error("rtcp observation packet is empty");
    }

    return {};
}

uint64_t rtcp_report_service::make_initial_delay_milliseconds(std::string_view key, const rtcp_report_service_config& config)
{
    if (config.report_interval_milliseconds <= 1)
    {
        return 0;
    }

    return make_schedule_hash(key, 0) % config.report_interval_milliseconds;
}

uint64_t rtcp_report_service::make_next_delay_milliseconds(std::string_view key, uint64_t generation_round, const rtcp_report_service_config& config)
{
    const uint64_t interval = config.report_interval_milliseconds;

    const uint64_t jitter = config.report_jitter_milliseconds;

    if (jitter == 0)
    {
        return interval;
    }

    const uint64_t max_uint64 = std::numeric_limits<uint64_t>::max();

    const uint64_t range = jitter > (max_uint64 - 1) / 2 ? max_uint64 : jitter * 2 + 1;

    const uint64_t value = make_schedule_hash(key, generation_round) % range;

    if (value <= jitter)
    {
        const uint64_t negative_offset = jitter - value;

        if (negative_offset >= interval)
        {
            return 1;
        }

        return interval - negative_offset;
    }

    const uint64_t positive_offset = value - jitter;

    if (max_uint64 - interval < positive_offset)
    {
        return max_uint64;
    }

    return interval + positive_offset;
}

uint64_t rtcp_report_service::add_milliseconds_saturated(uint64_t timestamp_milliseconds, uint64_t delay_milliseconds)
{
    const uint64_t max_uint64 = std::numeric_limits<uint64_t>::max();

    if (max_uint64 - timestamp_milliseconds < delay_milliseconds)
    {
        return max_uint64;
    }

    return timestamp_milliseconds + delay_milliseconds;
}

std::size_t rtcp_report_service::expire_stale_sources_locked(uint64_t now_milliseconds)
{
    last_cleanup_time_milliseconds_ = now_milliseconds;

    last_cleanup_expired_sources_ = 0;

    if (config_.stale_source_timeout_milliseconds == 0)
    {
        return 0;
    }

    std::size_t expired_sources = 0;

    for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
    {
        if (iterator->second.last_active_milliseconds == 0)
        {
            iterator->second.last_active_milliseconds = now_milliseconds;

            ++iterator;

            continue;
        }

        if (now_milliseconds < iterator->second.last_active_milliseconds)
        {
            iterator->second.last_active_milliseconds = now_milliseconds;

            ++iterator;

            continue;
        }

        const uint64_t idle_milliseconds = now_milliseconds - iterator->second.last_active_milliseconds;

        if (idle_milliseconds < config_.stale_source_timeout_milliseconds)
        {
            ++iterator;

            continue;
        }

        iterator = sources_by_key_.erase(iterator);

        expired_sources += 1;
    }

    if (expired_sources != 0)
    {
        stale_sources_expired_ += expired_sources;

        forgot_sources_ += expired_sources;
    }

    last_cleanup_expired_sources_ = expired_sources;

    return expired_sources;
}
rtcp_report_source_config rtcp_report_service::normalize_source(const rtcp_report_source_config& source) const
{
    rtcp_report_source_config normalized_source = source;

    if (normalized_source.max_report_blocks == 0)
    {
        normalized_source.max_report_blocks = config_.max_report_blocks == 0 ? k_max_rtcp_report_blocks : config_.max_report_blocks;
    }

    if (normalized_source.max_report_blocks > k_max_rtcp_report_blocks)
    {
        normalized_source.max_report_blocks = k_max_rtcp_report_blocks;
    }

    return normalized_source;
}

rtcp_report_generation_request rtcp_report_service::make_generation_request(const rtcp_report_source_config& source, uint64_t now_milliseconds) const
{
    rtcp_report_generation_request request;

    request.stream_id = source.stream_id;

    request.session_id = source.session_id;

    request.remote_endpoint = source.remote_endpoint;

    request.mid = source.mid;

    request.rid = source.rid;

    request.repaired_rid = source.repaired_rid;

    request.local_ssrc = source.local_ssrc;

    request.cname = source.cname;

    request.now_milliseconds = now_milliseconds;

    request.max_report_blocks = source.max_report_blocks == 0 ? config_.max_report_blocks : source.max_report_blocks;

    if (request.max_report_blocks == 0)
    {
        request.max_report_blocks = k_max_rtcp_report_blocks;
    }

    return request;
}

rtcp_report_generation_result_type rtcp_report_service::generate_report_packet(const rtcp_report_source_config& source, uint64_t now_milliseconds)
{
    const rtcp_report_generation_request request = make_generation_request(source, now_milliseconds);

    if (source.sender_report_enabled)
    {
        auto sender_report = generate_rtcp_sender_report(stats_, request);

        if (sender_report)
        {
            return sender_report;
        }

        if (!source.receiver_report_enabled)
        {
            std::string message = make_source_error(source, "sender report generation failed: ");

            message.append(sender_report.error());

            return std::unexpected(std::move(message));
        }
    }

    if (!source.receiver_report_enabled)
    {
        return make_error("rtcp report source receiver report is disabled");
    }

    auto receiver_report = generate_rtcp_receiver_report(stats_, request);

    if (!receiver_report)
    {
        std::string message = make_source_error(source, "receiver report generation failed: ");

        message.append(receiver_report.error());

        return std::unexpected(std::move(message));
    }

    return receiver_report;
}

void rtcp_report_service::reset_runtime_counters_locked()
{
    generated_report_rounds_ = 0;
    generated_packets_ = 0;
    skipped_packets_ = 0;
    failed_packets_ = 0;
    throttled_sources_ = 0;

    forgot_sources_ = 0;
    forgot_sessions_ = 0;
    forgot_streams_ = 0;
    forgot_peers_ = 0;
    stale_sources_expired_ = 0;

    last_cleanup_time_milliseconds_ = 0;
    last_cleanup_expired_sources_ = 0;

    observed_sender_reports_ = 0;

    last_generation_time_milliseconds_ = 0;
    last_generation_packets_ = 0;
    last_generation_skipped_ = 0;
    last_generation_failed_ = 0;
    last_generation_due_sources_ = 0;
    last_generation_throttled_sources_ = 0;
}

std::string rtcp_report_source_config_to_string(const rtcp_report_source_config& source)
{
    std::string result;

    result.reserve(256);

    result.append("stream=");
    result.append(source.stream_id);

    result.append(" session=");
    result.append(source.session_id);

    result.append(" remote=");
    result.append(source.remote_endpoint);

    result.append(" mid=");
    result.append(source.mid);

    result.append(" kind=");
    result.append(source.kind);

    if (source.rid.has_value())
    {
        result.append(" rid=");
        result.append(*source.rid);
    }

    if (source.repaired_rid.has_value())
    {
        result.append(" repaired_rid=");
        result.append(*source.repaired_rid);
    }

    result.append(" local_ssrc=");
    result.append(std::to_string(source.local_ssrc));

    result.append(" cname=");
    result.append(source.cname);

    result.append(" sender_report=");
    result.append(source.sender_report_enabled ? "1" : "0");

    result.append(" receiver_report=");
    result.append(source.receiver_report_enabled ? "1" : "0");

    result.append(" max_report_blocks=");
    result.append(std::to_string(source.max_report_blocks));

    return result;
}

std::string rtcp_report_service_generation_to_string(const rtcp_report_service_generation& generation)
{
    std::string result;

    result.reserve(192);

    result.append("packets=");
    result.append(std::to_string(generation.packets.size()));

    result.append(" skipped=");
    result.append(std::to_string(generation.skipped));

    result.append(" failed=");
    result.append(std::to_string(generation.failed));

    result.append(" errors=");
    result.append(std::to_string(generation.errors.size()));

    result.append(" due_sources=");
    result.append(std::to_string(generation.due_sources));

    result.append(" throttled_sources=");
    result.append(std::to_string(generation.throttled_sources));

    result.append(" stale_sources_expired=");
    result.append(std::to_string(generation.stale_sources_expired));
    return result;
}

std::string rtcp_report_service_runtime_snapshot_to_string(const rtcp_report_service_runtime_snapshot& snapshot)
{
    std::string result;

    result.reserve(768);

    result.append("configured_sources=");
    result.append(std::to_string(snapshot.configured_sources));

    result.append(" stats_sources=");
    result.append(std::to_string(snapshot.stats_sources));

    result.append(" max_report_blocks=");
    result.append(std::to_string(snapshot.max_report_blocks));

    result.append(" interval_ms=");
    result.append(std::to_string(snapshot.report_interval_milliseconds));

    result.append(" jitter_ms=");
    result.append(std::to_string(snapshot.report_jitter_milliseconds));

    result.append(" max_packets_per_generation=");
    result.append(std::to_string(snapshot.max_packets_per_generation));

    result.append(" stale_source_timeout_ms=");
    result.append(std::to_string(snapshot.stale_source_timeout_milliseconds));

    result.append(" inbound_observe_attempts=");
    result.append(std::to_string(snapshot.inbound_rtcp_observe_attempts));

    result.append(" inbound_observe_failed=");
    result.append(std::to_string(snapshot.inbound_rtcp_observe_failed));

    result.append(" inbound_sender_report_sources=");
    result.append(std::to_string(snapshot.inbound_sender_report_sources));

    result.append(" remember_source_attempts=");
    result.append(std::to_string(snapshot.remember_source_attempts));

    result.append(" remember_source_success=");
    result.append(std::to_string(snapshot.remember_source_success));

    result.append(" remember_source_failed=");
    result.append(std::to_string(snapshot.remember_source_failed));

    result.append(" send_attempts=");
    result.append(std::to_string(snapshot.send_attempts));

    result.append(" send_success=");
    result.append(std::to_string(snapshot.send_success));

    result.append(" endpoint_not_found=");
    result.append(std::to_string(snapshot.endpoint_not_found));

    result.append(" protect_failed=");
    result.append(std::to_string(snapshot.protect_failed));

    result.append(" protect_ignored=");
    result.append(std::to_string(snapshot.protect_ignored));

    result.append(" forgot_sources=");
    result.append(std::to_string(snapshot.forgot_sources));

    result.append(" forgot_sessions=");
    result.append(std::to_string(snapshot.forgot_sessions));

    result.append(" forgot_streams=");
    result.append(std::to_string(snapshot.forgot_streams));

    result.append(" forgot_peers=");
    result.append(std::to_string(snapshot.forgot_peers));

    result.append(" stale_sources_expired=");
    result.append(std::to_string(snapshot.stale_sources_expired));

    result.append(" last_cleanup_time_ms=");
    result.append(std::to_string(snapshot.last_cleanup_time_milliseconds));

    result.append(" last_cleanup_expired_sources=");
    result.append(std::to_string(snapshot.last_cleanup_expired_sources));

    result.append(" rounds=");
    result.append(std::to_string(snapshot.generated_report_rounds));

    result.append(" packets=");
    result.append(std::to_string(snapshot.generated_packets));

    result.append(" skipped=");
    result.append(std::to_string(snapshot.skipped_packets));

    result.append(" failed=");
    result.append(std::to_string(snapshot.failed_packets));

    result.append(" throttled_sources=");
    result.append(std::to_string(snapshot.throttled_sources));

    result.append(" observed_sender_reports=");
    result.append(std::to_string(snapshot.observed_sender_reports));

    result.append(" last_generation_time_ms=");
    result.append(std::to_string(snapshot.last_generation_time_milliseconds));

    result.append(" last_packets=");
    result.append(std::to_string(snapshot.last_generation_packets));

    result.append(" last_skipped=");
    result.append(std::to_string(snapshot.last_generation_skipped));

    result.append(" last_failed=");
    result.append(std::to_string(snapshot.last_generation_failed));

    result.append(" last_due_sources=");
    result.append(std::to_string(snapshot.last_generation_due_sources));

    result.append(" last_throttled_sources=");
    result.append(std::to_string(snapshot.last_generation_throttled_sources));

    return result;
}
std::string rtcp_report_service_runtime_snapshot_to_json(const rtcp_report_service_runtime_snapshot& snapshot)
{
    std::string output;

    output.reserve(1792);

    bool first = true;

    output.push_back('{');

    append_json_size(output, "configured_sources", snapshot.configured_sources, first);

    append_json_size(output, "stats_sources", snapshot.stats_sources, first);

    append_json_size(output, "max_report_blocks", snapshot.max_report_blocks, first);

    append_json_uint64(output, "report_interval_milliseconds", snapshot.report_interval_milliseconds, first);

    append_json_uint64(output, "report_jitter_milliseconds", snapshot.report_jitter_milliseconds, first);

    append_json_size(output, "max_packets_per_generation", snapshot.max_packets_per_generation, first);

    append_json_uint64(output, "stale_source_timeout_milliseconds", snapshot.stale_source_timeout_milliseconds, first);

    append_json_uint64(output, "inbound_rtcp_observe_attempts", snapshot.inbound_rtcp_observe_attempts, first);

    append_json_uint64(output, "inbound_rtcp_observe_failed", snapshot.inbound_rtcp_observe_failed, first);

    append_json_uint64(output, "inbound_sender_report_sources", snapshot.inbound_sender_report_sources, first);

    append_json_uint64(output, "remember_source_attempts", snapshot.remember_source_attempts, first);

    append_json_uint64(output, "remember_source_success", snapshot.remember_source_success, first);

    append_json_uint64(output, "remember_source_failed", snapshot.remember_source_failed, first);

    append_json_uint64(output, "send_attempts", snapshot.send_attempts, first);

    append_json_uint64(output, "send_success", snapshot.send_success, first);

    append_json_uint64(output, "endpoint_not_found", snapshot.endpoint_not_found, first);

    append_json_uint64(output, "protect_failed", snapshot.protect_failed, first);

    append_json_uint64(output, "protect_ignored", snapshot.protect_ignored, first);

    append_json_uint64(output, "forgot_sources", snapshot.forgot_sources, first);

    append_json_uint64(output, "forgot_sessions", snapshot.forgot_sessions, first);

    append_json_uint64(output, "forgot_streams", snapshot.forgot_streams, first);

    append_json_uint64(output, "forgot_peers", snapshot.forgot_peers, first);

    append_json_uint64(output, "stale_sources_expired", snapshot.stale_sources_expired, first);

    append_json_uint64(output, "last_cleanup_time_milliseconds", snapshot.last_cleanup_time_milliseconds, first);

    append_json_size(output, "last_cleanup_expired_sources", snapshot.last_cleanup_expired_sources, first);

    append_json_uint64(output, "generated_report_rounds", snapshot.generated_report_rounds, first);

    append_json_uint64(output, "generated_packets", snapshot.generated_packets, first);

    append_json_uint64(output, "skipped_packets", snapshot.skipped_packets, first);

    append_json_uint64(output, "failed_packets", snapshot.failed_packets, first);

    append_json_uint64(output, "throttled_sources", snapshot.throttled_sources, first);

    append_json_uint64(output, "observed_sender_reports", snapshot.observed_sender_reports, first);

    append_json_uint64(output, "last_generation_time_milliseconds", snapshot.last_generation_time_milliseconds, first);

    append_json_size(output, "last_generation_packets", snapshot.last_generation_packets, first);

    append_json_size(output, "last_generation_skipped", snapshot.last_generation_skipped, first);

    append_json_size(output, "last_generation_failed", snapshot.last_generation_failed, first);

    append_json_size(output, "last_generation_due_sources", snapshot.last_generation_due_sources, first);

    append_json_size(output, "last_generation_throttled_sources", snapshot.last_generation_throttled_sources, first);

    output.push_back('}');

    return output;
}
std::string rtcp_report_service_runtime_snapshot_to_prometheus(const rtcp_report_service_runtime_snapshot& snapshot)
{
    std::string output;

    output.reserve(16384);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_configured_sources", "configured active rtcp report sources", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_configured_sources", static_cast<uint64_t>(snapshot.configured_sources));

    append_metric_header(output, "simplewebrtc_rtcp_report_service_stats_sources", "rtcp statistics source count", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_stats_sources", static_cast<uint64_t>(snapshot.stats_sources));

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_max_report_blocks", "effective maximum rtcp report blocks per report packet", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_max_report_blocks", static_cast<uint64_t>(snapshot.max_report_blocks));

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_report_interval_milliseconds", "configured rtcp active report interval in milliseconds", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_report_interval_milliseconds", snapshot.report_interval_milliseconds);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_report_jitter_milliseconds", "configured rtcp active report jitter in milliseconds", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_report_jitter_milliseconds", snapshot.report_jitter_milliseconds);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_max_packets_per_generation",
                         "configured maximum rtcp active report packets per generation round zero means unlimited",
                         "gauge");

    append_metric_value(
        output, "simplewebrtc_rtcp_report_service_max_packets_per_generation", static_cast<uint64_t>(snapshot.max_packets_per_generation));

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_stale_source_timeout_milliseconds",
                         "configured rtcp report source stale timeout in milliseconds zero means disabled",
                         "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_stale_source_timeout_milliseconds", snapshot.stale_source_timeout_milliseconds);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_inbound_rtcp_observe_attempts_total",
                         "total inbound rtcp packets inspected for sender report observations",
                         "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_inbound_rtcp_observe_attempts_total", snapshot.inbound_rtcp_observe_attempts);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_inbound_rtcp_observe_failed_total",
                         "total inbound rtcp sender report observation failures",
                         "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_inbound_rtcp_observe_failed_total", snapshot.inbound_rtcp_observe_failed);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_inbound_sender_report_sources_total", "total inbound sender report source observations", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_inbound_sender_report_sources_total", snapshot.inbound_sender_report_sources);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_remember_source_attempts_total", "total rtcp report source remember attempts", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_remember_source_attempts_total", snapshot.remember_source_attempts);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_remember_source_success_total",
                         "total successful rtcp report source remember operations",
                         "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_remember_source_success_total", snapshot.remember_source_success);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_remember_source_failed_total", "total failed rtcp report source remember operations", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_remember_source_failed_total", snapshot.remember_source_failed);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_send_attempts_total", "total rtcp active report packets selected for outbound send", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_send_attempts_total", snapshot.send_attempts);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_send_success_total", "total rtcp active report packets submitted to udp send", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_send_success_total", snapshot.send_success);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_endpoint_not_found_total",
                         "total rtcp active report packets skipped because endpoint was not found",
                         "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_endpoint_not_found_total", snapshot.endpoint_not_found);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_protect_failed_total", "total rtcp active report packets that failed srtp protection", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_protect_failed_total", snapshot.protect_failed);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_protect_ignored_total", "total rtcp active report packets ignored by srtp protection", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_protect_ignored_total", snapshot.protect_ignored);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_forgot_sources_total", "total rtcp report sources removed from service", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_forgot_sources_total", snapshot.forgot_sources);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_forgot_sessions_total", "total rtcp report session cleanup operations", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_forgot_sessions_total", snapshot.forgot_sessions);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_forgot_streams_total", "total rtcp report stream cleanup operations", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_forgot_streams_total", snapshot.forgot_streams);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_forgot_peers_total", "total rtcp report peer cleanup operations", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_forgot_peers_total", snapshot.forgot_peers);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_stale_sources_expired_total", "total rtcp report sources expired by stale cleanup", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_stale_sources_expired_total", snapshot.stale_sources_expired);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_last_cleanup_time_milliseconds",
                         "last rtcp report source cleanup timestamp in milliseconds",
                         "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_cleanup_time_milliseconds", snapshot.last_cleanup_time_milliseconds);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_last_cleanup_expired_sources", "rtcp report sources expired in the last cleanup round", "gauge");

    append_metric_value(
        output, "simplewebrtc_rtcp_report_service_last_cleanup_expired_sources", static_cast<uint64_t>(snapshot.last_cleanup_expired_sources));

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_generated_report_rounds_total", "total rtcp active report generation rounds", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_generated_report_rounds_total", snapshot.generated_report_rounds);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_generated_packets_total", "total generated rtcp active report packets", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_generated_packets_total", snapshot.generated_packets);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_skipped_packets_total", "total skipped rtcp active report packets", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_skipped_packets_total", snapshot.skipped_packets);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_failed_packets_total", "total failed rtcp active report packets", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_failed_packets_total", snapshot.failed_packets);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_throttled_sources_total",
                         "total rtcp active report sources throttled by generation limit",
                         "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_throttled_sources_total", snapshot.throttled_sources);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_observed_sender_reports_total", "total observed inbound rtcp sender reports", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_observed_sender_reports_total", snapshot.observed_sender_reports);

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_last_generation_time_milliseconds",
                         "last rtcp active report generation timestamp in milliseconds",
                         "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_generation_time_milliseconds", snapshot.last_generation_time_milliseconds);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_last_generation_packets", "generated rtcp active report packets in the last round", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_generation_packets", static_cast<uint64_t>(snapshot.last_generation_packets));

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_last_generation_skipped", "skipped rtcp active report packets in the last round", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_generation_skipped", static_cast<uint64_t>(snapshot.last_generation_skipped));

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_last_generation_failed", "failed rtcp active report packets in the last round", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_generation_failed", static_cast<uint64_t>(snapshot.last_generation_failed));

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_last_generation_due_sources", "rtcp active report sources due in the last round", "gauge");

    append_metric_value(
        output, "simplewebrtc_rtcp_report_service_last_generation_due_sources", static_cast<uint64_t>(snapshot.last_generation_due_sources));

    append_metric_header(output,
                         "simplewebrtc_rtcp_report_service_last_generation_throttled_sources",
                         "rtcp active report sources throttled in the last round",
                         "gauge");

    append_metric_value(output,
                        "simplewebrtc_rtcp_report_service_last_generation_throttled_sources",
                        static_cast<uint64_t>(snapshot.last_generation_throttled_sources));

    return output;
}
}    // namespace webrtc
