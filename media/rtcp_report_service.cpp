#include "media/rtcp_report_service.h"

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
        config_.max_report_blocks = k_max_rtcp_report_blocks;
    }
}

rtcp_report_service_result rtcp_report_service::remember_source(const rtcp_report_source_config& source)
{
    auto validation_result = validate_source(source);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    rtcp_report_source_config normalized_source = normalize_source(source);

    const std::string key = make_source_key(normalized_source.session_id, normalized_source.remote_endpoint, normalized_source.local_ssrc);

    std::lock_guard lock(mutex_);

    sources_by_key_[key] = std::move(normalized_source);

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
        if (!block.is_sender_report || !block.has_sender_info || block.report_sender_ssrc == 0)
        {
            continue;
        }

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
    }

    observation.sender_report_count = observation.sender_report_ssrcs.size();

    return observation;
}

rtcp_report_service_generation rtcp_report_service::generate_reports(uint64_t now_milliseconds)
{
    std::vector<rtcp_report_source_config> sources;

    {
        std::lock_guard lock(mutex_);

        sources.reserve(sources_by_key_.size());

        for (const auto& [key, source] : sources_by_key_)
        {
            (void)key;

            sources.push_back(source);
        }
    }

    rtcp_report_service_generation generation;

    generation.packets.reserve(sources.size());

    for (const auto& source : sources)
    {
        auto packet = generate_report_for_source(source, now_milliseconds);

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

        last_generation_time_milliseconds_ = now_milliseconds;

        last_generation_packets_ = generation.packets.size();

        last_generation_skipped_ = generation.skipped;

        last_generation_failed_ = generation.failed;
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

void rtcp_report_service::forget_session(std::string_view session_id)
{
    if (session_id.empty())
    {
        return;
    }

    {
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

    stats_.forget_session(session_id);
}

void rtcp_report_service::forget_stream(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return;
    }

    {
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

    stats_.forget_stream(stream_id);
}

void rtcp_report_service::forget_peer(std::string_view remote_endpoint)
{
    if (remote_endpoint.empty())
    {
        return;
    }

    {
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

        snapshot.generated_report_rounds = generated_report_rounds_;

        snapshot.generated_packets = generated_packets_;

        snapshot.skipped_packets = skipped_packets_;

        snapshot.failed_packets = failed_packets_;

        snapshot.observed_sender_reports = observed_sender_reports_;

        snapshot.last_generation_time_milliseconds = last_generation_time_milliseconds_;

        snapshot.last_generation_packets = last_generation_packets_;

        snapshot.last_generation_skipped = last_generation_skipped_;

        snapshot.last_generation_failed = last_generation_failed_;
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

    observed_sender_reports_ = 0;

    last_generation_time_milliseconds_ = 0;
    last_generation_packets_ = 0;
    last_generation_skipped_ = 0;
    last_generation_failed_ = 0;
}

std::string rtcp_report_source_config_to_string(const rtcp_report_source_config& source)
{
    std::string result;

    result.reserve(192);

    result.append("stream=");
    result.append(source.stream_id);

    result.append(" session=");
    result.append(source.session_id);

    result.append(" remote=");
    result.append(source.remote_endpoint);

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

    result.reserve(128);

    result.append("packets=");
    result.append(std::to_string(generation.packets.size()));

    result.append(" skipped=");
    result.append(std::to_string(generation.skipped));

    result.append(" failed=");
    result.append(std::to_string(generation.failed));

    result.append(" errors=");
    result.append(std::to_string(generation.errors.size()));

    return result;
}

std::string rtcp_report_service_runtime_snapshot_to_string(const rtcp_report_service_runtime_snapshot& snapshot)
{
    std::string result;

    result.reserve(192);

    result.append("configured_sources=");
    result.append(std::to_string(snapshot.configured_sources));

    result.append(" stats_sources=");
    result.append(std::to_string(snapshot.stats_sources));

    result.append(" rounds=");
    result.append(std::to_string(snapshot.generated_report_rounds));

    result.append(" packets=");
    result.append(std::to_string(snapshot.generated_packets));

    result.append(" skipped=");
    result.append(std::to_string(snapshot.skipped_packets));

    result.append(" failed=");
    result.append(std::to_string(snapshot.failed_packets));

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

    return result;
}

std::string rtcp_report_service_runtime_snapshot_to_json(const rtcp_report_service_runtime_snapshot& snapshot)
{
    std::string output;

    output.reserve(384);

    bool first = true;

    output.push_back('{');

    append_json_size(output, "configured_sources", snapshot.configured_sources, first);

    append_json_size(output, "stats_sources", snapshot.stats_sources, first);

    append_json_uint64(output, "generated_report_rounds", snapshot.generated_report_rounds, first);

    append_json_uint64(output, "generated_packets", snapshot.generated_packets, first);

    append_json_uint64(output, "skipped_packets", snapshot.skipped_packets, first);

    append_json_uint64(output, "failed_packets", snapshot.failed_packets, first);

    append_json_uint64(output, "observed_sender_reports", snapshot.observed_sender_reports, first);

    append_json_uint64(output, "last_generation_time_milliseconds", snapshot.last_generation_time_milliseconds, first);

    append_json_size(output, "last_generation_packets", snapshot.last_generation_packets, first);

    append_json_size(output, "last_generation_skipped", snapshot.last_generation_skipped, first);

    append_json_size(output, "last_generation_failed", snapshot.last_generation_failed, first);

    output.push_back('}');

    return output;
}

std::string rtcp_report_service_runtime_snapshot_to_prometheus(const rtcp_report_service_runtime_snapshot& snapshot)
{
    std::string output;

    output.reserve(4096);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_configured_sources", "configured active rtcp report sources", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_configured_sources", snapshot.configured_sources);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_stats_sources", "rtcp statistics source count", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_stats_sources", snapshot.stats_sources);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_generated_report_rounds_total", "total rtcp active report generation rounds", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_generated_report_rounds_total", snapshot.generated_report_rounds);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_generated_packets_total", "total generated rtcp active report packets", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_generated_packets_total", snapshot.generated_packets);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_skipped_packets_total", "total skipped rtcp active report packets", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_skipped_packets_total", snapshot.skipped_packets);

    append_metric_header(output, "simplewebrtc_rtcp_report_service_failed_packets_total", "total failed rtcp active report packets", "counter");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_failed_packets_total", snapshot.failed_packets);

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

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_generation_packets", snapshot.last_generation_packets);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_last_generation_skipped", "skipped rtcp active report packets in the last round", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_generation_skipped", snapshot.last_generation_skipped);

    append_metric_header(
        output, "simplewebrtc_rtcp_report_service_last_generation_failed", "failed rtcp active report packets in the last round", "gauge");

    append_metric_value(output, "simplewebrtc_rtcp_report_service_last_generation_failed", snapshot.last_generation_failed);

    return output;
}
}    // namespace webrtc
