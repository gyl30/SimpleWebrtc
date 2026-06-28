#include "media/rtcp_transport_cc_feedback_service.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webrtc
{
namespace
{
constexpr uint8_t k_rtcp_version = 2;
constexpr uint8_t k_rtcp_packet_type_transport_feedback = 205;
constexpr uint8_t k_rtcp_transport_cc_feedback_format = 15;

constexpr uint16_t k_transport_cc_status_not_received = 0;
constexpr uint16_t k_transport_cc_status_small_delta = 1;

constexpr uint64_t k_transport_cc_reference_time_unit_milliseconds = 64;
constexpr uint64_t k_transport_cc_delta_unit_per_millisecond = 4;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

void append_key_part(std::string& key, std::string_view value)
{
    key.append(value);

    key.push_back('\n');
}

void append_u8(std::vector<uint8_t>& packet, uint8_t value) { packet.push_back(value); }

void append_u16(std::vector<uint8_t>& packet, uint16_t value)
{
    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void append_u24(std::vector<uint8_t>& packet, uint32_t value)
{
    packet.push_back(static_cast<uint8_t>((value >> 16U) & 0xffU));

    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void append_u32(std::vector<uint8_t>& packet, uint32_t value)
{
    packet.push_back(static_cast<uint8_t>((value >> 24U) & 0xffU));

    packet.push_back(static_cast<uint8_t>((value >> 16U) & 0xffU));

    packet.push_back(static_cast<uint8_t>((value >> 8U) & 0xffU));

    packet.push_back(static_cast<uint8_t>(value & 0xffU));
}

void patch_u16(std::vector<uint8_t>& packet, std::size_t offset, uint16_t value)
{
    packet[offset] = static_cast<uint8_t>((value >> 8U) & 0xffU);

    packet[offset + 1] = static_cast<uint8_t>(value & 0xffU);
}

uint16_t sequence_distance(uint16_t base_sequence_number, uint16_t sequence_number)
{
    return static_cast<uint16_t>(sequence_number - base_sequence_number);
}

bool packet_sequence_equals(const rtcp_transport_cc_feedback_service::observed_packet_state& packet, uint16_t sequence_number)
{
    return packet.transport_sequence_number == sequence_number;
}

struct feedback_status_entry
{
    uint16_t status = k_transport_cc_status_not_received;
    uint64_t arrival_time_milliseconds = 0;
};

struct feedback_build_plan
{
    uint16_t base_sequence_number = 0;
    uint16_t packet_status_count = 0;
    uint32_t reference_time_64ms = 0;

    std::vector<feedback_status_entry> statuses;
    std::vector<uint8_t> small_deltas;
};

std::vector<rtcp_transport_cc_feedback_service::observed_packet_state> sorted_unique_packets_for_feedback(
    const std::vector<rtcp_transport_cc_feedback_service::observed_packet_state>& packets, uint16_t base_sequence_number, uint16_t max_packets)
{
    std::vector<rtcp_transport_cc_feedback_service::observed_packet_state> result;

    result.reserve(packets.size());

    for (const auto& packet : packets)
    {
        const uint16_t distance = sequence_distance(base_sequence_number, packet.transport_sequence_number);

        if (distance >= max_packets)
        {
            continue;
        }

        result.push_back(packet);
    }

    std::sort(result.begin(),
              result.end(),
              [base_sequence_number](const auto& left, const auto& right)
              {
                  return sequence_distance(base_sequence_number, left.transport_sequence_number) <
                         sequence_distance(base_sequence_number, right.transport_sequence_number);
              });

    auto duplicate_begin =
        std::unique(result.begin(),
                    result.end(),
                    [](const auto& left, const auto& right) { return left.transport_sequence_number == right.transport_sequence_number; });

    result.erase(duplicate_begin, result.end());

    return result;
}

std::expected<feedback_build_plan, std::string> make_feedback_build_plan(
    const std::vector<rtcp_transport_cc_feedback_service::observed_packet_state>& packets, uint16_t max_packets)
{
    if (packets.empty())
    {
        return make_error("transport cc feedback source has no packets");
    }

    const uint16_t base_sequence_number = packets.front().transport_sequence_number;

    std::vector<rtcp_transport_cc_feedback_service::observed_packet_state> ordered_packets =
        sorted_unique_packets_for_feedback(packets, base_sequence_number, max_packets);

    if (ordered_packets.empty())
    {
        return make_error("transport cc feedback has no ordered packets");
    }

    const uint16_t last_distance = sequence_distance(base_sequence_number, ordered_packets.back().transport_sequence_number);

    const uint16_t packet_status_count = static_cast<uint16_t>(last_distance + 1U);

    feedback_build_plan plan;

    plan.base_sequence_number = base_sequence_number;

    plan.packet_status_count = packet_status_count;

    plan.statuses.resize(packet_status_count);

    for (const auto& packet : ordered_packets)
    {
        const uint16_t distance = sequence_distance(base_sequence_number, packet.transport_sequence_number);

        feedback_status_entry& status = plan.statuses[distance];

        status.status = k_transport_cc_status_small_delta;

        status.arrival_time_milliseconds = packet.arrival_time_milliseconds;
    }

    const uint64_t first_arrival_time_milliseconds = ordered_packets.front().arrival_time_milliseconds;

    const uint64_t reference_time_milliseconds =
        (first_arrival_time_milliseconds / k_transport_cc_reference_time_unit_milliseconds) * k_transport_cc_reference_time_unit_milliseconds;

    plan.reference_time_64ms = static_cast<uint32_t>((reference_time_milliseconds / k_transport_cc_reference_time_unit_milliseconds) & 0x00ffffffU);

    uint64_t previous_received_time_milliseconds = reference_time_milliseconds;

    std::size_t usable_status_count = 0;

    for (std::size_t index = 0; index < plan.statuses.size(); ++index)
    {
        const auto& status = plan.statuses[index];

        if (status.status == k_transport_cc_status_not_received)
        {
            usable_status_count = index + 1;

            continue;
        }

        if (status.arrival_time_milliseconds < previous_received_time_milliseconds)
        {
            break;
        }

        const uint64_t delta_milliseconds = status.arrival_time_milliseconds - previous_received_time_milliseconds;

        const uint64_t delta_units = delta_milliseconds * k_transport_cc_delta_unit_per_millisecond;

        if (delta_units > static_cast<uint64_t>(std::numeric_limits<uint8_t>::max()))
        {
            break;
        }

        plan.small_deltas.push_back(static_cast<uint8_t>(delta_units));

        previous_received_time_milliseconds = status.arrival_time_milliseconds;

        usable_status_count = index + 1;
    }

    if (usable_status_count == 0)
    {
        return make_error("transport cc feedback has no usable statuses");
    }

    plan.statuses.resize(usable_status_count);

    plan.packet_status_count = static_cast<uint16_t>(usable_status_count);

    return plan;
}

void append_status_chunks(std::vector<uint8_t>& packet, const std::vector<feedback_status_entry>& statuses)
{
    std::size_t index = 0;

    while (index < statuses.size())
    {
        const uint16_t status = statuses[index].status;

        std::size_t run_length = 1;

        while (index + run_length < statuses.size() && statuses[index + run_length].status == status && run_length < 0x1fffU)
        {
            run_length += 1;
        }

        const uint16_t chunk = static_cast<uint16_t>(((status & 0x03U) << 13U) | static_cast<uint16_t>(run_length & 0x1fffU));

        append_u16(packet, chunk);

        index += run_length;
    }
}

void append_padding_to_32bit_alignment(std::vector<uint8_t>& packet)
{
    while ((packet.size() % 4U) != 0)
    {
        packet.push_back(0);
    }
}

std::expected<std::vector<uint8_t>, std::string> write_transport_cc_feedback_packet(uint32_t sender_ssrc,
                                                                                    uint32_t media_ssrc,
                                                                                    uint8_t feedback_packet_count,
                                                                                    const feedback_build_plan& plan)
{
    if (sender_ssrc == 0)
    {
        return make_error("transport cc feedback sender ssrc is zero");
    }

    if (media_ssrc == 0)
    {
        return make_error("transport cc feedback media ssrc is zero");
    }

    if (plan.packet_status_count == 0)
    {
        return make_error("transport cc feedback packet status count is zero");
    }

    std::vector<uint8_t> packet;

    packet.reserve(64 + plan.statuses.size() + plan.small_deltas.size());

    append_u8(packet, static_cast<uint8_t>((k_rtcp_version << 6U) | k_rtcp_transport_cc_feedback_format));

    append_u8(packet, k_rtcp_packet_type_transport_feedback);

    append_u16(packet, 0);

    append_u32(packet, sender_ssrc);

    append_u32(packet, media_ssrc);

    append_u16(packet, plan.base_sequence_number);

    append_u16(packet, plan.packet_status_count);

    append_u24(packet, plan.reference_time_64ms);

    append_u8(packet, feedback_packet_count);

    append_status_chunks(packet, plan.statuses);

    for (uint8_t delta : plan.small_deltas)
    {
        append_u8(packet, delta);
    }

    append_padding_to_32bit_alignment(packet);

    const std::size_t length_words = packet.size() / 4U - 1U;

    if (length_words > static_cast<std::size_t>(std::numeric_limits<uint16_t>::max()))
    {
        return make_error("transport cc feedback packet is too large");
    }

    patch_u16(packet, 2, static_cast<uint16_t>(length_words));

    return packet;
}
}    // namespace

rtcp_transport_cc_feedback_service::rtcp_transport_cc_feedback_service() : config_() {}

rtcp_transport_cc_feedback_service::rtcp_transport_cc_feedback_service(rtcp_transport_cc_feedback_config config) : config_(std::move(config))
{
    if (config_.feedback_interval_milliseconds == 0)
    {
        config_.feedback_interval_milliseconds = 100;
    }

    if (config_.stale_source_milliseconds == 0)
    {
        config_.stale_source_milliseconds = 30000;
    }

    if (config_.max_observed_packets_per_source == 0)
    {
        config_.max_observed_packets_per_source = 512;
    }

    if (config_.max_packets_per_feedback == 0)
    {
        config_.max_packets_per_feedback = 64;
    }
}

std::string rtcp_transport_cc_feedback_service::make_source_key(std::string_view session_id, std::string_view remote_endpoint, uint32_t media_ssrc)
{
    std::string key;

    append_key_part(key, session_id);

    append_key_part(key, remote_endpoint);

    key.append(std::to_string(media_ssrc));

    return key;
}

rtcp_transport_cc_feedback_result rtcp_transport_cc_feedback_service::validate_observed_packet(const rtcp_transport_cc_observed_packet& packet)
{
    if (packet.stream_id.empty())
    {
        return make_error("transport cc observed packet stream id is empty");
    }

    if (packet.session_id.empty())
    {
        return make_error("transport cc observed packet session id is empty");
    }

    if (packet.remote_endpoint.empty())
    {
        return make_error("transport cc observed packet remote endpoint is empty");
    }

    if (packet.sender_ssrc == 0)
    {
        return make_error("transport cc observed packet sender ssrc is zero");
    }

    if (packet.media_ssrc == 0)
    {
        return make_error("transport cc observed packet media ssrc is zero");
    }

    if (packet.arrival_time_milliseconds == 0)
    {
        return make_error("transport cc observed packet arrival time is zero");
    }

    return {};
}

rtcp_transport_cc_feedback_result rtcp_transport_cc_feedback_service::observe_received_packet(const rtcp_transport_cc_observed_packet& packet)
{
    auto validation_result = validate_observed_packet(packet);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    const std::string key = make_source_key(packet.session_id, packet.remote_endpoint, packet.media_ssrc);

    std::lock_guard lock(mutex_);

    auto [iterator, inserted] = sources_by_key_.try_emplace(key);

    source_state& source = iterator->second;

    if (inserted)
    {
        source.stream_id = packet.stream_id;

        source.session_id = packet.session_id;

        source.remote_endpoint = packet.remote_endpoint;

        source.sender_ssrc = packet.sender_ssrc;

        source.media_ssrc = packet.media_ssrc;

        source.next_due_milliseconds = packet.arrival_time_milliseconds + config_.feedback_interval_milliseconds;
    }

    source.last_active_milliseconds = packet.arrival_time_milliseconds;

    for (const auto& observed_packet : source.packets)
    {
        if (packet_sequence_equals(observed_packet, packet.transport_sequence_number))
        {
            return {};
        }
    }

    observed_packet_state observed;

    observed.transport_sequence_number = packet.transport_sequence_number;

    observed.arrival_time_milliseconds = packet.arrival_time_milliseconds;

    source.packets.push_back(observed);

    while (source.packets.size() > config_.max_observed_packets_per_source)
    {
        source.packets.erase(source.packets.begin());
    }

    return {};
}

std::expected<rtcp_transport_cc_feedback_packet, std::string> rtcp_transport_cc_feedback_service::make_feedback_packet(source_state& source)
{
    auto plan = make_feedback_build_plan(source.packets, config_.max_packets_per_feedback);

    if (!plan)
    {
        return std::unexpected(plan.error());
    }

    source.feedback_packet_count = static_cast<uint8_t>(source.feedback_packet_count + 1U);

    auto packet = write_transport_cc_feedback_packet(source.sender_ssrc, source.media_ssrc, source.feedback_packet_count, *plan);

    if (!packet)
    {
        return std::unexpected(packet.error());
    }

    rtcp_transport_cc_feedback_packet result;

    result.stream_id = source.stream_id;

    result.session_id = source.session_id;

    result.remote_endpoint = source.remote_endpoint;

    result.sender_ssrc = source.sender_ssrc;

    result.media_ssrc = source.media_ssrc;

    result.base_sequence_number = plan->base_sequence_number;

    result.packet_status_count = plan->packet_status_count;

    result.feedback_packet_count = source.feedback_packet_count;

    result.packet = std::move(*packet);

    source.packets.erase(
        std::remove_if(source.packets.begin(),
                       source.packets.end(),
                       [&plan](const observed_packet_state& observed)
                       { return sequence_distance(plan->base_sequence_number, observed.transport_sequence_number) < plan->packet_status_count; }),
        source.packets.end());

    return result;
}

void rtcp_transport_cc_feedback_service::expire_stale_sources_locked(uint64_t now_milliseconds, rtcp_transport_cc_feedback_generation& generation)
{
    for (auto iterator = sources_by_key_.begin(); iterator != sources_by_key_.end();)
    {
        const source_state& source = iterator->second;

        const uint64_t age_milliseconds = now_milliseconds > source.last_active_milliseconds ? now_milliseconds - source.last_active_milliseconds : 0;

        if (age_milliseconds < config_.stale_source_milliseconds)
        {
            ++iterator;

            continue;
        }

        iterator = sources_by_key_.erase(iterator);

        generation.stale_sources_expired += 1;
    }
}

rtcp_transport_cc_feedback_generation rtcp_transport_cc_feedback_service::generate_due_feedback(uint64_t now_milliseconds)
{
    rtcp_transport_cc_feedback_generation generation;

    std::lock_guard lock(mutex_);

    expire_stale_sources_locked(now_milliseconds, generation);

    generation.source_count = sources_by_key_.size();

    for (auto& [key, source] : sources_by_key_)
    {
        (void)key;

        generation.pending_packet_count += source.packets.size();

        if (source.packets.empty())
        {
            continue;
        }

        if (source.next_due_milliseconds != 0 && now_milliseconds < source.next_due_milliseconds)
        {
            generation.skipped_sources += 1;

            continue;
        }

        auto packet = make_feedback_packet(source);

        source.next_due_milliseconds = now_milliseconds + config_.feedback_interval_milliseconds;

        if (!packet)
        {
            generation.errors.push_back(packet.error());

            continue;
        }

        generation.packets.push_back(std::move(*packet));
    }

    return generation;
}

void rtcp_transport_cc_feedback_service::forget_session(std::string_view session_id)
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

void rtcp_transport_cc_feedback_service::forget_stream(std::string_view stream_id)
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

void rtcp_transport_cc_feedback_service::forget_peer(std::string_view remote_endpoint)
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

void rtcp_transport_cc_feedback_service::clear()
{
    std::lock_guard lock(mutex_);

    sources_by_key_.clear();
}

std::size_t rtcp_transport_cc_feedback_service::source_count() const
{
    std::lock_guard lock(mutex_);

    return sources_by_key_.size();
}

std::size_t rtcp_transport_cc_feedback_service::pending_packet_count() const
{
    std::lock_guard lock(mutex_);

    std::size_t count = 0;

    for (const auto& [key, source] : sources_by_key_)
    {
        (void)key;

        count += source.packets.size();
    }

    return count;
}
}    // namespace webrtc
