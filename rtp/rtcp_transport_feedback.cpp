#include "rtp/rtcp_transport_feedback.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc
{
namespace
{
constexpr uint8_t k_rtcp_version = 2;
constexpr uint8_t k_rtcp_transport_feedback_fmt = 15;
constexpr uint8_t k_rtcp_transport_feedback_packet_type = 205;
constexpr std::size_t k_rtcp_transport_feedback_header_size = 20;
constexpr std::size_t k_statuses_per_two_bit_chunk = 7;
constexpr int64_t k_delta_tick_microseconds = 250;
constexpr int64_t k_reference_time_microseconds = 64000;
constexpr int64_t k_sequence_modulus = 1LL << 16;
constexpr int64_t k_sequence_half_range = k_sequence_modulus / 2;
constexpr int64_t k_maximum_sequence_jump = 4096;
constexpr std::size_t k_maximum_statuses_per_feedback = 4096;

std::unexpected<std::string> make_error(std::string_view message)
{
    return std::unexpected(std::string(message));
}

void write_u16(std::span<uint8_t> data, std::size_t offset, uint16_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 8U);
    data[offset + 1U] = static_cast<uint8_t>(value);
}

void write_u24(std::span<uint8_t> data, std::size_t offset, uint32_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 16U);
    data[offset + 1U] = static_cast<uint8_t>(value >> 8U);
    data[offset + 2U] = static_cast<uint8_t>(value);
}

void write_u32(std::span<uint8_t> data, std::size_t offset, uint32_t value)
{
    data[offset] = static_cast<uint8_t>(value >> 24U);
    data[offset + 1U] = static_cast<uint8_t>(value >> 16U);
    data[offset + 2U] = static_cast<uint8_t>(value >> 8U);
    data[offset + 3U] = static_cast<uint8_t>(value);
}

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) |
                                 static_cast<uint16_t>(data[offset + 1U]));
}

uint32_t read_u24(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 16U) |
           (static_cast<uint32_t>(data[offset + 1U]) << 8U) |
           static_cast<uint32_t>(data[offset + 2U]);
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) |
           (static_cast<uint32_t>(data[offset + 1U]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2U]) << 8U) |
           static_cast<uint32_t>(data[offset + 3U]);
}

int16_t read_i16(std::span<const uint8_t> data, std::size_t offset)
{
    return std::bit_cast<int16_t>(read_u16(data, offset));
}

int64_t arrival_time_microseconds(std::chrono::steady_clock::time_point time)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
               time.time_since_epoch())
        .count();
}

int64_t floor_reference_time(int64_t arrival_microseconds)
{
    if (arrival_microseconds >= 0)
    {
        return arrival_microseconds / k_reference_time_microseconds;
    }

    return -((-arrival_microseconds + k_reference_time_microseconds - 1) /
             k_reference_time_microseconds);
}

int64_t round_delta_ticks(int64_t delta_microseconds)
{
    if (delta_microseconds >= 0)
    {
        return (delta_microseconds + k_delta_tick_microseconds / 2) /
               k_delta_tick_microseconds;
    }

    return (delta_microseconds - k_delta_tick_microseconds / 2) /
           k_delta_tick_microseconds;
}

std::vector<uint16_t> encode_status_chunks(std::span<const uint8_t> symbols)
{
    std::vector<uint16_t> chunks;
    std::size_t offset = 0;

    while (offset < symbols.size())
    {
        const uint8_t symbol = symbols[offset];
        std::size_t run_length = 1;

        while (offset + run_length < symbols.size() &&
               symbols[offset + run_length] == symbol &&
               run_length < 0x1FFFU)
        {
            ++run_length;
        }

        if (run_length >= k_statuses_per_two_bit_chunk)
        {
            const uint16_t chunk = static_cast<uint16_t>(
                (static_cast<uint16_t>(symbol) << 13U) |
                static_cast<uint16_t>(run_length));
            chunks.push_back(chunk);
            offset += run_length;
            continue;
        }

        const std::size_t one_bit_count =
            std::min<std::size_t>(14U, symbols.size() - offset);
        bool one_bit_compatible = true;

        for (std::size_t index = 0; index < one_bit_count; ++index)
        {
            if (symbols[offset + index] > 1U)
            {
                one_bit_compatible = false;
                break;
            }
        }

        if (one_bit_compatible)
        {
            uint16_t chunk = 0x8000U;

            for (std::size_t index = 0; index < one_bit_count; ++index)
            {
                chunk = static_cast<uint16_t>(
                    chunk |
                    static_cast<uint16_t>(
                        static_cast<uint16_t>(symbols[offset + index])
                        << static_cast<unsigned>(13U - index)));
            }

            chunks.push_back(chunk);
            offset += one_bit_count;
            continue;
        }

        uint16_t chunk = 0xC000U;
        const std::size_t two_bit_count = std::min<std::size_t>(
            k_statuses_per_two_bit_chunk, symbols.size() - offset);

        for (std::size_t index = 0; index < two_bit_count; ++index)
        {
            const unsigned shift = static_cast<unsigned>(
                2U * (k_statuses_per_two_bit_chunk - 1U - index));
            chunk = static_cast<uint16_t>(
                chunk |
                static_cast<uint16_t>(
                    static_cast<uint16_t>(symbols[offset + index]) << shift));
        }

        chunks.push_back(chunk);
        offset += two_bit_count;
    }

    return chunks;
}

std::size_t encoded_packet_size(std::span<const uint8_t> delta_sizes)
{
    const auto chunks = encode_status_chunks(delta_sizes);
    std::size_t size = k_rtcp_transport_feedback_header_size + chunks.size() * 2U;

    for (const uint8_t delta_size : delta_sizes)
    {
        size += delta_size;
    }

    return (size + 3U) & ~std::size_t{3U};
}

std::vector<uint8_t> encode_transport_feedback_packet(
    uint32_t sender_ssrc,
    uint32_t media_ssrc,
    uint16_t base_sequence,
    uint32_t reference_time,
    uint8_t feedback_packet_count,
    std::span<const uint8_t> delta_sizes,
    std::span<const int16_t> deltas)
{
    const std::size_t packet_size = encoded_packet_size(delta_sizes);
    std::vector<uint8_t> packet(packet_size);
    const auto chunks = encode_status_chunks(delta_sizes);
    std::size_t unpadded_size =
        k_rtcp_transport_feedback_header_size + chunks.size() * 2U;

    for (const uint8_t delta_size : delta_sizes)
    {
        unpadded_size += delta_size;
    }

    const std::size_t padding_size = packet_size - unpadded_size;
    packet[0] = static_cast<uint8_t>((k_rtcp_version << 6U) |
                                     (padding_size != 0 ? 0x20U : 0U) |
                                     k_rtcp_transport_feedback_fmt);
    packet[1] = k_rtcp_transport_feedback_packet_type;
    write_u16(packet, 2U, static_cast<uint16_t>(packet_size / 4U - 1U));
    write_u32(packet, 4U, sender_ssrc);
    write_u32(packet, 8U, media_ssrc);
    write_u16(packet, 12U, base_sequence);
    write_u16(packet, 14U, static_cast<uint16_t>(delta_sizes.size()));
    write_u24(packet, 16U, reference_time & 0x00FFFFFFU);
    packet[19] = feedback_packet_count;

    std::size_t offset = k_rtcp_transport_feedback_header_size;

    for (const uint16_t chunk : chunks)
    {
        write_u16(packet, offset, chunk);
        offset += 2U;
    }

    std::size_t delta_index = 0;

    for (const uint8_t delta_size : delta_sizes)
    {
        if (delta_size == 0)
        {
            continue;
        }

        const int16_t delta = deltas[delta_index++];

        if (delta_size == 1)
        {
            packet[offset++] = static_cast<uint8_t>(delta);
        }
        else
        {
            write_u16(packet, offset, static_cast<uint16_t>(delta));
            offset += 2U;
        }
    }

    if (padding_size != 0)
    {
        packet[packet.size() - 1U] = static_cast<uint8_t>(padding_size);
    }

    return packet;
}
}    // namespace

transport_feedback_generator::transport_feedback_generator(
    std::chrono::milliseconds maximum_history_age,
    std::size_t maximum_history_packets)
    : maximum_history_age_(maximum_history_age),
      maximum_history_packets_(maximum_history_packets)
{
}

int64_t transport_feedback_generator::unwrap_sequence(
    uint16_t sequence_number, bool& discontinuity)
{
    discontinuity = false;

    if (!newest_extended_sequence_.has_value())
    {
        newest_extended_sequence_ = static_cast<int64_t>(sequence_number);
        return *newest_extended_sequence_;
    }

    const int64_t newest = *newest_extended_sequence_;
    int64_t candidate = (newest & ~(k_sequence_modulus - 1LL)) |
                        static_cast<int64_t>(sequence_number);

    if (candidate - newest > k_sequence_half_range)
    {
        candidate -= k_sequence_modulus;
    }
    else if (newest - candidate > k_sequence_half_range)
    {
        candidate += k_sequence_modulus;
    }

    const int64_t sequence_distance =
        candidate >= newest ? candidate - newest : newest - candidate;

    if (sequence_distance > k_maximum_sequence_jump)
    {
        discontinuity = true;
        arrivals_.clear();
        feedback_window_start_ = candidate;
        newest_extended_sequence_ = candidate;
        return candidate;
    }

    if (candidate > newest)
    {
        newest_extended_sequence_ = candidate;
    }

    return candidate;
}

void transport_feedback_generator::evict_old(
    std::chrono::steady_clock::time_point now)
{
    for (auto iterator = arrivals_.begin(); iterator != arrivals_.end();)
    {
        if (now - iterator->second.arrival_time > maximum_history_age_)
        {
            iterator = arrivals_.erase(iterator);
        }
        else
        {
            ++iterator;
        }
    }

    while (arrivals_.size() > maximum_history_packets_)
    {
        arrivals_.erase(arrivals_.begin());
    }

    if (feedback_window_start_.has_value() && arrivals_.empty())
    {
        if (newest_extended_sequence_.has_value())
        {
            feedback_window_start_ = *newest_extended_sequence_ + 1;
        }
        else
        {
            feedback_window_start_.reset();
        }
    }
    else if (feedback_window_start_.has_value())
    {
        const int64_t earliest_received = arrivals_.begin()->first;
        const int64_t earliest_encodable =
            earliest_received -
            static_cast<int64_t>(k_maximum_statuses_per_feedback - 1U);

        if (*feedback_window_start_ < earliest_encodable)
        {
            feedback_window_start_ = earliest_encodable;
        }
    }
}

transport_feedback_observe_result transport_feedback_generator::observe(
    uint16_t sequence_number,
    std::chrono::steady_clock::time_point arrival_time,
    uint32_t media_ssrc)
{
    bool discontinuity = false;
    const int64_t extended_sequence = unwrap_sequence(sequence_number, discontinuity);
    auto [iterator, inserted] = arrivals_.try_emplace(
        extended_sequence, arrival_record{.arrival_time = arrival_time});

    media_ssrc_ = media_ssrc;

    if (!inserted)
    {
        ++stats_.duplicate_packets;
        evict_old(arrival_time);
        stats_.history_packets = arrivals_.size();
        stats_.pending_packets = pending_status_count();
        return transport_feedback_observe_result{
            .inserted = false,
            .duplicate = true,
            .sequence_discontinuity = discontinuity,
            .extended_sequence_number = extended_sequence,
        };
    }

    if (!feedback_window_start_.has_value() ||
        extended_sequence < *feedback_window_start_)
    {
        feedback_window_start_ = extended_sequence;
    }

    ++stats_.observed_packets;

    if (discontinuity)
    {
        ++stats_.sequence_discontinuities;
    }

    evict_old(arrival_time);
    stats_.history_packets = arrivals_.size();
    stats_.pending_packets = pending_status_count();

    return transport_feedback_observe_result{
        .inserted = true,
        .duplicate = false,
        .sequence_discontinuity = discontinuity,
        .extended_sequence_number = extended_sequence,
    };
}

std::expected<std::optional<built_rtcp_transport_feedback>, std::string>
transport_feedback_generator::preview_feedback(uint32_t sender_ssrc,
                                               std::size_t maximum_packet_size) const
{
    if (sender_ssrc == 0)
    {
        return make_error("rtcp transport feedback sender ssrc is zero");
    }

    if (maximum_packet_size < k_rtcp_transport_feedback_header_size + 4U)
    {
        return make_error("rtcp transport feedback maximum packet size is too small");
    }

    if (!has_pending_feedback())
    {
        return std::optional<built_rtcp_transport_feedback>{};
    }

    const int64_t base_extended_sequence = *feedback_window_start_;
    const int64_t maximum_sequence = std::min(
        *newest_extended_sequence_,
        base_extended_sequence +
            static_cast<int64_t>(k_maximum_statuses_per_feedback - 1U));
    const auto first_received = arrivals_.lower_bound(base_extended_sequence);

    if (first_received == arrivals_.end() || first_received->first > maximum_sequence)
    {
        return make_error("rtcp transport feedback pending range has no received packet");
    }

    const int64_t first_arrival_us =
        arrival_time_microseconds(first_received->second.arrival_time);
    const int64_t reference_time_full = floor_reference_time(first_arrival_us);
    int64_t last_arrival_us = reference_time_full * k_reference_time_microseconds;
    std::vector<uint8_t> delta_sizes;
    std::vector<int16_t> deltas;
    delta_sizes.reserve(static_cast<std::size_t>(
        maximum_sequence - base_extended_sequence + 1));
    deltas.reserve(delta_sizes.capacity());
    std::size_t received_count = 0;
    std::size_t lost_count = 0;
    int64_t actual_end = base_extended_sequence - 1;

    for (int64_t sequence = base_extended_sequence;
         sequence <= maximum_sequence;
         ++sequence)
    {
        uint8_t delta_size = 0;
        std::optional<int16_t> delta;
        const auto arrival = arrivals_.find(sequence);

        if (arrival != arrivals_.end())
        {
            const int64_t current_arrival_us =
                arrival_time_microseconds(arrival->second.arrival_time);
            const int64_t delta_ticks =
                round_delta_ticks(current_arrival_us - last_arrival_us);

            if (delta_ticks < std::numeric_limits<int16_t>::min() ||
                delta_ticks > std::numeric_limits<int16_t>::max())
            {
                if (sequence == base_extended_sequence)
                {
                    return make_error("rtcp transport feedback first receive delta exceeds signed sixteen-bit field");
                }
                break;
            }

            delta = static_cast<int16_t>(delta_ticks);
            delta_size = delta_ticks >= 0 && delta_ticks <= 255 ? 1U : 2U;
        }

        delta_sizes.push_back(delta_size);

        if (delta.has_value())
        {
            deltas.push_back(*delta);
        }

        if (encoded_packet_size(delta_sizes) > maximum_packet_size)
        {
            delta_sizes.pop_back();

            if (delta.has_value())
            {
                deltas.pop_back();
            }
            break;
        }

        actual_end = sequence;

        if (delta.has_value())
        {
            ++received_count;
            last_arrival_us += static_cast<int64_t>(*delta) *
                               k_delta_tick_microseconds;
        }
        else
        {
            ++lost_count;
        }
    }

    if (delta_sizes.empty() || actual_end < base_extended_sequence)
    {
        return make_error("rtcp transport feedback packet cannot encode any status");
    }

    std::vector<uint8_t> packet = encode_transport_feedback_packet(
        sender_ssrc,
        media_ssrc_,
        static_cast<uint16_t>(base_extended_sequence & 0xFFFF),
        static_cast<uint32_t>(reference_time_full) & 0x00FFFFFFU,
        feedback_packet_count_,
        delta_sizes,
        deltas);

    return std::optional<built_rtcp_transport_feedback>(
        built_rtcp_transport_feedback{
            .packet = std::move(packet),
            .base_sequence_number =
                static_cast<uint16_t>(base_extended_sequence & 0xFFFF),
            .packet_status_count = static_cast<uint16_t>(delta_sizes.size()),
            .media_ssrc = media_ssrc_,
            .feedback_packet_count = feedback_packet_count_,
            .received_packet_count = received_count,
            .lost_packet_count = lost_count,
            .begin_extended_sequence = base_extended_sequence,
            .end_extended_sequence = actual_end,
        });
}

void transport_feedback_generator::commit_feedback(
    const built_rtcp_transport_feedback& feedback)
{
    if (!feedback_window_start_.has_value() ||
        feedback.begin_extended_sequence != *feedback_window_start_ ||
        feedback.end_extended_sequence < feedback.begin_extended_sequence ||
        feedback.feedback_packet_count != feedback_packet_count_)
    {
        return;
    }

    feedback_window_start_ = feedback.end_extended_sequence + 1;
    ++feedback_packet_count_;
    ++stats_.feedback_packets_built;
    stats_.packet_statuses_built += feedback.packet_status_count;
    stats_.history_packets = arrivals_.size();
    stats_.pending_packets = pending_status_count();
}

void transport_feedback_generator::expire(
    std::chrono::steady_clock::time_point now)
{
    evict_old(now);
    stats_.history_packets = arrivals_.size();
    stats_.pending_packets = pending_status_count();
}

std::size_t transport_feedback_generator::pending_status_count() const
{
    if (!has_pending_feedback())
    {
        return 0;
    }

    const uint64_t count = static_cast<uint64_t>(
        *newest_extended_sequence_ - *feedback_window_start_ + 1);
    return count > std::numeric_limits<std::size_t>::max()
               ? std::numeric_limits<std::size_t>::max()
               : static_cast<std::size_t>(count);
}

bool transport_feedback_generator::has_pending_feedback() const
{
    return feedback_window_start_.has_value() &&
           newest_extended_sequence_.has_value() &&
           *feedback_window_start_ <= *newest_extended_sequence_;
}

transport_feedback_generator_snapshot transport_feedback_generator::snapshot() const
{
    auto snapshot = stats_;
    snapshot.history_packets = arrivals_.size();
    snapshot.pending_packets = pending_status_count();
    return snapshot;
}

void transport_feedback_generator::reset()
{
    newest_extended_sequence_.reset();
    feedback_window_start_.reset();
    arrivals_.clear();
    media_ssrc_ = 0;
    feedback_packet_count_ = 0;
    stats_ = {};
}

rtcp_transport_feedback_parse_result parse_rtcp_transport_feedback(
    std::span<const uint8_t> data)
{
    if (data.size() < k_rtcp_transport_feedback_header_size ||
        data.size() % 4U != 0)
    {
        return make_error("rtcp transport feedback packet size is invalid");
    }

    if ((data[0] >> 6U) != k_rtcp_version ||
        (data[0] & 0x1FU) != k_rtcp_transport_feedback_fmt ||
        data[1] != k_rtcp_transport_feedback_packet_type)
    {
        return make_error("rtcp transport feedback header is invalid");
    }

    const std::size_t declared_size =
        (static_cast<std::size_t>(read_u16(data, 2U)) + 1U) * 4U;

    if (declared_size != data.size())
    {
        return make_error("rtcp transport feedback declared size does not match buffer");
    }

    std::size_t effective_size = data.size();

    if ((data[0] & 0x20U) != 0)
    {
        const std::size_t padding_size = data.back();

        if (padding_size == 0 || padding_size >
                                     effective_size -
                                         k_rtcp_transport_feedback_header_size)
        {
            return make_error("rtcp transport feedback padding is invalid");
        }

        effective_size -= padding_size;
    }

    parsed_rtcp_transport_feedback parsed;
    parsed.sender_ssrc = read_u32(data, 4U);
    parsed.media_ssrc = read_u32(data, 8U);
    parsed.base_sequence_number = read_u16(data, 12U);
    parsed.packet_status_count = read_u16(data, 14U);
    parsed.reference_time = read_u24(data, 16U);
    parsed.feedback_packet_count = data[19];

    if (parsed.packet_status_count == 0)
    {
        return make_error("rtcp transport feedback packet status count is zero");
    }

    std::size_t offset = k_rtcp_transport_feedback_header_size;
    std::vector<uint8_t> delta_sizes;
    delta_sizes.reserve(parsed.packet_status_count);

    while (delta_sizes.size() < parsed.packet_status_count)
    {
        if (offset + 2U > effective_size)
        {
            return make_error("rtcp transport feedback status chunk is truncated");
        }

        const uint16_t chunk = read_u16(data, offset);
        offset += 2U;

        if ((chunk & 0x8000U) == 0)
        {
            const uint8_t symbol = static_cast<uint8_t>((chunk >> 13U) & 0x03U);
            const std::size_t run_length = static_cast<std::size_t>(chunk & 0x1FFFU);

            if (run_length == 0 || symbol == 3U)
            {
                return make_error("rtcp transport feedback run-length chunk is invalid");
            }

            const std::size_t remaining =
                static_cast<std::size_t>(parsed.packet_status_count) -
                delta_sizes.size();
            delta_sizes.insert(delta_sizes.end(),
                               std::min(run_length, remaining),
                               symbol);
        }
        else if ((chunk & 0x4000U) == 0)
        {
            const std::size_t count = std::min<std::size_t>(
                14U,
                static_cast<std::size_t>(parsed.packet_status_count) -
                    delta_sizes.size());

            for (std::size_t index = 0; index < count; ++index)
            {
                delta_sizes.push_back(static_cast<uint8_t>(
                    (chunk >> static_cast<unsigned>(13U - index)) & 0x01U));
            }
        }
        else
        {
            const std::size_t count = std::min<std::size_t>(
                7U,
                static_cast<std::size_t>(parsed.packet_status_count) -
                    delta_sizes.size());

            for (std::size_t index = 0; index < count; ++index)
            {
                const unsigned shift = static_cast<unsigned>(
                    2U * (k_statuses_per_two_bit_chunk - 1U - index));
                const uint8_t symbol =
                    static_cast<uint8_t>((chunk >> shift) & 0x03U);

                if (symbol == 3U)
                {
                    return make_error("rtcp transport feedback status symbol is reserved");
                }

                delta_sizes.push_back(symbol);
            }
        }
    }

    parsed.statuses.reserve(parsed.packet_status_count);
    uint16_t sequence = parsed.base_sequence_number;

    for (const uint8_t delta_size : delta_sizes)
    {
        rtcp_transport_feedback_status status;
        status.sequence_number = sequence++;
        status.received = delta_size != 0;

        if (delta_size == 1)
        {
            if (offset + 1U > effective_size)
            {
                return make_error("rtcp transport feedback small delta is truncated");
            }

            status.delta_ticks = static_cast<int16_t>(data[offset++]);
        }
        else if (delta_size == 2)
        {
            if (offset + 2U > effective_size)
            {
                return make_error("rtcp transport feedback large delta is truncated");
            }

            status.delta_ticks = read_i16(data, offset);
            offset += 2U;
        }

        parsed.statuses.push_back(status);
    }

    if (offset != effective_size)
    {
        return make_error("rtcp transport feedback packet has trailing data");
    }

    return parsed;
}
}    // namespace webrtc
