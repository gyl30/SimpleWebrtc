#include "rtp/rtp_header_extension.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace webrtc
{
namespace
{
constexpr std::size_t k_rtp_fixed_header_size = 12;
constexpr std::size_t k_rtp_csrc_size = 4;
constexpr std::size_t k_rtp_extension_header_size = 4;
constexpr uint16_t k_one_byte_extension_profile = 0xBEDE;
constexpr uint16_t k_two_byte_extension_profile_mask = 0xFFF0;
constexpr uint16_t k_two_byte_extension_profile_value = 0x1000;
constexpr uint8_t k_one_byte_extension_reserved_id = 15;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

rtp_header_extension_result find_one_byte_extension(std::span<const uint8_t> payload, uint8_t extension_id)
{
    std::size_t offset = 0;

    while (offset < payload.size())
    {
        const uint8_t value = payload[offset++];

        if (value == 0)
        {
            continue;
        }

        const uint8_t id = static_cast<uint8_t>(value >> 4U);

        if (id == k_one_byte_extension_reserved_id)
        {
            return make_error("rtp one-byte extension id 15 is reserved");
        }

        const std::size_t size = static_cast<std::size_t>(value & 0x0FU) + 1U;

        if (offset + size > payload.size())
        {
            return make_error("rtp one-byte extension element is truncated");
        }

        if (id == extension_id)
        {
            return std::optional<std::span<const uint8_t>>(payload.subspan(offset, size));
        }

        offset += size;
    }

    return std::optional<std::span<const uint8_t>>{};
}

rtp_header_extension_result find_two_byte_extension(std::span<const uint8_t> payload, uint8_t extension_id)
{
    std::size_t offset = 0;

    while (offset < payload.size())
    {
        const uint8_t id = payload[offset++];

        if (id == 0)
        {
            continue;
        }

        if (offset >= payload.size())
        {
            return make_error("rtp two-byte extension length is truncated");
        }

        const std::size_t size = static_cast<std::size_t>(payload[offset++]);

        if (offset + size > payload.size())
        {
            return make_error("rtp two-byte extension element is truncated");
        }

        if (id == extension_id)
        {
            return std::optional<std::span<const uint8_t>>(payload.subspan(offset, size));
        }

        offset += size;
    }

    return std::optional<std::span<const uint8_t>>{};
}
}    // namespace

rtp_header_extension_result find_rtp_header_extension(std::span<const uint8_t> packet, uint8_t extension_id)
{
    if (extension_id == 0)
    {
        return make_error("rtp header extension id is zero");
    }

    if (packet.size() < k_rtp_fixed_header_size)
    {
        return make_error("rtp packet is shorter than fixed header");
    }

    if ((packet[0] >> 6U) != 2U)
    {
        return make_error("rtp version is invalid");
    }

    const bool has_extension = (packet[0] & 0x10U) != 0;

    if (!has_extension)
    {
        return std::optional<std::span<const uint8_t>>{};
    }

    const uint8_t csrc_count = static_cast<uint8_t>(packet[0] & 0x0FU);
    const std::size_t extension_header_offset = k_rtp_fixed_header_size + static_cast<std::size_t>(csrc_count) * k_rtp_csrc_size;

    if (extension_header_offset + k_rtp_extension_header_size > packet.size())
    {
        return make_error("rtp extension header is truncated");
    }

    const uint16_t profile = read_u16(packet, extension_header_offset);
    const uint16_t length_words = read_u16(packet, extension_header_offset + 2U);
    const std::size_t payload_offset = extension_header_offset + k_rtp_extension_header_size;
    const std::size_t payload_size = static_cast<std::size_t>(length_words) * 4U;

    if (payload_offset + payload_size > packet.size())
    {
        return make_error("rtp extension payload is truncated");
    }

    const auto payload = packet.subspan(payload_offset, payload_size);

    if (profile == k_one_byte_extension_profile)
    {
        if (extension_id >= k_one_byte_extension_reserved_id)
        {
            return std::optional<std::span<const uint8_t>>{};
        }

        return find_one_byte_extension(payload, extension_id);
    }

    if ((profile & k_two_byte_extension_profile_mask) == k_two_byte_extension_profile_value)
    {
        return find_two_byte_extension(payload, extension_id);
    }

    return std::optional<std::span<const uint8_t>>{};
}
}    // namespace webrtc
