#ifndef SIMPLE_WEBRTC_RTP_RTP_PACKET_H
#define SIMPLE_WEBRTC_RTP_RTP_PACKET_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace webrtc
{
enum class rtp_header_extension_format
{
    unknown,
    one_byte,
    two_byte,
};

struct rtp_header_extension_entry
{
    uint8_t id = 0;

    std::size_t offset = 0;
    std::size_t size = 0;
};

struct rtp_packet_header
{
    uint8_t version = 0;
    bool padding = false;
    bool extension = false;
    bool marker = false;

    uint8_t csrc_count = 0;
    uint8_t payload_type = 0;

    uint16_t sequence_number = 0;
    uint32_t timestamp = 0;
    uint32_t ssrc = 0;

    uint16_t extension_profile = 0;
    rtp_header_extension_format extension_format = rtp_header_extension_format::unknown;

    std::size_t extension_header_offset = 0;
    std::size_t extension_payload_offset = 0;
    std::size_t extension_payload_size = 0;

    std::vector<rtp_header_extension_entry> header_extensions;

    std::size_t header_size = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_size = 0;
    std::size_t padding_size = 0;
};

struct rtcp_packet_header
{
    uint8_t version = 0;
    bool padding = false;

    uint8_t count = 0;
    uint8_t packet_type = 0;
    uint16_t length = 0;

    std::size_t packet_size = 0;

    bool has_ssrc = false;
    uint32_t ssrc = 0;
};

using rtp_packet_header_result = std::expected<rtp_packet_header, std::string>;

using rtcp_packet_header_result = std::expected<rtcp_packet_header, std::string>;

[[nodiscard]]
bool is_rtp_or_rtcp_packet(std::span<const uint8_t> data);

[[nodiscard]]
bool is_rtcp_packet(std::span<const uint8_t> data);

[[nodiscard]]
bool is_rtp_packet(std::span<const uint8_t> data);

[[nodiscard]]
rtp_packet_header_result parse_rtp_packet_header(std::span<const uint8_t> data);

[[nodiscard]]
rtcp_packet_header_result parse_rtcp_packet_header(std::span<const uint8_t> data);

[[nodiscard]]
std::optional<std::span<const uint8_t>> find_rtp_header_extension(std::span<const uint8_t> packet,
                                                                  const rtp_packet_header& header,
                                                                  uint8_t extension_id);

[[nodiscard]]
bool is_one_byte_rtp_header_extension_profile(uint16_t profile);

[[nodiscard]]
bool is_two_byte_rtp_header_extension_profile(uint16_t profile);

[[nodiscard]]
std::string rtp_header_extension_format_to_string(rtp_header_extension_format format);

[[nodiscard]]
std::string rtcp_packet_type_to_string(uint8_t packet_type);
}    // namespace webrtc

#endif
