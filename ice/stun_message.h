#ifndef SIMPLE_WEBRTC_ICE_STUN_MESSAGE_H
#define SIMPLE_WEBRTC_ICE_STUN_MESSAGE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc
{
inline constexpr uint32_t kStunMagicCookie = 0x2112A442U;

inline constexpr uint16_t kStunAttributeMappedAddress = 0x0001U;
inline constexpr uint16_t kStunAttributeUsername = 0x0006U;
inline constexpr uint16_t kStunAttributeMessageIntegrity = 0x0008U;
inline constexpr uint16_t kStunAttributeXorMappedAddress = 0x0020U;
inline constexpr uint16_t kStunAttributePriority = 0x0024U;
inline constexpr uint16_t kStunAttributeUseCandidate = 0x0025U;
inline constexpr uint16_t kStunAttributeFingerprint = 0x8028U;
inline constexpr uint16_t kStunAttributeIceControlled = 0x8029U;
inline constexpr uint16_t kStunAttributeIceControlling = 0x802AU;

enum class stun_message_class
{
    request,
    indication,
    success_response,
    error_response,
    unknown,
};

enum class stun_method
{
    unknown = 0,
    binding = 1,
};

struct stun_address
{
    std::string ip;
    uint16_t port = 0;
    bool is_ipv6 = false;
};

struct stun_attribute
{
    uint16_t type = 0;
    std::vector<uint8_t> value;
};

struct stun_message
{
    uint16_t raw_type = 0;
    uint16_t raw_method = 0;

    stun_method method = stun_method::unknown;
    stun_message_class message_class = stun_message_class::unknown;

    std::array<uint8_t, 12> transaction_id{};

    std::vector<stun_attribute> attributes;

    std::optional<stun_address> mapped_address;
    std::optional<stun_address> xor_mapped_address;
    std::optional<std::string> username;
    std::optional<uint32_t> priority;
    std::optional<uint64_t> ice_controlling;
    std::optional<uint64_t> ice_controlled;

    bool use_candidate = false;

    bool has_message_integrity = false;
    std::size_t message_integrity_attribute_offset = 0;

    bool has_fingerprint = false;
    uint32_t fingerprint = 0;
    std::size_t fingerprint_attribute_offset = 0;
};

struct stun_binding_success_response_options
{
    stun_address mapped_address;

    std::string message_integrity_key;

    bool include_message_integrity = true;
    bool include_fingerprint = true;
};

using stun_validation_result = std::expected<void, std::string>;

using stun_message_result = std::expected<stun_message, std::string>;

using stun_packet_result = std::expected<std::vector<uint8_t>, std::string>;

[[nodiscard]] bool is_stun_packet(std::span<const uint8_t> data);

[[nodiscard]] stun_validation_result validate_stun_header(std::span<const uint8_t> data);

[[nodiscard]] stun_message_result parse_stun_message(std::span<const uint8_t> data);

[[nodiscard]] stun_packet_result write_stun_binding_success_response(const stun_message& request,
                                                                     const stun_binding_success_response_options& options);

[[nodiscard]] stun_validation_result verify_stun_fingerprint(std::span<const uint8_t> data);

[[nodiscard]] stun_validation_result verify_stun_message_integrity(std::span<const uint8_t> data, std::string_view key);

[[nodiscard]] std::string stun_class_to_string(stun_message_class value);

[[nodiscard]] std::string stun_method_to_string(stun_method value);
}    // namespace webrtc

#endif
