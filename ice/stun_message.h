#ifndef SIMPLE_WEBRTC_ICE_STUN_MESSAGE_H
#define SIMPLE_WEBRTC_ICE_STUN_MESSAGE_H

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc
{
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

struct stun_message
{
    stun_method method = stun_method::unknown;
    stun_message_class message_class = stun_message_class::unknown;

    std::array<uint8_t, 12> transaction_id{};

    std::optional<std::string> username;
    std::optional<uint32_t> priority;
    bool has_use_candidate = false;
    bool has_ice_controlling = false;
    bool has_ice_controlled = false;

    bool has_message_integrity = false;

    bool has_fingerprint = false;
};

using stun_validation_result = std::expected<void, std::string>;

using stun_message_result = std::expected<stun_message, std::string>;

using stun_packet_result = std::expected<std::vector<uint8_t>, std::string>;

[[nodiscard]] bool is_stun_packet(std::span<const uint8_t> data);

[[nodiscard]] stun_message_result parse_stun_message(std::span<const uint8_t> data);

[[nodiscard]] stun_packet_result write_stun_binding_success_response(const stun_message& request,
                                                                     std::string_view mapped_ip,
                                                                     uint16_t mapped_port,
                                                                     std::string_view message_integrity_key);

[[nodiscard]] stun_validation_result verify_stun_fingerprint(std::span<const uint8_t> data);

[[nodiscard]] stun_validation_result verify_stun_message_integrity(std::span<const uint8_t> data, std::string_view key);

[[nodiscard]] std::string stun_class_to_string(stun_message_class value);

[[nodiscard]] std::string stun_method_to_string(stun_method value);
}    // namespace webrtc

#endif
