#include "ice/stun_message.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace webrtc
{
namespace
{
constexpr std::size_t kStunHeaderSize = 20;
constexpr std::size_t kStunTransactionIdSize = 12;
constexpr std::size_t kStunMessageIntegritySize = 20;
constexpr std::size_t kStunFingerprintSize = 4;

constexpr uint16_t kStunBindingMethod = 0x0001U;
constexpr uint32_t kStunFingerprintXorValue = 0x5354554EU;

constexpr std::array<uint8_t, 4> kStunMagicCookieBytes{
    0x21,
    0x12,
    0xA4,
    0x42,
};

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }
uint16_t read_u16(std::span<const uint8_t> data, std::size_t offset)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | static_cast<uint16_t>(data[offset + 1]));
}

uint32_t read_u32(std::span<const uint8_t> data, std::size_t offset)
{
    return (static_cast<uint32_t>(data[offset]) << 24U) | (static_cast<uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<uint32_t>(data[offset + 2]) << 8U) | static_cast<uint32_t>(data[offset + 3]);
}

uint64_t read_u64(std::span<const uint8_t> data, std::size_t offset)
{
    const uint64_t high = static_cast<uint64_t>(read_u32(data, offset));

    const uint64_t low = static_cast<uint64_t>(read_u32(data, offset + 4));

    return (high << 32U) | low;
}

void append_u16(std::vector<uint8_t>& data, uint16_t value)
{
    data.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    data.push_back(static_cast<uint8_t>(value & 0xFFU));
}

void append_u32(std::vector<uint8_t>& data, uint32_t value)
{
    data.push_back(static_cast<uint8_t>((value >> 24U) & 0xFFU));
    data.push_back(static_cast<uint8_t>((value >> 16U) & 0xFFU));
    data.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    data.push_back(static_cast<uint8_t>(value & 0xFFU));
}
void write_u16(std::vector<uint8_t>& data, std::size_t offset, uint16_t value)
{
    data[offset] = static_cast<uint8_t>((value >> 8U) & 0xFFU);

    data[offset + 1] = static_cast<uint8_t>(value & 0xFFU);
}

void write_u32(std::vector<uint8_t>& data, std::size_t offset, uint32_t value)
{
    data[offset] = static_cast<uint8_t>((value >> 24U) & 0xFFU);

    data[offset + 1] = static_cast<uint8_t>((value >> 16U) & 0xFFU);

    data[offset + 2] = static_cast<uint8_t>((value >> 8U) & 0xFFU);

    data[offset + 3] = static_cast<uint8_t>(value & 0xFFU);
}

std::size_t padding_size(std::size_t value_length)
{
    const std::size_t remainder = value_length % 4U;

    if (remainder == 0)
    {
        return 0;
    }

    return 4U - remainder;
}

uint16_t encode_message_type(uint16_t method, stun_message_class message_class)
{
    uint16_t class_value = 0;

    switch (message_class)
    {
        case stun_message_class::request:
            class_value = 0;
            break;

        case stun_message_class::indication:
            class_value = 1;
            break;

        case stun_message_class::success_response:
            class_value = 2;
            break;

        case stun_message_class::error_response:
            class_value = 3;
            break;

        case stun_message_class::unknown:
            class_value = 0;
            break;
    }

    uint16_t value = 0;

    value |= static_cast<uint16_t>(method & 0x000FU);
    value |= static_cast<uint16_t>((method & 0x0070U) << 1U);
    value |= static_cast<uint16_t>((method & 0x0F80U) << 2U);
    value |= static_cast<uint16_t>((class_value & 0x0001U) << 4U);
    value |= static_cast<uint16_t>((class_value & 0x0002U) << 7U);

    return value;
}

uint16_t decode_method(uint16_t raw_type)
{
    uint16_t method = 0;

    method |= static_cast<uint16_t>(raw_type & 0x000FU);
    method |= static_cast<uint16_t>((raw_type & 0x00E0U) >> 1U);
    method |= static_cast<uint16_t>((raw_type & 0x3E00U) >> 2U);

    return method;
}

stun_method make_stun_method(uint16_t raw_method)
{
    if (raw_method == kStunBindingMethod)
    {
        return stun_method::binding;
    }

    return stun_method::unknown;
}

stun_message_class decode_message_class(uint16_t raw_type)
{
    const uint16_t value = static_cast<uint16_t>(((raw_type & 0x0010U) >> 4U) | ((raw_type & 0x0100U) >> 7U));

    switch (value)
    {
        case 0:
            return stun_message_class::request;

        case 1:
            return stun_message_class::indication;

        case 2:
            return stun_message_class::success_response;

        case 3:
            return stun_message_class::error_response;

        default:
            return stun_message_class::unknown;
    }
}

uint32_t calculate_crc32(std::span<const uint8_t> data)
{
    uint32_t crc = 0xFFFFFFFFU;

    for (const auto byte : data)
    {
        crc ^= static_cast<uint32_t>(byte);

        for (int bit = 0; bit < 8; ++bit)
        {
            if ((crc & 1U) != 0)
            {
                crc = (crc >> 1U) ^ 0xEDB88320U;
            }
            else
            {
                crc >>= 1U;
            }
        }
    }

    return crc ^ 0xFFFFFFFFU;
}

bool constant_time_equal(std::span<const uint8_t> left, std::span<const uint8_t> right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    uint8_t result = 0;

    for (std::size_t i = 0; i < left.size(); ++i)
    {
        result = static_cast<uint8_t>(result | (left[i] ^ right[i]));
    }

    return result == 0;
}

std::expected<std::array<uint8_t, kStunMessageIntegritySize>, std::string> calculate_hmac_sha1(std::span<const uint8_t> data, std::string_view key)
{
    if (key.empty())
    {
        return make_error("stun message integrity key is empty");
    }

    if (key.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return make_error("stun message integrity key is too large");
    }

    std::array<uint8_t, kStunMessageIntegritySize> digest{};
    unsigned int digest_size = 0;

    const auto* result = HMAC(EVP_sha1(),
                              reinterpret_cast<const unsigned char*>(key.data()),
                              static_cast<int>(key.size()),
                              data.data(),
                              data.size(),
                              digest.data(),
                              &digest_size);

    if (result == nullptr)
    {
        return make_error("calculate stun message integrity failed");
    }

    if (digest_size != kStunMessageIntegritySize)
    {
        return make_error("unexpected stun message integrity size");
    }

    return digest;
}

std::expected<void, std::string> set_stun_message_length(std::vector<uint8_t>& packet, std::size_t message_length)
{
    if (packet.size() < kStunHeaderSize)
    {
        return make_error("stun packet is shorter than header");
    }

    if (message_length > static_cast<std::size_t>(std::numeric_limits<uint16_t>::max()))
    {
        return make_error("stun packet is too large");
    }

    if ((message_length % 4U) != 0)
    {
        return make_error("stun message length is not aligned");
    }

    write_u16(packet, 2, static_cast<uint16_t>(message_length));

    return {};
}

std::vector<uint8_t> make_stun_header(uint16_t raw_type, const std::array<uint8_t, kStunTransactionIdSize>& transaction_id)
{
    std::vector<uint8_t> packet;
    packet.reserve(kStunHeaderSize + 128);

    append_u16(packet, raw_type);
    append_u16(packet, 0);
    append_u32(packet, kStunMagicCookie);

    packet.insert(packet.end(), transaction_id.begin(), transaction_id.end());

    return packet;
}

std::expected<void, std::string> append_attribute(std::vector<uint8_t>& packet, uint16_t type, std::span<const uint8_t> value)
{
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<uint16_t>::max()))
    {
        return make_error("stun attribute is too large");
    }

    append_u16(packet, type);
    append_u16(packet, static_cast<uint16_t>(value.size()));

    packet.insert(packet.end(), value.begin(), value.end());

    const std::size_t padding = padding_size(value.size());

    for (std::size_t i = 0; i < padding; ++i)
    {
        packet.push_back(0);
    }

    return {};
}

std::expected<std::string, std::string> format_ip_address(int family, const uint8_t* address)
{
    char buffer[INET6_ADDRSTRLEN]{};

    const char* result = inet_ntop(family, address, buffer, sizeof(buffer));

    if (result == nullptr)
    {
        return make_error("format stun address failed");
    }

    return std::string(buffer);
}

std::expected<stun_address, std::string> parse_address_attribute_value(uint16_t type,
                                                                       std::span<const uint8_t> value,
                                                                       const std::array<uint8_t, kStunTransactionIdSize>& transaction_id)
{
    if (value.size() < 4)
    {
        return make_error("stun address attribute is too short");
    }

    const uint8_t family = value[1];

    if (family == 0x01U && value.size() != 8)
    {
        return make_error("stun ipv4 address attribute has invalid size");
    }

    if (family == 0x02U && value.size() != 20)
    {
        return make_error("stun ipv6 address attribute has invalid size");
    }

    if (family != 0x01U && family != 0x02U)
    {
        return make_error("stun address attribute has unsupported family");
    }

    uint16_t port = read_u16(value, 2);

    if (type == kStunAttributeXorMappedAddress)
    {
        port = static_cast<uint16_t>(port ^ static_cast<uint16_t>(kStunMagicCookie >> 16U));
    }

    stun_address address;
    address.port = port;
    address.is_ipv6 = family == 0x02U;

    if (family == 0x01U)
    {
        std::array<uint8_t, 4> ip_bytes{};

        for (std::size_t i = 0; i < ip_bytes.size(); ++i)
        {
            ip_bytes[i] = value[4 + i];

            if (type == kStunAttributeXorMappedAddress)
            {
                ip_bytes[i] = static_cast<uint8_t>(ip_bytes[i] ^ kStunMagicCookieBytes[i]);
            }
        }

        auto text = format_ip_address(AF_INET, ip_bytes.data());

        if (!text)
        {
            return std::unexpected(text.error());
        }

        address.ip = std::move(*text);
        return address;
    }

    std::array<uint8_t, 16> ip_bytes{};

    for (std::size_t i = 0; i < ip_bytes.size(); ++i)
    {
        ip_bytes[i] = value[4 + i];

        if (type == kStunAttributeXorMappedAddress)
        {
            if (i < kStunMagicCookieBytes.size())
            {
                ip_bytes[i] = static_cast<uint8_t>(ip_bytes[i] ^ kStunMagicCookieBytes[i]);
            }
            else
            {
                ip_bytes[i] = static_cast<uint8_t>(ip_bytes[i] ^ transaction_id[i - kStunMagicCookieBytes.size()]);
            }
        }
    }

    auto text = format_ip_address(AF_INET6, ip_bytes.data());

    if (!text)
    {
        return std::unexpected(text.error());
    }

    address.ip = std::move(*text);
    return address;
}

std::expected<void, std::string> decode_known_attribute(stun_message& message, uint16_t type, std::span<const uint8_t> value)
{
    switch (type)
    {
        case kStunAttributeMappedAddress:
        {
            auto address = parse_address_attribute_value(type, value, message.transaction_id);

            if (!address)
            {
                return std::unexpected(address.error());
            }

            return {};
        }

        case kStunAttributeXorMappedAddress:
        {
            auto address = parse_address_attribute_value(type, value, message.transaction_id);

            if (!address)
            {
                return std::unexpected(address.error());
            }

            return {};
        }

        case kStunAttributeUsername:
        {
            message.username = std::string(reinterpret_cast<const char*>(value.data()), value.size());

            return {};
        }

        case kStunAttributePriority:
        {
            if (value.size() != 4)
            {
                return make_error("stun priority attribute has invalid size");
            }

            message.priority = read_u32(value, 0);
            return {};
        }

        case kStunAttributeUseCandidate:
        {
            if (!value.empty())
            {
                return make_error("stun use-candidate attribute must be empty");
            }

            return {};
        }

        case kStunAttributeIceControlling:
        {
            if (value.size() != 8)
            {
                return make_error("stun ice-controlling attribute has invalid size");
            }

            message.ice_controlling = read_u64(value, 0);
            return {};
        }

        case kStunAttributeIceControlled:
        {
            if (value.size() != 8)
            {
                return make_error("stun ice-controlled attribute has invalid size");
            }

            message.ice_controlled = read_u64(value, 0);
            return {};
        }

        case kStunAttributeMessageIntegrity:
        {
            if (value.size() != kStunMessageIntegritySize)
            {
                return make_error("stun message-integrity attribute has invalid size");
            }

            message.has_message_integrity = true;
            return {};
        }

        case kStunAttributeFingerprint:
        {
            if (value.size() != kStunFingerprintSize)
            {
                return make_error("stun fingerprint attribute has invalid size");
            }

            message.has_fingerprint = true;
            return {};
        }

        default:
            return {};
    }
}

struct parsed_ip_address
{
    int family = AF_INET;
    bool is_ipv6 = false;
    std::vector<uint8_t> bytes;
};

std::expected<parsed_ip_address, std::string> parse_ip_address(std::string_view ip)
{
    if (ip.empty())
    {
        return make_error("stun mapped address ip is empty");
    }

    std::string text(ip);

    std::array<uint8_t, 4> ipv4{};
    if (inet_pton(AF_INET, text.c_str(), ipv4.data()) == 1)
    {
        parsed_ip_address result;
        result.family = AF_INET;
        result.is_ipv6 = false;
        result.bytes.assign(ipv4.begin(), ipv4.end());
        return result;
    }

    std::array<uint8_t, 16> ipv6{};
    if (inet_pton(AF_INET6, text.c_str(), ipv6.data()) == 1)
    {
        parsed_ip_address result;
        result.family = AF_INET6;
        result.is_ipv6 = true;
        result.bytes.assign(ipv6.begin(), ipv6.end());
        return result;
    }

    return make_error("stun mapped address ip is invalid");
}

std::expected<std::vector<uint8_t>, std::string> make_xor_mapped_address_value(const stun_address& address,
                                                                               const std::array<uint8_t, kStunTransactionIdSize>& transaction_id)
{
    auto parsed = parse_ip_address(address.ip);
    if (!parsed)
    {
        return std::unexpected(parsed.error());
    }

    std::vector<uint8_t> value;
    value.reserve(parsed->is_ipv6 ? 20 : 8);

    value.push_back(0);
    value.push_back(parsed->is_ipv6 ? 0x02U : 0x01U);

    const uint16_t xor_port = static_cast<uint16_t>(address.port ^ static_cast<uint16_t>(kStunMagicCookie >> 16U));

    append_u16(value, xor_port);

    if (!parsed->is_ipv6)
    {
        for (std::size_t i = 0; i < parsed->bytes.size(); ++i)
        {
            value.push_back(static_cast<uint8_t>(parsed->bytes[i] ^ kStunMagicCookieBytes[i]));
        }

        return value;
    }

    for (std::size_t i = 0; i < parsed->bytes.size(); ++i)
    {
        if (i < kStunMagicCookieBytes.size())
        {
            value.push_back(static_cast<uint8_t>(parsed->bytes[i] ^ kStunMagicCookieBytes[i]));
        }
        else
        {
            value.push_back(static_cast<uint8_t>(parsed->bytes[i] ^ transaction_id[i - kStunMagicCookieBytes.size()]));
        }
    }

    return value;
}

std::expected<void, std::string> append_message_integrity(std::vector<uint8_t>& packet, std::string_view key)
{
    if (key.empty())
    {
        return make_error("stun message integrity key is empty");
    }

    append_u16(packet, kStunAttributeMessageIntegrity);
    append_u16(packet, static_cast<uint16_t>(kStunMessageIntegritySize));

    const std::size_t value_offset = packet.size();
    const std::size_t attribute_offset = value_offset - 4;

    packet.resize(packet.size() + kStunMessageIntegritySize, 0);

    auto length_result = set_stun_message_length(packet, packet.size() - kStunHeaderSize);

    if (!length_result)
    {
        return std::unexpected(length_result.error());
    }

    auto digest = calculate_hmac_sha1(std::span<const uint8_t>(packet.data(), attribute_offset), key);

    if (!digest)
    {
        return std::unexpected(digest.error());
    }

    std::copy(digest->begin(), digest->end(), packet.begin() + static_cast<std::ptrdiff_t>(value_offset));

    return {};
}

std::expected<void, std::string> append_fingerprint(std::vector<uint8_t>& packet)
{
    append_u16(packet, kStunAttributeFingerprint);
    append_u16(packet, static_cast<uint16_t>(kStunFingerprintSize));

    const std::size_t value_offset = packet.size();
    const std::size_t attribute_offset = value_offset - 4;

    append_u32(packet, 0);

    auto length_result = set_stun_message_length(packet, packet.size() - kStunHeaderSize);

    if (!length_result)
    {
        return std::unexpected(length_result.error());
    }

    const uint32_t crc = calculate_crc32(std::span<const uint8_t>(packet.data(), attribute_offset));

    const uint32_t fingerprint = crc ^ kStunFingerprintXorValue;

    write_u32(packet, value_offset, fingerprint);

    return {};
}

std::expected<void, std::string> validate_binding_request(const stun_message& request)
{
    if (request.method != stun_method::binding)
    {
        return make_error("stun request method must be binding");
    }

    if (request.message_class != stun_message_class::request)
    {
        return make_error("stun message class must be request");
    }

    return {};
}

std::expected<void, std::string> validate_response_options(const stun_binding_success_response_options& options)
{
    if (options.mapped_address.ip.empty())
    {
        return make_error("stun mapped address ip is empty");
    }

    if (options.mapped_address.port == 0)
    {
        return make_error("stun mapped address port is zero");
    }

    if (options.include_message_integrity && options.message_integrity_key.empty())
    {
        return make_error("stun message integrity key is empty");
    }

    return {};
}

std::expected<void, std::string> find_fingerprint_attribute(std::span<const uint8_t> data,
                                                            std::size_t& attribute_offset,
                                                            std::size_t& value_offset,
                                                            uint32_t& expected_fingerprint)
{
    const uint16_t message_length = read_u16(data, 2);
    const std::size_t total_size = kStunHeaderSize + static_cast<std::size_t>(message_length);

    std::size_t offset = kStunHeaderSize;

    while (offset < total_size)
    {
        if (offset + 4 > total_size)
        {
            return make_error("stun attribute header is truncated");
        }

        const uint16_t type = read_u16(data, offset);
        const uint16_t length = read_u16(data, offset + 2);

        const std::size_t current_value_offset = offset + 4;
        const std::size_t value_end = current_value_offset + static_cast<std::size_t>(length);

        const std::size_t padded_end = value_end + padding_size(length);

        if (value_end > total_size || padded_end > total_size)
        {
            return make_error("stun attribute value is truncated");
        }

        if (type == kStunAttributeFingerprint)
        {
            if (length != kStunFingerprintSize)
            {
                return make_error("stun fingerprint attribute has invalid size");
            }

            if (padded_end != total_size)
            {
                return make_error("stun fingerprint attribute must be last");
            }

            attribute_offset = offset;
            value_offset = current_value_offset;
            expected_fingerprint = read_u32(data, current_value_offset);
            return {};
        }

        offset = padded_end;
    }

    return make_error("stun fingerprint attribute not found");
}

std::expected<void, std::string> find_message_integrity_attribute(std::span<const uint8_t> data,
                                                                  std::size_t& attribute_offset,
                                                                  std::size_t& value_offset)
{
    const uint16_t message_length = read_u16(data, 2);
    const std::size_t total_size = kStunHeaderSize + static_cast<std::size_t>(message_length);

    std::size_t offset = kStunHeaderSize;

    while (offset < total_size)
    {
        if (offset + 4 > total_size)
        {
            return make_error("stun attribute header is truncated");
        }

        const uint16_t type = read_u16(data, offset);
        const uint16_t length = read_u16(data, offset + 2);

        const std::size_t current_value_offset = offset + 4;
        const std::size_t value_end = current_value_offset + static_cast<std::size_t>(length);

        const std::size_t padded_end = value_end + padding_size(length);

        if (value_end > total_size || padded_end > total_size)
        {
            return make_error("stun attribute value is truncated");
        }

        if (type == kStunAttributeMessageIntegrity)
        {
            if (length != kStunMessageIntegritySize)
            {
                return make_error("stun message-integrity attribute has invalid size");
            }

            attribute_offset = offset;
            value_offset = current_value_offset;
            return {};
        }

        offset = padded_end;
    }

    return make_error("stun message-integrity attribute not found");
}
}    // namespace

bool is_stun_packet(std::span<const uint8_t> data)
{
    if (data.size() < kStunHeaderSize)
    {
        return false;
    }

    if ((data[0] & 0xC0U) != 0)
    {
        return false;
    }

    const uint16_t message_length = read_u16(data, 2);

    if ((message_length % 4U) != 0)
    {
        return false;
    }

    if (read_u32(data, 4) != kStunMagicCookie)
    {
        return false;
    }

    const std::size_t total_size = kStunHeaderSize + static_cast<std::size_t>(message_length);

    return data.size() >= total_size;
}

stun_validation_result validate_stun_header(std::span<const uint8_t> data)
{
    if (data.size() < kStunHeaderSize)
    {
        return make_error("stun packet is shorter than header");
    }

    if ((data[0] & 0xC0U) != 0)
    {
        return make_error("stun packet first two bits must be zero");
    }

    const uint16_t message_length = read_u16(data, 2);

    if ((message_length % 4U) != 0)
    {
        return make_error("stun message length is not aligned");
    }

    if (read_u32(data, 4) != kStunMagicCookie)
    {
        return make_error("stun magic cookie is invalid");
    }

    const std::size_t total_size = kStunHeaderSize + static_cast<std::size_t>(message_length);

    if (data.size() < total_size)
    {
        return make_error("stun packet is truncated");
    }

    if (data.size() != total_size)
    {
        return make_error("stun packet has trailing bytes");
    }

    return {};
}

stun_message_result parse_stun_message(std::span<const uint8_t> data)
{
    auto header_result = validate_stun_header(data);
    if (!header_result)
    {
        return std::unexpected(header_result.error());
    }

    stun_message message;

    const uint16_t raw_type = read_u16(data, 0);
    const uint16_t raw_method = decode_method(raw_type);

    message.method = make_stun_method(raw_method);
    message.message_class = decode_message_class(raw_type);

    for (std::size_t i = 0; i < message.transaction_id.size(); ++i)
    {
        message.transaction_id[i] = data[8 + i];
    }

    const uint16_t message_length = read_u16(data, 2);
    const std::size_t total_size = kStunHeaderSize + static_cast<std::size_t>(message_length);

    std::size_t offset = kStunHeaderSize;

    while (offset < total_size)
    {
        if (offset + 4 > total_size)
        {
            return make_error("stun attribute header is truncated");
        }

        const uint16_t type = read_u16(data, offset);
        const uint16_t length = read_u16(data, offset + 2);

        const std::size_t value_offset = offset + 4;
        const std::size_t value_end = value_offset + static_cast<std::size_t>(length);

        const std::size_t padded_end = value_end + padding_size(length);

        if (value_end > total_size || padded_end > total_size)
        {
            return make_error("stun attribute value is truncated");
        }

        std::span<const uint8_t> value(data.data() + static_cast<std::ptrdiff_t>(value_offset), static_cast<std::size_t>(length));

        auto decode_result = decode_known_attribute(message, type, value);

        if (!decode_result)
        {
            return std::unexpected(decode_result.error());
        }

        offset = padded_end;
    }

    return message;
}

stun_packet_result write_stun_binding_success_response(const stun_message& request, const stun_binding_success_response_options& options)
{
    auto request_result = validate_binding_request(request);
    if (!request_result)
    {
        return std::unexpected(request_result.error());
    }

    auto options_result = validate_response_options(options);
    if (!options_result)
    {
        return std::unexpected(options_result.error());
    }

    const uint16_t response_type = encode_message_type(kStunBindingMethod, stun_message_class::success_response);

    std::vector<uint8_t> packet = make_stun_header(response_type, request.transaction_id);

    auto xor_address_value = make_xor_mapped_address_value(options.mapped_address, request.transaction_id);

    if (!xor_address_value)
    {
        return std::unexpected(xor_address_value.error());
    }

    auto append_xor_result =
        append_attribute(packet, kStunAttributeXorMappedAddress, std::span<const uint8_t>(xor_address_value->data(), xor_address_value->size()));

    if (!append_xor_result)
    {
        return std::unexpected(append_xor_result.error());
    }

    auto length_result = set_stun_message_length(packet, packet.size() - kStunHeaderSize);

    if (!length_result)
    {
        return std::unexpected(length_result.error());
    }

    if (options.include_message_integrity)
    {
        auto integrity_result = append_message_integrity(packet, options.message_integrity_key);

        if (!integrity_result)
        {
            return std::unexpected(integrity_result.error());
        }
    }

    if (options.include_fingerprint)
    {
        auto fingerprint_result = append_fingerprint(packet);
        if (!fingerprint_result)
        {
            return std::unexpected(fingerprint_result.error());
        }
    }

    return packet;
}

stun_validation_result verify_stun_fingerprint(std::span<const uint8_t> data)
{
    auto header_result = validate_stun_header(data);
    if (!header_result)
    {
        return std::unexpected(header_result.error());
    }

    std::size_t attribute_offset = 0;
    std::size_t value_offset = 0;
    uint32_t expected_fingerprint = 0;

    auto find_result = find_fingerprint_attribute(data, attribute_offset, value_offset, expected_fingerprint);

    if (!find_result)
    {
        return std::unexpected(find_result.error());
    }

    const uint32_t crc = calculate_crc32(data.subspan(0, attribute_offset));

    const uint32_t actual_fingerprint = crc ^ kStunFingerprintXorValue;

    if (actual_fingerprint != expected_fingerprint)
    {
        return make_error("stun fingerprint mismatch");
    }

    return {};
}

stun_validation_result verify_stun_message_integrity(std::span<const uint8_t> data, std::string_view key)
{
    auto header_result = validate_stun_header(data);
    if (!header_result)
    {
        return std::unexpected(header_result.error());
    }

    if (key.empty())
    {
        return make_error("stun message integrity key is empty");
    }

    std::size_t attribute_offset = 0;
    std::size_t value_offset = 0;

    auto find_result = find_message_integrity_attribute(data, attribute_offset, value_offset);

    if (!find_result)
    {
        return std::unexpected(find_result.error());
    }

    std::vector<uint8_t> hmac_input(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(attribute_offset));

    const std::size_t message_length = value_offset + kStunMessageIntegritySize - kStunHeaderSize;

    if (message_length > static_cast<std::size_t>(std::numeric_limits<uint16_t>::max()))
    {
        return make_error("stun message-integrity input is too large");
    }

    write_u16(hmac_input, 2, static_cast<uint16_t>(message_length));

    auto digest = calculate_hmac_sha1(std::span<const uint8_t>(hmac_input.data(), hmac_input.size()), key);

    if (!digest)
    {
        return std::unexpected(digest.error());
    }

    std::span<const uint8_t> expected(data.data() + static_cast<std::ptrdiff_t>(value_offset), kStunMessageIntegritySize);

    std::span<const uint8_t> actual(digest->data(), digest->size());

    if (!constant_time_equal(expected, actual))
    {
        return make_error("stun message-integrity mismatch");
    }

    return {};
}

std::string stun_class_to_string(stun_message_class value)
{
    switch (value)
    {
        case stun_message_class::request:
            return "request";

        case stun_message_class::indication:
            return "indication";

        case stun_message_class::success_response:
            return "success_response";

        case stun_message_class::error_response:
            return "error_response";

        case stun_message_class::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string stun_method_to_string(stun_method value)
{
    switch (value)
    {
        case stun_method::binding:
            return "binding";

        case stun_method::unknown:
            return "unknown";
    }

    return "unknown";
}
}    // namespace webrtc
