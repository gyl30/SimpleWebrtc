#include "signaling/sdp/h264_fmtp_compat.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc::sdp
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::string lower_copy(std::string_view value)
{
    std::string result;

    result.reserve(value.size());

    for (unsigned char ch : value)
    {
        result.push_back(static_cast<char>(std::tolower(ch)));
    }

    return result;
}

std::string trim_copy(std::string_view value)
{
    std::size_t begin = 0;

    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0)
    {
        begin += 1;
    }

    std::size_t end = value.size();

    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0)
    {
        end -= 1;
    }

    return std::string(value.substr(begin, end - begin));
}

std::vector<std::string_view> split_semicolon(std::string_view value)
{
    std::vector<std::string_view> result;

    std::size_t begin = 0;

    while (begin <= value.size())
    {
        const std::size_t end = value.find(';', begin);

        if (end == std::string_view::npos)
        {
            result.push_back(value.substr(begin));

            break;
        }

        result.push_back(value.substr(begin, end - begin));

        begin = end + 1;
    }

    return result;
}

std::expected<uint8_t, std::string> parse_u8_decimal(std::string_view value)
{
    const std::string normalized = trim_copy(value);

    if (normalized.empty())
    {
        return make_error("h264 fmtp integer is empty");
    }

    unsigned int parsed = 0;

    const char* begin = normalized.data();

    const char* end = normalized.data() + normalized.size();

    const auto result = std::from_chars(begin, end, parsed, 10);

    if (result.ec != std::errc{} || result.ptr != end || parsed > std::numeric_limits<uint8_t>::max())
    {
        return make_error("h264 fmtp integer is invalid");
    }

    return static_cast<uint8_t>(parsed);
}

std::expected<bool, std::string> parse_boolean_01(std::string_view value)
{
    const std::string normalized = lower_copy(trim_copy(value));

    if (normalized == "1" || normalized == "true" || normalized == "yes")
    {
        return true;
    }

    if (normalized == "0" || normalized == "false" || normalized == "no")
    {
        return false;
    }

    return make_error("h264 fmtp boolean is invalid");
}

bool is_hex_digit(char ch) { return std::isxdigit(static_cast<unsigned char>(ch)) != 0; }

std::expected<uint8_t, std::string> parse_hex_byte(std::string_view value)
{
    if (value.size() != 2)
    {
        return make_error("h264 profile-level-id byte length is invalid");
    }

    unsigned int parsed = 0;

    const char* begin = value.data();

    const char* end = value.data() + value.size();

    const auto result = std::from_chars(begin, end, parsed, 16);

    if (result.ec != std::errc{} || result.ptr != end || parsed > std::numeric_limits<uint8_t>::max())
    {
        return make_error("h264 profile-level-id byte is invalid");
    }

    return static_cast<uint8_t>(parsed);
}

h264_profile_kind classify_h264_profile(uint8_t profile_idc, uint8_t profile_iop)
{
    switch (profile_idc)
    {
        case 0x42:
            if ((profile_iop & 0x40U) != 0)
            {
                return h264_profile_kind::constrained_baseline;
            }

            return h264_profile_kind::baseline;

        case 0x4d:
            if ((profile_iop & 0x80U) != 0)
            {
                return h264_profile_kind::constrained_baseline;
            }

            return h264_profile_kind::main;

        case 0x58:
            if ((profile_iop & 0xc0U) == 0xc0U)
            {
                return h264_profile_kind::constrained_baseline;
            }

            return h264_profile_kind::unknown;

        case 0x64:
            if ((profile_iop & 0x0cU) == 0x0cU)
            {
                return h264_profile_kind::constrained_high;
            }

            return h264_profile_kind::high;

        default:
            return h264_profile_kind::unknown;
    }
}

std::expected<h264_profile_level_id, std::string> parse_profile_level_id(std::string_view value)
{
    const std::string normalized = lower_copy(trim_copy(value));

    if (normalized.size() != 6)
    {
        return make_error("h264 profile-level-id length is invalid");
    }

    for (char ch : normalized)
    {
        if (!is_hex_digit(ch))
        {
            return make_error("h264 profile-level-id contains non hex digit");
        }
    }

    auto profile_idc = parse_hex_byte(std::string_view(normalized.data(), 2));

    if (!profile_idc)
    {
        return std::unexpected(profile_idc.error());
    }

    auto profile_iop = parse_hex_byte(std::string_view(normalized.data() + 2, 2));

    if (!profile_iop)
    {
        return std::unexpected(profile_iop.error());
    }

    auto level_idc = parse_hex_byte(std::string_view(normalized.data() + 4, 2));

    if (!level_idc)
    {
        return std::unexpected(level_idc.error());
    }

    h264_profile_level_id result;

    result.profile_idc = *profile_idc;

    result.profile_iop = *profile_iop;

    result.level_idc = *level_idc;

    result.profile = classify_h264_profile(result.profile_idc, result.profile_iop);

    result.normalized_value = normalized;

    if (result.profile == h264_profile_kind::unknown)
    {
        return make_error("h264 profile-level-id profile is unsupported");
    }

    return result;
}

bool profile_is_baseline_family(h264_profile_kind profile)
{
    return profile == h264_profile_kind::baseline || profile == h264_profile_kind::constrained_baseline;
}

bool profile_is_high_family(h264_profile_kind profile)
{
    return profile == h264_profile_kind::high || profile == h264_profile_kind::constrained_high;
}

bool profiles_are_answer_compatible(h264_profile_kind offer_profile, h264_profile_kind local_profile)
{
    if (offer_profile == h264_profile_kind::unknown || local_profile == h264_profile_kind::unknown)
    {
        return false;
    }

    if (offer_profile == local_profile)
    {
        return true;
    }

    if (profile_is_baseline_family(offer_profile) && profile_is_baseline_family(local_profile))
    {
        return true;
    }

    if (profile_is_high_family(offer_profile) && profile_is_high_family(local_profile))
    {
        return true;
    }

    return false;
}

bool publisher_profile_is_decodable_by_subscriber(h264_profile_kind publisher_profile, h264_profile_kind subscriber_profile)
{
    if (publisher_profile == h264_profile_kind::unknown || subscriber_profile == h264_profile_kind::unknown)
    {
        return false;
    }

    if (publisher_profile == subscriber_profile)
    {
        return true;
    }

    if (publisher_profile == h264_profile_kind::constrained_baseline && profile_is_baseline_family(subscriber_profile))
    {
        return true;
    }

    if (publisher_profile == h264_profile_kind::constrained_high && profile_is_high_family(subscriber_profile))
    {
        return true;
    }

    return false;
}

uint16_t level_rank(const h264_profile_level_id& profile_level_id)
{
    if (profile_level_id.level_idc == 0x0b && (profile_level_id.profile_iop & 0x10U) != 0)
    {
        return 9;
    }

    return profile_level_id.level_idc;
}

h264_profile_level_id select_answer_profile_level_id(const h264_profile_level_id& offer_profile_level_id,
                                                     const h264_profile_level_id& local_profile_level_id,
                                                     bool level_asymmetry_allowed)
{
    h264_profile_level_id selected = local_profile_level_id;

    if (profile_is_baseline_family(offer_profile_level_id.profile) && profile_is_baseline_family(local_profile_level_id.profile))
    {
        if (offer_profile_level_id.profile == h264_profile_kind::constrained_baseline ||
            local_profile_level_id.profile == h264_profile_kind::constrained_baseline)
        {
            selected.profile = h264_profile_kind::constrained_baseline;

            selected.profile_idc = 0x42;

            selected.profile_iop = 0xe0;
        }
    }

    if (profile_is_high_family(offer_profile_level_id.profile) && profile_is_high_family(local_profile_level_id.profile))
    {
        if (offer_profile_level_id.profile == h264_profile_kind::constrained_high ||
            local_profile_level_id.profile == h264_profile_kind::constrained_high)
        {
            selected.profile = h264_profile_kind::constrained_high;

            selected.profile_idc = 0x64;

            selected.profile_iop = 0x0c;
        }
    }

    if (!level_asymmetry_allowed && level_rank(offer_profile_level_id) < level_rank(local_profile_level_id))
    {
        selected.level_idc = offer_profile_level_id.level_idc;
    }

    char buffer[7] = {};

    static constexpr char k_hex[] = "0123456789abcdef";

    buffer[0] = k_hex[(selected.profile_idc >> 4U) & 0x0fU];

    buffer[1] = k_hex[selected.profile_idc & 0x0fU];

    buffer[2] = k_hex[(selected.profile_iop >> 4U) & 0x0fU];

    buffer[3] = k_hex[selected.profile_iop & 0x0fU];

    buffer[4] = k_hex[(selected.level_idc >> 4U) & 0x0fU];

    buffer[5] = k_hex[selected.level_idc & 0x0fU];

    selected.normalized_value = std::string(buffer, 6);

    return selected;
}

h264_profile_level_id make_default_constrained_baseline_profile_level_id()
{
    h264_profile_level_id result;

    result.profile_idc = 0x42;

    result.profile_iop = 0xe0;

    result.level_idc = 0x1f;

    result.profile = h264_profile_kind::constrained_baseline;

    result.normalized_value = "42e01f";

    return result;
}

std::expected<uint8_t, std::string> effective_packetization_mode_for_answer(const h264_fmtp_parameters& parameters)
{
    if (!parameters.has_packetization_mode)
    {
        return 1;
    }

    if (parameters.packetization_mode == 1)
    {
        return 1;
    }

    return make_error("h264 packetization-mode is unsupported");
}

std::expected<uint8_t, std::string> effective_packetization_mode_for_relay(const h264_fmtp_parameters& parameters)
{
    if (!parameters.has_packetization_mode)
    {
        return 1;
    }

    if (parameters.packetization_mode == 1)
    {
        return 1;
    }

    return make_error("h264 relay packetization-mode is unsupported");
}

std::string make_answer_fmtp(const h264_profile_level_id& profile_level_id, uint8_t packetization_mode, bool level_asymmetry_allowed)
{
    std::string fmtp;

    fmtp.reserve(96);

    fmtp.append("level-asymmetry-allowed=");

    fmtp.append(level_asymmetry_allowed ? "1" : "0");

    fmtp.append(";packetization-mode=");

    fmtp.append(std::to_string(packetization_mode));

    fmtp.append(";profile-level-id=");

    fmtp.append(profile_level_id.normalized_value);

    return fmtp;
}

bool h264_assume_level_asymmetry_allowed_when_missing_from_env()
{
    const char* value = std::getenv("WEBRTC_H264_ASSUME_LEVEL_ASYMMETRY_ALLOWED_WHEN_MISSING");

    if (value == nullptr)
    {
        return false;
    }

    const std::string normalized = lower_copy(trim_copy(value));

    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

bool h264_level_asymmetry_allowed_effective_value(const h264_fmtp_parameters& parameters)
{
    if (parameters.has_level_asymmetry_allowed)
    {
        return parameters.level_asymmetry_allowed;
    }

    return h264_assume_level_asymmetry_allowed_when_missing_from_env();
}
}    // namespace

std::expected<h264_fmtp_parameters, std::string> parse_h264_fmtp(std::string_view fmtp)
{
    h264_fmtp_parameters parameters;

    for (std::string_view raw_part : split_semicolon(fmtp))
    {
        const std::string part = trim_copy(raw_part);

        if (part.empty())
        {
            continue;
        }

        const std::size_t equal_position = part.find('=');

        if (equal_position == std::string::npos)
        {
            continue;
        }

        const std::string key = lower_copy(trim_copy(std::string_view(part.data(), equal_position)));

        const std::string value = trim_copy(std::string_view(part.data() + equal_position + 1, part.size() - equal_position - 1));

        if (key == "packetization-mode")
        {
            auto parsed = parse_u8_decimal(value);

            if (!parsed)
            {
                return std::unexpected(parsed.error());
            }

            parameters.has_packetization_mode = true;

            parameters.packetization_mode = *parsed;

            continue;
        }

        if (key == "level-asymmetry-allowed")
        {
            auto parsed = parse_boolean_01(value);

            if (!parsed)
            {
                return std::unexpected(parsed.error());
            }

            parameters.has_level_asymmetry_allowed = true;

            parameters.level_asymmetry_allowed = *parsed;

            continue;
        }

        if (key == "profile-level-id")
        {
            auto parsed = parse_profile_level_id(value);

            if (!parsed)
            {
                return std::unexpected(parsed.error());
            }

            parameters.profile_level_id = *parsed;

            continue;
        }
    }

    return parameters;
}

std::expected<h264_fmtp_answer_negotiation, std::string> negotiate_h264_fmtp_for_answer(std::string_view offer_fmtp, std::string_view local_fmtp)
{
    auto offer_parameters = parse_h264_fmtp(offer_fmtp);

    if (!offer_parameters)
    {
        return std::unexpected(offer_parameters.error());
    }

    auto local_parameters = parse_h264_fmtp(local_fmtp);

    if (!local_parameters)
    {
        return std::unexpected(local_parameters.error());
    }

    auto offer_packetization_mode = effective_packetization_mode_for_answer(*offer_parameters);

    if (!offer_packetization_mode)
    {
        return std::unexpected(offer_packetization_mode.error());
    }

    auto local_packetization_mode = effective_packetization_mode_for_answer(*local_parameters);

    if (!local_packetization_mode)
    {
        return std::unexpected(local_packetization_mode.error());
    }

    if (*offer_packetization_mode != *local_packetization_mode)
    {
        return make_error("h264 packetization-mode is not compatible");
    }

    const h264_profile_level_id offer_profile_level_id =
        offer_parameters->profile_level_id.value_or(make_default_constrained_baseline_profile_level_id());

    const h264_profile_level_id local_profile_level_id =
        local_parameters->profile_level_id.value_or(make_default_constrained_baseline_profile_level_id());

    if (!profiles_are_answer_compatible(offer_profile_level_id.profile, local_profile_level_id.profile))
    {
        return make_error("h264 profile is not compatible");
    }

    const bool level_asymmetry_allowed =
        h264_level_asymmetry_allowed_effective_value(*offer_parameters) && h264_level_asymmetry_allowed_effective_value(*local_parameters);

    h264_fmtp_answer_negotiation negotiation;

    negotiation.offer_parameters = *offer_parameters;

    negotiation.local_parameters = *local_parameters;

    negotiation.selected_packetization_mode = *offer_packetization_mode;

    negotiation.selected_level_asymmetry_allowed = level_asymmetry_allowed;

    negotiation.selected_profile_level_id = select_answer_profile_level_id(offer_profile_level_id, local_profile_level_id, level_asymmetry_allowed);

    negotiation.answer_fmtp = make_answer_fmtp(
        negotiation.selected_profile_level_id, negotiation.selected_packetization_mode, negotiation.selected_level_asymmetry_allowed);

    return negotiation;
}

std::expected<h264_fmtp_relay_compatibility, std::string> check_h264_fmtp_relay_compatibility(std::string_view publisher_fmtp,
                                                                                              std::string_view subscriber_fmtp)
{
    h264_fmtp_relay_compatibility compatibility;

    auto publisher_parameters = parse_h264_fmtp(publisher_fmtp);

    if (!publisher_parameters)
    {
        return std::unexpected(publisher_parameters.error());
    }

    auto subscriber_parameters = parse_h264_fmtp(subscriber_fmtp);

    if (!subscriber_parameters)
    {
        return std::unexpected(subscriber_parameters.error());
    }

    compatibility.publisher_parameters = *publisher_parameters;

    compatibility.subscriber_parameters = *subscriber_parameters;

    auto publisher_packetization_mode = effective_packetization_mode_for_relay(compatibility.publisher_parameters);

    if (!publisher_packetization_mode)
    {
        compatibility.reason = publisher_packetization_mode.error();

        return compatibility;
    }

    auto subscriber_packetization_mode = effective_packetization_mode_for_relay(compatibility.subscriber_parameters);

    if (!subscriber_packetization_mode)
    {
        compatibility.reason = subscriber_packetization_mode.error();

        return compatibility;
    }

    if (*publisher_packetization_mode != *subscriber_packetization_mode)
    {
        compatibility.reason = "h264 relay packetization-mode mismatch";

        return compatibility;
    }

    if (compatibility.publisher_parameters.profile_level_id.has_value() && compatibility.subscriber_parameters.profile_level_id.has_value())
    {
        const h264_profile_level_id& publisher_profile_level_id = *compatibility.publisher_parameters.profile_level_id;

        const h264_profile_level_id& subscriber_profile_level_id = *compatibility.subscriber_parameters.profile_level_id;

        if (!publisher_profile_is_decodable_by_subscriber(publisher_profile_level_id.profile, subscriber_profile_level_id.profile))
        {
            compatibility.reason = "h264 relay profile is not decodable by subscriber";

            return compatibility;
        }

        if (level_rank(subscriber_profile_level_id) < level_rank(publisher_profile_level_id))
        {
            compatibility.reason = "h264 relay subscriber level is lower than publisher level";

            return compatibility;
        }
    }

    compatibility.compatible = true;

    compatibility.reason = "compatible";

    return compatibility;
}

}    // namespace webrtc::sdp
