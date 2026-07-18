#include "signaling/sdp/sdp_codec_negotiator.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "signaling/sdp/h264_fmtp_compat.h"

namespace webrtc::sdp
{
namespace
{

constexpr std::string_view kLocalH264Fmtp = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_media_error(const media_summary& media, std::string_view message)
{
    std::string error;
    error.reserve(media.mid.size() + message.size() + 16);
    error.append("media mid ");
    error.append(media.mid);
    error.push_back(' ');
    error.append(message);
    return std::unexpected(std::move(error));
}

std::string to_lower_ascii(std::string_view value)
{
    std::string result;
    result.reserve(value.size());

    for (const auto ch : value)
    {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }

    return result;
}

std::string_view trim_left(std::string_view value)
{
    const auto position = value.find_first_not_of(" \t");
    if (position == std::string_view::npos)
    {
        return {};
    }

    return value.substr(position);
}

std::string_view trim_right(std::string_view value)
{
    const auto position = value.find_last_not_of(" \t");
    if (position == std::string_view::npos)
    {
        return {};
    }

    return value.substr(0, position + 1);
}

std::string_view trim(std::string_view value) { return trim_right(trim_left(value)); }

bool equals_ignore_case(std::string_view left, std::string_view right) { return to_lower_ascii(left) == to_lower_ascii(right); }

bool is_opus_codec(const codec_info& codec)
{
    if (!equals_ignore_case(codec.name, "opus"))
    {
        return false;
    }

    if (codec.clock_rate != 48000)
    {
        return false;
    }

    if (!codec.encoding_parameters.empty() && codec.encoding_parameters != "2")
    {
        return false;
    }

    return true;
}

bool is_vp8_codec(const codec_info& codec)
{
    if (!equals_ignore_case(codec.name, "VP8"))
    {
        return false;
    }

    return codec.clock_rate == 90000;
}

bool is_rtx_codec(const codec_info& codec)
{
    if (!equals_ignore_case(codec.name, "rtx"))
    {
        return false;
    }

    return codec.clock_rate == 90000;
}

std::optional<uint16_t> parse_payload_type_text(std::string_view value)
{
    value = trim(value);

    if (value.empty())
    {
        return std::nullopt;
    }

    uint32_t payload_type = 0;

    const auto result = std::from_chars(value.data(), value.data() + value.size(), payload_type);

    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || payload_type > 127U)
    {
        return std::nullopt;
    }

    return static_cast<uint16_t>(payload_type);
}

std::optional<std::string> find_fmtp_parameter(std::string_view fmtp, std::string_view key)
{
    std::size_t start = 0;

    while (start <= fmtp.size())
    {
        const std::size_t separator = fmtp.find(';', start);

        const std::string_view part = separator == std::string_view::npos ? fmtp.substr(start) : fmtp.substr(start, separator - start);

        const std::string_view item = trim(part);
        const std::size_t equal_position = item.find('=');

        if (equal_position != std::string_view::npos)
        {
            const std::string_view item_key = trim(item.substr(0, equal_position));

            const std::string_view item_value = trim(item.substr(equal_position + 1));

            if (equals_ignore_case(item_key, key))
            {
                return std::string(item_value);
            }
        }

        if (separator == std::string_view::npos)
        {
            break;
        }

        start = separator + 1;
    }

    return std::nullopt;
}
std::optional<uint16_t> find_codec_apt_payload_type(const codec_info& codec)
{
    const auto apt = find_fmtp_parameter(codec.fmtp, "apt");

    if (!apt.has_value())
    {
        return std::nullopt;
    }

    return parse_payload_type_text(*apt);
}

std::optional<std::string> normalize_h264_answer_fmtp(std::string_view offer_fmtp)
{
    auto negotiation = negotiate_h264_fmtp_for_answer(offer_fmtp, kLocalH264Fmtp);

    if (!negotiation)
    {
        return std::nullopt;
    }

    return *negotiation;
}

bool is_h264_codec(const codec_info& codec)
{
    if (!equals_ignore_case(codec.name, "H264"))
    {
        return false;
    }

    if (codec.clock_rate != 90000)
    {
        return false;
    }

    return normalize_h264_answer_fmtp(codec.fmtp).has_value();
}

bool is_supported_audio_codec(const codec_info& codec) { return is_opus_codec(codec); }

bool is_supported_video_codec(const codec_info& codec)
{
    if (is_vp8_codec(codec))
    {
        return true;
    }

    if (is_h264_codec(codec))
    {
        return true;
    }

    return false;
}

bool is_supported_codec(const media_summary& media, const codec_info& codec)
{
    if (media.kind == "audio")
    {
        return is_supported_audio_codec(codec);
    }

    if (media.kind == "video")
    {
        return is_supported_video_codec(codec);
    }

    return false;
}

bool payload_type_exists(const std::vector<uint16_t>& payload_types, uint16_t payload_type)
{
    for (const auto current : payload_types)
    {
        if (current == payload_type)
        {
            return true;
        }
    }

    return false;
}

struct opus_fmtp_parameter
{
    std::string key;
    std::string value;
};

std::expected<uint32_t, std::string> parse_opus_fmtp_u32(std::string_view value, std::string_view key)
{
    value = trim(value);

    if (value.empty())
    {
        std::string message;

        message.append("opus fmtp ");

        message.append(key);

        message.append(" is empty");

        return make_error(message);
    }

    uint32_t result = 0;

    const auto parse_result = std::from_chars(value.data(), value.data() + value.size(), result);

    if (parse_result.ec != std::errc{} || parse_result.ptr != value.data() + value.size())
    {
        std::string message;

        message.append("opus fmtp ");

        message.append(key);

        message.append(" is invalid");

        return make_error(message);
    }

    return result;
}

std::expected<std::vector<opus_fmtp_parameter>, std::string> parse_opus_fmtp_parameters(std::string_view fmtp)
{
    std::vector<opus_fmtp_parameter> parameters;

    std::size_t start = 0;

    while (start <= fmtp.size())
    {
        const std::size_t separator = fmtp.find(';', start);

        const std::string_view part = separator == std::string_view::npos ? fmtp.substr(start) : fmtp.substr(start, separator - start);

        const std::string_view item = trim(part);

        if (!item.empty())
        {
            const std::size_t equal_position = item.find('=');

            if (equal_position == std::string_view::npos)
            {
                return make_error("opus fmtp parameter is missing value");
            }

            const std::string_view key = trim(item.substr(0, equal_position));

            const std::string_view value = trim(item.substr(equal_position + 1));

            if (key.empty())
            {
                return make_error("opus fmtp parameter key is empty");
            }

            if (value.empty())
            {
                return make_error("opus fmtp parameter value is empty");
            }

            opus_fmtp_parameter parameter;

            parameter.key = to_lower_ascii(key);

            parameter.value = std::string(value);

            parameters.push_back(std::move(parameter));
        }

        if (separator == std::string_view::npos)
        {
            break;
        }

        start = separator + 1;
    }

    return parameters;
}

std::expected<std::optional<std::string>, std::string> find_unique_opus_fmtp_parameter(const std::vector<opus_fmtp_parameter>& parameters,
                                                                                       std::string_view key)
{
    std::optional<std::string> value;

    for (const auto& parameter : parameters)
    {
        if (!equals_ignore_case(parameter.key, key))
        {
            continue;
        }

        if (value.has_value())
        {
            std::string message;

            message.append("opus fmtp parameter duplicated: ");

            message.append(key);

            return make_error(message);
        }

        value = parameter.value;
    }

    return value;
}

void append_normalized_opus_fmtp_parameter(std::string& result, std::string_view key, std::string_view value)
{
    if (!result.empty())
    {
        result.append(";");
    }

    result.append(key);

    result.append("=");

    result.append(value);
}

std::expected<void, std::string> append_boolean_opus_fmtp_parameter(std::string& result,
                                                                    const std::vector<opus_fmtp_parameter>& parameters,
                                                                    std::string_view key)
{
    const auto value = find_unique_opus_fmtp_parameter(parameters, key);

    if (!value)
    {
        return std::unexpected(value.error());
    }

    if (!value->has_value())
    {
        return {};
    }

    if (**value != "0" && **value != "1")
    {
        std::string message;

        message.append("opus fmtp ");

        message.append(key);

        message.append(" must be 0 or 1");

        return make_error(message);
    }

    append_normalized_opus_fmtp_parameter(result, key, **value);

    return {};
}

std::expected<void, std::string> append_u32_opus_fmtp_parameter(
    std::string& result, const std::vector<opus_fmtp_parameter>& parameters, std::string_view key, uint32_t minimum, uint32_t maximum)
{
    const auto value = find_unique_opus_fmtp_parameter(parameters, key);

    if (!value)
    {
        return std::unexpected(value.error());
    }

    if (!value->has_value())
    {
        return {};
    }

    const auto parsed_value = parse_opus_fmtp_u32(**value, key);

    if (!parsed_value)
    {
        return std::unexpected(parsed_value.error());
    }

    if (*parsed_value < minimum || *parsed_value > maximum)
    {
        std::string message;

        message.append("opus fmtp ");

        message.append(key);

        message.append(" is out of range");

        return make_error(message);
    }

    append_normalized_opus_fmtp_parameter(result, key, std::to_string(*parsed_value));

    return {};
}

std::expected<std::string, std::string> normalize_opus_fmtp(std::string_view fmtp)
{
    if (fmtp.empty())
    {
        return std::string();
    }

    const auto parameters = parse_opus_fmtp_parameters(fmtp);

    if (!parameters)
    {
        return std::unexpected(parameters.error());
    }

    std::string normalized;

    auto minptime_result = append_u32_opus_fmtp_parameter(normalized, *parameters, "minptime", 3, 120);

    if (!minptime_result)
    {
        return std::unexpected(minptime_result.error());
    }

    auto useinbandfec_result = append_boolean_opus_fmtp_parameter(normalized, *parameters, "useinbandfec");

    if (!useinbandfec_result)
    {
        return std::unexpected(useinbandfec_result.error());
    }

    auto usedtx_result = append_boolean_opus_fmtp_parameter(normalized, *parameters, "usedtx");

    if (!usedtx_result)
    {
        return std::unexpected(usedtx_result.error());
    }

    auto stereo_result = append_boolean_opus_fmtp_parameter(normalized, *parameters, "stereo");

    if (!stereo_result)
    {
        return std::unexpected(stereo_result.error());
    }

    auto sprop_stereo_result = append_boolean_opus_fmtp_parameter(normalized, *parameters, "sprop-stereo");

    if (!sprop_stereo_result)
    {
        return std::unexpected(sprop_stereo_result.error());
    }

    auto maxplaybackrate_result = append_u32_opus_fmtp_parameter(normalized, *parameters, "maxplaybackrate", 8000, 48000);

    if (!maxplaybackrate_result)
    {
        return std::unexpected(maxplaybackrate_result.error());
    }

    auto sprop_maxcapturerate_result = append_u32_opus_fmtp_parameter(normalized, *parameters, "sprop-maxcapturerate", 8000, 48000);

    if (!sprop_maxcapturerate_result)
    {
        return std::unexpected(sprop_maxcapturerate_result.error());
    }

    auto maxaveragebitrate_result = append_u32_opus_fmtp_parameter(normalized, *parameters, "maxaveragebitrate", 6000, 510000);

    if (!maxaveragebitrate_result)
    {
        return std::unexpected(maxaveragebitrate_result.error());
    }

    auto cbr_result = append_boolean_opus_fmtp_parameter(normalized, *parameters, "cbr");

    if (!cbr_result)
    {
        return std::unexpected(cbr_result.error());
    }

    return normalized;
}

std::optional<codec_info> normalize_supported_codec(const media_summary& media, const codec_info& codec)
{
    if (!is_supported_codec(media, codec))
    {
        return std::nullopt;
    }

    codec_info normalized_codec = codec;

    if (media.kind == "audio" && is_opus_codec(codec))
    {
        auto normalized_fmtp = normalize_opus_fmtp(codec.fmtp);

        if (!normalized_fmtp)
        {
            return std::nullopt;
        }

        normalized_codec.fmtp = *normalized_fmtp;
    }

    if (media.kind == "video" && is_h264_codec(codec))
    {
        auto normalized_fmtp = normalize_h264_answer_fmtp(codec.fmtp);
        if (!normalized_fmtp.has_value())
        {
            return std::nullopt;
        }

        normalized_codec.fmtp = *normalized_fmtp;
    }

    return normalized_codec;
}

uint8_t codec_answer_preference_rank(const media_summary& media, const codec_info& codec)
{
    if (media.kind == "audio")
    {
        if (is_opus_codec(codec))
        {
            return 0;
        }

        return 100;
    }

    if (media.kind == "video")
    {
        if (is_vp8_codec(codec))
        {
            return 0;
        }

        if (is_h264_codec(codec))
        {
            return 10;
        }

        return 100;
    }

    return 100;
}

void sort_primary_codecs_by_answer_preference(const media_summary& media, std::vector<codec_info>& selected_codecs)
{
    std::stable_sort(selected_codecs.begin(),
                     selected_codecs.end(),
                     [&media](const codec_info& left, const codec_info& right)
                     {
                         const uint8_t left_rank = codec_answer_preference_rank(media, left);

                         const uint8_t right_rank = codec_answer_preference_rank(media, right);

                         return left_rank < right_rank;
                     });
}

bool media_can_send(const media_summary& media)
{
    return media.direction == media_direction::send_only || media.direction == media_direction::send_recv;
}

bool codec_encoding_parameters_are_compatible(std::string_view publisher_encoding_parameters, std::string_view subscriber_encoding_parameters)
{
    if (publisher_encoding_parameters.empty() || subscriber_encoding_parameters.empty())
    {
        return true;
    }

    return publisher_encoding_parameters == subscriber_encoding_parameters;
}

bool h264_codecs_are_compatible(const codec_info& publisher_codec, const codec_info& subscriber_codec)
{
    auto compatibility = check_h264_fmtp_relay_compatibility(publisher_codec.fmtp, subscriber_codec.fmtp);

    if (!compatibility)
    {
        return false;
    }

    return *compatibility;
}
bool codecs_are_compatible(const codec_info& publisher_codec, const codec_info& subscriber_codec)
{
    if (!equals_ignore_case(publisher_codec.name, subscriber_codec.name))
    {
        return false;
    }

    if (publisher_codec.clock_rate != subscriber_codec.clock_rate)
    {
        return false;
    }

    if (!codec_encoding_parameters_are_compatible(publisher_codec.encoding_parameters, subscriber_codec.encoding_parameters))
    {
        return false;
    }

    if (is_h264_codec(publisher_codec))
    {
        return h264_codecs_are_compatible(publisher_codec, subscriber_codec);
    }

    return true;
}

bool has_compatible_publisher_codec(const media_summary& publisher_media, const codec_info& subscriber_codec)
{
    for (const auto& publisher_codec : publisher_media.codecs)
    {
        if (!payload_type_exists(publisher_media.payload_types, publisher_codec.payload_type))
        {
            continue;
        }

        std::optional<codec_info> normalized_publisher_codec = normalize_supported_codec(publisher_media, publisher_codec);

        if (!normalized_publisher_codec.has_value())
        {
            continue;
        }

        if (!codecs_are_compatible(*normalized_publisher_codec, subscriber_codec))
        {
            continue;
        }

        return true;
    }

    return false;
}
const codec_info* find_selected_codec_by_payload_type(const std::vector<codec_info>& codecs, uint16_t payload_type)
{
    for (const auto& codec : codecs)
    {
        if (codec.payload_type == payload_type)
        {
            return &codec;
        }
    }

    return nullptr;
}

const codec_info* find_compatible_publisher_primary_codec(const media_summary& publisher_media, const codec_info& subscriber_codec)
{
    for (const auto& publisher_codec : publisher_media.codecs)
    {
        if (!payload_type_exists(publisher_media.payload_types, publisher_codec.payload_type))
        {
            continue;
        }

        if (is_rtx_codec(publisher_codec))
        {
            continue;
        }

        std::optional<codec_info> normalized_publisher_codec = normalize_supported_codec(publisher_media, publisher_codec);

        if (!normalized_publisher_codec.has_value())
        {
            continue;
        }

        if (!codecs_are_compatible(*normalized_publisher_codec, subscriber_codec))
        {
            continue;
        }

        return &publisher_codec;
    }

    return nullptr;
}

bool media_has_rtx_codec_for_apt(const media_summary& media, uint16_t apt_payload_type)
{
    for (const auto& codec : media.codecs)
    {
        if (!payload_type_exists(media.payload_types, codec.payload_type))
        {
            continue;
        }

        if (!is_rtx_codec(codec))
        {
            continue;
        }

        const auto codec_apt = find_codec_apt_payload_type(codec);

        if (!codec_apt.has_value() || *codec_apt != apt_payload_type)
        {
            continue;
        }

        return true;
    }

    return false;
}

bool rtx_codec_is_answerable(const media_summary& subscriber_media,
                             const media_summary& publisher_media,
                             const codec_info& subscriber_rtx_codec,
                             const std::vector<codec_info>& selected_codecs)
{
    if (subscriber_media.kind != "video" || publisher_media.kind != "video")
    {
        return false;
    }

    if (!is_rtx_codec(subscriber_rtx_codec))
    {
        return false;
    }

    if (!payload_type_exists(subscriber_media.payload_types, subscriber_rtx_codec.payload_type))
    {
        return false;
    }

    const auto subscriber_apt = find_codec_apt_payload_type(subscriber_rtx_codec);

    if (!subscriber_apt.has_value())
    {
        return false;
    }

    const codec_info* selected_primary_codec = find_selected_codec_by_payload_type(selected_codecs, *subscriber_apt);

    if (selected_primary_codec == nullptr)
    {
        return false;
    }

    const codec_info* publisher_primary_codec = find_compatible_publisher_primary_codec(publisher_media, *selected_primary_codec);

    if (publisher_primary_codec == nullptr)
    {
        return false;
    }

    return media_has_rtx_codec_for_apt(publisher_media, publisher_primary_codec->payload_type);
}

void append_answerable_rtx_codecs(const media_summary& subscriber_media,
                                  const media_summary& publisher_media,
                                  std::vector<codec_info>& selected_codecs)
{
    for (const auto& subscriber_codec : subscriber_media.codecs)
    {
        if (!rtx_codec_is_answerable(subscriber_media, publisher_media, subscriber_codec, selected_codecs))
        {
            continue;
        }

        selected_codecs.push_back(subscriber_codec);
    }
}
bool rtx_codec_is_answerable_for_offer(const media_summary& offer_media, const codec_info& rtx_codec, const std::vector<codec_info>& selected_codecs)
{
    if (offer_media.kind != "video")
    {
        return false;
    }

    if (!is_rtx_codec(rtx_codec))
    {
        return false;
    }

    if (!payload_type_exists(offer_media.payload_types, rtx_codec.payload_type))
    {
        return false;
    }

    const auto apt_payload_type = find_codec_apt_payload_type(rtx_codec);

    if (!apt_payload_type.has_value())
    {
        return false;
    }

    const codec_info* selected_primary_codec = find_selected_codec_by_payload_type(selected_codecs, *apt_payload_type);

    if (selected_primary_codec == nullptr)
    {
        return false;
    }

    if (is_rtx_codec(*selected_primary_codec))
    {
        return false;
    }

    return true;
}

void append_answerable_offer_rtx_codecs(const media_summary& offer_media, std::vector<codec_info>& selected_codecs)
{
    for (const auto& codec : offer_media.codecs)
    {
        if (!rtx_codec_is_answerable_for_offer(offer_media, codec, selected_codecs))
        {
            continue;
        }

        selected_codecs.push_back(codec);
    }
}

std::expected<void, std::string> validate_offer_media(const media_summary& media)
{
    if (media.kind != "audio" && media.kind != "video")
    {
        return make_media_error(media, "has unsupported kind");
    }

    if (media.mid.empty())
    {
        return make_error("media mid is empty");
    }

    if (media.payload_types.empty())
    {
        return make_media_error(media, "has no payload types");
    }

    if (media.codecs.empty())
    {
        return make_media_error(media, "has no codecs");
    }

    return {};
}
}    // namespace

codec_negotiation_result negotiate_codecs(const media_summary& offer_media)
{
    auto validation_result = validate_offer_media(offer_media);

    if (!validation_result)
    {
        return std::unexpected(validation_result.error());
    }

    std::vector<codec_info> selected_codecs;

    for (const auto& codec : offer_media.codecs)
    {
        if (!payload_type_exists(offer_media.payload_types, codec.payload_type))
        {
            continue;
        }

        std::optional<codec_info> normalized_codec = normalize_supported_codec(offer_media, codec);

        if (!normalized_codec.has_value())
        {
            continue;
        }

        selected_codecs.push_back(std::move(*normalized_codec));
    }

    if (selected_codecs.empty())
    {
        return make_media_error(offer_media, "has no supported codecs");
    }

    sort_primary_codecs_by_answer_preference(offer_media, selected_codecs);

    append_answerable_offer_rtx_codecs(offer_media, selected_codecs);

    return selected_codecs;
}
codec_negotiation_result negotiate_codecs(const media_summary& subscriber_media, const media_summary& publisher_media)
{
    auto subscriber_validation_result = validate_offer_media(subscriber_media);

    if (!subscriber_validation_result)
    {
        return std::unexpected(subscriber_validation_result.error());
    }

    auto publisher_validation_result = validate_offer_media(publisher_media);

    if (!publisher_validation_result)
    {
        return std::unexpected(publisher_validation_result.error());
    }

    if (subscriber_media.kind != publisher_media.kind)
    {
        return make_media_error(subscriber_media, "publisher media kind does not match");
    }

    if (!media_can_send(publisher_media))
    {
        return make_media_error(subscriber_media, "publisher media is not send-capable");
    }

    std::vector<codec_info> selected_codecs;

    for (const auto& subscriber_codec : subscriber_media.codecs)
    {
        if (!payload_type_exists(subscriber_media.payload_types, subscriber_codec.payload_type))
        {
            continue;
        }

        std::optional<codec_info> normalized_codec = normalize_supported_codec(subscriber_media, subscriber_codec);

        if (!normalized_codec.has_value())
        {
            continue;
        }

        if (!has_compatible_publisher_codec(publisher_media, *normalized_codec))
        {
            continue;
        }

        selected_codecs.push_back(std::move(*normalized_codec));
    }

    if (selected_codecs.empty())
    {
        return make_media_error(subscriber_media, "has no publisher-compatible codecs");
    }

    sort_primary_codecs_by_answer_preference(subscriber_media, selected_codecs);

    append_answerable_rtx_codecs(subscriber_media, publisher_media, selected_codecs);

    return selected_codecs;
}

}    // namespace webrtc::sdp
