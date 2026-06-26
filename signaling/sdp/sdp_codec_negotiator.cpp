#include "signaling/sdp/sdp_codec_negotiator.h"

#include <cctype>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webrtc::sdp
{
namespace
{
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

bool is_supported_h264_packetization_mode(const codec_info& codec)
{
    const auto packetization_mode = find_fmtp_parameter(codec.fmtp, "packetization-mode");

    if (!packetization_mode.has_value())
    {
        return false;
    }

    return packetization_mode.value() == "1";
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

    return is_supported_h264_packetization_mode(codec);
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
    const auto publisher_packetization_mode = find_fmtp_parameter(publisher_codec.fmtp, "packetization-mode");

    const auto subscriber_packetization_mode = find_fmtp_parameter(subscriber_codec.fmtp, "packetization-mode");

    if (publisher_packetization_mode != subscriber_packetization_mode)
    {
        return false;
    }

    const auto publisher_profile_level_id = find_fmtp_parameter(publisher_codec.fmtp, "profile-level-id");

    const auto subscriber_profile_level_id = find_fmtp_parameter(subscriber_codec.fmtp, "profile-level-id");

    if (publisher_profile_level_id.has_value() && subscriber_profile_level_id.has_value() &&
        !equals_ignore_case(*publisher_profile_level_id, *subscriber_profile_level_id))
    {
        return false;
    }

    return true;
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

        if (!is_supported_codec(publisher_media, publisher_codec))
        {
            continue;
        }

        if (!codecs_are_compatible(publisher_codec, subscriber_codec))
        {
            continue;
        }

        return true;
    }

    return false;
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

        if (!is_supported_codec(offer_media, codec))
        {
            continue;
        }

        selected_codecs.push_back(codec);
    }

    if (selected_codecs.empty())
    {
        return make_media_error(offer_media, "has no supported codecs");
    }

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

        if (!is_supported_codec(subscriber_media, subscriber_codec))
        {
            continue;
        }

        if (!has_compatible_publisher_codec(publisher_media, subscriber_codec))
        {
            continue;
        }

        selected_codecs.push_back(subscriber_codec);
    }

    if (selected_codecs.empty())
    {
        return make_media_error(subscriber_media, "has no publisher-compatible codecs");
    }

    return selected_codecs;
}
}    // namespace webrtc::sdp
