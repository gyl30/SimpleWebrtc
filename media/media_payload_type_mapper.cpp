#include "media/media_payload_type_mapper.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace webrtc
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool is_space(char value) { return value == ' ' || value == '\t'; }

std::string_view trim_left(std::string_view value)
{
    std::size_t offset = 0;

    while (offset < value.size() && is_space(value[offset]))
    {
        offset += 1;
    }

    return value.substr(offset);
}

std::string_view trim_right(std::string_view value)
{
    while (!value.empty() && is_space(value.back()))
    {
        value.remove_suffix(1);
    }

    return value;
}

std::string_view trim(std::string_view value) { return trim_right(trim_left(value)); }

bool equals_ignore_case(std::string_view left, std::string_view right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        const auto left_char = static_cast<unsigned char>(left[index]);

        const auto right_char = static_cast<unsigned char>(right[index]);

        if (std::tolower(left_char) != std::tolower(right_char))
        {
            return false;
        }
    }

    return true;
}

bool payload_type_exists(const sdp::media_summary& media, uint16_t payload_type)
{
    for (uint16_t current : media.payload_types)
    {
        if (current == payload_type)
        {
            return true;
        }
    }

    return false;
}

bool media_can_send(const sdp::media_summary& media)
{
    return media.direction == sdp::media_direction::send_recv || media.direction == sdp::media_direction::send_only ||
           media.direction == sdp::media_direction::unknown;
}

bool media_can_receive(const sdp::media_summary& media)
{
    return media.direction == sdp::media_direction::send_recv || media.direction == sdp::media_direction::recv_only ||
           media.direction == sdp::media_direction::unknown;
}

std::optional<std::string> find_fmtp_parameter(std::string_view fmtp, std::string_view key)
{
    std::size_t start = 0;

    while (start <= fmtp.size())
    {
        const std::size_t separator = fmtp.find(';', start);

        const std::string_view item = separator == std::string_view::npos ? fmtp.substr(start) : fmtp.substr(start, separator - start);

        const std::string_view trimmed_item = trim(item);

        const std::size_t equal_position = trimmed_item.find('=');

        if (equal_position != std::string_view::npos)
        {
            const std::string_view item_key = trim(trimmed_item.substr(0, equal_position));

            const std::string_view item_value = trim(trimmed_item.substr(equal_position + 1));

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

bool is_h264_codec(const sdp::codec_info& codec) { return equals_ignore_case(codec.name, "h264"); }

bool h264_codecs_are_compatible(const sdp::codec_info& publisher_codec, const sdp::codec_info& subscriber_codec)
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

bool codec_encoding_parameters_are_compatible(std::string_view publisher_encoding_parameters, std::string_view subscriber_encoding_parameters)
{
    if (publisher_encoding_parameters.empty() || subscriber_encoding_parameters.empty())
    {
        return true;
    }

    return publisher_encoding_parameters == subscriber_encoding_parameters;
}

bool codecs_are_compatible(const sdp::codec_info& publisher_codec, const sdp::codec_info& subscriber_codec)
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

const sdp::media_summary* find_matching_subscriber_media(const sdp::media_summary& publisher_media, const sdp::webrtc_offer_summary& subscriber_offer)
{
    for (const auto& subscriber_media : subscriber_offer.media)
    {
        if (subscriber_media.mid == publisher_media.mid && subscriber_media.kind == publisher_media.kind && media_can_receive(subscriber_media))
        {
            return &subscriber_media;
        }
    }

    const sdp::media_summary* selected_media = nullptr;

    for (const auto& subscriber_media : subscriber_offer.media)
    {
        if (subscriber_media.kind != publisher_media.kind)
        {
            continue;
        }

        if (!media_can_receive(subscriber_media))
        {
            continue;
        }

        if (selected_media != nullptr)
        {
            return nullptr;
        }

        selected_media = &subscriber_media;
    }

    return selected_media;
}

std::optional<sdp::codec_info> find_compatible_subscriber_codec(const sdp::media_summary& subscriber_media, const sdp::codec_info& publisher_codec)
{
    for (const auto& subscriber_codec : subscriber_media.codecs)
    {
        if (!payload_type_exists(subscriber_media, subscriber_codec.payload_type))
        {
            continue;
        }

        if (!codecs_are_compatible(publisher_codec, subscriber_codec))
        {
            continue;
        }

        return subscriber_codec;
    }

    return std::nullopt;
}

void append_media_mappings(media_payload_type_mapping_table& table,
                           const sdp::media_summary& publisher_media,
                           const sdp::media_summary& subscriber_media)
{
    for (const auto& publisher_codec : publisher_media.codecs)
    {
        if (!payload_type_exists(publisher_media, publisher_codec.payload_type))
        {
            continue;
        }

        auto subscriber_codec = find_compatible_subscriber_codec(subscriber_media, publisher_codec);

        if (!subscriber_codec.has_value())
        {
            continue;
        }

        media_payload_type_mapping mapping;

        mapping.stream_id = table.stream_id;

        mapping.kind = publisher_media.kind;

        mapping.publisher_mid = publisher_media.mid;

        mapping.subscriber_mid = subscriber_media.mid;

        mapping.publisher_payload_type = publisher_codec.payload_type;

        mapping.subscriber_payload_type = subscriber_codec->payload_type;

        mapping.codec_name = publisher_codec.name;

        mapping.clock_rate = publisher_codec.clock_rate;

        mapping.encoding_parameters =
            publisher_codec.encoding_parameters.empty() ? subscriber_codec->encoding_parameters : publisher_codec.encoding_parameters;

        mapping.payload_type_rewrite_required = mapping.publisher_payload_type != mapping.subscriber_payload_type;

        mapping.mid_rewrite_required = mapping.publisher_mid != mapping.subscriber_mid;

        table.mappings.push_back(std::move(mapping));
    }
}
}    // namespace

media_payload_type_mapping_table_result build_media_payload_type_mapping_table(std::string_view stream_id,
                                                                               const sdp::webrtc_offer_summary& publisher_offer,
                                                                               const sdp::webrtc_offer_summary& subscriber_offer)
{
    if (stream_id.empty())
    {
        return make_error("media payload type mapping stream id is empty");
    }

    if (publisher_offer.media.empty())
    {
        return make_error("media payload type mapping publisher offer has no media");
    }

    if (subscriber_offer.media.empty())
    {
        return make_error("media payload type mapping subscriber offer has no media");
    }

    media_payload_type_mapping_table table;

    table.stream_id = std::string(stream_id);

    for (const auto& publisher_media : publisher_offer.media)
    {
        if (!media_can_send(publisher_media))
        {
            continue;
        }

        if (publisher_media.kind.empty() || publisher_media.mid.empty())
        {
            continue;
        }

        const sdp::media_summary* subscriber_media = find_matching_subscriber_media(publisher_media, subscriber_offer);

        if (subscriber_media == nullptr)
        {
            continue;
        }

        append_media_mappings(table, publisher_media, *subscriber_media);
    }

    if (table.mappings.empty())
    {
        return make_error("media payload type mapping has no compatible codecs");
    }

    return table;
}

std::optional<media_payload_type_mapping> find_media_payload_type_mapping(const media_payload_type_mapping_table& table,
                                                                          std::string_view publisher_mid,
                                                                          uint16_t publisher_payload_type)
{
    if (publisher_mid.empty())
    {
        return std::nullopt;
    }

    for (const auto& mapping : table.mappings)
    {
        if (mapping.publisher_mid == publisher_mid && mapping.publisher_payload_type == publisher_payload_type)
        {
            return mapping;
        }
    }

    return std::nullopt;
}

std::optional<media_payload_type_mapping> find_media_payload_type_mapping_by_kind(const media_payload_type_mapping_table& table,
                                                                                  std::string_view kind,
                                                                                  uint16_t publisher_payload_type)
{
    if (kind.empty())
    {
        return std::nullopt;
    }

    for (const auto& mapping : table.mappings)
    {
        if (mapping.kind == kind && mapping.publisher_payload_type == publisher_payload_type)
        {
            return mapping;
        }
    }

    return std::nullopt;
}

bool media_payload_type_mapping_requires_packet_rewrite(const media_payload_type_mapping& mapping)
{
    return mapping.payload_type_rewrite_required || mapping.mid_rewrite_required;
}

std::string media_payload_type_mapping_to_string(const media_payload_type_mapping& mapping)
{
    std::string result;

    result.reserve(128);

    result.append("stream=");
    result.append(mapping.stream_id);

    result.append(" kind=");
    result.append(mapping.kind);

    result.append(" publisher_mid=");
    result.append(mapping.publisher_mid);

    result.append(" subscriber_mid=");
    result.append(mapping.subscriber_mid);

    result.append(" publisher_pt=");
    result.append(std::to_string(mapping.publisher_payload_type));

    result.append(" subscriber_pt=");
    result.append(std::to_string(mapping.subscriber_payload_type));

    result.append(" codec=");
    result.append(mapping.codec_name);

    result.append(" clock=");
    result.append(std::to_string(mapping.clock_rate));

    return result;
}
}    // namespace webrtc
