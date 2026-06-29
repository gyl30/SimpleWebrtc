#include "media/media_payload_type_mapper.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "signaling/sdp/h264_fmtp_compat.h"
#include "signaling/sdp/sdp_summary.h"

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

std::size_t count_send_capable_media_by_kind(const sdp::webrtc_offer_summary& offer, std::string_view kind)
{
    std::size_t count = 0;

    for (const auto& media : offer.media)
    {
        if (media.kind != kind)
        {
            continue;
        }

        if (!media_can_send(media))
        {
            continue;
        }

        count += 1;
    }

    return count;
}

std::size_t count_receive_capable_media_by_kind(const sdp::webrtc_offer_summary& offer, std::string_view kind)
{
    std::size_t count = 0;

    for (const auto& media : offer.media)
    {
        if (media.kind != kind)
        {
            continue;
        }

        if (!media_can_receive(media))
        {
            continue;
        }

        count += 1;
    }

    return count;
}

std::optional<std::size_t> find_send_capable_media_ordinal_by_kind(const sdp::webrtc_offer_summary& offer, const sdp::media_summary& target_media)
{
    std::size_t ordinal = 0;

    for (const auto& media : offer.media)
    {
        if (media.kind != target_media.kind)
        {
            continue;
        }

        if (!media_can_send(media))
        {
            continue;
        }

        if (&media == &target_media)
        {
            return ordinal;
        }

        ordinal += 1;
    }

    return std::nullopt;
}

const sdp::media_summary* find_receive_capable_media_by_kind_ordinal(const sdp::webrtc_offer_summary& offer,
                                                                     std::string_view kind,
                                                                     std::size_t target_ordinal)
{
    std::size_t ordinal = 0;

    for (const auto& media : offer.media)
    {
        if (media.kind != kind)
        {
            continue;
        }

        if (!media_can_receive(media))
        {
            continue;
        }

        if (ordinal == target_ordinal)
        {
            return &media;
        }

        ordinal += 1;
    }

    return nullptr;
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
std::string to_lower_ascii(std::string_view value)
{
    std::string result;

    result.reserve(value.size());

    for (char ch : value)
    {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }

    return result;
}

std::expected<std::optional<std::string>, std::string> find_unique_fmtp_parameter(std::string_view fmtp,
                                                                                  std::string_view key,
                                                                                  std::string_view codec_name)
{
    std::optional<std::string> value;

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
                if (value.has_value())
                {
                    std::string message;

                    message.append(codec_name);

                    message.append(" fmtp ");

                    message.append(key);

                    message.append(" is duplicated");

                    return make_error(message);
                }

                value = std::string(item_value);
            }
        }

        if (separator == std::string_view::npos)
        {
            break;
        }

        start = separator + 1;
    }

    return value;
}

bool is_hex_digit_ascii(char value)
{
    const auto ch = static_cast<unsigned char>(value);

    return std::isdigit(ch) != 0 || (ch >= static_cast<unsigned char>('a') && ch <= static_cast<unsigned char>('f')) ||
           (ch >= static_cast<unsigned char>('A') && ch <= static_cast<unsigned char>('F'));
}

std::expected<std::string, std::string> normalize_h264_profile_level_id(std::string_view value)
{
    value = trim(value);

    if (value.size() != 6)
    {
        return make_error("h264 fmtp profile-level-id must be 6 hex characters");
    }

    for (char ch : value)
    {
        if (!is_hex_digit_ascii(ch))
        {
            return make_error("h264 fmtp profile-level-id contains non-hex character");
        }
    }

    return to_lower_ascii(value);
}

std::expected<std::string, std::string> normalize_h264_fmtp(std::string_view fmtp)
{
    auto packetization_mode = find_unique_fmtp_parameter(fmtp, "packetization-mode", "h264");

    if (!packetization_mode)
    {
        return std::unexpected(packetization_mode.error());
    }

    if (!packetization_mode->has_value())
    {
        return make_error("h264 fmtp packetization-mode is missing");
    }

    if (**packetization_mode != "1")
    {
        return make_error("h264 fmtp packetization-mode must be 1");
    }

    auto level_asymmetry_allowed = find_unique_fmtp_parameter(fmtp, "level-asymmetry-allowed", "h264");

    if (!level_asymmetry_allowed)
    {
        return std::unexpected(level_asymmetry_allowed.error());
    }

    if (level_asymmetry_allowed->has_value() && **level_asymmetry_allowed != "0" && **level_asymmetry_allowed != "1")
    {
        return make_error("h264 fmtp level-asymmetry-allowed must be 0 or 1");
    }

    auto profile_level_id = find_unique_fmtp_parameter(fmtp, "profile-level-id", "h264");

    if (!profile_level_id)
    {
        return std::unexpected(profile_level_id.error());
    }

    std::string normalized;

    if (level_asymmetry_allowed->has_value())
    {
        normalized.append("level-asymmetry-allowed=");

        normalized.append(**level_asymmetry_allowed);

        normalized.append(";");
    }

    normalized.append("packetization-mode=1");

    if (profile_level_id->has_value())
    {
        auto normalized_profile_level_id = normalize_h264_profile_level_id(**profile_level_id);

        if (!normalized_profile_level_id)
        {
            return std::unexpected(normalized_profile_level_id.error());
        }

        normalized.append(";profile-level-id=");

        normalized.append(*normalized_profile_level_id);
    }

    return normalized;
}

struct h264_fmtp_compat_info
{
    std::optional<std::string> profile_level_id;
    std::optional<std::string> profile_id;
    bool level_asymmetry_allowed = false;
};

std::expected<h264_fmtp_compat_info, std::string> make_h264_fmtp_compat_info(std::string_view fmtp)
{
    auto normalized_fmtp = normalize_h264_fmtp(fmtp);

    if (!normalized_fmtp)
    {
        return std::unexpected(normalized_fmtp.error());
    }

    h264_fmtp_compat_info info;

    auto level_asymmetry_allowed = find_fmtp_parameter(*normalized_fmtp, "level-asymmetry-allowed");

    info.level_asymmetry_allowed = level_asymmetry_allowed.has_value() && *level_asymmetry_allowed == "1";

    auto profile_level_id = find_fmtp_parameter(*normalized_fmtp, "profile-level-id");

    if (profile_level_id.has_value())
    {
        info.profile_level_id = *profile_level_id;

        info.profile_id = profile_level_id->substr(0, 4);
    }

    return info;
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

    if (result.ec != std::errc() || result.ptr != value.data() + value.size() || payload_type > 127U)
    {
        return std::nullopt;
    }

    return static_cast<uint16_t>(payload_type);
}

bool codec_is_rtx(const sdp::codec_info& codec) { return equals_ignore_case(codec.name, "rtx"); }

std::optional<uint16_t> find_codec_apt_payload_type(const sdp::codec_info& codec)
{
    const auto apt = find_fmtp_parameter(codec.fmtp, "apt");

    if (!apt.has_value())
    {
        return std::nullopt;
    }

    return parse_payload_type_text(*apt);
}

const sdp::codec_info* find_codec_by_payload_type(const sdp::media_summary& media, uint16_t payload_type)
{
    if (!payload_type_exists(media, payload_type))
    {
        return nullptr;
    }

    for (const auto& codec : media.codecs)
    {
        if (codec.payload_type == payload_type)
        {
            return &codec;
        }
    }

    return nullptr;
}

bool mapping_exists(const media_payload_type_mapping_table& table, std::string_view publisher_mid, uint16_t publisher_payload_type)
{
    for (const auto& mapping : table.mappings)
    {
        if (mapping.publisher_mid == publisher_mid && mapping.publisher_payload_type == publisher_payload_type)
        {
            return true;
        }
    }

    return false;
}

const media_payload_type_mapping* find_mapping_by_publisher_payload_type(const media_payload_type_mapping_table& table,
                                                                         std::string_view publisher_mid,
                                                                         uint16_t publisher_payload_type)
{
    for (const auto& mapping : table.mappings)
    {
        if (mapping.publisher_mid == publisher_mid && mapping.publisher_payload_type == publisher_payload_type)
        {
            return &mapping;
        }
    }

    return nullptr;
}

const sdp::codec_info* find_rtx_codec_for_apt(const sdp::media_summary& media, uint16_t apt_payload_type)
{
    for (const auto& codec : media.codecs)
    {
        if (!payload_type_exists(media, codec.payload_type))
        {
            continue;
        }

        if (!codec_is_rtx(codec))
        {
            continue;
        }

        const auto codec_apt = find_codec_apt_payload_type(codec);

        if (!codec_apt.has_value() || *codec_apt != apt_payload_type)
        {
            continue;
        }

        return &codec;
    }

    return nullptr;
}

void append_rtx_mappings(media_payload_type_mapping_table& table,
                         const sdp::media_summary& publisher_media,
                         const sdp::media_summary& subscriber_media)
{
    for (const auto& publisher_codec : publisher_media.codecs)
    {
        if (!payload_type_exists(publisher_media, publisher_codec.payload_type))
        {
            continue;
        }

        if (!codec_is_rtx(publisher_codec))
        {
            continue;
        }

        const auto publisher_apt = find_codec_apt_payload_type(publisher_codec);

        if (!publisher_apt.has_value())
        {
            continue;
        }

        const media_payload_type_mapping* primary_mapping = find_mapping_by_publisher_payload_type(table, publisher_media.mid, *publisher_apt);

        if (primary_mapping == nullptr)
        {
            continue;
        }

        const sdp::codec_info* subscriber_rtx_codec = find_rtx_codec_for_apt(subscriber_media, primary_mapping->subscriber_payload_type);

        if (subscriber_rtx_codec == nullptr)
        {
            continue;
        }

        if (mapping_exists(table, publisher_media.mid, publisher_codec.payload_type))
        {
            continue;
        }

        media_payload_type_mapping mapping;

        mapping.stream_id = table.stream_id;
        mapping.kind = publisher_media.kind;

        mapping.publisher_mid = publisher_media.mid;
        mapping.subscriber_mid = subscriber_media.mid;

        mapping.publisher_payload_type = publisher_codec.payload_type;
        mapping.subscriber_payload_type = subscriber_rtx_codec->payload_type;

        mapping.codec_name = publisher_codec.name;
        mapping.clock_rate = publisher_codec.clock_rate;

        mapping.encoding_parameters =
            publisher_codec.encoding_parameters.empty() ? subscriber_rtx_codec->encoding_parameters : publisher_codec.encoding_parameters;

        mapping.rtx = true;
        mapping.publisher_apt_payload_type = *publisher_apt;
        mapping.subscriber_apt_payload_type = primary_mapping->subscriber_payload_type;

        mapping.payload_type_rewrite_required = mapping.publisher_payload_type != mapping.subscriber_payload_type;

        mapping.mid_rewrite_required = mapping.publisher_mid != mapping.subscriber_mid;

        table.mappings.push_back(std::move(mapping));
    }
}

bool is_h264_codec(const sdp::codec_info& codec) { return equals_ignore_case(codec.name, "h264") && codec.clock_rate == 90000; }

bool h264_codecs_are_compatible(const sdp::codec_info& publisher_codec, const sdp::codec_info& subscriber_codec)
{
    auto compatibility = sdp::check_h264_fmtp_relay_compatibility(publisher_codec.fmtp, subscriber_codec.fmtp);

    if (!compatibility)
    {
        return false;
    }

    return compatibility->compatible;
}

constexpr std::string_view k_rtp_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";

constexpr std::string_view k_rtp_stream_id_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";

constexpr std::string_view k_repaired_rtp_stream_id_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

constexpr std::string_view k_absolute_send_time_extension_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

std::unexpected<std::string> make_payload_mapping_error(std::string_view message) { return std::unexpected(std::string(message)); }

const sdp::rtp_header_extension* find_header_extension_by_uri(const sdp::media_summary& media, std::string_view uri)
{
    if (uri.empty())
    {
        return nullptr;
    }

    for (const auto& extension : media.header_extensions)
    {
        if (extension.uri == uri)
        {
            return &extension;
        }
    }

    return nullptr;
}

const sdp::rtp_header_extension* find_header_extension_by_id(const sdp::media_summary& media, int32_t id)
{
    if (id <= 0)
    {
        return nullptr;
    }

    for (const auto& extension : media.header_extensions)
    {
        if (extension.id == id)
        {
            return &extension;
        }
    }

    return nullptr;
}

std::expected<void, std::string> validate_media_summary_for_payload_mapping(const sdp::media_summary& media)
{
    auto result = sdp::validate_media_summary_identity(media);

    if (!result)
    {
        return std::unexpected(result.error());
    }

    return {};
}

std::expected<void, std::string> validate_forwarded_header_extension_collision(const sdp::media_summary& publisher_media,
                                                                               const sdp::media_summary& subscriber_media,
                                                                               std::string_view uri)
{
    const sdp::rtp_header_extension* publisher_extension = find_header_extension_by_uri(publisher_media, uri);

    if (publisher_extension == nullptr)
    {
        return {};
    }

    const sdp::rtp_header_extension* subscriber_same_uri_extension = find_header_extension_by_uri(subscriber_media, uri);

    if (subscriber_same_uri_extension != nullptr && subscriber_same_uri_extension->id == publisher_extension->id)
    {
        return {};
    }

    const sdp::rtp_header_extension* subscriber_extension_with_same_id = find_header_extension_by_id(subscriber_media, publisher_extension->id);

    if (subscriber_extension_with_same_id == nullptr)
    {
        return {};
    }

    if (subscriber_extension_with_same_id->uri == uri)
    {
        return {};
    }

    std::string message = "payload mapping rejected because forwarded header extension id conflicts uri=";

    message.append(std::string(uri));

    message.append(" subscriber_uri=");

    message.append(subscriber_extension_with_same_id->uri);

    return std::unexpected(std::move(message));
}

std::expected<void, std::string> validate_forwarded_rid_extension_compatibility(const sdp::media_summary& publisher_media,
                                                                                const sdp::media_summary& subscriber_media)
{
    const sdp::rtp_header_extension* publisher_rid_extension = find_header_extension_by_uri(publisher_media, k_rtp_stream_id_extension_uri);

    if (publisher_rid_extension == nullptr)
    {
        return {};
    }

    auto collision_result = validate_forwarded_header_extension_collision(publisher_media, subscriber_media, k_rtp_stream_id_extension_uri);

    if (!collision_result)
    {
        return std::unexpected(collision_result.error());
    }

    const sdp::rtp_header_extension* subscriber_rid_extension = find_header_extension_by_uri(subscriber_media, k_rtp_stream_id_extension_uri);

    if (subscriber_rid_extension == nullptr)
    {
        return {};
    }

    /*
     * Publisher and subscriber may negotiate different extmap ids for RID.
     * RTP forwarding rewrites the extension id when both peers support RID
     * and the subscriber id does not collide with another forwarded URI.
     */
    return {};
}

std::expected<void, std::string> validate_repaired_rid_extension_compatibility(const sdp::media_summary& publisher_media,
                                                                               const sdp::media_summary& subscriber_media,
                                                                               bool rtx_mapping)
{
    const sdp::rtp_header_extension* publisher_repaired_rid_extension =
        find_header_extension_by_uri(publisher_media, k_repaired_rtp_stream_id_extension_uri);

    const sdp::rtp_header_extension* subscriber_repaired_rid_extension =
        find_header_extension_by_uri(subscriber_media, k_repaired_rtp_stream_id_extension_uri);

    const bool publisher_has_repaired_rid = publisher_repaired_rid_extension != nullptr;

    const bool subscriber_has_repaired_rid = subscriber_repaired_rid_extension != nullptr;

    if (!publisher_has_repaired_rid && !subscriber_has_repaired_rid)
    {
        return {};
    }

    if (!rtx_mapping)
    {
        auto collision_result =
            validate_forwarded_header_extension_collision(publisher_media, subscriber_media, k_repaired_rtp_stream_id_extension_uri);

        if (!collision_result)
        {
            return std::unexpected(collision_result.error());
        }

        return {};
    }

    if (!publisher_has_repaired_rid || !subscriber_has_repaired_rid)
    {
        return make_payload_mapping_error("payload mapping rejected because repaired-rid extmap is not supported by both peers");
    }

    if (!sdp::media_has_rtx_codec(publisher_media) || !sdp::media_has_rtx_codec(subscriber_media))
    {
        return make_payload_mapping_error("payload mapping rejected because repaired-rid requires rtx codec on both peers");
    }

    if (!sdp::media_has_rtp_header_extension_uri(publisher_media, k_rtp_stream_id_extension_uri) ||
        !sdp::media_has_rtp_header_extension_uri(subscriber_media, k_rtp_stream_id_extension_uri))
    {
        return make_payload_mapping_error("payload mapping rejected because repaired-rid requires rid extmap on both peers");
    }

    /*
     * Publisher and subscriber may negotiate different extmap ids for
     * repaired-rid. RTP forwarding rewrites the extension id for RTX packets
     * after validating that both peers support repaired-rid and RTX.
     */
    return {};
}
std::expected<void, std::string> validate_forwarded_absolute_send_time_extension_compatibility(const sdp::media_summary& publisher_media,
                                                                                               const sdp::media_summary& subscriber_media)
{
    return validate_forwarded_header_extension_collision(publisher_media, subscriber_media, k_absolute_send_time_extension_uri);
}

std::expected<void, std::string> validate_payload_mapping_identity_compatibility(const sdp::media_summary& publisher_media,
                                                                                 const sdp::media_summary& subscriber_media,
                                                                                 const sdp::codec_info& publisher_codec,
                                                                                 const sdp::codec_info& subscriber_codec)
{
    auto publisher_identity_result = validate_media_summary_for_payload_mapping(publisher_media);

    if (!publisher_identity_result)
    {
        return std::unexpected(publisher_identity_result.error());
    }

    auto subscriber_identity_result = validate_media_summary_for_payload_mapping(subscriber_media);

    if (!subscriber_identity_result)
    {
        return std::unexpected(subscriber_identity_result.error());
    }

    if (publisher_media.kind != subscriber_media.kind)
    {
        return make_payload_mapping_error("payload mapping rejected because media kind mismatched");
    }

    const bool publisher_codec_is_rtx = codec_is_rtx(publisher_codec);

    const bool subscriber_codec_is_rtx = codec_is_rtx(subscriber_codec);

    if (publisher_codec_is_rtx != subscriber_codec_is_rtx)
    {
        return make_payload_mapping_error("payload mapping rejected because rtx codec pairing mismatched");
    }

    auto rid_result = validate_forwarded_rid_extension_compatibility(publisher_media, subscriber_media);

    if (!rid_result)
    {
        return std::unexpected(rid_result.error());
    }

    auto repaired_rid_result =
        validate_repaired_rid_extension_compatibility(publisher_media, subscriber_media, publisher_codec_is_rtx && subscriber_codec_is_rtx);
    if (!repaired_rid_result)
    {
        return std::unexpected(repaired_rid_result.error());
    }

    auto absolute_send_time_result = validate_forwarded_absolute_send_time_extension_compatibility(publisher_media, subscriber_media);
    if (!absolute_send_time_result)
    {
        return std::unexpected(absolute_send_time_result.error());
    }

    return {};
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

const sdp::media_summary* find_matching_subscriber_media(const sdp::media_summary& publisher_media,
                                                         const sdp::webrtc_offer_summary& publisher_offer,
                                                         const sdp::webrtc_offer_summary& subscriber_offer)
{
    for (const auto& subscriber_media : subscriber_offer.media)
    {
        if (subscriber_media.mid == publisher_media.mid && subscriber_media.kind == publisher_media.kind && media_can_receive(subscriber_media))
        {
            return &subscriber_media;
        }
    }

    const std::optional<std::size_t> publisher_ordinal = find_send_capable_media_ordinal_by_kind(publisher_offer, publisher_media);

    if (!publisher_ordinal.has_value())
    {
        return nullptr;
    }

    const std::size_t publisher_kind_count = count_send_capable_media_by_kind(publisher_offer, publisher_media.kind);

    const std::size_t subscriber_kind_count = count_receive_capable_media_by_kind(subscriber_offer, publisher_media.kind);

    if (publisher_kind_count != subscriber_kind_count)
    {
        return nullptr;
    }

    return find_receive_capable_media_by_kind_ordinal(subscriber_offer, publisher_media.kind, *publisher_ordinal);
}
std::optional<sdp::codec_info> find_compatible_subscriber_codec(const sdp::media_summary& subscriber_media, const sdp::codec_info& publisher_codec)
{
    if (codec_is_rtx(publisher_codec))
    {
        return std::nullopt;
    }

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

        if (codec_is_rtx(publisher_codec))
        {
            continue;
        }

        auto subscriber_codec = find_compatible_subscriber_codec(subscriber_media, publisher_codec);
        if (!subscriber_codec.has_value())
        {
            continue;
        }

        auto identity_result = validate_payload_mapping_identity_compatibility(publisher_media, subscriber_media, publisher_codec, *subscriber_codec);
        if (!identity_result)
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
    append_rtx_mappings(table, publisher_media, subscriber_media);
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

        const sdp::media_summary* subscriber_media = find_matching_subscriber_media(publisher_media, publisher_offer, subscriber_offer);
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

    std::optional<media_payload_type_mapping> matched_mapping;

    for (const auto& mapping : table.mappings)
    {
        if (mapping.kind != kind || mapping.publisher_payload_type != publisher_payload_type)
        {
            continue;
        }

        if (matched_mapping.has_value())
        {
            return std::nullopt;
        }

        matched_mapping = mapping;
    }

    return matched_mapping;
}

bool media_payload_type_mapping_is_rtx(const media_payload_type_mapping& mapping) { return mapping.rtx; }

bool media_payload_type_is_rtx(const sdp::media_summary& media, uint16_t payload_type)
{
    const sdp::codec_info* codec = find_codec_by_payload_type(media, payload_type);

    return codec != nullptr && codec_is_rtx(*codec);
}

bool media_offer_payload_type_is_rtx(const sdp::webrtc_offer_summary& offer, std::string_view mid, uint16_t payload_type)
{
    bool matched = false;
    bool rtx = false;

    for (const auto& media : offer.media)
    {
        if (!mid.empty() && media.mid != mid)
        {
            continue;
        }

        if (!payload_type_exists(media, payload_type))
        {
            continue;
        }

        const sdp::codec_info* codec = find_codec_by_payload_type(media, payload_type);

        if (codec == nullptr)
        {
            continue;
        }

        if (matched)
        {
            return false;
        }

        matched = true;
        rtx = codec_is_rtx(*codec);
    }

    return matched && rtx;
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
    result.append(" rtx=");
    result.append(mapping.rtx ? "1" : "0");

    if (mapping.rtx)
    {
        result.append(" publisher_apt=");
        result.append(std::to_string(mapping.publisher_apt_payload_type));

        result.append(" subscriber_apt=");
        result.append(std::to_string(mapping.subscriber_apt_payload_type));
    }

    return result;
}
}    // namespace webrtc
