#include "signaling/sdp/sdp_summary.h"

#include <charconv>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace webrtc::sdp
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool is_space(char value) { return value == ' ' || value == '\t'; }

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

std::vector<std::string_view> split_whitespace(std::string_view value)
{
    std::vector<std::string_view> result;

    std::size_t position = 0;
    while (position < value.size())
    {
        while (position < value.size() && is_space(value[position]))
        {
            ++position;
        }

        if (position >= value.size())
        {
            break;
        }

        const std::size_t start = position;

        while (position < value.size() && !is_space(value[position]))
        {
            ++position;
        }

        result.push_back(value.substr(start, position - start));
    }

    return result;
}

std::vector<std::string_view> split_by_char(std::string_view value, char separator)
{
    std::vector<std::string_view> result;

    std::size_t start = 0;
    while (start <= value.size())
    {
        const std::size_t position = value.find(separator, start);
        if (position == std::string_view::npos)
        {
            result.push_back(value.substr(start));
            break;
        }

        result.push_back(value.substr(start, position - start));
        start = position + 1;
    }

    return result;
}

std::expected<uint16_t, std::string> parse_payload_type(std::string_view value)
{
    value = trim(value);
    if (value.empty())
    {
        return make_error("empty payload type");
    }

    uint32_t payload_type = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), payload_type);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size())
    {
        return make_error("invalid payload type");
    }

    if (payload_type > 127)
    {
        return make_error("payload type out of range");
    }

    return static_cast<uint16_t>(payload_type);
}

std::expected<uint32_t, std::string> parse_clock_rate(std::string_view value)
{
    value = trim(value);
    if (value.empty())
    {
        return make_error("empty codec clock rate");
    }

    uint32_t clock_rate = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), clock_rate);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size())
    {
        return make_error("invalid codec clock rate");
    }

    return clock_rate;
}

bool media_has_attribute(const media_description& media, std::string_view key)
{
    for (const auto& attribute : media.attributes)
    {
        if (std::string_view(attribute.key) == key && attribute.value.empty())
        {
            return true;
        }
    }

    return false;
}

std::optional<std::string> find_effective_attribute_value(const session_description& description,
                                                          const media_description& media,
                                                          std::string_view key)
{
    auto media_value = media.find_attribute_value(key);
    if (media_value.has_value() && !media_value->empty())
    {
        return media_value;
    }

    return description.find_attribute_value(key);
}

std::optional<std::string> find_first_attribute_value(const session_description& description, std::string_view key)
{
    auto session_value = description.find_attribute_value(key);
    if (session_value.has_value() && !session_value->empty())
    {
        return session_value;
    }

    for (const auto& media : description.media_descriptions)
    {
        auto media_value = media.find_attribute_value(key);
        if (media_value.has_value() && !media_value->empty())
        {
            return media_value;
        }
    }

    return std::nullopt;
}

std::vector<std::string> parse_bundle_mids(const session_description& description)
{
    std::vector<std::string> mids;

    const auto group_attributes = description.find_attributes(k_attribute_group);
    for (const auto* attribute : group_attributes)
    {
        const auto fields = split_whitespace(attribute->value);
        if (fields.empty())
        {
            continue;
        }

        if (fields[0] != "BUNDLE")
        {
            continue;
        }

        for (std::size_t i = 1; i < fields.size(); ++i)
        {
            if (!fields[i].empty())
            {
                mids.push_back(std::string(fields[i]));
            }
        }
    }

    return mids;
}

std::expected<fingerprint_info, std::string> parse_fingerprint(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.size() != 2)
    {
        return make_error("invalid fingerprint attribute");
    }

    fingerprint_info fingerprint;
    fingerprint.algorithm = std::string(fields[0]);
    fingerprint.value = std::string(fields[1]);

    return fingerprint;
}

std::expected<dtls_connection_role, std::string> parse_setup(std::string_view value)
{
    auto role = parse_dtls_connection_role(trim(value));
    if (!role.has_value() || role.value() == dtls_connection_role::unknown)
    {
        return make_error("invalid setup attribute");
    }

    return role.value();
}

std::expected<media_direction, std::string> parse_media_direction_from_attributes(const media_description& media)
{
    media_direction direction = media_direction::unknown;
    int count = 0;

    const auto check_direction = [&](std::string_view key, media_direction value)
    {
        if (media_has_attribute(media, key))
        {
            direction = value;
            ++count;
        }
    };

    check_direction(k_attribute_send_recv, media_direction::send_recv);
    check_direction(k_attribute_send_only, media_direction::send_only);
    check_direction(k_attribute_recv_only, media_direction::recv_only);
    check_direction(k_attribute_inactive, media_direction::inactive);

    if (count > 1)
    {
        return make_error("media has multiple direction attributes");
    }

    if (direction == media_direction::unknown)
    {
        return media_direction::send_recv;
    }

    return direction;
}

std::expected<codec_info, std::string> parse_rtp_map_attribute(std::string_view value)
{
    const auto fields = split_whitespace(value);
    if (fields.size() != 2)
    {
        return make_error("invalid rtpmap attribute");
    }

    auto payload_type = parse_payload_type(fields[0]);
    if (!payload_type)
    {
        return make_error(payload_type.error());
    }

    const auto codec_parts = split_by_char(fields[1], '/');
    if (codec_parts.size() < 2 || codec_parts[0].empty() || codec_parts[1].empty())
    {
        return make_error("invalid rtpmap codec description");
    }

    auto clock_rate = parse_clock_rate(codec_parts[1]);
    if (!clock_rate)
    {
        return make_error(clock_rate.error());
    }

    codec_info codec;
    codec.payload_type = *payload_type;
    codec.name = std::string(codec_parts[0]);
    codec.clock_rate = *clock_rate;

    if (codec_parts.size() >= 3 && !codec_parts[2].empty())
    {
        codec.encoding_parameters = std::string(codec_parts[2]);
    }

    return codec;
}

codec_info* find_codec_by_payload_type(std::vector<codec_info>& codecs, uint16_t payload_type)
{
    for (auto& codec : codecs)
    {
        if (codec.payload_type == payload_type)
        {
            return &codec;
        }
    }

    return nullptr;
}

bool payload_type_exists(const std::vector<uint16_t>& payload_types, uint16_t payload_type)
{
    for (const auto existing : payload_types)
    {
        if (existing == payload_type)
        {
            return true;
        }
    }

    return false;
}

std::expected<void, std::string> parse_payload_types(media_summary& summary, const media_description& media)
{
    for (const auto& format : media.media_name.formats)
    {
        auto payload_type = parse_payload_type(format);
        if (!payload_type)
        {
            return make_error(payload_type.error());
        }

        summary.payload_types.push_back(*payload_type);
    }

    if (summary.payload_types.empty())
    {
        return make_error("media has no payload types");
    }

    return {};
}

std::expected<void, std::string> parse_codecs(media_summary& summary, const media_description& media)
{
    const auto rtp_map_attributes = media.find_attributes(k_attribute_rtp_map);

    for (const auto* attribute : rtp_map_attributes)
    {
        auto codec = parse_rtp_map_attribute(attribute->value);
        if (!codec)
        {
            return make_error(codec.error());
        }

        if (!payload_type_exists(summary.payload_types, codec->payload_type))
        {
            continue;
        }

        summary.codecs.push_back(std::move(*codec));
    }

    const auto fmtp_attributes = media.find_attributes(k_attribute_fmtp);
    for (const auto* attribute : fmtp_attributes)
    {
        const std::string_view value = attribute->value;
        const auto fields = split_whitespace(value);
        if (fields.size() < 2)
        {
            return make_error("invalid fmtp attribute");
        }

        auto payload_type = parse_payload_type(fields[0]);
        if (!payload_type)
        {
            return make_error(payload_type.error());
        }

        auto* codec = find_codec_by_payload_type(summary.codecs, *payload_type);
        if (codec == nullptr)
        {
            continue;
        }

        const auto first_space = value.find_first_of(" \t");
        if (first_space != std::string_view::npos)
        {
            codec->fmtp = std::string(trim(value.substr(first_space + 1)));
        }
    }

    const auto rtcp_feedback_attributes = media.find_attributes(k_attribute_rtcp_feedback);
    for (const auto* attribute : rtcp_feedback_attributes)
    {
        const std::string_view value = attribute->value;
        const auto fields = split_whitespace(value);
        if (fields.size() < 2)
        {
            return make_error("invalid rtcp-fb attribute");
        }

        const auto feedback_start = value.find_first_of(" \t");
        if (feedback_start == std::string_view::npos)
        {
            return make_error("invalid rtcp-fb attribute");
        }

        const std::string feedback(trim(value.substr(feedback_start + 1)));

        if (fields[0] == "*")
        {
            for (auto& codec : summary.codecs)
            {
                codec.rtcp_feedback.push_back(feedback);
            }

            continue;
        }

        auto payload_type = parse_payload_type(fields[0]);
        if (!payload_type)
        {
            return make_error(payload_type.error());
        }

        auto* codec = find_codec_by_payload_type(summary.codecs, *payload_type);
        if (codec != nullptr)
        {
            codec->rtcp_feedback.push_back(feedback);
        }
    }

    if (summary.codecs.empty())
    {
        return make_error("media has no rtpmap codecs");
    }

    return {};
}

std::optional<uint32_t> parse_u32_text(std::string_view value)
{
    value = trim(value);

    if (value.empty())
    {
        return std::nullopt;
    }

    uint32_t result = 0;

    const auto parse_result = std::from_chars(value.data(), value.data() + value.size(), result);

    if (parse_result.ec != std::errc() || parse_result.ptr != value.data() + value.size())
    {
        return std::nullopt;
    }

    return result;
}

bool equals_ignore_case_ascii(std::string_view left, std::string_view right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        const char left_char = static_cast<char>(std::tolower(static_cast<unsigned char>(left[index])));

        const char right_char = static_cast<char>(std::tolower(static_cast<unsigned char>(right[index])));

        if (left_char != right_char)
        {
            return false;
        }
    }

    return true;
}

std::expected<void, std::string> parse_ssrc_groups(media_summary& summary, const media_description& media)
{
    const auto attributes = media.find_attributes("ssrc-group");

    for (const auto* attribute : attributes)
    {
        const std::string_view value = attribute->value;

        const auto fields = split_whitespace(value);

        if (fields.size() < 2)
        {
            continue;
        }

        ssrc_group_summary group;

        group.semantics = std::string(fields[0]);

        for (std::size_t index = 1; index < fields.size(); ++index)
        {
            const std::optional<uint32_t> ssrc = parse_u32_text(fields[index]);

            if (!ssrc.has_value() || *ssrc == 0)
            {
                return make_error("invalid ssrc-group ssrc");
            }

            group.ssrcs.push_back(*ssrc);
        }

        if (!group.semantics.empty() && !group.ssrcs.empty())
        {
            summary.ssrc_groups.push_back(std::move(group));
        }
    }

    return {};
}
std::expected<void, std::string> parse_header_extensions(media_summary& summary, const media_description& media)
{
    const auto ext_map_attributes = media.find_attributes(k_attribute_ext_map);

    for (const auto* attribute : ext_map_attributes)
    {
        rtp_header_extension extension;
        if (!extension.parse_attribute_value(attribute->value))
        {
            return make_error("invalid extmap attribute");
        }

        summary.header_extensions.push_back(std::move(extension));
    }

    return {};
}

std::expected<media_summary, std::string> parse_media_summary(const session_description& description, const media_description& media)
{
    media_summary summary;

    summary.kind = media.media_name.media;

    if (summary.kind != "audio" && summary.kind != "video")
    {
        return make_error("unsupported media type");
    }

    auto mid = media.find_attribute_value(k_attribute_mid);
    if (!mid.has_value() || mid->empty())
    {
        return make_error("media missing mid");
    }

    summary.mid = mid.value();

    auto direction = parse_media_direction_from_attributes(media);
    if (!direction)
    {
        return make_error(direction.error());
    }

    summary.direction = *direction;
    summary.rtcp_mux = media_has_attribute(media, k_attribute_rtcp_mux);

    if (!summary.rtcp_mux)
    {
        return make_error("media missing rtcp-mux");
    }

    const auto ice_ufrag = find_effective_attribute_value(description, media, k_attribute_ice_ufrag);
    if (!ice_ufrag.has_value() || ice_ufrag->empty())
    {
        return make_error("media missing ice-ufrag");
    }

    const auto ice_pwd = find_effective_attribute_value(description, media, k_attribute_ice_pwd);
    if (!ice_pwd.has_value() || ice_pwd->empty())
    {
        return make_error("media missing ice-pwd");
    }

    const auto fingerprint = find_effective_attribute_value(description, media, k_attribute_fingerprint);
    if (!fingerprint.has_value() || fingerprint->empty())
    {
        return make_error("media missing fingerprint");
    }

    const auto setup = find_effective_attribute_value(description, media, k_attribute_setup);
    if (!setup.has_value() || setup->empty())
    {
        return make_error("media missing setup");
    }

    auto payload_result = parse_payload_types(summary, media);
    if (!payload_result)
    {
        return make_error(payload_result.error());
    }

    auto codec_result = parse_codecs(summary, media);
    if (!codec_result)
    {
        return make_error(codec_result.error());
    }

    auto header_extension_result = parse_header_extensions(summary, media);

    if (!header_extension_result)
    {
        return make_error(header_extension_result.error());
    }

    auto ssrc_group_result = parse_ssrc_groups(summary, media);

    if (!ssrc_group_result)
    {
        return make_error(ssrc_group_result.error());
    }

    return summary;
}

std::expected<void, std::string> validate_bundle_mids(const webrtc_offer_summary& summary)
{
    if (summary.bundle_mids.empty())
    {
        return make_error("missing BUNDLE group");
    }

    for (const auto& media : summary.media)
    {
        bool found = false;

        for (const auto& mid : summary.bundle_mids)
        {
            if (mid == media.mid)
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            return make_error("media mid not present in BUNDLE group");
        }
    }

    return {};
}
}    // namespace

webrtc_offer_summary_result extract_webrtc_offer_summary(const session_description& description)
{
    webrtc_offer_summary summary;

    summary.bundle_mids = parse_bundle_mids(description);

    auto ice_ufrag = find_first_attribute_value(description, k_attribute_ice_ufrag);
    if (!ice_ufrag.has_value() || ice_ufrag->empty())
    {
        return make_error("missing ice-ufrag");
    }

    summary.ice_ufrag = ice_ufrag.value();

    auto ice_pwd = find_first_attribute_value(description, k_attribute_ice_pwd);
    if (!ice_pwd.has_value() || ice_pwd->empty())
    {
        return make_error("missing ice-pwd");
    }

    summary.ice_pwd = ice_pwd.value();

    auto fingerprint = find_first_attribute_value(description, k_attribute_fingerprint);
    if (!fingerprint.has_value() || fingerprint->empty())
    {
        return make_error("missing fingerprint");
    }

    auto parsed_fingerprint = parse_fingerprint(fingerprint.value());
    if (!parsed_fingerprint)
    {
        return make_error(parsed_fingerprint.error());
    }

    summary.fingerprint = *parsed_fingerprint;

    auto setup = find_first_attribute_value(description, k_attribute_setup);
    if (!setup.has_value() || setup->empty())
    {
        return make_error("missing setup");
    }

    auto parsed_setup = parse_setup(setup.value());
    if (!parsed_setup)
    {
        return make_error(parsed_setup.error());
    }

    summary.setup = *parsed_setup;

    for (const auto& media : description.media_descriptions)
    {
        if (media.media_name.media != "audio" && media.media_name.media != "video")
        {
            continue;
        }

        auto parsed_media = parse_media_summary(description, media);
        if (!parsed_media)
        {
            return make_error(parsed_media.error());
        }

        summary.media.push_back(std::move(*parsed_media));
    }

    if (summary.media.empty())
    {
        return make_error("missing audio or video media");
    }

    auto bundle_result = validate_bundle_mids(summary);
    if (!bundle_result)
    {
        return make_error(bundle_result.error());
    }

    return summary;
}
std::optional<uint32_t> find_rtx_primary_ssrc(const media_summary& media, uint32_t repair_ssrc)
{
    if (repair_ssrc == 0)
    {
        return std::nullopt;
    }

    for (const auto& group : media.ssrc_groups)
    {
        if (!equals_ignore_case_ascii(group.semantics, "FID"))
        {
            continue;
        }

        if (group.ssrcs.size() < 2)
        {
            continue;
        }

        if (group.ssrcs[1] == repair_ssrc)
        {
            return group.ssrcs[0];
        }
    }

    return std::nullopt;
}

std::optional<uint32_t> find_rtx_repair_ssrc(const media_summary& media, uint32_t primary_ssrc)
{
    if (primary_ssrc == 0)
    {
        return std::nullopt;
    }

    for (const auto& group : media.ssrc_groups)
    {
        if (!equals_ignore_case_ascii(group.semantics, "FID"))
        {
            continue;
        }

        if (group.ssrcs.size() < 2)
        {
            continue;
        }

        if (group.ssrcs[0] == primary_ssrc)
        {
            return group.ssrcs[1];
        }
    }

    return std::nullopt;
}

bool media_ssrc_is_rtx_repair(const media_summary& media, uint32_t ssrc) { return find_rtx_primary_ssrc(media, ssrc).has_value(); }
}    // namespace webrtc::sdp
