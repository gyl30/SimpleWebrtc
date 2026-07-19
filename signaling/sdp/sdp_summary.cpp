#include "signaling/sdp/sdp_summary.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <expected>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace webrtc::sdp
{
namespace
{
bool media_has_rtp_header_extension_uri(const media_summary& media, std::string_view uri);
bool media_has_rid(const media_summary& media, std::string_view rid);
std::expected<void, std::string> validate_media_summary_identity(const media_summary& media);

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }
std::unexpected<std::string> make_media_restart_error(const media_summary& media, std::string_view message)
{
    std::string error;

    error.reserve(media.mid.size() + message.size() + 16);

    error.append("media mid ");

    error.append(media.mid);

    error.push_back(' ');

    error.append(message);

    return std::unexpected(std::move(error));
}

bool fingerprint_equal(const fingerprint_info& left, const fingerprint_info& right)
{
    return left.algorithm == right.algorithm && left.value == right.value;
}

bool codec_equal(const codec_info& left, const codec_info& right)
{
    return left.payload_type == right.payload_type && left.name == right.name && left.clock_rate == right.clock_rate &&
           left.encoding_parameters == right.encoding_parameters && left.fmtp == right.fmtp && left.rtcp_feedback == right.rtcp_feedback;
}

bool payload_type_list_equal_ignoring_order(const std::vector<uint16_t>& left, const std::vector<uint16_t>& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    std::vector<uint16_t> sorted_left = left;
    std::vector<uint16_t> sorted_right = right;

    std::sort(sorted_left.begin(), sorted_left.end());
    std::sort(sorted_right.begin(), sorted_right.end());

    return sorted_left == sorted_right;
}

bool codec_list_equal_ignoring_order(const std::vector<codec_info>& left, const std::vector<codec_info>& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (const auto& left_codec : left)
    {
        const auto right_codec =
            std::find_if(right.begin(), right.end(), [&left_codec](const codec_info& item) { return item.payload_type == left_codec.payload_type; });

        if (right_codec == right.end())
        {
            return false;
        }

        if (!codec_equal(left_codec, *right_codec))
        {
            return false;
        }
    }

    return true;
}

bool header_extension_equal(const rtp_header_extension& left, const rtp_header_extension& right)
{
    return left.id == right.id && left.direction == right.direction && left.uri == right.uri &&
           left.extension_attributes == right.extension_attributes;
}

bool header_extension_list_equal(const std::vector<rtp_header_extension>& left, const std::vector<rtp_header_extension>& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        if (!header_extension_equal(left[index], right[index]))
        {
            return false;
        }
    }

    return true;
}

bool ssrc_group_equal(const ssrc_group_summary& left, const ssrc_group_summary& right)
{
    return left.semantics == right.semantics && left.ssrcs == right.ssrcs;
}

bool ssrc_group_list_equal(const std::vector<ssrc_group_summary>& left, const std::vector<ssrc_group_summary>& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        if (!ssrc_group_equal(left[index], right[index]))
        {
            return false;
        }
    }

    return true;
}

bool rid_equal(const rid_summary& left, const rid_summary& right) { return left.id == right.id && left.direction == right.direction; }

bool rid_list_equal(const std::vector<rid_summary>& left, const std::vector<rid_summary>& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        if (!rid_equal(left[index], right[index]))
        {
            return false;
        }
    }

    return true;
}

bool simulcast_equal(const std::optional<simulcast_summary>& left, const std::optional<simulcast_summary>& right)
{
    if (left.has_value() != right.has_value())
    {
        return false;
    }

    if (!left.has_value())
    {
        return true;
    }

    return left->send_rids == right->send_rids && left->recv_rids == right->recv_rids;
}

bool msid_equal(const msid_summary& left, const msid_summary& right) { return left.stream_id == right.stream_id && left.track_id == right.track_id; }

bool msid_list_equal(const std::vector<msid_summary>& left, const std::vector<msid_summary>& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        if (!msid_equal(left[index], right[index]))
        {
            return false;
        }
    }

    return true;
}

std::expected<void, std::string> validate_media_restart_compatibility(const media_summary& previous_media,
                                                                      const media_summary& next_media,
                                                                      bool allow_header_extension_changes)
{
    if (previous_media.mid != next_media.mid)
    {
        return make_media_restart_error(previous_media, "mid changed");
    }

    if (previous_media.kind != next_media.kind)
    {
        return make_media_restart_error(previous_media, "kind changed");
    }

    if (previous_media.direction != next_media.direction)
    {
        return make_media_restart_error(previous_media, "direction changed");
    }

    if (previous_media.rtcp_mux != next_media.rtcp_mux)
    {
        return make_media_restart_error(previous_media, "rtcp mux changed");
    }

    if (previous_media.rtcp_rsize != next_media.rtcp_rsize)
    {
        return make_media_restart_error(previous_media, "rtcp rsize changed");
    }

    if (previous_media.ptime != next_media.ptime)
    {
        return make_media_restart_error(previous_media, "ptime changed");
    }

    if (previous_media.maxptime != next_media.maxptime)
    {
        return make_media_restart_error(previous_media, "maxptime changed");
    }

    if (!payload_type_list_equal_ignoring_order(previous_media.payload_types, next_media.payload_types))
    {
        return make_media_restart_error(previous_media, "payload types changed");
    }

    if (!codec_list_equal_ignoring_order(previous_media.codecs, next_media.codecs))
    {
        return make_media_restart_error(previous_media, "codecs changed");
    }

    if (!allow_header_extension_changes && !header_extension_list_equal(previous_media.header_extensions, next_media.header_extensions))
    {
        return make_media_restart_error(previous_media, "rtp header extensions changed");
    }

    if (!ssrc_group_list_equal(previous_media.ssrc_groups, next_media.ssrc_groups))
    {
        return make_media_restart_error(previous_media, "ssrc groups changed");
    }

    if (!rid_list_equal(previous_media.rids, next_media.rids))
    {
        return make_media_restart_error(previous_media, "rids changed");
    }

    if (!simulcast_equal(previous_media.simulcast, next_media.simulcast))
    {
        return make_media_restart_error(previous_media, "simulcast changed");
    }

    if (!msid_list_equal(previous_media.msids, next_media.msids))
    {
        return make_media_restart_error(previous_media, "msid changed");
    }

    return {};
}
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
bool session_has_attribute(const session_description& description, std::string_view key) { return !description.find_attributes(key).empty(); }

bool effective_property_attribute_exists(const session_description& description, const media_description& media, std::string_view key)
{
    if (media_has_attribute(media, key))
    {
        return true;
    }

    return session_has_attribute(description, key);
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
std::expected<void, std::string> parse_media_timing_attributes(media_summary& summary, const media_description& media)
{
    const auto ptime_attributes = media.find_attributes("ptime");

    if (ptime_attributes.size() > 1)
    {
        return make_error("media has multiple ptime attributes");
    }

    if (!ptime_attributes.empty())
    {
        const std::optional<uint32_t> ptime = parse_u32_text(ptime_attributes.front()->value);

        if (!ptime.has_value() || *ptime == 0 || *ptime > 1000)
        {
            return make_error("media ptime is invalid");
        }

        summary.ptime = *ptime;
    }

    const auto maxptime_attributes = media.find_attributes("maxptime");

    if (maxptime_attributes.size() > 1)
    {
        return make_error("media has multiple maxptime attributes");
    }

    if (!maxptime_attributes.empty())
    {
        const std::optional<uint32_t> maxptime = parse_u32_text(maxptime_attributes.front()->value);

        if (!maxptime.has_value() || *maxptime == 0 || *maxptime > 1000)
        {
            return make_error("media maxptime is invalid");
        }

        summary.maxptime = *maxptime;
    }

    if (summary.ptime.has_value() && summary.maxptime.has_value() && *summary.ptime > *summary.maxptime)
    {
        return make_error("media ptime is greater than maxptime");
    }

    return {};
}

std::string lower_ascii_copy(std::string_view value)
{
    std::string result;

    result.reserve(value.size());

    for (char ch : value)
    {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }

    return result;
}

std::vector<std::string> split_sdp_tokens(std::string_view value)
{
    std::vector<std::string> tokens;

    std::size_t offset = 0;

    while (offset < value.size())
    {
        while (offset < value.size() && std::isspace(static_cast<unsigned char>(value[offset])) != 0)
        {
            offset += 1;
        }

        if (offset >= value.size())
        {
            break;
        }

        const std::size_t begin = offset;

        while (offset < value.size() && std::isspace(static_cast<unsigned char>(value[offset])) == 0)
        {
            offset += 1;
        }

        tokens.push_back(std::string(value.substr(begin, offset - begin)));
    }

    return tokens;
}

std::expected<rid_summary, std::string> parse_rid_summary(std::string_view value)
{
    const std::vector<std::string> tokens = split_sdp_tokens(value);

    if (tokens.size() < 2)
    {
        return make_error("rid attribute is incomplete");
    }

    rid_summary result;

    result.id = tokens[0];

    result.direction = lower_ascii_copy(tokens[1]);

    if (result.id.empty())
    {
        return make_error("rid id is empty");
    }

    if (result.direction != "send" && result.direction != "recv")
    {
        return make_error("rid direction is invalid");
    }

    return result;
}

std::expected<std::vector<rid_summary>, std::string> parse_rid_summaries(const media_description& media)
{
    std::vector<rid_summary> rids;

    std::set<std::string> ids;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key != "rid")
        {
            continue;
        }

        auto rid = parse_rid_summary(attribute.value);

        if (!rid)
        {
            return std::unexpected(rid.error());
        }

        if (!ids.insert(rid->id).second)
        {
            return make_error("rid id is duplicated");
        }

        rids.push_back(std::move(*rid));
    }

    return rids;
}

std::vector<std::string> parse_simulcast_rid_list(std::string_view value)
{
    std::vector<std::string> rids;

    std::string current;

    for (char ch : value)
    {
        if (ch == ';' || ch == ',')
        {
            if (!current.empty())
            {
                rids.push_back(current);

                current.clear();
            }

            continue;
        }

        if (ch == '~')
        {
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty())
    {
        rids.push_back(current);
    }

    return rids;
}

std::expected<std::optional<simulcast_summary>, std::string> parse_simulcast_summary(const media_description& media)
{
    std::optional<simulcast_summary> result;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key != "simulcast")
        {
            continue;
        }

        if (result.has_value())
        {
            return make_error("simulcast attribute is duplicated");
        }

        const std::vector<std::string> tokens = split_sdp_tokens(attribute.value);

        if (tokens.size() < 2 || (tokens.size() % 2U) != 0)
        {
            return make_error("simulcast attribute is invalid");
        }

        simulcast_summary summary;

        for (std::size_t index = 0; index < tokens.size(); index += 2)
        {
            const std::string direction = lower_ascii_copy(tokens[index]);

            const std::vector<std::string> rids = parse_simulcast_rid_list(tokens[index + 1]);

            if (direction == "send")
            {
                summary.send_rids.insert(summary.send_rids.end(), rids.begin(), rids.end());

                continue;
            }

            if (direction == "recv")
            {
                summary.recv_rids.insert(summary.recv_rids.end(), rids.begin(), rids.end());

                continue;
            }

            return make_error("simulcast direction is invalid");
        }

        result = std::move(summary);
    }

    return result;
}

std::expected<msid_summary, std::string> parse_msid_summary(std::string_view value)
{
    const std::vector<std::string> tokens = split_sdp_tokens(value);

    if (tokens.empty())
    {
        return make_error("msid attribute is empty");
    }

    if (tokens[0] == "-")
    {
        return make_error("msid stream id is invalid");
    }

    msid_summary result;

    result.stream_id = tokens[0];

    if (tokens.size() >= 2)
    {
        result.track_id = tokens[1];
    }

    return result;
}

std::expected<std::vector<msid_summary>, std::string> parse_msid_summaries(const media_description& media)
{
    std::vector<msid_summary> msids;

    std::set<std::string> values;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key != "msid")
        {
            continue;
        }

        if (!values.insert(attribute.value).second)
        {
            return make_error("msid attribute is duplicated");
        }

        auto msid = parse_msid_summary(attribute.value);

        if (!msid)
        {
            return std::unexpected(msid.error());
        }

        msids.push_back(std::move(*msid));
    }

    return msids;
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
    summary.rtcp_rsize = media_has_attribute(media, k_attribute_rtcp_rsize);
    summary.extmap_allow_mixed = effective_property_attribute_exists(description, media, k_attribute_ext_map_allow_mixed);
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

    auto media_timing_result = parse_media_timing_attributes(summary, media);

    if (!media_timing_result)
    {
        return make_error(media_timing_result.error());
    }

    auto ssrc_group_result = parse_ssrc_groups(summary, media);

    if (!ssrc_group_result)
    {
        return make_error(ssrc_group_result.error());
    }

    auto rid_result = parse_rid_summaries(media);

    if (!rid_result)
    {
        return std::unexpected(rid_result.error());
    }

    summary.rids = std::move(*rid_result);

    auto simulcast_result = parse_simulcast_summary(media);

    if (!simulcast_result)
    {
        return std::unexpected(simulcast_result.error());
    }

    summary.simulcast = std::move(*simulcast_result);

    auto msid_result = parse_msid_summaries(media);

    if (!msid_result)
    {
        return std::unexpected(msid_result.error());
    }

    summary.msids = std::move(*msid_result);

    auto identity_result = validate_media_summary_identity(summary);

    if (!identity_result)
    {
        return std::unexpected(identity_result.error());
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

namespace
{
bool offer_ice_credentials_are_complete(const webrtc_offer_summary& offer) { return !offer.ice_ufrag.empty() && !offer.ice_pwd.empty(); }

bool offer_ice_credentials_equal(const webrtc_offer_summary& left, const webrtc_offer_summary& right)
{
    return left.ice_ufrag == right.ice_ufrag && left.ice_pwd == right.ice_pwd;
}
}    // namespace

bool offer_has_ice_restart(const webrtc_offer_summary& previous_offer, const webrtc_offer_summary& next_offer)
{
    if (!offer_ice_credentials_are_complete(previous_offer))
    {
        return false;
    }

    if (!offer_ice_credentials_are_complete(next_offer))
    {
        return false;
    }

    return !offer_ice_credentials_equal(previous_offer, next_offer);
}

namespace
{
std::expected<void, std::string> validate_ice_restart_offer_compatibility_impl(const webrtc_offer_summary& previous_offer,
                                                                               const webrtc_offer_summary& next_offer,
                                                                               bool allow_header_extension_changes)
{
    if (!offer_has_ice_restart(previous_offer, next_offer))
    {
        return make_error("offer does not contain ice restart");
    }

    if (!fingerprint_equal(previous_offer.fingerprint, next_offer.fingerprint))
    {
        return make_error("dtls fingerprint changed");
    }

    if (previous_offer.setup != next_offer.setup)
    {
        return make_error("dtls setup changed");
    }

    if (previous_offer.bundle_mids != next_offer.bundle_mids)
    {
        return make_error("bundle mids changed");
    }

    if (previous_offer.media.size() != next_offer.media.size())
    {
        return make_error("media count changed");
    }

    for (std::size_t index = 0; index < previous_offer.media.size(); ++index)
    {
        auto media_result = validate_media_restart_compatibility(
            previous_offer.media[index], next_offer.media[index], allow_header_extension_changes);

        if (!media_result)
        {
            return std::unexpected(media_result.error());
        }
    }

    return {};
}
}    // namespace

std::expected<void, std::string> validate_ice_restart_offer_compatibility(const webrtc_offer_summary& previous_offer,
                                                                          const webrtc_offer_summary& next_offer)
{
    return validate_ice_restart_offer_compatibility_impl(previous_offer, next_offer, false);
}

std::expected<void, std::string> validate_ice_restart_offer_compatibility_ignoring_header_extensions(
    const webrtc_offer_summary& previous_offer, const webrtc_offer_summary& next_offer)
{
    return validate_ice_restart_offer_compatibility_impl(previous_offer, next_offer, true);
}

std::string offer_ice_credentials_to_string(const webrtc_offer_summary& offer)
{
    std::string result;

    result.reserve(offer.ice_ufrag.size() + 32);

    result.append("ufrag=");

    result.append(offer.ice_ufrag);

    result.append(" pwd=");

    result.append(offer.ice_pwd.empty() ? "empty" : "***");

    return result;
}

namespace
{
bool media_has_rtp_header_extension_uri(const media_summary& media, std::string_view uri)
{
    if (uri.empty())
    {
        return false;
    }

    for (const auto& extension : media.header_extensions)
    {
        if (extension.uri == uri)
        {
            return true;
        }
    }

    return false;
}
}    // namespace

bool media_has_rtx_codec(const media_summary& media)
{
    for (const auto& codec : media.codecs)
    {
        if (equals_ignore_case_ascii(codec.name, "rtx"))
        {
            return true;
        }
    }

    return false;
}
namespace
{
bool media_has_rid(const media_summary& media, std::string_view rid)
{
    if (rid.empty())
    {
        return false;
    }

    for (const auto& current_rid : media.rids)
    {
        if (current_rid.id == rid)
        {
            return true;
        }
    }

    return false;
}

std::expected<void, std::string> validate_media_summary_identity(const media_summary& media)
{
    if (media.mid.empty())
    {
        return make_error("media summary mid is empty");
    }

    std::unordered_set<int32_t> extension_ids;
    std::unordered_set<std::string> extension_uris;

    for (const auto& extension : media.header_extensions)
    {
        if (extension.id <= 0 || extension.id > 255)
        {
            return make_error("media summary extmap id is out of range");
        }

        if (!extension_ids.insert(extension.id).second)
        {
            return make_error("media summary extmap id is duplicated");
        }

        if (!extension_uris.insert(extension.uri).second)
        {
            return make_error("media summary extmap uri is duplicated");
        }
    }

    const bool has_rid_extension = media_has_rtp_header_extension_uri(media, k_rtp_header_extension_sdes_rtp_stream_id_uri);

    const bool has_repaired_rid_extension = media_has_rtp_header_extension_uri(media, k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri);

    if (has_repaired_rid_extension && !has_rid_extension)
    {
        return make_error("media summary repaired-rid extmap requires rid extmap");
    }

    if (has_repaired_rid_extension && !media_has_rtx_codec(media))
    {
        return make_error("media summary repaired-rid extmap requires rtx codec");
    }

    if (media.simulcast.has_value())
    {
        for (const auto& rid : media.simulcast->send_rids)
        {
            if (!media_has_rid(media, rid))
            {
                return make_error("media summary simulcast send references unknown rid");
            }
        }

        for (const auto& rid : media.simulcast->recv_rids)
        {
            if (!media_has_rid(media, rid))
            {
                return make_error("media summary simulcast recv references unknown rid");
            }
        }
    }

    std::set<std::string> msid_values;

    for (const auto& msid : media.msids)
    {
        if (msid.stream_id.empty() || msid.stream_id == "-")
        {
            return make_error("media summary msid stream id is invalid");
        }

        std::string value = msid.stream_id;

        value.push_back('\n');

        value.append(msid.track_id);

        if (!msid_values.insert(value).second)
        {
            return make_error("media summary msid is duplicated");
        }
    }

    return {};
}
}    // namespace

}    // namespace webrtc::sdp
