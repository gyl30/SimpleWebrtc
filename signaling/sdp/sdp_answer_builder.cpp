#include "signaling/sdp/sdp_answer_builder.h"

#include <algorithm>
#include <cstddef>
#include <expected>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "signaling/sdp/sdp_formatter.h"
#include "signaling/sdp/sdp_codec_negotiator.h"

namespace webrtc::sdp
{
namespace
{
using validation_result = std::expected<void, std::string>;
struct built_sdp_answer
{
    session_description description;
    std::vector<int> accepted_mline_indexes;
};

using sdp_answer_result = std::expected<built_sdp_answer, std::string>;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool contains_whitespace(std::string_view value)
{
    for (const auto ch : value)
    {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

validation_result validate_token(std::string_view value, std::string_view name)
{
    if (value.empty())
    {
        std::string message(name);
        message.append(" is empty");
        return std::unexpected(std::move(message));
    }

    if (contains_whitespace(value))
    {
        std::string message(name);
        message.append(" contains whitespace");
        return std::unexpected(std::move(message));
    }

    return {};
}

std::string make_candidate_field_name(std::string_view prefix, std::string_view field)
{
    std::string value;

    value.reserve(prefix.size() + field.size() + 1);

    value.append(prefix);
    value.push_back(' ');
    value.append(field);

    return value;
}

validation_result validate_candidate_options(const sdp_answer_options& options)
{
    if (options.local_candidate_addresses.empty())
    {
        return make_error("local candidate address list is empty");
    }

    if (options.local_candidate_port == 0)
    {
        return make_error("local candidate port is zero");
    }

    for (std::size_t index = 0; index < options.local_candidate_addresses.size(); ++index)
    {
        std::string prefix("local candidate ");

        prefix.append(std::to_string(index));

        auto result = validate_token(options.local_candidate_addresses[index], make_candidate_field_name(prefix, "address"));

        if (!result)
        {
            return std::unexpected(result.error());
        }
    }

    return {};
}

validation_result validate_options(const sdp_answer_options& options)
{
    auto ice_ufrag_result = validate_token(options.local_ice_ufrag, "local ice-ufrag");

    if (!ice_ufrag_result)
    {
        return std::unexpected(ice_ufrag_result.error());
    }

    auto ice_pwd_result = validate_token(options.local_ice_pwd, "local ice-pwd");

    if (!ice_pwd_result)
    {
        return std::unexpected(ice_pwd_result.error());
    }

    auto fingerprint_algorithm_result = validate_token(options.local_fingerprint.algorithm, "local fingerprint algorithm");

    if (!fingerprint_algorithm_result)
    {
        return std::unexpected(fingerprint_algorithm_result.error());
    }

    auto fingerprint_value_result = validate_token(options.local_fingerprint.value, "local fingerprint value");

    if (!fingerprint_value_result)
    {
        return std::unexpected(fingerprint_value_result.error());
    }

    auto stream_id_result = validate_token(options.local_stream_id, "local stream id");

    if (!stream_id_result)
    {
        return std::unexpected(stream_id_result.error());
    }

    return validate_candidate_options(options);
}

std::string make_bundle_group_value(const webrtc_offer_summary& offer, std::span<const int> accepted_mline_indexes)
{
    std::string value = "BUNDLE";

    for (const int mline_index : accepted_mline_indexes)
    {
        value.push_back(' ');
        value.append(offer.media[static_cast<std::size_t>(mline_index)].mid);
    }

    return value;
}
bool is_answer_media_rejected(const media_description& media) { return media.media_name.port == 0; }

media_direction make_answer_direction(bool is_whep, const media_summary& media)
{
    if (media.direction == media_direction::inactive)
    {
        return media_direction::inactive;
    }

    return is_whep ? media_direction::send_only : media_direction::recv_only;
}
bool media_can_send(const media_summary& media)
{
    return media.direction == media_direction::send_only || media.direction == media_direction::send_recv;
}

bool media_can_receive(const media_summary& media)
{
    return media.direction == media_direction::recv_only || media.direction == media_direction::send_recv;
}

std::size_t count_send_capable_media_by_kind(const webrtc_offer_summary& offer, std::string_view kind)
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

std::size_t count_receive_capable_media_by_kind(const webrtc_offer_summary& offer, std::string_view kind)
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
std::optional<std::size_t> find_receive_capable_media_ordinal_by_kind(const webrtc_offer_summary& offer, const media_summary& target_media)
{
    std::size_t ordinal = 0;

    for (const auto& media : offer.media)
    {
        if (media.kind != target_media.kind)
        {
            continue;
        }

        if (!media_can_receive(media))
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

const media_summary* find_send_capable_media_by_kind_ordinal(const webrtc_offer_summary& offer, std::string_view kind, std::size_t target_ordinal)
{
    std::size_t ordinal = 0;

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

        if (ordinal == target_ordinal)
        {
            return &media;
        }

        ordinal += 1;
    }

    return nullptr;
}

const media_summary* find_matching_publisher_media_impl(const media_summary& subscriber_media,
                                                         const webrtc_offer_summary& subscriber_offer,
                                                         const webrtc_offer_summary& publisher_offer)
{
    if (!media_can_receive(subscriber_media))
    {
        return nullptr;
    }

    const std::optional<std::size_t> subscriber_ordinal = find_receive_capable_media_ordinal_by_kind(subscriber_offer, subscriber_media);

    if (!subscriber_ordinal.has_value())
    {
        return nullptr;
    }

    const std::size_t subscriber_kind_count = count_receive_capable_media_by_kind(subscriber_offer, subscriber_media.kind);

    const std::size_t publisher_kind_count = count_send_capable_media_by_kind(publisher_offer, subscriber_media.kind);

    /*
     * Publisher and subscriber MID namespaces are independent.
     * Match media sections by kind-local ordinal so SDP answer
     * generation and runtime RTP mapping use the same authority.
     */
    if (subscriber_kind_count == 0 || subscriber_kind_count != publisher_kind_count)
    {
        return nullptr;
    }

    return find_send_capable_media_by_kind_ordinal(publisher_offer, subscriber_media.kind, *subscriber_ordinal);
}

constexpr std::string_view k_rtp_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";

constexpr std::string_view k_rtp_stream_id_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";

constexpr std::string_view k_repaired_rtp_stream_id_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

constexpr std::string_view k_transport_wide_cc_extension_uri = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

constexpr std::string_view k_absolute_send_time_extension_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

constexpr std::string_view k_audio_level_extension_uri = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

bool media_has_header_extension_uri(const media_summary& media, std::string_view uri)
{
    for (const auto& extension : media.header_extensions)
    {
        if (extension.uri == uri)
        {
            return true;
        }
    }

    return false;
}
bool media_has_answerable_send_rid(const media_summary& media, std::string_view rid)
{
    if (rid.empty())
    {
        return false;
    }

    for (const auto& current : media.rids)
    {
        if (current.id != rid)
        {
            continue;
        }

        return current.direction == "send" || current.direction == "sendrecv";
    }

    return false;
}
bool media_has_answerable_recv_rid(const media_summary& media, std::string_view rid)
{
    if (rid.empty())
    {
        return false;
    }

    for (const auto& current : media.rids)
    {
        if (current.id != rid)
        {
            continue;
        }

        return current.direction == "recv" || current.direction == "sendrecv";
    }

    return false;
}

void push_attribute(std::vector<sdp_attribute>& attributes, std::string_view key, std::string_view value)
{
    attributes.push_back(make_attribute(std::string(key), std::string(value)));
}

void push_property_attribute(std::vector<sdp_attribute>& attributes, std::string_view key)
{
    attributes.push_back(make_property_attribute(std::string(key)));
}

std::string make_fingerprint_value(const fingerprint_info& fingerprint)
{
    std::string value;
    value.reserve(fingerprint.algorithm.size() + fingerprint.value.size() + 1);

    value.append(fingerprint.algorithm);
    value.push_back(' ');
    value.append(fingerprint.value);

    return value;
}

std::string make_rtp_map_value(const codec_info& codec)
{
    std::string value;
    value.reserve(codec.name.size() + codec.encoding_parameters.size() + 32);

    value.append(std::to_string(codec.payload_type));
    value.push_back(' ');
    value.append(codec.name);
    value.push_back('/');
    value.append(std::to_string(codec.clock_rate));

    if (!codec.encoding_parameters.empty())
    {
        value.push_back('/');
        value.append(codec.encoding_parameters);
    }

    return value;
}

std::string make_fmtp_value(const codec_info& codec)
{
    std::string value;
    value.reserve(codec.fmtp.size() + 8);

    value.append(std::to_string(codec.payload_type));
    value.push_back(' ');
    value.append(codec.fmtp);

    return value;
}

std::string make_rtcp_feedback_value(const codec_info& codec, std::string_view feedback)
{
    std::string value;
    value.reserve(feedback.size() + 8);

    value.append(std::to_string(codec.payload_type));
    value.push_back(' ');
    value.append(feedback);

    return value;
}
std::string normalize_rtcp_feedback_value(std::string_view feedback)
{
    std::vector<std::string> tokens;
    boost::algorithm::split(tokens,
                            feedback,
                            boost::algorithm::is_space(),
                            boost::algorithm::token_compress_on);
    std::erase(tokens, std::string{});

    for (auto& token : tokens)
    {
        boost::algorithm::to_lower(token);
    }

    return boost::algorithm::join(tokens, " ");
}

bool rtcp_feedback_is_supported_for_answer_media(std::string_view media_kind,
                                                 std::string_view feedback,
                                                 bool generic_nack_enabled,
                                                 bool transport_cc_enabled)
{
    const std::string normalized_feedback = normalize_rtcp_feedback_value(feedback);

    if (transport_cc_enabled && normalized_feedback == "transport-cc")
    {
        return media_kind == "audio" || media_kind == "video";
    }

    if (media_kind != "video")
    {
        return false;
    }

    return (generic_nack_enabled && normalized_feedback == "nack") ||
           normalized_feedback == "nack pli" || normalized_feedback == "ccm fir";
}

std::string make_rtcp_feedback_deduplication_key(const codec_info& codec, std::string_view normalized_feedback)
{
    std::string key;

    key.reserve(normalized_feedback.size() + 8);

    key.append(std::to_string(codec.payload_type));

    key.push_back('|');

    key.append(normalized_feedback);

    return key;
}

bool is_supported_answer_header_extension_uri(std::string_view kind, std::string_view uri, bool transport_cc_enabled)
{
    if (transport_cc_enabled && uri == k_transport_wide_cc_extension_uri)
    {
        return kind == "audio" || kind == "video";
    }

    if (uri == k_rtp_mid_extension_uri)
    {
        return kind == "audio" || kind == "video";
    }

    if (uri == k_rtp_stream_id_extension_uri)
    {
        return kind == "video";
    }

    if (uri == k_audio_level_extension_uri)
    {
        return kind == "audio";
    }

    return false;
}

std::string make_extmap_value(const rtp_header_extension& extension)
{
    std::string value;

    value.reserve(extension.uri.size() + 16);

    value.append(std::to_string(extension.id));

    value.push_back(' ');

    value.append(extension.uri);

    return value;
}
bool rtp_header_extension_id_requires_two_byte(int id) { return id >= 15 && id <= 255; }

std::vector<rtp_header_extension> select_answer_header_extensions_impl(
    const media_summary& media,
    const media_summary* forwarded_publisher_media,
    bool transport_cc_enabled)
{
    std::vector<rtp_header_extension> selected_extensions;

    for (const auto& extension : media.header_extensions)
    {
        if (extension.id <= 0 || extension.id > 255)
        {
            continue;
        }

        if (extension.uri.empty())
        {
            continue;
        }

        if (!is_supported_answer_header_extension_uri(media.kind, extension.uri, transport_cc_enabled))
        {
            continue;
        }

        if (forwarded_publisher_media != nullptr &&
            extension.uri != k_transport_wide_cc_extension_uri &&
            !media_has_header_extension_uri(*forwarded_publisher_media, extension.uri))
        {
            continue;
        }

        if (rtp_header_extension_id_requires_two_byte(extension.id) && !media.extmap_allow_mixed)
        {
            continue;
        }

        selected_extensions.push_back(extension);
    }

    return selected_extensions;
}

void append_header_extension_attributes(media_description& answer_media,
                                        const media_summary& media,
                                        const media_summary* forwarded_publisher_media,
                                        bool transport_cc_enabled)
{
    const auto selected_extensions = select_answer_header_extensions_impl(
        media, forwarded_publisher_media, transport_cc_enabled);

    bool answer_needs_extmap_allow_mixed = false;

    for (const auto& extension : selected_extensions)
    {
        if (rtp_header_extension_id_requires_two_byte(extension.id))
        {
            answer_needs_extmap_allow_mixed = true;
        }

        push_attribute(answer_media.attributes, "extmap", make_extmap_value(extension));
    }

    if (answer_needs_extmap_allow_mixed)
    {
        push_property_attribute(answer_media.attributes, k_attribute_ext_map_allow_mixed);
    }
}

std::vector<std::string> collect_answerable_whep_simulcast_rids(const media_summary& subscriber_media, const media_summary& publisher_media)
{
    std::vector<std::string> rids;

    if (subscriber_media.kind != "video" || publisher_media.kind != "video")
    {
        return rids;
    }

    if (!subscriber_media.simulcast.has_value() || !publisher_media.simulcast.has_value())
    {
        return rids;
    }

    if (subscriber_media.simulcast->recv_rids.empty() || publisher_media.simulcast->send_rids.empty())
    {
        return rids;
    }

    if (!media_has_header_extension_uri(subscriber_media, k_rtp_stream_id_extension_uri) ||
        !media_has_header_extension_uri(publisher_media, k_rtp_stream_id_extension_uri))
    {
        return rids;
    }

    for (const auto& rid : subscriber_media.simulcast->recv_rids)
    {
        if (!media_has_answerable_recv_rid(subscriber_media, rid))
        {
            continue;
        }

        if (!media_has_answerable_send_rid(publisher_media, rid))
        {
            continue;
        }

        if (std::ranges::find(publisher_media.simulcast->send_rids, rid) == publisher_media.simulcast->send_rids.end())
        {
            continue;
        }

        if (std::ranges::find(rids, rid) != rids.end())
        {
            continue;
        }

        rids.push_back(rid);
    }

    return rids;
}
void append_whep_simulcast_send_attributes(media_description& answer_media,
                                           const media_summary& subscriber_media,
                                           const media_summary* forwarded_publisher_media)
{
    if (forwarded_publisher_media == nullptr)
    {
        return;
    }

    const std::vector<std::string> rids = collect_answerable_whep_simulcast_rids(subscriber_media, *forwarded_publisher_media);

    if (rids.empty())
    {
        return;
    }

    for (const auto& rid : rids)
    {
        std::string rid_value;

        rid_value.reserve(rid.size() + 8);

        rid_value.append(rid);

        rid_value.append(" send");

        push_attribute(answer_media.attributes, "rid", rid_value);
    }

    const std::string joined_rids = boost::algorithm::join(rids, ";");
    std::string simulcast_value;
    simulcast_value.reserve(joined_rids.size() + 8);

    simulcast_value.append("send ");

    simulcast_value.append(joined_rids);

    push_attribute(answer_media.attributes, "simulcast", simulcast_value);
}

std::vector<std::string> collect_answerable_whip_simulcast_rids(const media_summary& media)
{
    std::vector<std::string> rids;

    if (media.kind != "video")
    {
        return rids;
    }

    if (!media.simulcast.has_value())
    {
        return rids;
    }

    if (media.simulcast->send_rids.empty())
    {
        return rids;
    }

    if (!media_has_header_extension_uri(media, k_rtp_stream_id_extension_uri))
    {
        return rids;
    }

    for (const auto& rid : media.simulcast->send_rids)
    {
        if (!media_has_answerable_send_rid(media, rid))
        {
            continue;
        }

        if (std::ranges::find(rids, rid) != rids.end())
        {
            continue;
        }

        rids.push_back(rid);
    }

    return rids;
}

void append_whip_simulcast_receive_attributes(media_description& answer_media, const media_summary& media)
{
    const std::vector<std::string> rids = collect_answerable_whip_simulcast_rids(media);

    if (rids.empty())
    {
        return;
    }

    for (const auto& rid : rids)
    {
        std::string rid_value;

        rid_value.reserve(rid.size() + 8);

        rid_value.append(rid);

        rid_value.append(" recv");

        push_attribute(answer_media.attributes, "rid", rid_value);
    }

    const std::string joined_rids = boost::algorithm::join(rids, ";");
    std::string simulcast_value;
    simulcast_value.reserve(joined_rids.size() + 8);

    simulcast_value.append("recv ");

    simulcast_value.append(joined_rids);

    push_attribute(answer_media.attributes, "simulcast", simulcast_value);
}

std::string make_msid_value(const sdp_answer_options& options, const media_summary& media)
{
    std::string value;
    value.reserve(options.local_stream_id.size() + media.kind.size() + media.mid.size() + 8);

    value.append(options.local_stream_id);
    value.push_back(' ');
    value.append(media.kind);
    value.push_back('-');
    value.append(media.mid);

    return value;
}

std::string make_answer_msid_value(bool is_whep,
                                   const sdp_answer_options& options,
                                   const media_summary& media,
                                   const media_summary* forwarded_publisher_media)
{
    if (is_whep)
    {
        return make_msid_value(options, *forwarded_publisher_media);
    }

    return make_msid_value(options, media);
}

bool answer_media_source_matches_media(const sdp_answer_media_source& source, const media_summary& media)
{
    if (source.ssrc == 0)
    {
        return false;
    }

    if (source.mid != media.mid)
    {
        return false;
    }

    if (source.kind != media.kind)
    {
        return false;
    }

    return true;
}

const sdp_answer_media_source* find_unique_answer_media_source_by_kind(const sdp_answer_options& options, std::string_view kind)
{
    const sdp_answer_media_source* matched_source = nullptr;

    for (const auto& source : options.media_sources)
    {
        if (source.ssrc == 0)
        {
            continue;
        }

        if (source.kind != kind)
        {
            continue;
        }

        if (matched_source != nullptr)
        {
            return nullptr;
        }

        matched_source = &source;
    }

    return matched_source;
}

const sdp_answer_media_source* find_answer_media_source(const sdp_answer_options& options,
                                                        const media_summary& media,
                                                        const media_summary* forwarded_publisher_media)
{
    for (const auto& source : options.media_sources)
    {
        if (answer_media_source_matches_media(source, media))
        {
            return &source;
        }
    }

    if (forwarded_publisher_media != nullptr)
    {
        for (const auto& source : options.media_sources)
        {
            if (answer_media_source_matches_media(source, *forwarded_publisher_media))
            {
                return &source;
            }
        }
    }

    return find_unique_answer_media_source_by_kind(options, media.kind);
}

void append_media_source_attributes(media_description& answer_media,
                                    const sdp_answer_media_source& source,
                                    std::string_view answer_msid_value,
                                    bool include_rtx_repair_source)
{
    const std::string primary_ssrc = std::to_string(source.ssrc);

    push_attribute(answer_media.attributes, "ssrc", primary_ssrc + " cname:" + source.cname);

    std::string primary_msid_value;

    primary_msid_value.reserve(primary_ssrc.size() + answer_msid_value.size() + 7);

    primary_msid_value.append(primary_ssrc);
    primary_msid_value.append(" msid:");
    primary_msid_value.append(answer_msid_value);

    push_attribute(answer_media.attributes, "ssrc", std::move(primary_msid_value));

    if (!include_rtx_repair_source || source.rtx_repair_ssrc == 0)
    {
        return;
    }

    const std::string repair_ssrc = std::to_string(source.rtx_repair_ssrc);

    push_attribute(answer_media.attributes, k_attribute_ssrc_group, "FID " + primary_ssrc + " " + repair_ssrc);

    push_attribute(answer_media.attributes, "ssrc", repair_ssrc + " cname:" + source.cname);

    std::string repair_msid_value;

    repair_msid_value.reserve(repair_ssrc.size() + answer_msid_value.size() + 7);

    repair_msid_value.append(repair_ssrc);
    repair_msid_value.append(" msid:");
    repair_msid_value.append(answer_msid_value);

    push_attribute(answer_media.attributes, "ssrc", std::move(repair_msid_value));
}

void remove_unimplemented_answer_codecs(std::vector<codec_info>& codecs)
{
    std::erase_if(codecs, [](const codec_info& codec) { return boost::algorithm::iequals(codec.name, "rtx"); });
}

bool parse_fmtp_payload_type(std::string_view value, uint16_t& payload_type)
{
    value = boost::algorithm::trim_copy_if(value, boost::algorithm::is_any_of(" \t"));

    if (value.empty())
    {
        return false;
    }

    uint32_t parsed = 0;

    for (const char ch : value)
    {
        if (ch < '0' || ch > '9')
        {
            return false;
        }

        parsed = (parsed * 10U) + static_cast<uint32_t>(ch - '0');

        if (parsed > 127U)
        {
            return false;
        }
    }

    payload_type = static_cast<uint16_t>(parsed);

    return true;
}

bool find_rtx_apt_payload_type(const codec_info& codec, uint16_t& apt_payload_type)
{
    std::vector<std::string_view> parts;
    boost::algorithm::split(parts, codec.fmtp, boost::algorithm::is_any_of(";"));

    for (const std::string_view part : parts)
    {
        const std::string_view item = boost::algorithm::trim_copy_if(part, boost::algorithm::is_any_of(" \t"));
        const std::size_t equal_position = item.find('=');

        if (equal_position != std::string_view::npos)
        {
            const std::string_view key =
                boost::algorithm::trim_copy_if(item.substr(0, equal_position), boost::algorithm::is_any_of(" \t"));
            const std::string_view value =
                boost::algorithm::trim_copy_if(item.substr(equal_position + 1), boost::algorithm::is_any_of(" \t"));

            if (boost::algorithm::iequals(key, "apt"))
            {
                return parse_fmtp_payload_type(value, apt_payload_type);
            }
        }

    }

    return false;
}

bool answer_primary_payload_type_exists(const std::vector<codec_info>& codecs, uint16_t payload_type)
{
    for (const auto& codec : codecs)
    {
        if (codec.payload_type != payload_type)
        {
            continue;
        }

        if (boost::algorithm::iequals(codec.name, "rtx"))
        {
            continue;
        }

        return true;
    }

    return false;
}

bool answer_codecs_include_usable_rtx(const std::vector<codec_info>& codecs)
{
    for (const auto& codec : codecs)
    {
        if (!boost::algorithm::iequals(codec.name, "rtx"))
        {
            continue;
        }

        if (codec.clock_rate != 90000)
        {
            continue;
        }

        uint16_t apt_payload_type = 0;

        if (!find_rtx_apt_payload_type(codec, apt_payload_type))
        {
            continue;
        }

        if (!answer_primary_payload_type_exists(codecs, apt_payload_type))
        {
            continue;
        }

        return true;
    }

    return false;
}

std::string make_candidate_value(std::string_view address, uint16_t port, std::size_t index)
{
    std::string value;

    value.reserve(address.size() + 64);

    value.append(std::to_string(index + 1));
    value.append(" 1 udp ");
    value.append(std::to_string(2130706431U - static_cast<uint32_t>(index)));
    value.push_back(' ');
    value.append(address);
    value.push_back(' ');
    value.append(std::to_string(port));
    value.append(" typ host");

    return value;
}

void append_codec_attributes(media_description& answer_media,
                             std::string_view media_kind,
                             const std::vector<codec_info>& codecs,
                             bool generic_nack_enabled,
                             bool transport_cc_enabled)
{
    std::set<std::string> emitted_rtcp_feedback;

    for (const auto& codec : codecs)
    {
        push_attribute(answer_media.attributes, k_attribute_rtp_map, make_rtp_map_value(codec));

        if (!codec.fmtp.empty())
        {
            push_attribute(answer_media.attributes, k_attribute_fmtp, make_fmtp_value(codec));
        }

        for (const auto& feedback : codec.rtcp_feedback)
        {
            if (!rtcp_feedback_is_supported_for_answer_media(
                    media_kind, feedback, generic_nack_enabled, transport_cc_enabled))
            {
                continue;
            }

            const std::string normalized_feedback = normalize_rtcp_feedback_value(feedback);

            const std::string deduplication_key = make_rtcp_feedback_deduplication_key(codec, normalized_feedback);

            if (!emitted_rtcp_feedback.insert(deduplication_key).second)
            {
                continue;
            }

            push_attribute(answer_media.attributes, k_attribute_rtcp_feedback, make_rtcp_feedback_value(codec, normalized_feedback));
        }
    }
}

void append_media_timing_attributes(media_description& answer_media, const media_summary& media)
{
    if (media.kind != "audio")
    {
        return;
    }

    if (media.ptime.has_value())
    {
        push_attribute(answer_media.attributes, "ptime", std::to_string(*media.ptime));
    }

    if (media.maxptime.has_value())
    {
        push_attribute(answer_media.attributes, "maxptime", std::to_string(*media.maxptime));
    }
}

void append_ice_candidate_attributes(media_description& answer_media, const sdp_answer_options& options)
{
    for (std::size_t index = 0; index < options.local_candidate_addresses.size(); ++index)
    {
        push_attribute(answer_media.attributes,
                       "candidate",
                       make_candidate_value(options.local_candidate_addresses[index], options.local_candidate_port, index));
    }

    push_property_attribute(answer_media.attributes, "end-of-candidates");
}
media_description make_rejected_answer_media(const media_summary& media)
{
    media_description answer_media;

    answer_media.media_name.media = media.kind;

    answer_media.media_name.port = 0;

    for (uint16_t payload_type : media.payload_types)
    {
        answer_media.media_name.formats.push_back(std::to_string(payload_type));
    }

    if (answer_media.media_name.formats.empty())
    {
        answer_media.media_name.formats.push_back("0");
    }

    answer_media.connection_address = "0.0.0.0";

    push_attribute(answer_media.attributes, k_attribute_mid, media.mid);

    push_property_attribute(answer_media.attributes, to_string(media_direction::inactive));

    if (media.rtcp_mux)
    {
        push_property_attribute(answer_media.attributes, k_attribute_rtcp_mux);
    }

    if (media.rtcp_rsize)
    {
        push_property_attribute(answer_media.attributes, k_attribute_rtcp_rsize);
    }

    return answer_media;
}
bool media_offers_transport_cc(const media_summary& media,
                               const std::vector<codec_info>& codecs,
                               bool remote_sends_rtp)
{
    const bool has_extension = std::ranges::any_of(
        media.header_extensions,
        [remote_sends_rtp](const rtp_header_extension& extension)
        {
            const bool direction_matches =
                extension.direction == media_direction::unknown ||
                extension.direction == media_direction::send_recv ||
                extension.direction == (remote_sends_rtp ? media_direction::send_only : media_direction::recv_only);
            return direction_matches &&
                   extension.uri == k_transport_wide_cc_extension_uri;
        });

    if (!has_extension)
    {
        return false;
    }

    return std::ranges::any_of(
        codecs,
        [](const codec_info& codec)
        {
            return std::ranges::any_of(
                codec.rtcp_feedback,
                [](const std::string& feedback)
                { return normalize_rtcp_feedback_value(feedback) == "transport-cc"; });
        });
}

std::expected<media_description, std::string> make_answer_media(const sdp_answer_options& options,
                                                                const media_summary& media,
                                                                const webrtc_offer_summary& offer,
                                                                const webrtc_offer_summary* whep_publisher_offer)
{
    const bool is_whep = whep_publisher_offer != nullptr;
    const media_direction answer_direction = make_answer_direction(is_whep, media);

    if (answer_direction == media_direction::inactive)
    {
        return make_rejected_answer_media(media);
    }
    std::vector<codec_info> codecs;
    const media_summary* forwarded_publisher_media = nullptr;
    if (is_whep)
    {
        const media_summary* publisher_media = find_whep_forwarded_publisher_media(media, offer, *whep_publisher_offer);
        if (publisher_media == nullptr)
        {
            return make_rejected_answer_media(media);
        }
        forwarded_publisher_media = publisher_media;

        auto codec_result = negotiate_codecs(media, *publisher_media);
        if (!codec_result)
        {
            return make_rejected_answer_media(media);
        }

        codecs = std::move(*codec_result);

        if (codecs.empty())
        {
            return make_rejected_answer_media(media);
        }
    }
    else
    {
        auto codec_result = negotiate_codecs(media);

        if (!codec_result)
        {
            return make_rejected_answer_media(media);
        }

        codecs = std::move(*codec_result);
        remove_unimplemented_answer_codecs(codecs);

        if (codecs.empty())
        {
            return make_rejected_answer_media(media);
        }
    }

    const bool transport_cc_enabled = media_offers_transport_cc(media, codecs, !is_whep);

    media_description answer_media;

    answer_media.media_name.media = media.kind;
    answer_media.media_name.port = 9;
    for (const auto& codec : codecs)
    {
        answer_media.media_name.formats.push_back(std::to_string(codec.payload_type));
    }

    answer_media.connection_address = options.local_candidate_addresses.front();

    push_attribute(answer_media.attributes, k_attribute_mid, media.mid);

    push_property_attribute(answer_media.attributes, to_string(answer_direction));

    push_property_attribute(answer_media.attributes, k_attribute_rtcp_mux);

    if (media.rtcp_rsize)
    {
        push_property_attribute(answer_media.attributes, k_attribute_rtcp_rsize);
    }

    append_header_extension_attributes(
        answer_media, media, forwarded_publisher_media, transport_cc_enabled);

    if (!is_whep && answer_direction == media_direction::recv_only)
    {
        append_whip_simulcast_receive_attributes(answer_media, media);
    }
    if (is_whep && answer_direction == media_direction::send_only)
    {
        append_whep_simulcast_send_attributes(answer_media, media, forwarded_publisher_media);
    }

    append_codec_attributes(
        answer_media, media.kind, codecs, is_whep, transport_cc_enabled);

    append_media_timing_attributes(answer_media, media);

    append_ice_candidate_attributes(answer_media, options);

    if (answer_direction == media_direction::send_only || answer_direction == media_direction::send_recv)
    {
        const std::string answer_msid_value = make_answer_msid_value(is_whep, options, media, forwarded_publisher_media);

        push_attribute(answer_media.attributes, "msid", answer_msid_value);

        if (is_whep)
        {
            const auto* media_source = find_answer_media_source(options, media, forwarded_publisher_media);

            if (media_source != nullptr)
            {
                append_media_source_attributes(answer_media, *media_source, answer_msid_value, answer_codecs_include_usable_rtx(codecs));
            }
        }
    }

    return answer_media;
}

std::expected<std::vector<int>, std::string> append_answer_media_descriptions(
    session_description& answer,
    const sdp_answer_options& options,
    const webrtc_offer_summary& offer,
    const webrtc_offer_summary* whep_publisher_offer)
{
    std::vector<int> accepted_mline_indexes;

    accepted_mline_indexes.reserve(offer.media.size());

    for (std::size_t index = 0; index < offer.media.size(); ++index)
    {
        const auto& media = offer.media[index];

        auto answer_media = make_answer_media(options, media, offer, whep_publisher_offer);
        if (!answer_media)
        {
            return std::unexpected(answer_media.error());
        }

        if (!is_answer_media_rejected(*answer_media))
        {
            if (index > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            {
                return make_error("accepted offer media mline index is too large");
            }

            accepted_mline_indexes.push_back(static_cast<int>(index));
        }

        answer.media_descriptions.push_back(std::move(*answer_media));
    }

    if (accepted_mline_indexes.empty())
    {
        return whep_publisher_offer == nullptr ? make_error("whip answer has no supported publisher media")
                                               : make_error("whep answer has no compatible publisher media");
    }

    return accepted_mline_indexes;
}

sdp_answer_result build_answer(const webrtc_offer_summary& offer,
                               const sdp_answer_options& options,
                               const webrtc_offer_summary* whep_publisher_offer)
{
    auto options_result = validate_options(options);
    if (!options_result)
    {
        return std::unexpected(options_result.error());
    }

    built_sdp_answer answer;

    answer.description.session_id = options.session_id;
    answer.description.session_version = options.session_version;

    push_property_attribute(answer.description.attributes, "ice-lite");
    push_attribute(answer.description.attributes, "ice-options", "trickle");
    push_attribute(answer.description.attributes, k_attribute_ice_ufrag, options.local_ice_ufrag);
    push_attribute(answer.description.attributes, k_attribute_ice_pwd, options.local_ice_pwd);
    push_attribute(answer.description.attributes, k_attribute_fingerprint, make_fingerprint_value(options.local_fingerprint));
    push_attribute(answer.description.attributes, k_attribute_setup, "passive");
    push_attribute(answer.description.attributes, "msid-semantic", "WMS *");

    auto accepted_media = append_answer_media_descriptions(answer.description, options, offer, whep_publisher_offer);
    if (!accepted_media)
    {
        return std::unexpected(accepted_media.error());
    }

    answer.accepted_mline_indexes = std::move(*accepted_media);

    answer.description.attributes.insert(
        answer.description.attributes.begin(),
        make_attribute(std::string(k_attribute_group), make_bundle_group_value(offer, answer.accepted_mline_indexes)));

    return answer;
}

sdp_answer_text_result build_answer_sdp(const webrtc_offer_summary& offer,
                                        const sdp_answer_options& options,
                                        const webrtc_offer_summary* whep_publisher_offer)
{
    auto answer = build_answer(offer, options, whep_publisher_offer);
    if (!answer)
    {
        return std::unexpected(answer.error());
    }

    generated_sdp_answer_text result;
    result.sdp = format_session_description(answer->description);
    result.accepted_mline_indexes = std::move(answer->accepted_mline_indexes);

    return result;
}
}    // namespace

const media_summary* find_whep_forwarded_publisher_media(const media_summary& subscriber_media,
                                                         const webrtc_offer_summary& subscriber_offer,
                                                         const webrtc_offer_summary& publisher_offer)
{
    return find_matching_publisher_media_impl(subscriber_media, subscriber_offer, publisher_offer);
}

std::vector<rtp_header_extension> select_whep_answer_header_extensions(const media_summary& subscriber_media,
                                                                       const media_summary& publisher_media)
{
    auto codecs = negotiate_codecs(subscriber_media, publisher_media);

    if (!codecs)
    {
        return {};
    }

    return select_answer_header_extensions_impl(
        subscriber_media,
        &publisher_media,
        media_offers_transport_cc(subscriber_media, *codecs, false));
}

sdp_answer_text_result build_whip_answer_sdp(const webrtc_offer_summary& offer, const sdp_answer_options& options)
{
    return build_answer_sdp(offer, options, nullptr);
}

sdp_answer_text_result build_whep_answer_sdp(const webrtc_offer_summary& subscriber_offer,
                                             const webrtc_offer_summary& publisher_offer,
                                             const sdp_answer_options& options)
{
    return build_answer_sdp(subscriber_offer, options, &publisher_offer);
}

}    // namespace webrtc::sdp
