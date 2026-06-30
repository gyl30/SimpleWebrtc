#include "signaling/sdp/sdp_answer_builder.h"

#include <algorithm>
#include <cstddef>
#include <expected>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "signaling/sdp/sdp_formatter.h"
#include "signaling/sdp/sdp_codec_negotiator.h"

namespace webrtc::sdp
{
namespace
{
enum class answer_endpoint_role
{
    whip,
    whep,
};

using validation_result = std::expected<void, std::string>;
using media_direction_result = std::expected<media_direction, std::string>;
using setup_text_result = std::expected<std::string, std::string>;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_media_error(std::string_view prefix, const media_summary& media, std::string_view suffix)
{
    std::string message;
    message.reserve(prefix.size() + media.mid.size() + suffix.size() + 16);
    message.append(prefix);
    message.append(" media mid ");
    message.append(media.mid);
    message.push_back(' ');
    message.append(suffix);
    return std::unexpected(std::move(message));
}

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

sdp_ice_candidate_options make_legacy_candidate_options(const sdp_answer_options& options)
{
    sdp_ice_candidate_options candidate;

    candidate.foundation = options.local_candidate_foundation;
    candidate.component = options.local_candidate_component;
    candidate.transport = options.local_candidate_transport;
    candidate.priority = options.local_candidate_priority;
    candidate.address = options.local_candidate_address;
    candidate.port = options.local_candidate_port;
    candidate.type = options.local_candidate_type;

    return candidate;
}

validation_result validate_candidate_options(const sdp_ice_candidate_options& candidate, std::string_view prefix)
{
    auto foundation_result = validate_token(candidate.foundation, make_candidate_field_name(prefix, "foundation"));

    if (!foundation_result)
    {
        return std::unexpected(foundation_result.error());
    }

    if (candidate.component == 0)
    {
        return make_error(make_candidate_field_name(prefix, "component is zero"));
    }

    auto transport_result = validate_token(candidate.transport, make_candidate_field_name(prefix, "transport"));

    if (!transport_result)
    {
        return std::unexpected(transport_result.error());
    }

    if (candidate.priority == 0)
    {
        return make_error(make_candidate_field_name(prefix, "priority is zero"));
    }

    auto address_result = validate_token(candidate.address, make_candidate_field_name(prefix, "address"));

    if (!address_result)
    {
        return std::unexpected(address_result.error());
    }

    if (candidate.port == 0)
    {
        return make_error(make_candidate_field_name(prefix, "port is zero"));
    }

    auto type_result = validate_token(candidate.type, make_candidate_field_name(prefix, "type"));

    if (!type_result)
    {
        return std::unexpected(type_result.error());
    }

    return {};
}

validation_result validate_candidate_options(const sdp_answer_options& options)
{
    if (!options.include_host_candidate)
    {
        return {};
    }

    if (options.local_candidates.empty())
    {
        return validate_candidate_options(make_legacy_candidate_options(options), "local candidate");
    }

    for (std::size_t index = 0; index < options.local_candidates.size(); ++index)
    {
        std::string prefix("local candidate ");

        prefix.append(std::to_string(index));

        auto result = validate_candidate_options(options.local_candidates[index], prefix);

        if (!result)
        {
            return std::unexpected(result.error());
        }
    }

    return {};
}

validation_result validate_options(const sdp_answer_options& options)
{
    auto origin_username_result = validate_token(options.origin_username, "origin username");

    if (!origin_username_result)
    {
        return std::unexpected(origin_username_result.error());
    }

    auto network_type_result = validate_token(options.network_type, "network type");

    if (!network_type_result)
    {
        return std::unexpected(network_type_result.error());
    }

    auto address_type_result = validate_token(options.address_type, "address type");

    if (!address_type_result)
    {
        return std::unexpected(address_type_result.error());
    }

    auto unicast_address_result = validate_token(options.unicast_address, "unicast address");

    if (!unicast_address_result)
    {
        return std::unexpected(unicast_address_result.error());
    }

    auto media_address_result = validate_token(options.media_address, "media address");

    if (!media_address_result)
    {
        return std::unexpected(media_address_result.error());
    }

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

    auto candidate_result = validate_candidate_options(options);

    if (!candidate_result)
    {
        return std::unexpected(candidate_result.error());
    }

    switch (options.local_setup)
    {
        case dtls_connection_role::active:
        case dtls_connection_role::passive:
            break;

        case dtls_connection_role::actpass:
            return make_error("local setup must not be actpass");

        case dtls_connection_role::holdconn:
            return make_error("local setup must not be holdconn");

        case dtls_connection_role::unknown:
            return make_error("local setup must not be unknown");
    }

    return {};
}

validation_result validate_offer_for_answer(const webrtc_offer_summary& offer)
{
    if (offer.ice_ufrag.empty())
    {
        return make_error("offer ice-ufrag is empty");
    }

    if (offer.ice_pwd.empty())
    {
        return make_error("offer ice-pwd is empty");
    }

    if (offer.fingerprint.algorithm.empty())
    {
        return make_error("offer fingerprint algorithm is empty");
    }

    if (offer.fingerprint.value.empty())
    {
        return make_error("offer fingerprint value is empty");
    }

    if (offer.setup != dtls_connection_role::actpass)
    {
        return make_error("offer setup must be actpass");
    }

    if (offer.bundle_mids.empty())
    {
        return make_error("offer has no bundle mids");
    }

    if (offer.media.empty())
    {
        return make_error("offer has no media");
    }

    for (const auto& media : offer.media)
    {
        auto mid_result = validate_token(media.mid, "media mid");
        if (!mid_result)
        {
            return std::unexpected(mid_result.error());
        }

        auto kind_result = validate_token(media.kind, "media kind");
        if (!kind_result)
        {
            return std::unexpected(kind_result.error());
        }

        if (media.kind != "audio" && media.kind != "video")
        {
            return make_media_error("offer", media, "has unsupported kind");
        }

        if (!media.rtcp_mux)
        {
            return make_media_error("offer", media, "does not enable rtcp-mux");
        }

        if (media.codecs.empty())
        {
            return make_media_error("offer", media, "has no codecs");
        }
    }

    return {};
}

std::optional<std::string> find_answer_media_mid(const media_description& media)
{
    const std::optional<std::string> mid = media.find_attribute_value(k_attribute_mid);

    if (!mid.has_value() || mid->empty())
    {
        return std::nullopt;
    }

    return mid;
}

std::expected<std::string, std::string> make_bundle_group_value(const session_description& answer)
{
    std::string value = "BUNDLE";

    std::size_t count = 0;

    for (const auto& media : answer.media_descriptions)
    {
        if (media.media_name.port.value == 0)
        {
            continue;
        }

        const std::optional<std::string> mid = find_answer_media_mid(media);

        if (!mid.has_value())
        {
            return make_error("accepted answer media is missing mid");
        }

        value.push_back(' ');

        value.append(*mid);

        count += 1;
    }

    if (count == 0)
    {
        return make_error("bundle group has no accepted media mids");
    }

    return value;
}
std::vector<std::string> split_space_separated_tokens(std::string_view value)
{
    std::vector<std::string> tokens;

    std::size_t position = 0;

    while (position < value.size())
    {
        position = value.find_first_not_of(" \t", position);

        if (position == std::string_view::npos)
        {
            break;
        }

        const std::size_t end = value.find_first_of(" \t", position);

        if (end == std::string_view::npos)
        {
            tokens.emplace_back(value.substr(position));

            break;
        }

        tokens.emplace_back(value.substr(position, end - position));

        position = end + 1;
    }

    return tokens;
}

bool string_vector_contains(const std::vector<std::string>& values, std::string_view value)
{
    for (const auto& current : values)
    {
        if (current == value)
        {
            return true;
        }
    }

    return false;
}

bool is_answer_media_rejected(const media_description& media) { return media.media_name.port.value == 0; }
std::expected<std::vector<std::string>, std::string> collect_accepted_answer_media_mids(const session_description& answer)
{
    std::vector<std::string> accepted_mids;

    for (const auto& media : answer.media_descriptions)
    {
        if (is_answer_media_rejected(media))
        {
            continue;
        }

        const std::optional<std::string> mid = find_answer_media_mid(media);

        if (!mid.has_value())
        {
            return make_error("accepted answer media is missing mid");
        }

        if (string_vector_contains(accepted_mids, *mid))
        {
            std::string message = "accepted answer media mid duplicated mid=";

            message.append(*mid);

            return std::unexpected(std::move(message));
        }

        accepted_mids.push_back(*mid);
    }

    if (accepted_mids.empty())
    {
        return make_error("answer has no accepted media mids");
    }

    return accepted_mids;
}

std::expected<std::vector<std::string>, std::string> collect_answer_bundle_mids(const session_description& answer)
{
    const auto group_attributes = answer.find_attributes(k_attribute_group);

    std::optional<std::vector<std::string>> bundle_mids;

    for (const auto* attribute : group_attributes)
    {
        if (attribute == nullptr)
        {
            continue;
        }

        const std::vector<std::string> tokens = split_space_separated_tokens(attribute->value);

        if (tokens.empty())
        {
            return make_error("answer group attribute is empty");
        }

        if (tokens.front() != "BUNDLE")
        {
            continue;
        }

        if (bundle_mids.has_value())
        {
            return make_error("answer has multiple bundle groups");
        }

        if (tokens.size() == 1)
        {
            return make_error("answer bundle group has no mids");
        }

        std::vector<std::string> current_bundle_mids;

        current_bundle_mids.reserve(tokens.size() - 1);

        for (std::size_t index = 1; index < tokens.size(); ++index)
        {
            const std::string& mid = tokens[index];

            if (mid.empty())
            {
                return make_error("answer bundle mid is empty");
            }

            if (string_vector_contains(current_bundle_mids, mid))
            {
                std::string message = "answer bundle mid duplicated mid=";

                message.append(mid);

                return std::unexpected(std::move(message));
            }

            current_bundle_mids.push_back(mid);
        }

        bundle_mids = std::move(current_bundle_mids);
    }

    if (!bundle_mids.has_value())
    {
        return make_error("answer bundle group is missing");
    }

    return *bundle_mids;
}
struct answer_media_mid_state
{
    std::vector<std::string> all_mids;

    std::vector<std::string> accepted_mids;

    std::vector<std::string> rejected_mids;
};

std::expected<answer_media_mid_state, std::string> collect_answer_media_mid_state(const session_description& answer)
{
    answer_media_mid_state state;

    if (answer.media_descriptions.empty())
    {
        return make_error("answer has no media descriptions");
    }

    for (const auto& media : answer.media_descriptions)
    {
        const std::optional<std::string> mid = find_answer_media_mid(media);

        if (!mid.has_value())
        {
            return make_error("answer media is missing mid");
        }

        if (string_vector_contains(state.all_mids, *mid))
        {
            std::string message = "answer media mid duplicated mid=";

            message.append(*mid);

            return std::unexpected(std::move(message));
        }

        state.all_mids.push_back(*mid);

        if (is_answer_media_rejected(media))
        {
            state.rejected_mids.push_back(*mid);
        }
        else
        {
            state.accepted_mids.push_back(*mid);
        }
    }

    if (state.accepted_mids.empty())
    {
        return make_error("answer has no accepted media mids");
    }

    return state;
}

std::expected<void, std::string> validate_rejected_mids_are_not_bundled(const std::vector<std::string>& rejected_mids,
                                                                        const std::vector<std::string>& bundle_mids)
{
    for (const auto& rejected_mid : rejected_mids)
    {
        if (string_vector_contains(bundle_mids, rejected_mid))
        {
            std::string message = "answer bundle contains rejected mid=";

            message.append(rejected_mid);

            return std::unexpected(std::move(message));
        }
    }

    return {};
}

std::expected<void, std::string> validate_answer_bundle_group(const session_description& answer)
{
    auto media_mid_state = collect_answer_media_mid_state(answer);

    if (!media_mid_state)
    {
        return std::unexpected(media_mid_state.error());
    }

    auto bundle_mids = collect_answer_bundle_mids(answer);

    if (!bundle_mids)
    {
        return std::unexpected(bundle_mids.error());
    }

    auto rejected_bundle_result = validate_rejected_mids_are_not_bundled(media_mid_state->rejected_mids, *bundle_mids);

    if (!rejected_bundle_result)
    {
        return std::unexpected(rejected_bundle_result.error());
    }

    if (media_mid_state->accepted_mids.size() != bundle_mids->size())
    {
        return make_error("answer bundle mids and accepted media mids size mismatch");
    }

    for (std::size_t index = 0; index < media_mid_state->accepted_mids.size(); ++index)
    {
        const std::string& accepted_mid = media_mid_state->accepted_mids[index];

        const std::string& bundle_mid = (*bundle_mids)[index];

        if (!string_vector_contains(media_mid_state->accepted_mids, bundle_mid))
        {
            std::string message = "answer bundle mid is not accepted mid=";

            message.append(bundle_mid);

            return std::unexpected(std::move(message));
        }

        if (accepted_mid != bundle_mid)
        {
            std::string message = "answer bundle mid order mismatch expected=";

            message.append(accepted_mid);

            message.append(" actual=");

            message.append(bundle_mid);

            return std::unexpected(std::move(message));
        }
    }

    return {};
}

setup_text_result format_setup_role(dtls_connection_role role)
{
    switch (role)
    {
        case dtls_connection_role::active:
            return std::string("active");

        case dtls_connection_role::passive:
            return std::string("passive");

        case dtls_connection_role::actpass:
            return make_error("answer setup must not be actpass");

        case dtls_connection_role::holdconn:
            return make_error("answer setup must not be holdconn");

        case dtls_connection_role::unknown:
            return make_error("answer setup is unknown");
    }

    return make_error("unsupported answer setup");
}

std::expected<std::string, std::string> format_direction(media_direction direction)
{
    switch (direction)
    {
        case media_direction::send_recv:
            return std::string(k_attribute_send_recv);

        case media_direction::send_only:
            return std::string(k_attribute_send_only);

        case media_direction::recv_only:
            return std::string(k_attribute_recv_only);

        case media_direction::inactive:
            return std::string(k_attribute_inactive);

        case media_direction::unknown:
            return make_error("media direction is unknown");
    }

    return make_error("unsupported media direction");
}

media_direction_result make_answer_direction(answer_endpoint_role role, const media_summary& media)
{
    if (role == answer_endpoint_role::whip)
    {
        switch (media.direction)
        {
            case media_direction::send_only:
            case media_direction::send_recv:
                return media_direction::recv_only;

            case media_direction::inactive:
                return media_direction::inactive;

            case media_direction::recv_only:
                return make_media_error("whip", media, "must not be recvonly");

            case media_direction::unknown:
                return make_media_error("whip", media, "has unknown direction");
        }
    }

    if (role == answer_endpoint_role::whep)
    {
        switch (media.direction)
        {
            case media_direction::recv_only:
            case media_direction::send_recv:
                return media_direction::send_only;

            case media_direction::inactive:
                return media_direction::inactive;

            case media_direction::send_only:
                return make_media_error("whep", media, "must not be sendonly");

            case media_direction::unknown:
                return make_media_error("whep", media, "has unknown direction");
        }
    }

    return make_error("unsupported answer endpoint role");
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

const media_summary* find_matching_publisher_media(const media_summary& subscriber_media,
                                                   const webrtc_offer_summary& subscriber_offer,
                                                   const webrtc_offer_summary& publisher_offer)
{
    if (!media_can_receive(subscriber_media))
    {
        return nullptr;
    }

    for (const auto& publisher_media : publisher_offer.media)
    {
        if (publisher_media.mid == subscriber_media.mid && publisher_media.kind == subscriber_media.kind && media_can_send(publisher_media))
        {
            return &publisher_media;
        }
    }

    const std::optional<std::size_t> subscriber_ordinal = find_receive_capable_media_ordinal_by_kind(subscriber_offer, subscriber_media);

    if (!subscriber_ordinal.has_value())
    {
        return nullptr;
    }

    const std::size_t publisher_kind_count = count_send_capable_media_by_kind(publisher_offer, subscriber_media.kind);

    const std::size_t subscriber_kind_count = count_receive_capable_media_by_kind(subscriber_offer, subscriber_media.kind);

    if (publisher_kind_count != subscriber_kind_count)
    {
        return nullptr;
    }

    return find_send_capable_media_by_kind_ordinal(publisher_offer, subscriber_media.kind, *subscriber_ordinal);
}

bool answer_media_has_inactive_direction(const media_description& media)
{
    const auto inactive_attributes = media.find_attributes(k_attribute_inactive);

    return !inactive_attributes.empty();
}
bool answer_media_has_send_direction(const media_description& media)
{
    for (const auto& attribute : media.attributes)
    {
        if (attribute.key == k_attribute_send_only || attribute.key == k_attribute_send_recv)
        {
            return true;
        }
    }

    return false;
}

bool answer_media_has_receive_only_direction(const media_description& media)
{
    for (const auto& attribute : media.attributes)
    {
        if (attribute.key == k_attribute_recv_only)
        {
            return true;
        }
    }

    return false;
}

bool rejected_answer_media_attribute_is_allowed(std::string_view key)
{
    if (key == k_attribute_mid)
    {
        return true;
    }

    if (key == k_attribute_inactive)
    {
        return true;
    }

    if (key == k_attribute_rtcp_mux)
    {
        return true;
    }

    if (key == k_attribute_rtcp_rsize)
    {
        return true;
    }

    return false;
}

bool rejected_answer_media_attribute_is_forbidden(std::string_view key)
{
    if (key == k_attribute_rtp_map || key == k_attribute_fmtp || key == k_attribute_rtcp_feedback || key == "extmap" || key == "msid" ||
        key == "ssrc" || key == "ssrc-group" || key == "rid" || key == "repaired-rid" || key == "simulcast" || key == "candidate" ||
        key == "end-of-candidates" || key == k_attribute_ice_ufrag || key == k_attribute_ice_pwd || key == k_attribute_fingerprint ||
        key == k_attribute_setup || key == k_attribute_send_recv || key == k_attribute_send_only || key == k_attribute_recv_only || key == "ptime" ||
        key == "maxptime")
    {
        return true;
    }

    return false;
}

std::expected<void, std::string> validate_rejected_answer_media_attributes(const media_description& media)
{
    std::size_t mid_count = 0;
    std::size_t inactive_count = 0;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key == k_attribute_mid)
        {
            mid_count += 1;

            if (attribute.value.empty())
            {
                return make_error("rejected answer media mid is empty");
            }

            continue;
        }

        if (attribute.key == k_attribute_inactive)
        {
            inactive_count += 1;

            if (!attribute.value.empty())
            {
                return make_error("rejected answer media inactive attribute must be property");
            }

            continue;
        }

        if (rejected_answer_media_attribute_is_forbidden(attribute.key))
        {
            std::string message = "rejected answer media has forbidden attribute key=";

            message.append(attribute.key);

            return std::unexpected(std::move(message));
        }

        if (!rejected_answer_media_attribute_is_allowed(attribute.key))
        {
            std::string message = "rejected answer media has unsupported attribute key=";

            message.append(attribute.key);

            return std::unexpected(std::move(message));
        }
    }

    if (mid_count != 1)
    {
        return make_error("rejected answer media must have exactly one mid attribute");
    }

    if (inactive_count != 1)
    {
        return make_error("rejected answer media must have exactly one inactive attribute");
    }

    return {};
}
constexpr std::string_view k_rtp_mid_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:mid";

constexpr std::string_view k_rtp_stream_id_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";

constexpr std::string_view k_repaired_rtp_stream_id_extension_uri = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

constexpr std::string_view k_transport_wide_cc_extension_uri = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

constexpr std::string_view k_transport_wide_cc_extension_uri_02 = "http://www.webrtc.org/experiments/rtp-hdrext/transport-wide-cc-02";

constexpr std::string_view k_absolute_send_time_extension_uri = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

constexpr std::string_view k_audio_level_extension_uri = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

struct parsed_extmap_attribute
{
    uint16_t id = 0;
    std::string direction;
    std::string uri;
};

struct parsed_rid_attribute
{
    std::string rid;
    std::string direction;
};

std::string trim_sdp_token(std::string_view value)
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

std::string lower_sdp_copy(std::string_view value)
{
    std::string result;

    result.reserve(value.size());

    for (unsigned char ch : value)
    {
        result.push_back(static_cast<char>(std::tolower(ch)));
    }

    return result;
}

std::expected<uint16_t, std::string> parse_u16_sdp_token(std::string_view value)
{
    const std::string normalized = trim_sdp_token(value);

    if (normalized.empty())
    {
        return make_error("sdp integer token is empty");
    }

    uint32_t parsed = 0;

    for (char ch : normalized)
    {
        if (std::isdigit(static_cast<unsigned char>(ch)) == 0)
        {
            return make_error("sdp integer token is invalid");
        }

        parsed = parsed * 10U + static_cast<uint32_t>(ch - '0');

        if (parsed > 65535U)
        {
            return make_error("sdp integer token is out of range");
        }
    }

    return static_cast<uint16_t>(parsed);
}

std::expected<parsed_extmap_attribute, std::string> parse_extmap_attribute_value(std::string_view value)
{
    const std::vector<std::string> tokens = split_sdp_tokens(value);

    if (tokens.size() < 2)
    {
        return make_error("extmap attribute value is incomplete");
    }

    const std::string& id_token = tokens[0];

    const std::size_t slash_position = id_token.find('/');

    const std::string id_text = slash_position == std::string::npos ? id_token : id_token.substr(0, slash_position);

    auto id = parse_u16_sdp_token(id_text);

    if (!id)
    {
        return std::unexpected(id.error());
    }

    if (*id == 0 || *id > 255)
    {
        return make_error("extmap id is out of range");
    }

    parsed_extmap_attribute result;

    result.id = *id;

    if (slash_position != std::string::npos)
    {
        result.direction = lower_sdp_copy(id_token.substr(slash_position + 1));
    }

    result.uri = tokens[1];

    if (result.uri.empty())
    {
        return make_error("extmap uri is empty");
    }

    return result;
}

std::expected<parsed_rid_attribute, std::string> parse_rid_attribute_value(std::string_view value)
{
    const std::vector<std::string> tokens = split_sdp_tokens(value);

    if (tokens.size() < 2)
    {
        return make_error("rid attribute value is incomplete");
    }

    parsed_rid_attribute result;

    result.rid = tokens[0];

    result.direction = lower_sdp_copy(tokens[1]);

    if (result.rid.empty())
    {
        return make_error("rid id is empty");
    }

    if (result.direction != "send" && result.direction != "recv")
    {
        return make_error("rid direction is invalid");
    }

    return result;
}

std::vector<std::string> collect_attribute_values(const media_description& media, std::string_view key)
{
    std::vector<std::string> values;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key == key)
        {
            values.push_back(attribute.value);
        }
    }

    return values;
}

std::unordered_map<std::string, parsed_extmap_attribute> collect_extmaps_by_uri(const media_summary& media)
{
    std::unordered_map<std::string, parsed_extmap_attribute> extmaps;

    for (const auto& extension : media.header_extensions)
    {
        parsed_extmap_attribute parsed;

        parsed.id = static_cast<uint16_t>(extension.id);

        parsed.uri = extension.uri;

        parsed.direction = std::string(to_string(extension.direction));

        extmaps.emplace(parsed.uri, std::move(parsed));
    }

    return extmaps;
}

std::expected<std::vector<parsed_extmap_attribute>, std::string> parse_answer_extmaps(const media_description& media)
{
    std::vector<parsed_extmap_attribute> extmaps;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key != "extmap")
        {
            continue;
        }

        auto parsed = parse_extmap_attribute_value(attribute.value);

        if (!parsed)
        {
            return std::unexpected(parsed.error());
        }

        extmaps.push_back(*parsed);
    }

    return extmaps;
}

std::expected<std::vector<parsed_rid_attribute>, std::string> parse_answer_rids(const media_description& media)
{
    std::vector<parsed_rid_attribute> rids;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key != "rid")
        {
            continue;
        }

        auto parsed = parse_rid_attribute_value(attribute.value);

        if (!parsed)
        {
            return std::unexpected(parsed.error());
        }

        rids.push_back(*parsed);
    }

    return rids;
}

bool extmap_uri_is_rid_related(std::string_view uri) { return uri == k_rtp_stream_id_extension_uri || uri == k_repaired_rtp_stream_id_extension_uri; }

bool extmap_uri_is_media_identity(std::string_view uri)
{
    return uri == k_rtp_mid_extension_uri || uri == k_rtp_stream_id_extension_uri || uri == k_repaired_rtp_stream_id_extension_uri;
}

bool answer_media_has_rtx_codec(const media_description& media)
{
    for (const auto& attribute : media.attributes)
    {
        if (attribute.key != k_attribute_rtp_map)
        {
            continue;
        }

        const std::vector<std::string> tokens = split_sdp_tokens(attribute.value);

        if (tokens.size() < 2)
        {
            continue;
        }

        const std::string codec_text = lower_sdp_copy(tokens[1]);

        if (codec_text.rfind("rtx/", 0) == 0)
        {
            return true;
        }
    }

    return false;
}

std::expected<void, std::string> validate_answer_extmap_uniqueness(const media_description& media)
{
    auto extmaps = parse_answer_extmaps(media);

    if (!extmaps)
    {
        return std::unexpected(extmaps.error());
    }

    std::unordered_set<uint16_t> ids;
    std::unordered_set<std::string> uris;

    for (const auto& extmap : *extmaps)
    {
        if (!ids.insert(extmap.id).second)
        {
            return make_error("answer media has duplicate extmap id");
        }

        if (!uris.insert(extmap.uri).second)
        {
            return make_error("answer media has duplicate extmap uri");
        }
    }

    return {};
}

std::expected<void, std::string> validate_answer_extmaps_are_offer_subset(const media_summary& offer_media, const media_description& answer_media)
{
    const auto offer_extmaps_by_uri = collect_extmaps_by_uri(offer_media);

    auto answer_extmaps = parse_answer_extmaps(answer_media);

    if (!answer_extmaps)
    {
        return std::unexpected(answer_extmaps.error());
    }

    for (const auto& answer_extmap : *answer_extmaps)
    {
        auto offer_iterator = offer_extmaps_by_uri.find(answer_extmap.uri);

        if (offer_iterator == offer_extmaps_by_uri.end())
        {
            std::string message = "answer media extmap uri was not offered uri=";

            message.append(answer_extmap.uri);

            return std::unexpected(std::move(message));
        }

        if (offer_iterator->second.id != answer_extmap.id)
        {
            std::string message = "answer media extmap id does not match offer uri=";

            message.append(answer_extmap.uri);

            return std::unexpected(std::move(message));
        }
    }

    return {};
}

std::expected<void, std::string> validate_repaired_rid_extmap_consistency(const media_description& answer_media)
{
    auto answer_extmaps = parse_answer_extmaps(answer_media);

    if (!answer_extmaps)
    {
        return std::unexpected(answer_extmaps.error());
    }

    bool has_rid_extmap = false;
    bool has_repaired_rid_extmap = false;

    for (const auto& extmap : *answer_extmaps)
    {
        if (extmap.uri == k_rtp_stream_id_extension_uri)
        {
            has_rid_extmap = true;
        }

        if (extmap.uri == k_repaired_rtp_stream_id_extension_uri)
        {
            has_repaired_rid_extmap = true;
        }
    }

    if (!has_repaired_rid_extmap)
    {
        return {};
    }

    if (!has_rid_extmap)
    {
        return make_error("answer media repaired-rid extmap requires rid extmap");
    }

    if (!answer_media_has_rtx_codec(answer_media))
    {
        return make_error("answer media repaired-rid extmap requires rtx codec");
    }

    return {};
}

std::set<std::string> collect_offer_rid_ids(const media_summary& offer_media)
{
    std::set<std::string> rid_ids;

    for (const auto& rid : offer_media.rids)
    {
        rid_ids.insert(rid.id);
    }

    return rid_ids;
}

std::expected<void, std::string> validate_answer_rids(const media_summary& offer_media, const media_description& answer_media)
{
    auto answer_rids = parse_answer_rids(answer_media);

    if (!answer_rids)
    {
        return std::unexpected(answer_rids.error());
    }

    if (answer_rids->empty())
    {
        return {};
    }

    const std::set<std::string> offer_rids = collect_offer_rid_ids(offer_media);

    if (offer_rids.empty())
    {
        return make_error("answer media has rid attributes but offer has none");
    }

    std::set<std::string> answer_rid_ids;

    for (const auto& rid : *answer_rids)
    {
        if (!answer_rid_ids.insert(rid.rid).second)
        {
            return make_error("answer media has duplicate rid id");
        }

        if (offer_rids.find(rid.rid) == offer_rids.end())
        {
            std::string message = "answer media rid was not offered rid=";

            message.append(rid.rid);

            return std::unexpected(std::move(message));
        }
    }

    return {};
}

std::vector<std::string> extract_simulcast_rids_from_list(std::string_view value)
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

std::expected<void, std::string> validate_answer_simulcast_rids(const media_description& answer_media)
{
    auto answer_rids = parse_answer_rids(answer_media);

    if (!answer_rids)
    {
        return std::unexpected(answer_rids.error());
    }

    std::set<std::string> rid_ids;

    for (const auto& rid : *answer_rids)
    {
        rid_ids.insert(rid.rid);
    }

    for (const auto& attribute : answer_media.attributes)
    {
        if (attribute.key != "simulcast")
        {
            continue;
        }

        const std::vector<std::string> tokens = split_sdp_tokens(attribute.value);

        if (tokens.size() < 2)
        {
            return make_error("answer simulcast attribute is incomplete");
        }

        for (std::size_t index = 1; index < tokens.size(); index += 2)
        {
            const std::vector<std::string> simulcast_rids = extract_simulcast_rids_from_list(tokens[index]);

            for (const auto& rid : simulcast_rids)
            {
                if (rid_ids.find(rid) == rid_ids.end())
                {
                    std::string message = "answer simulcast references unknown rid=";

                    message.append(rid);

                    return std::unexpected(std::move(message));
                }
            }
        }
    }

    return {};
}
std::size_t count_msid_attributes(const media_description& media)
{
    std::size_t count = 0;

    for (const auto& attribute : media.attributes)
    {
        if (attribute.key == "msid")
        {
            count += 1;
        }
    }

    return count;
}
std::expected<void, std::string> validate_answer_msid_attributes(const media_description& answer_media)
{
    std::set<std::string> msid_values;

    for (const auto& attribute : answer_media.attributes)
    {
        if (attribute.key != "msid")
        {
            continue;
        }

        const std::vector<std::string> tokens = split_sdp_tokens(attribute.value);

        if (tokens.empty())
        {
            return make_error("answer msid attribute is empty");
        }

        if (tokens[0] == "-")
        {
            return make_error("answer msid stream id is invalid");
        }

        if (!msid_values.insert(attribute.value).second)
        {
            return make_error("answer media has duplicate msid attribute");
        }
    }

    return {};
}
std::expected<void, std::string> validate_answer_msid_direction_consistency(const media_description& answer_media)
{
    if (is_answer_media_rejected(answer_media))
    {
        return {};
    }

    const std::size_t msid_count = count_msid_attributes(answer_media);

    if (answer_media_has_send_direction(answer_media))
    {
        if (msid_count != 1)
        {
            return make_error("sending answer media must have exactly one msid attribute");
        }

        return {};
    }

    if (msid_count != 0)
    {
        return make_error("non sending answer media must not have msid attribute");
    }

    return {};
}
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
bool media_has_compatible_header_extension_uri(const media_summary& media, std::string_view uri)
{
    if (uri == k_transport_wide_cc_extension_uri || uri == k_transport_wide_cc_extension_uri_02)
    {
        return media_has_header_extension_uri(media, k_transport_wide_cc_extension_uri) ||
               media_has_header_extension_uri(media, k_transport_wide_cc_extension_uri_02);
    }

    return media_has_header_extension_uri(media, uri);
}

bool forwarded_publisher_can_supply_header_extension(const media_summary* forwarded_publisher_media, std::string_view uri)
{
    if (forwarded_publisher_media == nullptr)
    {
        return true;
    }

    return media_has_compatible_header_extension_uri(*forwarded_publisher_media, uri);
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

std::expected<void, std::string> validate_accepted_answer_media_identity(const media_summary& offer_media, const media_description& answer_media)
{
    if (is_answer_media_rejected(answer_media))
    {
        return {};
    }

    auto extmap_uniqueness_result = validate_answer_extmap_uniqueness(answer_media);

    if (!extmap_uniqueness_result)
    {
        return std::unexpected(extmap_uniqueness_result.error());
    }

    auto extmap_subset_result = validate_answer_extmaps_are_offer_subset(offer_media, answer_media);

    if (!extmap_subset_result)
    {
        return std::unexpected(extmap_subset_result.error());
    }

    auto repaired_rid_result = validate_repaired_rid_extmap_consistency(answer_media);

    if (!repaired_rid_result)
    {
        return std::unexpected(repaired_rid_result.error());
    }

    auto rid_result = validate_answer_rids(offer_media, answer_media);

    if (!rid_result)
    {
        return std::unexpected(rid_result.error());
    }

    auto simulcast_result = validate_answer_simulcast_rids(answer_media);

    if (!simulcast_result)
    {
        return std::unexpected(simulcast_result.error());
    }

    auto msid_result = validate_answer_msid_attributes(answer_media);
    if (!msid_result)
    {
        return std::unexpected(msid_result.error());
    }

    auto msid_direction_result = validate_answer_msid_direction_consistency(answer_media);
    if (!msid_direction_result)
    {
        return std::unexpected(msid_direction_result.error());
    }

    return {};
}
bool string_vector_contains_value(const std::vector<std::string>& values, std::string_view value)
{
    for (const auto& current : values)
    {
        if (current == value)
        {
            return true;
        }
    }

    return false;
}
std::expected<void, std::string> validate_whep_answer_media_forwarding_identity(const media_summary& subscriber_media,
                                                                                const media_summary* forwarded_publisher_media,
                                                                                const media_description& answer_media)
{
    if (is_answer_media_rejected(answer_media))
    {
        return {};
    }

    if (forwarded_publisher_media == nullptr)
    {
        return {};
    }

    if (subscriber_media.kind != forwarded_publisher_media->kind)
    {
        return make_error("whep answer publisher media kind mismatch");
    }

    auto answer_extmaps = parse_answer_extmaps(answer_media);

    if (!answer_extmaps)
    {
        return std::unexpected(answer_extmaps.error());
    }

    for (const auto& extmap : *answer_extmaps)
    {
        if (!forwarded_publisher_can_supply_header_extension(forwarded_publisher_media, extmap.uri))
        {
            std::string message = "whep answer extmap is not supplied by publisher uri=";

            message.append(extmap.uri);

            return std::unexpected(std::move(message));
        }
    }

    auto answer_rids = parse_answer_rids(answer_media);

    if (!answer_rids)
    {
        return std::unexpected(answer_rids.error());
    }

    std::set<std::string> answer_rid_ids;

    for (const auto& rid : *answer_rids)
    {
        if (!answer_rid_ids.insert(rid.rid).second)
        {
            return make_error("whep answer media has duplicate rid id");
        }

        if (rid.direction != "send" && rid.direction != "sendrecv")
        {
            std::string message = "whep answer rid direction must be send rid=";

            message.append(rid.rid);

            return std::unexpected(std::move(message));
        }

        if (!media_has_answerable_send_rid(*forwarded_publisher_media, rid.rid))
        {
            std::string message = "whep answer rid is not supplied by publisher rid=";

            message.append(rid.rid);

            return std::unexpected(std::move(message));
        }

        if (forwarded_publisher_media->simulcast.has_value() &&
            !string_vector_contains_value(forwarded_publisher_media->simulcast->send_rids, rid.rid))
        {
            std::string message = "whep answer rid is not in publisher simulcast send list rid=";

            message.append(rid.rid);

            return std::unexpected(std::move(message));
        }
    }

    for (const auto& attribute : answer_media.attributes)
    {
        if (attribute.key != "simulcast")
        {
            continue;
        }

        const std::vector<std::string> tokens = split_sdp_tokens(attribute.value);

        if (tokens.size() < 2)
        {
            return make_error("whep answer simulcast attribute is incomplete");
        }

        if ((tokens.size() % 2U) != 0U)
        {
            return make_error("whep answer simulcast attribute must contain direction rid-list pairs");
        }

        for (std::size_t index = 0; index < tokens.size(); index += 2)
        {
            const std::string& direction = tokens[index];

            if (direction != "send")
            {
                std::string message = "whep answer simulcast direction must be send direction=";

                message.append(direction);

                return std::unexpected(std::move(message));
            }

            const std::vector<std::string> simulcast_rids = extract_simulcast_rids_from_list(tokens[index + 1]);

            for (const auto& rid : simulcast_rids)
            {
                if (answer_rid_ids.find(rid) == answer_rid_ids.end())
                {
                    std::string message = "whep answer simulcast references unknown rid=";

                    message.append(rid);

                    return std::unexpected(std::move(message));
                }

                if (!media_has_answerable_send_rid(*forwarded_publisher_media, rid))
                {
                    std::string message = "whep answer simulcast rid is not supplied by publisher rid=";

                    message.append(rid);

                    return std::unexpected(std::move(message));
                }

                if (!forwarded_publisher_media->simulcast.has_value() ||
                    !string_vector_contains_value(forwarded_publisher_media->simulcast->send_rids, rid))
                {
                    std::string message = "whep answer simulcast rid is not in publisher send list rid=";

                    message.append(rid);

                    return std::unexpected(std::move(message));
                }
            }
        }
    }

    return {};
}

connection_information make_rejected_connection(const sdp_answer_options& options)
{
    connection_information connection;

    connection.network_type = options.network_type;

    connection.address_type = options.address_type;

    sdp_address address;

    if (options.address_type == "IP6")
    {
        address.address = "::";
    }
    else
    {
        address.address = "0.0.0.0";
    }

    connection.address = address;

    return connection;
}
std::expected<void, std::string> validate_answer_media_rejection_state(const media_description& media)
{
    const bool rejected = is_answer_media_rejected(media);

    const bool inactive = answer_media_has_inactive_direction(media);

    if (!rejected && inactive)
    {
        return make_error("answer media must not use inactive direction with nonzero port");
    }

    if (rejected && !inactive)
    {
        return make_error("rejected answer media must use inactive direction");
    }

    if (rejected)
    {
        auto attribute_result = validate_rejected_answer_media_attributes(media);

        if (!attribute_result)
        {
            return std::unexpected(attribute_result.error());
        }
    }

    return {};
}
void push_attribute(std::vector<sdp_attribute>& attributes, std::string_view key, std::string_view value)
{
    attributes.push_back(make_attribute(std::string(key), std::string(value)));
}

void push_property_attribute(std::vector<sdp_attribute>& attributes, std::string_view key)
{
    attributes.push_back(make_property_attribute(std::string(key)));
}

origin_line make_origin(const sdp_answer_options& options)
{
    origin_line origin;
    origin.username = options.origin_username;
    origin.session_id = options.session_id;
    origin.session_version = options.session_version;
    origin.network_type = options.network_type;
    origin.address_type = options.address_type;
    origin.unicast_address = options.unicast_address;
    return origin;
}

connection_information make_connection(const sdp_answer_options& options)
{
    connection_information connection;
    connection.network_type = options.network_type;
    connection.address_type = options.address_type;

    sdp_address address;
    address.address = options.media_address;
    connection.address = address;

    return connection;
}

time_description make_zero_time_description()
{
    time_description time;
    time.timing.start_time = 0;
    time.timing.stop_time = 0;
    return time;
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

bool is_supported_answer_header_extension_uri(std::string_view kind, std::string_view uri)
{
    if (uri == k_rtp_mid_extension_uri)
    {
        return kind == "audio" || kind == "video";
    }

    if (uri == k_rtp_stream_id_extension_uri)
    {
        return kind == "video";
    }

    if (uri == k_repaired_rtp_stream_id_extension_uri)
    {
        return kind == "video";
    }

    if (uri == k_transport_wide_cc_extension_uri || uri == k_transport_wide_cc_extension_uri_02)
    {
        return kind == "audio" || kind == "video";
    }

    if (uri == k_absolute_send_time_extension_uri)
    {
        return kind == "audio" || kind == "video";
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

void append_header_extension_attributes(media_description& answer_media, const media_summary& media, const media_summary* forwarded_publisher_media)
{
    bool answer_needs_extmap_allow_mixed = false;

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

        if (!is_supported_answer_header_extension_uri(media.kind, extension.uri))
        {
            continue;
        }

        if (!forwarded_publisher_can_supply_header_extension(forwarded_publisher_media, extension.uri))
        {
            continue;
        }

        if (rtp_header_extension_id_requires_two_byte(extension.id))
        {
            if (!media.extmap_allow_mixed)
            {
                continue;
            }

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

    if (!media_has_compatible_header_extension_uri(subscriber_media, k_rtp_stream_id_extension_uri) ||
        !media_has_compatible_header_extension_uri(publisher_media, k_rtp_stream_id_extension_uri))
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

        if (!string_vector_contains_value(publisher_media.simulcast->send_rids, rid))
        {
            continue;
        }

        if (string_vector_contains_value(rids, rid))
        {
            continue;
        }

        rids.push_back(rid);
    }

    return rids;
}
std::string join_rids_with_semicolon(const std::vector<std::string>& rids)
{
    std::string value;

    for (const auto& rid : rids)
    {
        if (!value.empty())
        {
            value.push_back(';');
        }

        value.append(rid);
    }

    return value;
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

    std::string simulcast_value;

    simulcast_value.reserve(join_rids_with_semicolon(rids).size() + 8);

    simulcast_value.append("send ");

    simulcast_value.append(join_rids_with_semicolon(rids));

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

        if (string_vector_contains_value(rids, rid))
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

    std::string simulcast_value;

    simulcast_value.reserve(join_rids_with_semicolon(rids).size() + 8);

    simulcast_value.append("recv ");

    simulcast_value.append(join_rids_with_semicolon(rids));

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

std::string make_candidate_value(const sdp_ice_candidate_options& candidate)
{
    std::string value;

    value.reserve(candidate.foundation.size() + candidate.transport.size() + candidate.address.size() + candidate.type.size() + 64);

    value.append(candidate.foundation);
    value.push_back(' ');
    value.append(std::to_string(candidate.component));
    value.push_back(' ');
    value.append(candidate.transport);
    value.push_back(' ');
    value.append(std::to_string(candidate.priority));
    value.push_back(' ');
    value.append(candidate.address);
    value.push_back(' ');
    value.append(std::to_string(candidate.port));
    value.append(" typ ");
    value.append(candidate.type);

    return value;
}

void append_codec_attributes(media_description& answer_media, const std::vector<codec_info>& codecs)
{
    for (const auto& codec : codecs)
    {
        push_attribute(answer_media.attributes, k_attribute_rtp_map, make_rtp_map_value(codec));

        if (!codec.fmtp.empty())
        {
            push_attribute(answer_media.attributes, k_attribute_fmtp, make_fmtp_value(codec));
        }

        for (const auto& feedback : codec.rtcp_feedback)
        {
            push_attribute(answer_media.attributes, k_attribute_rtcp_feedback, make_rtcp_feedback_value(codec, feedback));
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
    if (options.include_host_candidate)
    {
        if (options.local_candidates.empty())
        {
            push_attribute(answer_media.attributes, "candidate", make_candidate_value(make_legacy_candidate_options(options)));
        }
        else
        {
            for (const auto& candidate : options.local_candidates)
            {
                push_attribute(answer_media.attributes, "candidate", make_candidate_value(candidate));
            }
        }
    }

    if (options.end_of_candidates)
    {
        push_property_attribute(answer_media.attributes, "end-of-candidates");
    }
}
std::expected<media_description, std::string> make_rejected_answer_media(const sdp_answer_options& options, const media_summary& media)
{
    auto inactive_text = format_direction(media_direction::inactive);

    if (!inactive_text)
    {
        return std::unexpected(inactive_text.error());
    }

    media_description answer_media;

    answer_media.media_name.media = media.kind;

    answer_media.media_name.port.value = 0;

    answer_media.media_name.protocols.push_back("UDP");

    answer_media.media_name.protocols.push_back("TLS");

    answer_media.media_name.protocols.push_back("RTP");

    answer_media.media_name.protocols.push_back("SAVPF");

    for (uint16_t payload_type : media.payload_types)
    {
        answer_media.media_name.formats.push_back(std::to_string(payload_type));
    }

    if (answer_media.media_name.formats.empty())
    {
        answer_media.media_name.formats.push_back("0");
    }

    answer_media.connection = make_rejected_connection(options);

    push_attribute(answer_media.attributes, k_attribute_mid, media.mid);

    push_property_attribute(answer_media.attributes, *inactive_text);

    if (media.rtcp_mux)
    {
        push_property_attribute(answer_media.attributes, k_attribute_rtcp_mux);
    }

    if (media.rtcp_rsize)
    {
        push_property_attribute(answer_media.attributes, k_attribute_rtcp_rsize);
    }

    auto rejection_state_result = validate_answer_media_rejection_state(answer_media);
    if (!rejection_state_result)
    {
        return std::unexpected(rejection_state_result.error());
    }

    return answer_media;
}
std::expected<media_description, std::string> make_answer_media(answer_endpoint_role role,
                                                                const sdp_answer_options& options,
                                                                const media_summary& media,
                                                                const webrtc_offer_summary* whep_subscriber_offer,
                                                                const webrtc_offer_summary* whep_publisher_offer)
{
    auto answer_direction = make_answer_direction(role, media);
    if (!answer_direction)
    {
        return std::unexpected(answer_direction.error());
    }

    if (*answer_direction == media_direction::inactive)
    {
        return make_rejected_answer_media(options, media);
    }
    std::vector<codec_info> codecs;
    const media_summary* forwarded_publisher_media = nullptr;
    if (role == answer_endpoint_role::whep && whep_publisher_offer != nullptr)
    {
        if (whep_subscriber_offer == nullptr)
        {
            return make_rejected_answer_media(options, media);
        }
        const media_summary* publisher_media = find_matching_publisher_media(media, *whep_subscriber_offer, *whep_publisher_offer);
        if (publisher_media == nullptr)
        {
            return make_rejected_answer_media(options, media);
        }
        forwarded_publisher_media = publisher_media;

        auto codec_result = negotiate_codecs(media, *publisher_media);
        if (!codec_result)
        {
            return make_rejected_answer_media(options, media);
        }

        codecs = std::move(*codec_result);
    }
    else
    {
        auto codec_result = negotiate_codecs(media);

        if (!codec_result)
        {
            return std::unexpected(codec_result.error());
        }

        codecs = std::move(*codec_result);
    }

    auto answer_direction_text = format_direction(*answer_direction);

    if (!answer_direction_text)
    {
        return std::unexpected(answer_direction_text.error());
    }
    media_description answer_media;

    answer_media.media_name.media = media.kind;
    answer_media.media_name.port.value = 9;
    answer_media.media_name.protocols.push_back("UDP");
    answer_media.media_name.protocols.push_back("TLS");
    answer_media.media_name.protocols.push_back("RTP");
    answer_media.media_name.protocols.push_back("SAVPF");

    for (const auto& codec : codecs)
    {
        answer_media.media_name.formats.push_back(std::to_string(codec.payload_type));
    }

    answer_media.connection = make_connection(options);

    push_attribute(answer_media.attributes, k_attribute_mid, media.mid);

    push_property_attribute(answer_media.attributes, *answer_direction_text);

    push_property_attribute(answer_media.attributes, k_attribute_rtcp_mux);

    if (media.rtcp_rsize)
    {
        push_property_attribute(answer_media.attributes, k_attribute_rtcp_rsize);
    }

    append_header_extension_attributes(answer_media, media, forwarded_publisher_media);

    if (role == answer_endpoint_role::whip && *answer_direction == media_direction::recv_only)
    {
        append_whip_simulcast_receive_attributes(answer_media, media);
    }
    if (role == answer_endpoint_role::whep && *answer_direction == media_direction::send_only)
    {
        append_whep_simulcast_send_attributes(answer_media, media, forwarded_publisher_media);
    }

    append_codec_attributes(answer_media, codecs);

    append_media_timing_attributes(answer_media, media);

    append_ice_candidate_attributes(answer_media, options);

    if (*answer_direction == media_direction::send_only || *answer_direction == media_direction::send_recv)
    {
        push_attribute(answer_media.attributes, "msid", make_msid_value(options, media));
    }
    auto identity_result = validate_accepted_answer_media_identity(media, answer_media);

    if (!identity_result)
    {
        return std::unexpected(identity_result.error());
    }

    if (role == answer_endpoint_role::whep && forwarded_publisher_media != nullptr)
    {
        auto forwarding_identity_result = validate_whep_answer_media_forwarding_identity(media, forwarded_publisher_media, answer_media);

        if (!forwarding_identity_result)
        {
            return std::unexpected(forwarding_identity_result.error());
        }
    }

    return answer_media;
}

validation_result append_answer_media_descriptions(session_description& answer,
                                                   answer_endpoint_role role,
                                                   const sdp_answer_options& options,
                                                   const webrtc_offer_summary& offer,
                                                   const webrtc_offer_summary* whep_publisher_offer)
{
    bool has_accepted_media = false;

    for (const auto& media : offer.media)
    {
        auto answer_media = make_answer_media(role, options, media, &offer, whep_publisher_offer);
        if (!answer_media)
        {
            return std::unexpected(answer_media.error());
        }

        auto rejection_state_result = validate_answer_media_rejection_state(*answer_media);

        if (!rejection_state_result)
        {
            return std::unexpected(rejection_state_result.error());
        }

        if (!is_answer_media_rejected(*answer_media))
        {
            has_accepted_media = true;
        }
        answer.media_descriptions.push_back(std::move(*answer_media));
    }

    if (role == answer_endpoint_role::whep && whep_publisher_offer != nullptr && !has_accepted_media)
    {
        return make_error("whep answer has no compatible publisher media");
    }

    return {};
}

sdp_answer_result build_answer(answer_endpoint_role role,
                               const webrtc_offer_summary& offer,
                               const sdp_answer_options& options,
                               const webrtc_offer_summary* whep_publisher_offer)
{
    auto options_result = validate_options(options);
    if (!options_result)
    {
        return std::unexpected(options_result.error());
    }

    auto offer_result = validate_offer_for_answer(offer);
    if (!offer_result)
    {
        return std::unexpected(offer_result.error());
    }

    auto setup_text = format_setup_role(options.local_setup);

    if (!setup_text)
    {
        return std::unexpected(setup_text.error());
    }

    session_description answer;

    answer.version.value = 0;
    answer.origin = make_origin(options);
    answer.session_name = "-";
    answer.time_descriptions.push_back(make_zero_time_description());
    if (options.ice_lite)
    {
        push_property_attribute(answer.attributes, "ice-lite");
    }

    if (options.enable_trickle)
    {
        push_attribute(answer.attributes, "ice-options", "trickle");
    }

    push_attribute(answer.attributes, k_attribute_ice_ufrag, options.local_ice_ufrag);

    push_attribute(answer.attributes, k_attribute_ice_pwd, options.local_ice_pwd);

    push_attribute(answer.attributes, k_attribute_fingerprint, make_fingerprint_value(options.local_fingerprint));

    push_attribute(answer.attributes, k_attribute_setup, *setup_text);

    push_attribute(answer.attributes, "msid-semantic", "WMS " + options.local_stream_id);

    auto media_result = append_answer_media_descriptions(answer, role, options, offer, whep_publisher_offer);
    if (!media_result)
    {
        return std::unexpected(media_result.error());
    }

    auto bundle_group_value = make_bundle_group_value(answer);

    if (!bundle_group_value)
    {
        return std::unexpected(bundle_group_value.error());
    }

    answer.attributes.insert(answer.attributes.begin(), make_attribute(std::string(k_attribute_group), *bundle_group_value));

    auto bundle_group_validation = validate_answer_bundle_group(answer);

    if (!bundle_group_validation)
    {
        return std::unexpected(bundle_group_validation.error());
    }

    return answer;
}

sdp_answer_text_result build_answer_sdp(answer_endpoint_role role,
                                        const webrtc_offer_summary& offer,
                                        const sdp_answer_options& options,
                                        const webrtc_offer_summary* whep_publisher_offer)
{
    auto answer = build_answer(role, offer, options, whep_publisher_offer);
    if (!answer)
    {
        return std::unexpected(answer.error());
    }

    auto text = format_session_description(*answer);
    if (!text)
    {
        return std::unexpected(text.error());
    }

    return *text;
}
}    // namespace

sdp_answer_result build_whip_answer(const webrtc_offer_summary& offer, const sdp_answer_options& options)
{
    return build_answer(answer_endpoint_role::whip, offer, options, nullptr);
}

sdp_answer_result build_whep_answer(const webrtc_offer_summary& offer, const sdp_answer_options& options)
{
    return build_answer(answer_endpoint_role::whep, offer, options, nullptr);
}

sdp_answer_result build_whep_answer(const webrtc_offer_summary& subscriber_offer,
                                    const webrtc_offer_summary& publisher_offer,
                                    const sdp_answer_options& options)
{
    return build_answer(answer_endpoint_role::whep, subscriber_offer, options, &publisher_offer);
}

sdp_answer_text_result build_whip_answer_sdp(const webrtc_offer_summary& offer, const sdp_answer_options& options)
{
    return build_answer_sdp(answer_endpoint_role::whip, offer, options, nullptr);
}

sdp_answer_text_result build_whep_answer_sdp(const webrtc_offer_summary& offer, const sdp_answer_options& options)
{
    return build_answer_sdp(answer_endpoint_role::whep, offer, options, nullptr);
}

sdp_answer_text_result build_whep_answer_sdp(const webrtc_offer_summary& subscriber_offer,
                                             const webrtc_offer_summary& publisher_offer,
                                             const sdp_answer_options& options)
{
    return build_answer_sdp(answer_endpoint_role::whep, subscriber_offer, options, &publisher_offer);
}

}    // namespace webrtc::sdp
