#include "signaling/sdp/sdp_answer_builder.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "signaling/sdp/sdp_codec_negotiator.h"
#include "signaling/sdp/sdp_formatter.h"

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

bool media_mid_exists(const std::vector<media_summary>& media_values, std::string_view mid)
{
    for (const auto& media : media_values)
    {
        if (media.mid == mid)
        {
            return true;
        }
    }

    return false;
}

std::expected<std::string, std::string> make_bundle_group_value(const webrtc_offer_summary& offer)
{
    std::string value = "BUNDLE";
    std::size_t count = 0;

    for (const auto& mid : offer.bundle_mids)
    {
        if (!media_mid_exists(offer.media, mid))
        {
            continue;
        }

        value.push_back(' ');
        value.append(mid);
        ++count;
    }

    if (count == 0)
    {
        return make_error("bundle group has no supported media mids");
    }

    return value;
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

    const std::size_t publisher_kind_count = count_send_capable_media_by_kind(publisher_offer, subscriber_media.kind);

    const std::size_t subscriber_kind_count = count_receive_capable_media_by_kind(subscriber_offer, subscriber_media.kind);

    if (publisher_kind_count != 1 || subscriber_kind_count != 1)
    {
        return nullptr;
    }

    for (const auto& publisher_media : publisher_offer.media)
    {
        if (publisher_media.kind != subscriber_media.kind)
        {
            continue;
        }

        if (!media_can_send(publisher_media))
        {
            continue;
        }

        return &publisher_media;
    }

    return nullptr;
}

bool is_answer_media_rejected(const media_description& media) { return media.media_name.port.value == 0; }

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

    answer_media.connection = make_connection(options);

    push_attribute(answer_media.attributes, k_attribute_mid, media.mid);

    push_property_attribute(answer_media.attributes, *inactive_text);

    if (media.rtcp_mux)
    {
        push_property_attribute(answer_media.attributes, k_attribute_rtcp_mux);
    }

    return answer_media;
}

std::expected<media_description, std::string> make_answer_media(answer_endpoint_role role,
                                                                const sdp_answer_options& options,
                                                                const media_summary& media,
                                                                const webrtc_offer_summary* whep_subscriber_offer,
                                                                const webrtc_offer_summary* whep_publisher_offer)
{
    std::vector<codec_info> codecs;

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

    auto answer_direction = make_answer_direction(role, media);

    if (!answer_direction)
    {
        return std::unexpected(answer_direction.error());
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

    append_codec_attributes(answer_media, codecs);

    append_ice_candidate_attributes(answer_media, options);

    if (*answer_direction == media_direction::send_only || *answer_direction == media_direction::send_recv)
    {
        push_attribute(answer_media.attributes, "msid", make_msid_value(options, media));
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

    auto bundle_group_value = make_bundle_group_value(offer);
    if (!bundle_group_value)
    {
        return std::unexpected(bundle_group_value.error());
    }

    session_description answer;

    answer.version.value = 0;
    answer.origin = make_origin(options);
    answer.session_name = "-";
    answer.time_descriptions.push_back(make_zero_time_description());

    push_attribute(answer.attributes, k_attribute_group, *bundle_group_value);

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
