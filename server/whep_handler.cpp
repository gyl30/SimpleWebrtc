#include "server/whep_handler.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "server/http_error_response.h"
#include "server/runtime_offer_filter.h"
#include "server/trickle_ice_patch_handler.h"
#include "signaling/sdp/sdp_offer_validator.h"
#include "signaling/sdp/sdp_parser.h"
#include "signaling/sdp/sdp_summary.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;
constexpr std::string_view k_whep_invalid_sdp_offer_error = "whep_invalid_sdp_offer";
constexpr std::string_view k_whep_invalid_webrtc_offer_error = "whep_invalid_webrtc_offer";
constexpr std::string_view k_whep_invalid_offer_error = "whep_invalid_offer";
constexpr std::string_view k_whep_answer_factory_unavailable_error = "whep_answer_factory_unavailable";
constexpr std::string_view k_whep_publisher_not_found_error = "whep_publisher_not_found";
constexpr std::string_view k_whep_previous_subscriber_not_found_error = "whep_previous_subscriber_not_found";
constexpr std::string_view k_whep_reconnect_stream_mismatch_error = "whep_reconnect_stream_mismatch";
constexpr std::string_view k_whep_precondition_failed_error = "whep_precondition_failed";
constexpr std::string_view k_whep_sdp_answer_failed_error = "whep_sdp_answer_failed";
constexpr std::string_view k_whep_runtime_offer_filter_failed_error = "whep_runtime_offer_filter_failed";
constexpr std::string_view k_whep_create_session_failed_error = "whep_create_session_failed";
constexpr std::string_view k_whep_session_not_found_error = "whep_session_not_found";
constexpr std::string_view k_whep_delete_session_failed_error = "whep_delete_session_failed";
constexpr std::string_view k_whep_ice_restart_incompatible_offer_error = "whep_ice_restart_incompatible_offer";

std::string make_prefixed_error(std::string_view prefix, std::string_view error)
{
    std::string message;

    message.reserve(prefix.size() + error.size());

    message.append(prefix);

    message.append(error);

    return message;
}
constexpr std::string_view k_restart_application_sdp = "application/sdp";

char to_lower_ascii_char(char ch) { return static_cast<char>(std::tolower(static_cast<unsigned char>(ch))); }

bool restart_content_type_matches(std::string_view content_type, std::string_view expected)
{
    if (content_type.size() < expected.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < expected.size(); ++index)
    {
        if (to_lower_ascii_char(content_type[index]) != expected[index])
        {
            return false;
        }
    }

    if (content_type.size() == expected.size())
    {
        return true;
    }

    return content_type[expected.size()] == ';';
}

bool is_application_sdp_restart_request(http_request_t& request)
{
    const auto content_type_field = request.req[http::field::content_type];

    const std::string_view content_type(content_type_field.data(), content_type_field.size());

    if (content_type.empty())
    {
        return false;
    }

    return restart_content_type_matches(content_type, k_restart_application_sdp);
}
constexpr std::string_view k_whep_reconnect_session_header = "WHEP-Reconnect-Session";

std::string_view trim_ascii_whitespace(std::string_view value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0)
    {
        value.remove_prefix(1);
    }

    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0)
    {
        value.remove_suffix(1);
    }

    return value;
}

std::optional<std::string> read_whep_reconnect_session_id(http_request_t& request)
{
    const auto field = request.req[std::string(k_whep_reconnect_session_header)];

    std::string_view value(field.data(), field.size());

    value = trim_ascii_whitespace(value);

    if (value.empty())
    {
        return std::nullopt;
    }

    return std::string(value);
}

bool is_primary_whep_media_source_kind(std::string_view kind) { return kind == "audio" || kind == "video"; }

uint32_t make_whep_outbound_ssrc(std::unordered_set<uint32_t>& used_ssrcs)
{
    thread_local std::mt19937 generator(std::random_device{}());

    std::uniform_int_distribution<uint32_t> distribution(1U, std::numeric_limits<uint32_t>::max());

    for (uint32_t attempt = 0; attempt < 4096; ++attempt)
    {
        const uint32_t candidate = distribution(generator);

        if (candidate == 0)
        {
            continue;
        }

        if (used_ssrcs.insert(candidate).second)
        {
            return candidate;
        }
    }

    for (uint32_t candidate = 1; candidate < std::numeric_limits<uint32_t>::max(); ++candidate)
    {
        if (used_ssrcs.insert(candidate).second)
        {
            return candidate;
        }
    }

    return 1;
}

std::string make_whep_outbound_source_cname()
{
    thread_local std::mt19937 generator(std::random_device{}());

    std::uniform_int_distribution<uint32_t> distribution(0U, 15U);

    std::string cname;

    cname.reserve(19);

    cname.append("sw-");

    for (std::size_t index = 0; index < 16; ++index)
    {
        const uint32_t value = distribution(generator);

        if (value < 10)
        {
            cname.push_back(static_cast<char>('0' + value));
        }
        else
        {
            cname.push_back(static_cast<char>('a' + (value - 10)));
        }
    }

    return cname;
}

std::string make_whep_outbound_track_id(const sdp::media_summary& media)
{
    std::string track_id;

    track_id.reserve(media.kind.size() + media.mid.size() + 1);

    track_id.append(media.kind);
    track_id.push_back('-');
    track_id.append(media.mid);

    return track_id;
}

std::vector<sdp::sdp_answer_media_source> make_whep_outbound_media_sources(const sdp::webrtc_offer_summary& offer)
{
    std::vector<sdp::sdp_answer_media_source> sources;

    sources.reserve(offer.media.size());

    std::unordered_set<uint32_t> used_ssrcs;

    const std::string cname = make_whep_outbound_source_cname();

    for (const auto& media : offer.media)
    {
        if (!is_primary_whep_media_source_kind(media.kind))
        {
            continue;
        }

        if (media.mid.empty())
        {
            continue;
        }

        sdp::sdp_answer_media_source source;

        source.mid = media.mid;
        source.kind = media.kind;
        source.ssrc = make_whep_outbound_ssrc(used_ssrcs);
        source.cname = cname;
        source.track_id = make_whep_outbound_track_id(media);

        sources.push_back(std::move(source));
    }

    return sources;
}

bool whep_accepted_mids_contains(const std::vector<std::string>& accepted_mids, std::string_view mid)
{
    for (const auto& accepted_mid : accepted_mids)
    {
        if (accepted_mid == mid)
        {
            return true;
        }
    }

    return false;
}

std::vector<sdp::sdp_answer_media_source> filter_whep_outbound_media_sources(const std::vector<sdp::sdp_answer_media_source>& sources,
                                                                             const std::vector<std::string>& accepted_mids)
{
    std::vector<sdp::sdp_answer_media_source> filtered_sources;

    filtered_sources.reserve(sources.size());

    for (const auto& source : sources)
    {
        if (!whep_accepted_mids_contains(accepted_mids, source.mid))
        {
            continue;
        }

        filtered_sources.push_back(source);
    }

    return filtered_sources;
}
}    // namespace

whep_handler::whep_handler(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory)
    : registry_(std::move(registry)), answer_factory_(std::move(answer_factory))
{
}

http_response_ptr whep_handler::create_subscriber(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);

    if (!description)
    {
        WEBRTC_LOG_WARN("WHEP parse SDP offer failed stream={} error={}", stream_id, description.error());
        return json_error_response(request, 400, k_whep_invalid_sdp_offer_error, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    WEBRTC_LOG_INFO("WHEP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHEP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());
        return json_error_response(
            request, 400, k_whep_invalid_webrtc_offer_error, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whep_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHEP validate WebRTC offer failed stream={} error={}", stream_id, validation_result.error());
        return json_error_response(request, 400, k_whep_invalid_offer_error, make_prefixed_error("invalid whep offer: ", validation_result.error()));
    }

    WEBRTC_LOG_INFO("WHEP validated WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHEP answer factory is not configured stream={}", stream_id);
        return json_error_response(request, 500, k_whep_answer_factory_unavailable_error, "answer factory is not configured");
    }

    auto publisher = registry_->find_publisher_by_stream_id(stream_id);

    if (publisher == nullptr)
    {
        WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

        return json_error_response(request, 404, k_whep_publisher_not_found_error, "publisher not found");
    }
    const std::optional<std::string> reconnect_session_id = read_whep_reconnect_session_id(request);

    std::shared_ptr<subscriber_session> reconnect_previous_session;
    stream_reconnected_session reconnected_session;
    if (reconnect_session_id.has_value())
    {
        reconnect_previous_session = registry_->find_subscriber_by_session_id(*reconnect_session_id);

        if (reconnect_previous_session == nullptr)
        {
            const auto removed_session = registry_->find_removed_session_tombstone(*reconnect_session_id);

            if (removed_session.has_value() && removed_session->kind == stream_session_kind::subscriber)
            {
                WEBRTC_LOG_WARN("WHEP reconnect failed previous subscriber gone stream={} previous_session={}", stream_id, *reconnect_session_id);

                return json_error_response(request, 410, "whep_session_gone", "previous subscriber session already deleted");
            }

            WEBRTC_LOG_WARN("WHEP reconnect failed previous subscriber not found stream={} previous_session={}", stream_id, *reconnect_session_id);

            return json_error_response(request, 404, k_whep_previous_subscriber_not_found_error, "previous subscriber session not found");
        }
        if (reconnect_previous_session->stream_id() != stream_id)
        {
            WEBRTC_LOG_WARN("WHEP reconnect failed stream mismatch stream={} previous_stream={} previous_session={}",
                            stream_id,
                            reconnect_previous_session->stream_id(),
                            reconnect_previous_session->session_id());
            return json_error_response(request, 409, k_whep_reconnect_stream_mismatch_error, "previous subscriber session belongs to another stream");
        }

        auto precondition = validate_session_if_match(request, *reconnect_previous_session);

        if (!precondition)
        {
            WEBRTC_LOG_WARN("WHEP reconnect precondition failed stream={} previous_session={} error={}",
                            stream_id,
                            reconnect_previous_session->session_id(),
                            precondition.error());

            return json_error_response(request, 412, k_whep_precondition_failed_error, precondition.error());
        }
        reconnected_session.stream_id = reconnect_previous_session->stream_id();
        reconnected_session.old_session_id = reconnect_previous_session->session_id();
        reconnected_session.old_local_ice_ufrag = reconnect_previous_session->local_ice().ufrag;
        reconnected_session.old_remote_ice_ufrag = reconnect_previous_session->remote_offer_summary().ice_ufrag;
    }
    auto outbound_media_sources = make_whep_outbound_media_sources(*offer_summary);
    if (outbound_media_sources.empty())
    {
        WEBRTC_LOG_WARN(
            "WHEP create subscriber failed stream={} outbound media source empty offer_media_count={}", stream_id, offer_summary->media.size());

        return json_error_response(request, 400, k_whep_sdp_answer_failed_error, "failed to build sdp answer: outbound media source empty");
    }

    auto generated_answer =
        answer_factory_->build_whep_answer(stream_id, *offer_summary, publisher->remote_offer_summary(), std::move(outbound_media_sources));
    if (!generated_answer)
    {
        WEBRTC_LOG_WARN("WHEP build SDP answer failed stream={} error={}", stream_id, generated_answer.error());
        return json_error_response(
            request, 400, k_whep_sdp_answer_failed_error, make_prefixed_error("failed to build sdp answer: ", generated_answer.error()));
    }

    auto runtime_offer_filter = make_runtime_offer_filter_result(*offer_summary, generated_answer->sdp);

    if (!runtime_offer_filter)
    {
        WEBRTC_LOG_WARN("WHEP runtime subscriber offer filter failed stream={} error={}", stream_id, runtime_offer_filter.error());
        return json_error_response(request,
                                   400,
                                   k_whep_runtime_offer_filter_failed_error,
                                   make_prefixed_error("failed to filter runtime subscriber offer: ", runtime_offer_filter.error()));
    }

    auto session_result = [&]() -> subscriber_session_result
    {
        if (reconnect_session_id.has_value())
        {
            return registry_->replace_subscriber_session(
                *reconnect_session_id, std::string(stream_id), offer, std::move(runtime_offer_filter->offer_summary));
        }

        return registry_->create_subscriber_session(std::string(stream_id), offer, std::move(runtime_offer_filter->offer_summary));
    }();
    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::publisher_not_found)
        {
            WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

            return json_error_response(request, 404, "publisher not found");
        }

        if (error == stream_registry_error::subscriber_session_not_found)
        {
            if (reconnect_session_id.has_value())
            {
                const auto removed_session = registry_->find_removed_session_tombstone(*reconnect_session_id);

                if (removed_session.has_value() && removed_session->kind == stream_session_kind::subscriber)
                {
                    WEBRTC_LOG_WARN("WHEP reconnect failed previous subscriber gone stream={} previous_session={}", stream_id, *reconnect_session_id);

                    return json_error_response(request, 410, "whep_session_gone", "previous subscriber session already deleted");
                }
            }

            WEBRTC_LOG_WARN(
                "WHEP reconnect failed previous subscriber not found stream={} previous_session={}", stream_id, reconnect_session_id.value_or(""));

            return json_error_response(request, 404, k_whep_previous_subscriber_not_found_error, "previous subscriber session not found");
        }
        if (error == stream_registry_error::subscriber_reconnect_stream_mismatch)
        {
            WEBRTC_LOG_WARN("WHEP reconnect failed previous subscriber stream mismatch stream={} previous_session={}",
                            stream_id,
                            reconnect_session_id.value_or(""));

            return json_error_response(request, 409, "previous subscriber session belongs to another stream");
        }

        WEBRTC_LOG_ERROR("WHEP create subscriber failed stream={} error={}", stream_id, stream_registry_error_to_string(error));
        return json_error_response(request, 500, k_whep_create_session_failed_error, "create subscriber session failed");
    }

    const auto& session = *session_result;

    generated_sdp_answer generated = std::move(*generated_answer);

    auto accepted_outbound_media_sources = filter_whep_outbound_media_sources(generated.media_sources, runtime_offer_filter->accepted_mids);

    session->set_accepted_remote_media_mline_indexes(std::move(runtime_offer_filter->accepted_mline_indexes));

    session->set_outbound_media_sources(std::move(accepted_outbound_media_sources));

    session->set_local_answer(std::move(generated.sdp),
                              std::move(generated.local_ice),
                              std::move(generated.local_fingerprint),
                              generated.sdp_session_id,
                              generated.sdp_session_version);
    if (reconnect_session_id.has_value())
    {
        reconnected_session.new_session_id = session->session_id();
        reconnected_session.new_local_ice_ufrag = session->local_ice().ufrag;
        reconnected_session.new_remote_ice_ufrag = session->remote_offer_summary().ice_ufrag;

        if (registry_ != nullptr)
        {
            registry_->notify_subscriber_reconnect(std::move(reconnected_session));
        }
    }
    WEBRTC_LOG_INFO(
        "WHEP create subscriber stream={} session={} reconnect={} previous_session={} sdp_size={} offer_media_count={} accepted_media_count={} "
        "outbound_media_source_count={}",
        session->stream_id(),
        session->session_id(),
        reconnect_session_id.has_value() ? 1 : 0,
        reconnect_session_id.value_or(""),
        session->local_sdp_answer().size(),
        session->remote_offer_summary().media.size(),
        runtime_offer_filter->accepted_mids.size(),
        session->outbound_media_sources().size());
    auto response = sdp_response(request, 201, session->local_sdp_answer());
    const std::string session_location_path = "/whep/session/" + session->session_id();
    response->set(http::field::location, make_absolute_resource_url(request, session_location_path));
    set_session_resource_headers(response, *session);
    return response;
}

http_response_ptr whep_handler::patch_sdp_restart(http_request_t& request,
                                                  std::string_view session_id,
                                                  const std::shared_ptr<subscriber_session>& session)
{
    if (session == nullptr)
    {
        const auto removed_session = registry_->find_removed_session_tombstone(session_id);

        if (removed_session.has_value() && removed_session->kind == stream_session_kind::subscriber)
        {
            return json_error_response(request, 410, "whep_session_gone", "subscriber session already deleted");
        }

        return json_error_response(request, 404, "subscriber session not found");
    }

    auto precondition = validate_session_if_match(request, *session);

    if (!precondition)
    {
        WEBRTC_LOG_WARN("WHEP sdp restart precondition failed session={} error={}", session_id, precondition.error());

        return json_error_response(request, 412, precondition.error());
    }

    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHEP answer factory is not configured session={}", session_id);

        return json_error_response(request, 500, "answer factory is not configured");
    }

    auto publisher = registry_->find_publisher_by_stream_id(session->stream_id());

    if (publisher == nullptr)
    {
        WEBRTC_LOG_WARN("WHEP SDP ICE restart failed session={} stream={} publisher not found", session_id, session->stream_id());

        return json_error_response(request, 404, "publisher not found");
    }

    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);

    if (!description)
    {
        WEBRTC_LOG_WARN("WHEP parse SDP restart offer failed session={} error={}", session_id, description.error());

        return json_error_response(request, 400, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHEP extract SDP restart offer failed session={} error={}", session_id, offer_summary.error());

        return json_error_response(request, 400, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whep_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHEP validate SDP restart offer failed session={} error={}", session_id, validation_result.error());

        return json_error_response(request, 400, make_prefixed_error("invalid whep offer: ", validation_result.error()));
    }

    if (!sdp::offer_has_ice_restart(session->remote_offer_summary(), *offer_summary))
    {
        WEBRTC_LOG_WARN("WHEP SDP patch without ICE restart session={} previous={} next={}",
                        session_id,
                        sdp::offer_ice_credentials_to_string(session->remote_offer_summary()),
                        sdp::offer_ice_credentials_to_string(*offer_summary));

        return json_error_response(request, 400, "sdp patch does not contain ice restart");
    }

    const uint64_t next_sdp_session_version = session->sdp_session_version() + 1U;

    auto restart_outbound_media_sources = session->outbound_media_sources();

    if (restart_outbound_media_sources.empty())
    {
        restart_outbound_media_sources = make_whep_outbound_media_sources(*offer_summary);
    }

    auto answer = answer_factory_->build_whep_restart_answer(session->stream_id(),
                                                             *offer_summary,
                                                             publisher->remote_offer_summary(),
                                                             session->sdp_session_id(),
                                                             next_sdp_session_version,
                                                             std::move(restart_outbound_media_sources));
    if (!answer)
    {
        WEBRTC_LOG_WARN("WHEP build SDP restart answer failed session={} error={}", session_id, answer.error());

        return json_error_response(request, 400, make_prefixed_error("cannot build sdp answer: ", answer.error()));
    }

    auto runtime_offer_filter = make_runtime_offer_filter_result(*offer_summary, answer->sdp);
    if (!runtime_offer_filter)
    {
        WEBRTC_LOG_WARN("WHEP runtime restart offer summary failed session={} error={}", session_id, runtime_offer_filter.error());

        return json_error_response(
            request, 400, make_prefixed_error("failed to build runtime subscriber offer summary: ", runtime_offer_filter.error()));
    }
    auto restart_compatibility = sdp::validate_ice_restart_offer_compatibility(session->remote_offer_summary(), runtime_offer_filter->offer_summary);

    if (!restart_compatibility)
    {
        WEBRTC_LOG_WARN("WHEP SDP ICE restart incompatible offer session={} error={}", session_id, restart_compatibility.error());

        return json_error_response(request,
                                   409,
                                   k_whep_ice_restart_incompatible_offer_error,
                                   make_prefixed_error("invalid ice restart offer: ", restart_compatibility.error()));
    }
    generated_sdp_answer generated_answer = std::move(*answer);

    auto accepted_outbound_media_sources = filter_whep_outbound_media_sources(generated_answer.media_sources, runtime_offer_filter->accepted_mids);

    stream_restarted_session restarted_session;
    restarted_session.kind = stream_session_kind::subscriber;

    restarted_session.stream_id = session->stream_id();

    restarted_session.session_id = session->session_id();

    restarted_session.old_local_ice_ufrag = session->local_ice().ufrag;

    restarted_session.old_remote_ice_ufrag = session->remote_offer_summary().ice_ufrag;

    restarted_session.new_local_ice_ufrag = generated_answer.local_ice.ufrag;

    restarted_session.new_remote_ice_ufrag = runtime_offer_filter->offer_summary.ice_ufrag;
    session->apply_remote_ice_restart_offer(offer, std::move(runtime_offer_filter->offer_summary));

    session->set_accepted_remote_media_mline_indexes(std::move(runtime_offer_filter->accepted_mline_indexes));

    session->set_outbound_media_sources(std::move(accepted_outbound_media_sources));

    session->set_local_answer(std::move(generated_answer.sdp),
                              std::move(generated_answer.local_ice),
                              std::move(generated_answer.local_fingerprint),
                              generated_answer.sdp_session_id,
                              generated_answer.sdp_session_version);
    if (registry_ != nullptr)
    {
        registry_->notify_session_ice_restart(std::move(restarted_session));
    }
    WEBRTC_LOG_INFO(
        "WHEP SDP ICE restart accepted stream={} session={} offer_size={} answer_size={} accepted_media_count={} accepted_mline_count={} "
        "outbound_media_source_count={}",
        session->stream_id(),
        session->session_id(),
        offer.size(),
        session->local_sdp_answer().size(),
        session->remote_offer_summary().media.size(),
        session->accepted_remote_media_mline_indexes().size(),
        session->outbound_media_sources().size());
    auto response = sdp_response(request, 200, session->local_sdp_answer());

    set_session_resource_headers(response, *session);

    return response;
}

http_response_ptr whep_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    auto session = registry_->find_subscriber_by_session_id(session_id);

    if (session == nullptr)
    {
        const auto removed_session = registry_->find_removed_session_tombstone(session_id);

        if (removed_session.has_value() && removed_session->kind == stream_session_kind::subscriber)
        {
            return json_error_response(request, 410, "whep_session_gone", "subscriber session already deleted");
        }
    }

    if (is_application_sdp_restart_request(request))
    {
        return patch_sdp_restart(request, session_id, session);
    }

    return handle_trickle_ice_patch_request(
        request,
        session_id,
        session,
        "WHEP",
        "subscriber session not found",
        [this, &request](int status, std::string_view error_code, std::string_view message) -> http_response_ptr
        { return json_error_response(request, status, error_code, message); },
        [this, &request](const auto& updated_session) -> http_response_ptr
        {
            auto response = create_response(request, 204, "");

            add_common_headers(response);

            set_session_resource_headers(response, updated_session);

            return response;
        });
}

http_response_ptr whep_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHEP delete session={}", session_id);

    auto session = registry_->find_subscriber_by_session_id(session_id);

    if (session == nullptr)
    {
        const auto removed_session = registry_->find_removed_session_tombstone(session_id);

        if (removed_session.has_value() && removed_session->kind == stream_session_kind::subscriber)
        {
            return json_error_response(request, 410, "whep_session_gone", "subscriber session already deleted");
        }

        return json_error_response(request, 404, k_whep_session_not_found_error, "subscriber session not found");
    }
    auto precondition = validate_session_if_match(request, *session);

    if (!precondition)
    {
        WEBRTC_LOG_WARN("WHEP delete session precondition failed session={} error={}", session_id, precondition.error());

        return json_error_response(request, 412, precondition.error());
    }

    auto result = registry_->remove_subscriber_session(session_id);

    if (!result)
    {
        if (result.error() == stream_registry_error::subscriber_session_not_found)
        {
            const auto removed_session = registry_->find_removed_session_tombstone(session_id);

            if (removed_session.has_value() && removed_session->kind == stream_session_kind::subscriber)
            {
                return json_error_response(request, 410, "whep_session_gone", "subscriber session already deleted");
            }

            return json_error_response(request, 404, k_whep_session_not_found_error, "subscriber session not found");
        }

        WEBRTC_LOG_ERROR("WHEP delete subscriber failed session={} error={}", session_id, stream_registry_error_to_string(result.error()));
        return json_error_response(request, 500, k_whep_delete_session_failed_error, "delete subscriber session failed");
    }
    auto response = create_response(request, 204, "");

    add_common_headers(response);

    return response;
}

http_response_ptr whep_handler::json_response(http_request_t& request, int code, std::string_view body)
{
    return make_json_http_response(request, code, body);
}

http_response_ptr whep_handler::json_error_response(http_request_t& request, int code, std::string_view message)
{
    return json_error_response(request, code, "whep_error", message);
}

http_response_ptr whep_handler::json_error_response(http_request_t& request, int code, std::string_view error_code, std::string_view message)
{
    return make_json_http_error_response(request, code, error_code, message);
}

http_response_ptr whep_handler::sdp_response(http_request_t& request, int code, std::string_view body)
{
    return make_sdp_http_response(request, code, body);
}

void whep_handler::add_common_headers(const http_response_ptr& response) { add_http_common_headers(response); }

}    // namespace webrtc
