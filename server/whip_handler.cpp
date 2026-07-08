#include "server/whip_handler.h"

#include <cstddef>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
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
constexpr std::string_view k_whip_invalid_sdp_offer_error = "whip_invalid_sdp_offer";
constexpr std::string_view k_whip_invalid_webrtc_offer_error = "whip_invalid_webrtc_offer";
constexpr std::string_view k_whip_invalid_offer_error = "whip_invalid_offer";
constexpr std::string_view k_whip_answer_factory_unavailable_error = "whip_answer_factory_unavailable";
constexpr std::string_view k_whip_sdp_answer_failed_error = "whip_sdp_answer_failed";
constexpr std::string_view k_whip_runtime_offer_filter_failed_error = "whip_runtime_offer_filter_failed";
constexpr std::string_view k_whip_previous_publisher_not_found_error = "whip_previous_publisher_not_found";
constexpr std::string_view k_whip_republish_stream_mismatch_error = "whip_republish_stream_mismatch";
constexpr std::string_view k_whip_precondition_failed_error = "whip_precondition_failed";
constexpr std::string_view k_whip_stream_already_has_publisher_error = "whip_stream_already_has_publisher";
constexpr std::string_view k_whip_create_session_failed_error = "whip_create_session_failed";
constexpr std::string_view k_whip_session_not_found_error = "whip_session_not_found";
constexpr std::string_view k_whip_delete_session_failed_error = "whip_delete_session_failed";
constexpr std::string_view k_whip_ice_restart_incompatible_offer_error = "whip_ice_restart_incompatible_offer";
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

http_response_ptr validate_sdp_restart_body(http_request_t& request,
                                            std::string_view protocol_name,
                                            std::string_view session_id,
                                            std::string_view empty_error_code,
                                            std::string_view too_large_error_code)
{
    const std::string& body = request.req.body();

    if (body.empty())
    {
        WEBRTC_LOG_WARN("{} SDP restart body empty session={}", protocol_name, session_id);

        return make_json_http_error_response(request, 400, empty_error_code, "sdp restart body is empty");
    }

    if (body.size() > k_trickle_ice_max_patch_body_bytes)
    {
        WEBRTC_LOG_WARN("{} SDP restart body too large session={} body_size={} limit={}",
                        protocol_name,
                        session_id,
                        body.size(),
                        k_trickle_ice_max_patch_body_bytes);

        return make_json_http_error_response(request, 413, too_large_error_code, "sdp restart body is too large");
    }

    return nullptr;
}
constexpr std::string_view k_whip_replace_session_header = "WHIP-Replace-Session";

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

std::optional<std::string> read_whip_replace_session_id(http_request_t& request)
{
    const auto field = request.req[std::string(k_whip_replace_session_header)];

    std::string_view value(field.data(), field.size());

    value = trim_ascii_whitespace(value);

    if (value.empty())
    {
        return std::nullopt;
    }

    return std::string(value);
}

}    // namespace

whip_handler::whip_handler(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory)
    : registry_(std::move(registry)), answer_factory_(std::move(answer_factory))
{
}

http_response_ptr whip_handler::create_publisher(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);

    if (!description)
    {
        WEBRTC_LOG_WARN("WHIP parse SDP offer failed stream={} error={}", stream_id, description.error());

        return json_error_response(request, 400, k_whip_invalid_sdp_offer_error, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    WEBRTC_LOG_INFO("WHIP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHIP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());

        return json_error_response(
            request, 400, k_whip_invalid_webrtc_offer_error, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whip_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHIP validate offer failed stream={} error={}", stream_id, validation_result.error());

        return json_error_response(request, 400, k_whip_invalid_offer_error, make_prefixed_error("invalid whip offer: ", validation_result.error()));
    }

    const std::optional<std::string> replace_session_id = read_whip_replace_session_id(request);

    std::shared_ptr<publisher_session> replace_previous_session;

    stream_republished_session republished_session;

    if (replace_session_id.has_value())
    {
        replace_previous_session = registry_->find_publisher_by_session_id(*replace_session_id);

        if (replace_previous_session == nullptr)
        {
            const auto removed_session = registry_->find_removed_session_tombstone(*replace_session_id);

            if (removed_session.has_value() && removed_session->kind == stream_session_kind::publisher)
            {
                WEBRTC_LOG_WARN("WHIP republish failed previous publisher gone stream={} previous_session={}", stream_id, *replace_session_id);

                return json_error_response(request, 410, "whip_session_gone", "previous publisher session already deleted");
            }

            WEBRTC_LOG_WARN("WHIP republish failed previous publisher not found stream={} previous_session={}", stream_id, *replace_session_id);

            return json_error_response(request, 404, k_whip_previous_publisher_not_found_error, "previous publisher session not found");
        }
        if (replace_previous_session->stream_id() != stream_id)
        {
            WEBRTC_LOG_WARN("WHIP republish failed stream mismatch stream={} previous_stream={} previous_session={}",
                            stream_id,
                            replace_previous_session->stream_id(),
                            replace_previous_session->session_id());

            return json_error_response(request, 409, "previous publisher session belongs to another stream");
        }

        auto precondition = validate_session_if_match(request, *replace_previous_session);

        if (!precondition)
        {
            WEBRTC_LOG_WARN("WHIP republish precondition failed stream={} previous_session={} error={}",
                            stream_id,
                            replace_previous_session->session_id(),
                            precondition.error());

            return json_error_response(request, 412, k_whip_precondition_failed_error, precondition.error());
        }

        republished_session.stream_id = replace_previous_session->stream_id();

        republished_session.old_session_id = replace_previous_session->session_id();

        republished_session.old_local_ice_ufrag = replace_previous_session->local_ice().ufrag;

        republished_session.old_remote_ice_ufrag = replace_previous_session->remote_offer_summary().ice_ufrag;
    }

    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHIP answer factory is not configured stream={}", stream_id);

        return json_error_response(request, 500, k_whip_answer_factory_unavailable_error, "answer factory is not configured");
    }

    auto answer = answer_factory_->build_whip_answer(stream_id, *offer_summary);

    if (!answer)
    {
        WEBRTC_LOG_WARN("WHIP build SDP answer failed stream={} error={}", stream_id, answer.error());

        return json_error_response(request, 400, k_whip_sdp_answer_failed_error, make_prefixed_error("cannot build sdp answer: ", answer.error()));
    }

    auto runtime_offer_filter = make_runtime_offer_filter_result(*offer_summary, answer->sdp);

    if (!runtime_offer_filter)
    {
        WEBRTC_LOG_WARN("WHIP runtime publisher offer filter failed stream={} error={}", stream_id, runtime_offer_filter.error());

        return json_error_response(request,
                                   400,
                                   k_whip_runtime_offer_filter_failed_error,
                                   make_prefixed_error("failed to filter runtime publisher offer: ", runtime_offer_filter.error()));
    }

    auto session_result = [&]() -> publisher_session_result
    {
        if (replace_session_id.has_value())
        {
            return registry_->replace_publisher_session(
                *replace_session_id, std::string(stream_id), offer, std::move(runtime_offer_filter->offer_summary));
        }

        return registry_->create_publisher_session(std::string(stream_id), offer, std::move(runtime_offer_filter->offer_summary));
    }();
    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::stream_already_has_publisher)
        {
            WEBRTC_LOG_WARN("WHIP create publisher failed stream={} already has publisher", stream_id);

            return json_error_response(request, 409, k_whip_stream_already_has_publisher_error, "stream already has publisher");
        }

        if (error == stream_registry_error::publisher_session_not_found)
        {
            if (replace_session_id.has_value())
            {
                const auto removed_session = registry_->find_removed_session_tombstone(*replace_session_id);

                if (removed_session.has_value() && removed_session->kind == stream_session_kind::publisher)
                {
                    WEBRTC_LOG_WARN("WHIP republish failed previous publisher gone stream={} previous_session={}", stream_id, *replace_session_id);

                    return json_error_response(request, 410, "whip_session_gone", "previous publisher session already deleted");
                }
            }

            WEBRTC_LOG_WARN(
                "WHIP republish failed previous publisher not found stream={} previous_session={}", stream_id, replace_session_id.value_or(""));

            return json_error_response(request, 404, k_whip_previous_publisher_not_found_error, "previous publisher session not found");
        }
        if (error == stream_registry_error::publisher_republish_stream_mismatch)
        {
            WEBRTC_LOG_WARN(
                "WHIP republish failed previous publisher stream mismatch stream={} previous_session={}", stream_id, replace_session_id.value_or(""));

            return json_error_response(request, 409, k_whip_republish_stream_mismatch_error, "previous publisher session belongs to another stream");
        }

        WEBRTC_LOG_ERROR("WHIP create publisher failed stream={} error={}", stream_id, stream_registry_error_to_string(error));
        return json_error_response(request, 500, k_whip_create_session_failed_error, "create publisher session failed");
    }

    const auto& session = *session_result;

    session->set_accepted_remote_media_mline_indexes(std::move(runtime_offer_filter->accepted_mline_indexes));

    generated_sdp_answer generated_answer = std::move(*answer);

    const std::string new_local_ice_ufrag = generated_answer.local_ice.ufrag;

    session->set_local_answer(std::move(generated_answer.sdp),
                              std::move(generated_answer.local_ice),
                              std::move(generated_answer.local_fingerprint),
                              generated_answer.sdp_session_id,
                              generated_answer.sdp_session_version);

    if (replace_session_id.has_value())
    {
        republished_session.new_session_id = session->session_id();

        republished_session.new_local_ice_ufrag = new_local_ice_ufrag;

        republished_session.new_remote_ice_ufrag = session->remote_offer_summary().ice_ufrag;

        if (registry_ != nullptr)
        {
            registry_->notify_publisher_republish(std::move(republished_session));
        }
    }

    WEBRTC_LOG_INFO(
        "WHIP create publisher stream={} session={} republish={} previous_session={} sdp_size={} offer_media_count={} accepted_media_count={} "
        "accepted_mline_count={}",
        session->stream_id(),
        session->session_id(),
        replace_session_id.has_value() ? 1 : 0,
        replace_session_id.value_or(""),
        offer.size(),
        offer_summary->media.size(),
        session->remote_offer_summary().media.size(),
        session->accepted_remote_media_mline_indexes().size());

    auto response = sdp_response(request, 201, session->local_sdp_answer());

    const std::string session_location_path = "/whip/session/" + session->session_id();

    response->set(http::field::location, make_absolute_resource_url(request, session_location_path));

    set_session_resource_headers(response, *session);

    return response;
}

http_response_ptr whip_handler::patch_sdp_restart(http_request_t& request,
                                                  std::string_view session_id,
                                                  const std::shared_ptr<publisher_session>& session)
{
    if (session == nullptr)
    {
        const auto removed_session = registry_->find_removed_session_tombstone(session_id);

        if (removed_session.has_value() && removed_session->kind == stream_session_kind::publisher)
        {
            return json_error_response(request, 410, "whip_session_gone", "publisher session already deleted");
        }

        return json_error_response(request, 404, "publisher session not found");
    }
    auto precondition = validate_session_if_match(request, *session);

    if (!precondition)
    {
        WEBRTC_LOG_WARN("WHIP sdp restart precondition failed session={} error={}", session_id, precondition.error());

        return json_error_response(request, 412, k_whip_precondition_failed_error, precondition.error());
    }

    auto body_validation_error =
        validate_sdp_restart_body(request, "WHIP", session_id, "whip_sdp_restart_body_empty", "whip_sdp_restart_body_too_large");

    if (body_validation_error != nullptr)
    {
        return body_validation_error;
    }

    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHIP answer factory is not configured session={}", session_id);

        return json_error_response(request, 500, k_whip_answer_factory_unavailable_error, "answer factory is not configured");
    }

    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);
    if (!description)
    {
        WEBRTC_LOG_WARN("WHIP parse SDP restart offer failed session={} error={}", session_id, description.error());

        return json_error_response(request, 400, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHIP extract SDP restart offer failed session={} error={}", session_id, offer_summary.error());

        return json_error_response(request, 400, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whip_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHIP validate SDP restart offer failed session={} error={}", session_id, validation_result.error());

        return json_error_response(request, 400, make_prefixed_error("invalid whip offer: ", validation_result.error()));
    }

    if (!sdp::offer_has_ice_restart(session->remote_offer_summary(), *offer_summary))
    {
        WEBRTC_LOG_WARN("WHIP SDP patch without ICE restart session={} previous={} next={}",
                        session_id,
                        sdp::offer_ice_credentials_to_string(session->remote_offer_summary()),
                        sdp::offer_ice_credentials_to_string(*offer_summary));

        return json_error_response(request, 400, "sdp patch does not contain ice restart");
    }

    const uint64_t next_sdp_session_version = session->sdp_session_version() + 1U;

    auto answer =
        answer_factory_->build_whip_restart_answer(session->stream_id(), *offer_summary, session->sdp_session_id(), next_sdp_session_version);
    if (!answer)
    {
        WEBRTC_LOG_WARN("WHIP build SDP restart answer failed session={} error={}", session_id, answer.error());

        return json_error_response(request, 400, make_prefixed_error("cannot build sdp answer: ", answer.error()));
    }

    auto runtime_offer_filter = make_runtime_offer_filter_result(*offer_summary, answer->sdp);

    if (!runtime_offer_filter)
    {
        WEBRTC_LOG_WARN("WHIP runtime restart offer summary failed session={} error={}", session_id, runtime_offer_filter.error());

        return json_error_response(
            request, 400, make_prefixed_error("failed to build runtime publisher offer summary: ", runtime_offer_filter.error()));
    }
    auto restart_compatibility = sdp::validate_ice_restart_offer_compatibility(session->remote_offer_summary(), runtime_offer_filter->offer_summary);
    if (!restart_compatibility)
    {
        WEBRTC_LOG_WARN("WHIP SDP ICE restart incompatible offer session={} error={}", session_id, restart_compatibility.error());

        return json_error_response(request,
                                   409,
                                   k_whip_ice_restart_incompatible_offer_error,
                                   make_prefixed_error("invalid ice restart offer: ", restart_compatibility.error()));
    }
    generated_sdp_answer generated_answer = std::move(*answer);
    stream_restarted_session restarted_session;

    restarted_session.kind = stream_session_kind::publisher;

    restarted_session.stream_id = session->stream_id();

    restarted_session.session_id = session->session_id();

    restarted_session.old_local_ice_ufrag = session->local_ice().ufrag;

    restarted_session.old_remote_ice_ufrag = session->remote_offer_summary().ice_ufrag;

    restarted_session.new_local_ice_ufrag = generated_answer.local_ice.ufrag;

    restarted_session.new_remote_ice_ufrag = runtime_offer_filter->offer_summary.ice_ufrag;
    session->apply_remote_ice_restart_offer(offer, std::move(runtime_offer_filter->offer_summary));

    session->set_accepted_remote_media_mline_indexes(std::move(runtime_offer_filter->accepted_mline_indexes));

    session->set_local_answer(std::move(generated_answer.sdp),
                              std::move(generated_answer.local_ice),
                              std::move(generated_answer.local_fingerprint),
                              generated_answer.sdp_session_id,
                              generated_answer.sdp_session_version);

    if (registry_ != nullptr)
    {
        registry_->notify_session_ice_restart(std::move(restarted_session));
    }
    WEBRTC_LOG_INFO("WHIP SDP ICE restart accepted stream={} session={} offer_size={} answer_size={} accepted_media_count={} accepted_mline_count={}",
                    session->stream_id(),
                    session->session_id(),
                    offer.size(),
                    session->local_sdp_answer().size(),
                    session->remote_offer_summary().media.size(),
                    session->accepted_remote_media_mline_indexes().size());

    auto response = sdp_response(request, 200, session->local_sdp_answer());

    set_session_resource_headers(response, *session);

    return response;
}

http_response_ptr whip_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    auto session = registry_->find_publisher_by_session_id(session_id);

    if (session == nullptr)
    {
        const auto removed_session = registry_->find_removed_session_tombstone(session_id);

        if (removed_session.has_value() && removed_session->kind == stream_session_kind::publisher)
        {
            return json_error_response(request, 410, "whip_session_gone", "publisher session already deleted");
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
        "WHIP",
        "publisher session not found",
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

http_response_ptr whip_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHIP delete session={}", session_id);

    auto session = registry_->find_publisher_by_session_id(session_id);

    if (session == nullptr)
    {
        const auto removed_session = registry_->find_removed_session_tombstone(session_id);

        if (removed_session.has_value() && removed_session->kind == stream_session_kind::publisher)
        {
            return json_error_response(request, 410, "whip_session_gone", "publisher session already deleted");
        }

        return json_error_response(request, 404, k_whip_session_not_found_error, "publisher session not found");
    }
    auto precondition = validate_session_if_match(request, *session);

    if (!precondition)
    {
        WEBRTC_LOG_WARN("WHIP delete session precondition failed session={} error={}", session_id, precondition.error());
        return json_error_response(request, 412, k_whip_precondition_failed_error, precondition.error());
    }

    auto result = registry_->remove_publisher_session(session_id);

    if (!result)
    {
        if (result.error() == stream_registry_error::publisher_session_not_found)
        {
            const auto removed_session = registry_->find_removed_session_tombstone(session_id);

            if (removed_session.has_value() && removed_session->kind == stream_session_kind::publisher)
            {
                return json_error_response(request, 410, "whip_session_gone", "publisher session already deleted");
            }

            return json_error_response(request, 404, k_whip_session_not_found_error, "publisher session not found");
        }

        WEBRTC_LOG_ERROR("WHIP delete publisher failed session={} error={}", session_id, stream_registry_error_to_string(result.error()));
        return json_error_response(request, 500, k_whip_delete_session_failed_error, "delete publisher session failed");
    }

    auto response = create_response(request, 204, "");

    add_common_headers(response);

    return response;
}

http_response_ptr whip_handler::json_response(http_request_t& request, int code, std::string_view body)
{
    return make_json_http_response(request, code, body);
}

http_response_ptr whip_handler::json_error_response(http_request_t& request, int code, std::string_view message)
{
    return json_error_response(request, code, "whip_error", message);
}

http_response_ptr whip_handler::json_error_response(http_request_t& request, int code, std::string_view error_code, std::string_view message)
{
    return make_json_http_error_response(request, code, error_code, message);
}

http_response_ptr whip_handler::sdp_response(http_request_t& request, int code, std::string_view body)
{
    return make_sdp_http_response(request, code, body);
}

void whip_handler::add_common_headers(const http_response_ptr& response) { add_http_common_headers(response); }
}    // namespace webrtc
