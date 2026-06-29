#include "server/whep_handler.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <optional>
#include <limits>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "server/trickle_ice_patch_handler.h"
#include "server/runtime_offer_filter.h"
#include "signaling/sdp/sdp_offer_validator.h"
#include "signaling/sdp/sdp_parser.h"
#include "signaling/sdp/sdp_summary.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

constexpr std::string_view k_cors_private_network_header = "Access-Control-Allow-Private-Network";

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

        return json_error_response(request, 400, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    WEBRTC_LOG_INFO("WHEP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHEP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());

        return json_error_response(request, 400, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whep_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHEP validate WebRTC offer failed stream={} error={}", stream_id, validation_result.error());

        return json_error_response(request, 400, make_prefixed_error("invalid whep offer: ", validation_result.error()));
    }

    WEBRTC_LOG_INFO("WHEP validated WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHEP answer factory is not configured stream={}", stream_id);

        return json_error_response(request, 500, "answer factory is not configured");
    }

    auto publisher = registry_->find_publisher_by_stream_id(stream_id);

    if (publisher == nullptr)
    {
        WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

        return json_error_response(request, 404, "publisher not found");
    }
    const std::optional<std::string> reconnect_session_id = read_whep_reconnect_session_id(request);

    std::shared_ptr<subscriber_session> reconnect_previous_session;
    if (reconnect_session_id.has_value())
    {
        reconnect_previous_session = registry_->find_subscriber_by_session_id(*reconnect_session_id);

        if (reconnect_previous_session == nullptr)
        {
            WEBRTC_LOG_WARN("WHEP reconnect failed previous subscriber not found stream={} previous_session={}", stream_id, *reconnect_session_id);

            return json_error_response(request, 404, "previous subscriber session not found");
        }

        if (reconnect_previous_session->stream_id() != stream_id)
        {
            WEBRTC_LOG_WARN("WHEP reconnect failed stream mismatch stream={} previous_stream={} previous_session={}",
                            stream_id,
                            reconnect_previous_session->stream_id(),
                            reconnect_previous_session->session_id());

            return json_error_response(request, 409, "previous subscriber session belongs to another stream");
        }

        auto precondition = validate_session_if_match(request, *reconnect_previous_session);

        if (!precondition)
        {
            WEBRTC_LOG_WARN("WHEP reconnect precondition failed stream={} previous_session={} error={}",
                            stream_id,
                            reconnect_previous_session->session_id(),
                            precondition.error());

            return json_error_response(request, 412, precondition.error());
        }
    }
    auto generated_answer = answer_factory_->build_whep_answer(stream_id, *offer_summary, publisher->remote_offer_summary());
    if (!generated_answer)
    {
        WEBRTC_LOG_WARN("WHEP build SDP answer failed stream={} error={}", stream_id, generated_answer.error());

        return json_error_response(request, 400, make_prefixed_error("failed to build sdp answer: ", generated_answer.error()));
    }

    auto runtime_offer_filter = make_runtime_offer_filter_result(*offer_summary, generated_answer->sdp);

    if (!runtime_offer_filter)
    {
        WEBRTC_LOG_WARN("WHEP runtime subscriber offer filter failed stream={} error={}", stream_id, runtime_offer_filter.error());

        return json_error_response(request, 400, make_prefixed_error("failed to filter runtime subscriber offer: ", runtime_offer_filter.error()));
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
            WEBRTC_LOG_WARN(
                "WHEP reconnect failed previous subscriber not found stream={} previous_session={}", stream_id, reconnect_session_id.value_or(""));

            return json_error_response(request, 404, "previous subscriber session not found");
        }

        if (error == stream_registry_error::subscriber_reconnect_stream_mismatch)
        {
            WEBRTC_LOG_WARN("WHEP reconnect failed previous subscriber stream mismatch stream={} previous_session={}",
                            stream_id,
                            reconnect_session_id.value_or(""));

            return json_error_response(request, 409, "previous subscriber session belongs to another stream");
        }

        WEBRTC_LOG_ERROR("WHEP create subscriber failed stream={} error={}", stream_id, stream_registry_error_to_string(error));

        return json_error_response(request, 500, "create subscriber session failed");
    }

    const auto& session = *session_result;

    session->set_accepted_remote_media_mline_indexes(std::move(runtime_offer_filter->accepted_mline_indexes));
    generated_sdp_answer generated = std::move(*generated_answer);

    session->set_local_answer(std::move(generated.sdp),
                              std::move(generated.local_ice),
                              std::move(generated.local_fingerprint),
                              generated.sdp_session_id,
                              generated.sdp_session_version);

    WEBRTC_LOG_INFO(
        "WHEP create subscriber stream={} session={} reconnect={} previous_session={} sdp_size={} offer_media_count={} accepted_media_count={}",
        session->stream_id(),
        session->session_id(),
        reconnect_session_id.has_value() ? 1 : 0,
        reconnect_session_id.value_or(""),
        offer.size(),
        offer_summary->media.size(),
        session->remote_offer_summary().media.size());
    auto response = sdp_response(request, 201, session->local_sdp_answer());

    response->set(http::field::location, "/whep/session/" + session->session_id());

    set_session_resource_headers(response, *session);

    return response;
}
http_response_ptr whep_handler::patch_sdp_restart(http_request_t& request,
                                                  std::string_view session_id,
                                                  const std::shared_ptr<subscriber_session>& session)
{
    if (session == nullptr)
    {
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

    auto answer = answer_factory_->build_whep_answer(session->stream_id(), *offer_summary, publisher->remote_offer_summary());

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

    generated_sdp_answer generated_answer = std::move(*answer);

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

    session->set_local_answer(std::move(generated_answer.sdp),
                              std::move(generated_answer.local_ice),
                              std::move(generated_answer.local_fingerprint),
                              generated_answer.sdp_session_id,
                              generated_answer.sdp_session_version);

    if (registry_ != nullptr)
    {
        registry_->notify_session_ice_restart(std::move(restarted_session));
    }
    WEBRTC_LOG_INFO("WHEP SDP ICE restart accepted stream={} session={} offer_size={} answer_size={} accepted_media_count={} accepted_mline_count={}",
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

http_response_ptr whep_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    auto session = registry_->find_subscriber_by_session_id(session_id);

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
        [this, &request](int status, std::string_view message) -> http_response_ptr { return json_error_response(request, status, message); },
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
        return json_error_response(request, 404, "subscriber session not found");
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
            return json_error_response(request, 404, "subscriber session not found");
        }

        WEBRTC_LOG_ERROR("WHEP delete subscriber failed session={} error={}", session_id, stream_registry_error_to_string(result.error()));

        return json_error_response(request, 500, "delete subscriber session failed");
    }

    auto response = create_response(request, 204, "");

    add_common_headers(response);

    return response;
}

http_response_ptr whep_handler::json_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    content.push_back('\n');

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "application/json; charset=utf-8");

    add_common_headers(response);

    return response;
}

http_response_ptr whep_handler::json_error_response(http_request_t& request, int code, std::string_view message)
{
    return json_response(request, code, make_error_response_body(message));
}

http_response_ptr whep_handler::sdp_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "application/sdp");

    add_common_headers(response);

    return response;
}

void whep_handler::add_common_headers(const http_response_ptr& response)
{
    if (response == nullptr)
    {
        return;
    }

    response->set(http::field::access_control_allow_origin, "*");

    response->set(http::field::access_control_expose_headers, std::string(k_trickle_ice_expose_headers_value));

    response->set(std::string(k_cors_private_network_header), "true");

    response->set(http::field::cache_control, "no-store");

    set_trickle_ice_patch_headers(response);
}

}    // namespace webrtc
