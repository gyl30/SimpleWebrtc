#include "server/whep_handler.h"

#include <string>
#include <string_view>
#include <utility>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/beast/http.hpp>

#include "ice/ice_candidate.h"
#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_json.h"
#include "signaling/sdp/sdp_offer_validator.h"
#include "signaling/sdp/sdp_parser.h"
#include "signaling/sdp/sdp_summary.h"
#include "util/timestamp.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

constexpr std::string_view kApplicationJson = "application/json";
constexpr std::string_view kApplicationTrickleIceJson = "application/trickle-ice+json";

inline constexpr std::string_view k_application_json = "application/json";

std::string_view beast_string_view_to_std_string_view(boost::beast::string_view value) { return std::string_view(value.data(), value.size()); }

bool is_application_json(http_request_t& request)
{
    const auto content_type_field = request.req[http::field::content_type];

    const std::string_view content_type = beast_string_view_to_std_string_view(content_type_field);

    if (content_type.empty())
    {
        return false;
    }

    if (boost::algorithm::iequals(content_type, k_application_json))
    {
        return true;
    }

    if (!boost::algorithm::istarts_with(content_type, k_application_json))
    {
        return false;
    }

    if (content_type.size() <= k_application_json.size())
    {
        return false;
    }

    return content_type[k_application_json.size()] == ';';
}

uint64_t now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }

std::expected<remote_ice_candidate, std::string> make_remote_ice_candidate_from_http_body(std::string_view body)
{
    auto request = parse_trickle_ice_candidate_request(body);

    if (!request)
    {
        return std::unexpected(request.error());
    }

    return make_remote_ice_candidate_from_trickle_request(*request, now_milliseconds());
}

bool content_type_matches(std::string_view content_type, std::string_view expected)
{
    if (boost::algorithm::iequals(content_type, expected))
    {
        return true;
    }

    if (!boost::algorithm::istarts_with(content_type, expected))
    {
        return false;
    }

    if (content_type.size() <= expected.size())
    {
        return false;
    }

    return content_type[expected.size()] == ';';
}

}    // namespace

whep_handler::whep_handler(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory)
    : registry_(std::move(registry)), answer_factory_(std::move(answer_factory))
{
}

http_response_ptr whep_handler::create_subscriber(http_request_t& request, std::string_view stream_id)
{
    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHEP answer factory is null");

        return json_error_response(request, 500, "answer factory not initialized");
    }

    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);
    if (!description)
    {
        WEBRTC_LOG_WARN("WHEP parse SDP offer failed stream={} error={}", stream_id, description.error());

        std::string error_message;
        error_message.reserve(description.error().size() + 20);
        error_message.append("invalid sdp offer: ");
        error_message.append(description.error());

        return json_error_response(request, 400, error_message);
    }

    WEBRTC_LOG_INFO("WHEP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHEP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());

        std::string error_message;
        error_message.reserve(offer_summary.error().size() + 24);
        error_message.append("invalid webrtc offer: ");
        error_message.append(offer_summary.error());

        return json_error_response(request, 400, error_message);
    }

    auto validation_result = sdp::validate_whep_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHEP validate offer failed stream={} error={}", stream_id, validation_result.error());

        std::string error_message;
        error_message.reserve(validation_result.error().size() + 20);
        error_message.append("invalid whep offer: ");
        error_message.append(validation_result.error());

        return json_error_response(request, 400, error_message);
    }

    WEBRTC_LOG_INFO("WHEP validated WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

    auto generated_answer = answer_factory_->build_whep_answer(stream_id, *offer_summary);

    if (!generated_answer)
    {
        WEBRTC_LOG_WARN("WHEP build SDP answer failed stream={} error={}", stream_id, generated_answer.error());

        std::string error_message;
        error_message.reserve(generated_answer.error().size() + 32);
        error_message.append("failed to build sdp answer: ");
        error_message.append(generated_answer.error());

        return json_error_response(request, 400, error_message);
    }

    auto session_result = registry_->create_subscriber_session(std::string(stream_id), offer, std::move(*offer_summary));

    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::publisher_not_found)
        {
            WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

            return json_error_response(request, 404, "publisher not found");
        }

        WEBRTC_LOG_ERROR("WHEP create subscriber failed stream={} error={}", stream_id, stream_registry_error_to_string(error));

        return json_error_response(request, 500, "create subscriber session failed");
    }

    const auto& session = *session_result;

    session->set_local_answer(generated_answer->sdp,
                              std::move(generated_answer->local_ice),
                              std::move(generated_answer->local_fingerprint),
                              generated_answer->sdp_session_id,
                              generated_answer->sdp_session_version);

    WEBRTC_LOG_INFO("WHEP create subscriber stream={} session={} offer_size={} answer_size={} media_count={}",
                    session->stream_id(),
                    session->session_id(),
                    offer.size(),
                    session->local_sdp_answer().size(),
                    session->remote_offer_summary().media.size());

    auto response = sdp_response(request, 201, session->local_sdp_answer());

    response->set(http::field::location, "/whep/session/" + session->session_id());

    return response;
}

http_response_ptr whep_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHEP patch session={} body_size={}", session_id, request.req.body().size());

    if (!is_application_json(request))
    {
        return json_error_response(request, 415, "unsupported media type, expected application/json");
    }

    auto session = registry_->find_subscriber_by_session_id(session_id);

    if (session == nullptr)
    {
        return json_error_response(request, 404, "subscriber session not found");
    }

    auto candidate = make_remote_ice_candidate_from_http_body(request.req.body());

    if (!candidate)
    {
        WEBRTC_LOG_WARN("WHEP trickle ice candidate invalid session={} error={}", session_id, candidate.error());

        std::string message;
        message.reserve(candidate.error().size() + 32);

        message.append("invalid trickle ice candidate: ");

        message.append(candidate.error());

        return json_error_response(request, 400, message);
    }

    const bool end_of_candidates = candidate->end_of_candidates;

    const std::size_t candidate_size = candidate->candidate.size();

    const std::string sdp_mid = candidate->sdp_mid;

    const int sdp_mline_index = candidate->sdp_mline_index;

    auto add_result = session->add_remote_ice_candidate(std::move(*candidate));

    if (!add_result)
    {
        WEBRTC_LOG_WARN(
            "WHEP trickle ice candidate rejected stream={} session={} error={}", session->stream_id(), session->session_id(), add_result.error());

        std::string message;
        message.reserve(add_result.error().size() + 32);

        message.append("trickle ice candidate rejected: ");

        message.append(add_result.error());

        return json_error_response(request, 400, message);
    }

    WEBRTC_LOG_INFO(
        "WHEP trickle ice candidate accepted stream={} session={} mid={} mline={} end={} candidate_size={} total_candidates={} completed={}",
        session->stream_id(),
        session->session_id(),
        sdp_mid,
        sdp_mline_index,
        end_of_candidates ? 1 : 0,
        candidate_size,
        session->remote_ice_candidates().size(),
        session->remote_ice_completed() ? 1 : 0);

    auto response = create_response(request, 204, "");

    add_common_headers(response);

    return response;
}
http_response_ptr whep_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHEP delete session={}", session_id);

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
    response->set(http::field::access_control_allow_origin, "*");

    response->set(http::field::access_control_expose_headers, "Location, ETag");

    response->set(http::field::cache_control, "no-store");
}
}    // namespace webrtc
