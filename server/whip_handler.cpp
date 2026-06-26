#include "server/whip_handler.h"

#include <string>
#include <string_view>
#include <utility>

#include <boost/beast/http.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "log/log.h"
#include "net/http.h"
#include "util/timestamp.h"
#include "ice/ice_candidate.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "server/trickle_ice_json.h"
#include "signaling/sdp/sdp_parser.h"
#include "signaling/sdp/sdp_summary.h"
#include "server/trickle_ice_metrics.h"
#include "server/trickle_ice_sdpfrag.h"
#include "signaling/sdp/sdp_offer_validator.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

inline constexpr std::string_view k_application_json = "application/json";

inline constexpr std::string_view k_application_trickle_ice_sdpfrag = "application/trickle-ice-sdpfrag";

using remote_ice_candidate_list_result = std::expected<std::vector<remote_ice_candidate>, std::string>;

std::string_view beast_string_view_to_std_string_view(boost::beast::string_view value) { return std::string_view(value.data(), value.size()); }

bool content_type_matches(http_request_t& request, std::string_view expected_content_type)
{
    const auto content_type_field = request.req[http::field::content_type];

    const std::string_view content_type = beast_string_view_to_std_string_view(content_type_field);

    if (content_type.empty())
    {
        return false;
    }

    if (boost::algorithm::iequals(content_type, expected_content_type))
    {
        return true;
    }

    if (!boost::algorithm::istarts_with(content_type, expected_content_type))
    {
        return false;
    }

    if (content_type.size() <= expected_content_type.size())
    {
        return false;
    }

    return content_type[expected_content_type.size()] == ';';
}

bool is_application_json(http_request_t& request) { return content_type_matches(request, k_application_json); }

bool is_application_trickle_ice_sdpfrag(http_request_t& request) { return content_type_matches(request, k_application_trickle_ice_sdpfrag); }

uint64_t now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }

remote_ice_candidate_list_result make_remote_ice_candidates_from_json_body(std::string_view body, uint64_t received_at_milliseconds)
{
    auto request = parse_trickle_ice_candidate_request(body);

    if (!request)
    {
        return std::unexpected(request.error());
    }

    auto candidate = make_remote_ice_candidate_from_trickle_request(*request, received_at_milliseconds);

    if (!candidate)
    {
        return std::unexpected(candidate.error());
    }

    std::vector<remote_ice_candidate> candidates;

    candidates.push_back(std::move(*candidate));

    return candidates;
}

remote_ice_candidate_list_result make_remote_ice_candidates_from_http_body(http_request_t& request)
{
    const uint64_t received_at_milliseconds = now_milliseconds();

    if (is_application_json(request))
    {
        return make_remote_ice_candidates_from_json_body(request.req.body(), received_at_milliseconds);
    }

    if (is_application_trickle_ice_sdpfrag(request))
    {
        return parse_trickle_ice_sdpfrag(request.req.body(), received_at_milliseconds);
    }

    return std::unexpected(std::string("unsupported media type, expected application/json or application/trickle-ice-sdpfrag"));
}

std::string describe_trickle_ice_content_type(http_request_t& request)
{
    if (is_application_json(request))
    {
        return std::string("application/json");
    }

    if (is_application_trickle_ice_sdpfrag(request))
    {
        return std::string("application/trickle-ice-sdpfrag");
    }

    const auto content_type_field = request.req[http::field::content_type];

    return std::string(content_type_field.data(), content_type_field.size());
}
trickle_ice_patch_content_kind trickle_ice_patch_content_kind_from_request(http_request_t& request)
{
    if (is_application_json(request))
    {
        return trickle_ice_patch_content_kind::kJson;
    }

    if (is_application_trickle_ice_sdpfrag(request))
    {
        return trickle_ice_patch_content_kind::kSdpfrag;
    }

    return trickle_ice_patch_content_kind::kUnsupported;
}

std::size_t count_end_of_candidates(const std::vector<remote_ice_candidate>& candidates)
{
    std::size_t count = 0;

    for (const auto& candidate : candidates)
    {
        if (candidate.end_of_candidates)
        {
            count += 1;
        }
    }

    return count;
}

std::size_t count_candidate_bytes(const std::vector<remote_ice_candidate>& candidates)
{
    std::size_t count = 0;

    for (const auto& candidate : candidates)
    {
        count += candidate.candidate.size();
    }

    return count;
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

whip_handler::whip_handler(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory)
    : registry_(std::move(registry)), answer_factory_(std::move(answer_factory))
{
}

http_response_ptr whip_handler::create_publisher(http_request_t& request, std::string_view stream_id)
{
    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHIP answer factory is null");

        return json_error_response(request, 500, "answer factory not initialized");
    }

    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);
    if (!description)
    {
        WEBRTC_LOG_WARN("WHIP parse SDP offer failed stream={} error={}", stream_id, description.error());

        std::string error_message;
        error_message.reserve(description.error().size() + 20);
        error_message.append("invalid sdp offer: ");
        error_message.append(description.error());

        return json_error_response(request, 400, error_message);
    }

    WEBRTC_LOG_INFO("WHIP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHIP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());

        std::string error_message;
        error_message.reserve(offer_summary.error().size() + 24);
        error_message.append("invalid webrtc offer: ");
        error_message.append(offer_summary.error());

        return json_error_response(request, 400, error_message);
    }

    auto validation_result = sdp::validate_whip_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHIP validate offer failed stream={} error={}", stream_id, validation_result.error());

        std::string error_message;
        error_message.reserve(validation_result.error().size() + 20);
        error_message.append("invalid whip offer: ");
        error_message.append(validation_result.error());

        return json_error_response(request, 400, error_message);
    }

    WEBRTC_LOG_INFO("WHIP validated WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

    auto generated_answer = answer_factory_->build_whip_answer(stream_id, *offer_summary);

    if (!generated_answer)
    {
        WEBRTC_LOG_WARN("WHIP build SDP answer failed stream={} error={}", stream_id, generated_answer.error());

        std::string error_message;
        error_message.reserve(generated_answer.error().size() + 32);
        error_message.append("failed to build sdp answer: ");
        error_message.append(generated_answer.error());

        return json_error_response(request, 400, error_message);
    }

    auto session_result = registry_->create_publisher_session(std::string(stream_id), offer, std::move(*offer_summary));

    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::stream_already_has_publisher)
        {
            WEBRTC_LOG_WARN("WHIP create publisher conflict stream={}", stream_id);

            return json_error_response(request, 409, "stream already has publisher");
        }

        WEBRTC_LOG_ERROR("WHIP create publisher failed stream={} error={}", stream_id, stream_registry_error_to_string(error));

        return json_error_response(request, 500, "create publisher session failed");
    }

    const auto& session = *session_result;

    session->set_local_answer(generated_answer->sdp,
                              std::move(generated_answer->local_ice),
                              std::move(generated_answer->local_fingerprint),
                              generated_answer->sdp_session_id,
                              generated_answer->sdp_session_version);

    WEBRTC_LOG_INFO("WHIP create publisher stream={} session={} offer_size={} answer_size={} media_count={}",
                    session->stream_id(),
                    session->session_id(),
                    offer.size(),
                    session->local_sdp_answer().size(),
                    session->remote_offer_summary().media.size());

    auto response = sdp_response(request, 201, session->local_sdp_answer());

    response->set(http::field::location, "/whip/session/" + session->session_id());

    return response;
}

http_response_ptr whip_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO(
        "WHIP patch session={} body_size={} content_type={}", session_id, request.req.body().size(), describe_trickle_ice_content_type(request));

    global_trickle_ice_metrics().record_patch_request(trickle_ice_patch_content_kind_from_request(request));

    if (!is_application_json(request) && !is_application_trickle_ice_sdpfrag(request))
    {
        global_trickle_ice_metrics().record_patch_failed();

        return json_error_response(request, 415, "unsupported media type, expected application/json or application/trickle-ice-sdpfrag");
    }

    if (trickle_ice_patch_body_too_large(request.req.body()))
    {
        global_trickle_ice_metrics().record_body_too_large();
        global_trickle_ice_metrics().record_patch_failed();

        WEBRTC_LOG_WARN("WHIP trickle ice patch body too large session={} body_size={} limit={}",
                        session_id,
                        request.req.body().size(),
                        k_trickle_ice_max_patch_body_bytes);

        return json_error_response(request, 413, "trickle ice patch body too large");
    }

    auto session = registry_->find_publisher_by_session_id(session_id);

    if (session == nullptr)
    {
        global_trickle_ice_metrics().record_session_not_found();
        global_trickle_ice_metrics().record_patch_failed();

        return json_error_response(request, 404, "publisher session not found");
    }

    auto candidates = make_remote_ice_candidates_from_http_body(request);

    if (!candidates)
    {
        global_trickle_ice_metrics().record_parse_failed();
        global_trickle_ice_metrics().record_patch_failed();

        WEBRTC_LOG_WARN("WHIP trickle ice candidates invalid session={} error={}", session_id, candidates.error());

        std::string message;

        message.reserve(candidates.error().size() + 32);

        message.append("invalid trickle ice candidates: ");

        message.append(candidates.error());

        return json_error_response(request, 400, message);
    }

    if (trickle_ice_candidate_batch_too_large(candidates->size()))
    {
        global_trickle_ice_metrics().record_too_many_candidates();
        global_trickle_ice_metrics().record_patch_failed();

        WEBRTC_LOG_WARN("WHIP trickle ice patch too many candidates session={} candidates={} limit={}",
                        session_id,
                        candidates->size(),
                        k_trickle_ice_max_candidates_per_patch);

        return json_error_response(request, 413, "too many trickle ice candidates in one patch");
    }

    const std::size_t received_count = candidates->size();

    const std::size_t end_of_candidates_received_count = count_end_of_candidates(*candidates);

    const std::size_t received_candidate_bytes = count_candidate_bytes(*candidates);

    global_trickle_ice_metrics().record_candidate_batch(received_count, end_of_candidates_received_count, received_candidate_bytes);

    std::size_t accepted_count = 0;
    std::size_t end_of_candidates_count = 0;
    std::size_t total_candidate_bytes = 0;

    for (auto& candidate : *candidates)
    {
        const bool end_of_candidates = candidate.end_of_candidates;

        const std::size_t candidate_size = candidate.candidate.size();

        const std::string sdp_mid = candidate.sdp_mid;

        const int sdp_mline_index = candidate.sdp_mline_index;

        auto add_result = session->add_remote_ice_candidate(std::move(candidate));

        if (!add_result)
        {
            global_trickle_ice_metrics().record_candidate_rejected();
            global_trickle_ice_metrics().record_patch_failed();

            WEBRTC_LOG_WARN("WHIP trickle ice candidate rejected stream={} session={} mid={} mline={} end={} error={}",
                            session->stream_id(),
                            session->session_id(),
                            sdp_mid,
                            sdp_mline_index,
                            end_of_candidates ? 1 : 0,
                            add_result.error());

            std::string message;

            message.reserve(add_result.error().size() + 32);

            message.append("trickle ice candidate rejected: ");

            message.append(add_result.error());

            return json_error_response(request, 400, message);
        }

        global_trickle_ice_metrics().record_candidate_accepted(end_of_candidates);

        accepted_count += 1;

        total_candidate_bytes += candidate_size;

        if (end_of_candidates)
        {
            end_of_candidates_count += 1;
        }

        WEBRTC_LOG_DEBUG("WHIP trickle ice candidate accepted stream={} session={} mid={} mline={} end={} candidate_size={}",
                         session->stream_id(),
                         session->session_id(),
                         sdp_mid,
                         sdp_mline_index,
                         end_of_candidates ? 1 : 0,
                         candidate_size);
    }

    global_trickle_ice_metrics().record_patch_success();

    WEBRTC_LOG_INFO(
        "WHIP trickle ice patch accepted stream={} session={} candidates={} end_of_candidates={} candidate_bytes={} total_candidates={} completed={}",
        session->stream_id(),
        session->session_id(),
        accepted_count,
        end_of_candidates_count,
        total_candidate_bytes,
        session->remote_ice_candidates().size(),
        session->remote_ice_completed() ? 1 : 0);

    auto response = create_response(request, 204, "");

    add_common_headers(response);

    return response;
}

http_response_ptr whip_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHIP delete session={}", session_id);

    auto result = registry_->remove_publisher_session(session_id);

    if (!result)
    {
        if (result.error() == stream_registry_error::publisher_session_not_found)
        {
            return json_error_response(request, 404, "publisher session not found");
        }

        WEBRTC_LOG_ERROR("WHIP delete publisher failed session={} error={}", session_id, stream_registry_error_to_string(result.error()));

        return json_error_response(request, 500, "delete publisher session failed");
    }

    auto response = create_response(request, 204, "");

    add_common_headers(response);

    return response;
}

http_response_ptr whip_handler::json_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);
    content.push_back('\n');

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "application/json; charset=utf-8");

    add_common_headers(response);

    return response;
}

http_response_ptr whip_handler::json_error_response(http_request_t& request, int code, std::string_view message)
{
    return json_response(request, code, make_error_response_body(message));
}

http_response_ptr whip_handler::sdp_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "application/sdp");

    add_common_headers(response);

    return response;
}

void whip_handler::add_common_headers(const http_response_ptr& response)
{
    response->set(http::field::access_control_allow_origin, "*");

    response->set(http::field::cache_control, "no-store");

    response->set(http::field::access_control_expose_headers, std::string(k_trickle_ice_expose_headers_value));

    set_trickle_ice_patch_headers(response);
}
}    // namespace webrtc
