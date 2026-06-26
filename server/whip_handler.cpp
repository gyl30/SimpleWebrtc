#include "server/whip_handler.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
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

constexpr std::string_view k_cors_private_network_header = "Access-Control-Allow-Private-Network";

std::string make_prefixed_error(std::string_view prefix, std::string_view error)
{
    std::string message;

    message.reserve(prefix.size() + error.size());

    message.append(prefix);

    message.append(error);

    return message;
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

        return json_error_response(request, 400, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    WEBRTC_LOG_INFO("WHIP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHIP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());

        return json_error_response(request, 400, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whip_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHIP validate WebRTC offer failed stream={} error={}", stream_id, validation_result.error());

        return json_error_response(request, 400, make_prefixed_error("invalid whip offer: ", validation_result.error()));
    }

    WEBRTC_LOG_INFO("WHIP validated WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHIP answer factory is not configured stream={}", stream_id);

        return json_error_response(request, 500, "answer factory is not configured");
    }

    auto answer = answer_factory_->build_whip_answer(stream_id, *offer_summary);

    if (!answer)
    {
        WEBRTC_LOG_WARN("WHIP build SDP answer failed stream={} error={}", stream_id, answer.error());

        return json_error_response(request, 400, make_prefixed_error("cannot build sdp answer: ", answer.error()));
    }

    auto session_result = registry_->create_publisher_session(std::string(stream_id), offer, std::move(*offer_summary));

    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::stream_already_has_publisher)
        {
            WEBRTC_LOG_WARN("WHIP create publisher failed stream={} already has publisher", stream_id);

            return json_error_response(request, 409, "stream already has publisher");
        }

        WEBRTC_LOG_ERROR("WHIP create publisher failed stream={} error={}", stream_id, stream_registry_error_to_string(error));

        return json_error_response(request, 500, "create publisher session failed");
    }

    const auto& session = *session_result;

    generated_sdp_answer generated_answer = std::move(*answer);

    session->set_local_answer(std::move(generated_answer.sdp),
                              std::move(generated_answer.local_ice),
                              std::move(generated_answer.local_fingerprint),
                              generated_answer.sdp_session_id,
                              generated_answer.sdp_session_version);

    WEBRTC_LOG_INFO("WHIP create publisher stream={} session={} sdp_size={} media_count={}",
                    session->stream_id(),
                    session->session_id(),
                    offer.size(),
                    session->remote_offer_summary().media.size());

    auto response = sdp_response(request, 201, session->local_sdp_answer());

    response->set(http::field::location, "/whip/session/" + session->session_id());

    set_session_resource_headers(response, *session);

    return response;
}

http_response_ptr whip_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    auto session = registry_->find_publisher_by_session_id(session_id);

    return handle_trickle_ice_patch_request(
        request,
        session_id,
        session,
        "WHIP",
        "publisher session not found",
        [this, &request](int status, std::string_view message) -> http_response_ptr { return json_error_response(request, status, message); },
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
        return json_error_response(request, 404, "publisher session not found");
    }

    auto precondition = validate_session_if_match(request, *session);

    if (!precondition)
    {
        WEBRTC_LOG_WARN("WHIP delete session precondition failed session={} error={}", session_id, precondition.error());

        return json_error_response(request, 412, precondition.error());
    }

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
