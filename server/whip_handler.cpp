#include "server/whip_handler.h"

#include <string>
#include <string_view>
#include <utility>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "signaling/sdp/sdp_parser.h"
#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;
}    // namespace

whip_handler::whip_handler(std::shared_ptr<stream_registry> registry) : registry_(std::move(registry)) {}

http_response_ptr whip_handler::create_publisher(http_request_t& request, std::string_view stream_id)
{
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

    WEBRTC_LOG_INFO("WHIP extracted WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

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

    WEBRTC_LOG_INFO("WHIP create publisher stream={} session={} sdp_size={} media_count={}",
                    session->stream_id(),
                    session->session_id(),
                    offer.size(),
                    session->remote_offer_summary().media.size());

    const auto body = make_session_created_response_body(
        "publisher", session->stream_id(), session->session_id(), session->state_string(), "SDP answer not implemented");

    auto response = json_response(request, 201, body);
    response->set(http::field::location, "/whip/session/" + session->session_id());

    return response;
}

http_response_ptr whip_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHIP patch session={} body_size={}", session_id, request.req.body().size());

    auto session = registry_->find_publisher_by_session_id(session_id);
    if (session == nullptr)
    {
        return json_error_response(request, 404, "publisher session not found");
    }

    return json_error_response(request, 501, "WHIP trickle ICE not implemented");
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

void whip_handler::add_common_headers(const http_response_ptr& response)
{
    response->set(http::field::access_control_allow_origin, "*");

    response->set(http::field::cache_control, "no-store");
}
}    // namespace webrtc
