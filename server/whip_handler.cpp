#include "server/whip_handler.h"

#include <string>
#include <utility>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

std::string json_error_body(std::string_view message)
{
    std::string body;
    body.reserve(message.size() + 16);
    body.append(R"({"error":")");
    body.append(message);
    body.append(R"("})");
    return body;
}
}    // namespace

whip_handler::whip_handler(std::shared_ptr<stream_registry> registry) : registry_(std::move(registry)) {}

http_response_ptr whip_handler::create_publisher(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    auto result = registry_->create_publisher_session(stream_id, offer);

    if (result.error == stream_registry_error::stream_already_has_publisher)
    {
        WEBRTC_LOG_WARN(
            "WHIP create publisher conflict stream={} existing_session={}", stream_id, result.session ? result.session->session_id() : "");
        return json_error_response(request, 409, "stream already has publisher");
    }

    if (result.error != stream_registry_error::none || result.session == nullptr)
    {
        WEBRTC_LOG_ERROR("WHIP create publisher failed stream={} error={}", stream_id, stream_registry_error_to_string(result.error));
        return json_error_response(request, 500, "create publisher session failed");
    }

    auto session = result.session;

    WEBRTC_LOG_INFO("WHIP create publisher stream={} session={} sdp_size={}", session->stream_id(), session->session_id(), offer.size());

    std::string body;
    body.reserve(256);
    body.append(R"({"type":"publisher","stream_id":")");
    body.append(session->stream_id());
    body.append(R"(","session_id":")");
    body.append(session->session_id());
    body.append(R"(","state":")");
    body.append(session->state_string());
    body.append(R"(","message":"SDP answer not implemented"})");

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
    if (result.error == stream_registry_error::publisher_session_not_found)
    {
        return json_error_response(request, 404, "publisher session not found");
    }

    if (result.error != stream_registry_error::none)
    {
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
    return json_response(request, code, json_error_body(message));
}

void whip_handler::add_common_headers(const http_response_ptr& response)
{
    response->set(http::field::access_control_allow_origin, "*");
    response->set(http::field::cache_control, "no-store");
}
}    // namespace webrtc
