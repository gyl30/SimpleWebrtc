#include <string>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/whep_handler.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

void add_common_headers(const http_response_ptr& response)
{
    response->set(http::field::access_control_allow_origin, "*");
    response->set(http::field::cache_control, "no-store");
}

http_response_ptr json_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);
    content.push_back('\n');

    auto response = create_response(request, code, content);
    response->set(http::field::content_type, "application/json; charset=utf-8");
    add_common_headers(response);
    return response;
}
}    // namespace

http_response_ptr whep_handler::create_subscriber(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    WEBRTC_LOG_INFO("WHEP create subscriber stream={} sdp_size={}", stream_id, offer.size());

    return json_response(request, 501, R"({"error":"WHEP SDP handling not implemented"})");
}

http_response_ptr whep_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHEP patch session={} body_size={}", session_id, request.req.body().size());

    return json_response(request, 501, R"({"error":"WHEP trickle ICE not implemented"})");
}

http_response_ptr whep_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHEP delete session={}", session_id);

    return json_response(request, 501, R"({"error":"WHEP delete session not implemented"})");
}
}    // namespace webrtc
