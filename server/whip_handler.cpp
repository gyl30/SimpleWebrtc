#include "server/whip_handler.h"

#include <string>
#include <utility>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "signaling/sdp/sdp_parser.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

std::string json_escape(std::string_view value)
{
    std::string result;
    result.reserve(value.size());

    for (const auto ch : value)
    {
        switch (ch)
        {
            case '\\':
                result += "\\\\";
                break;
            case '"':
                result += "\\\"";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
            {
                const auto byte = static_cast<unsigned char>(ch);
                if (byte < 0x20)
                {
                    constexpr char digits[] = "0123456789abcdef";
                    result += "\\u00";
                    result.push_back(digits[byte >> 4]);
                    result.push_back(digits[byte & 0x0f]);
                }
                else
                {
                    result.push_back(ch);
                }
                break;
            }
        }
    }

    return result;
}

std::string json_error_body(std::string_view message)
{
    std::string body;
    body.reserve(message.size() + 32);
    body.append(R"({"error":")");
    body.append(json_escape(message));
    body.append(R"("})");
    return body;
}
}    // namespace

whip_handler::whip_handler(std::shared_ptr<stream_registry> registry) : registry_(std::move(registry)) {}

http_response_ptr whip_handler::create_publisher(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    auto sdp_parse_result = sdp::parse_session_description(offer);
    if (!sdp_parse_result.success)
    {
        WEBRTC_LOG_WARN("WHIP parse SDP offer failed stream={} error={}", stream_id, sdp_parse_result.error);

        std::string error_message;
        error_message.reserve(sdp_parse_result.error.size() + 20);
        error_message.append("invalid sdp offer: ");
        error_message.append(sdp_parse_result.error);

        return json_error_response(request, 400, error_message);
    }

    WEBRTC_LOG_INFO("WHIP parsed SDP offer stream={} media_count={}", stream_id, sdp_parse_result.description.media_descriptions.size());

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
    body.append(json_escape(session->stream_id()));
    body.append(R"(","session_id":")");
    body.append(json_escape(session->session_id()));
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
