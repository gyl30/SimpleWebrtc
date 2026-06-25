#include "server/router.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/beast/http.hpp>

#include "log/log.h"
#include "media/media_router.h"
#include "media/media_router_stats_json.h"
#include "media/media_router_stats_prometheus.h"
#include "net/http.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

inline constexpr std::string_view k_application_sdp = "application/sdp";

inline constexpr std::string_view k_whip_prefix = "/whip/";

inline constexpr std::string_view k_whep_prefix = "/whep/";

inline constexpr std::string_view k_whip_session_prefix = "/whip/session/";

inline constexpr std::string_view k_whep_session_prefix = "/whep/session/";

inline constexpr std::string_view k_media_stats_path = "/api/stats/media";

inline constexpr std::string_view k_prometheus_metrics_path = "/metrics";

std::string_view remove_query(std::string_view target)
{
    const std::size_t query_position = target.find('?');

    if (query_position == std::string_view::npos)
    {
        return target;
    }

    return target.substr(0, query_position);
}

bool match_single_value_path(std::string_view path, std::string_view prefix, std::string_view& value)
{
    if (!boost::algorithm::starts_with(path, prefix))
    {
        return false;
    }

    value = path.substr(prefix.size());

    if (value.empty())
    {
        return false;
    }

    return value.find('/') == std::string_view::npos;
}

std::string json_error_body(std::string_view message)
{
    std::string body;
    body.reserve(message.size() + 16);
    body.append(R"({"error":")");
    body.append(message);
    body.append(R"("})");
    return body;
}

std::string beast_string_view_to_string(boost::beast::string_view value) { return std::string(value.data(), value.size()); }

std::string_view beast_string_view_to_std_string_view(boost::beast::string_view value) { return std::string_view(value.data(), value.size()); }
}    // namespace

router::router(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory)
    : router(std::move(registry), std::move(answer_factory), nullptr)
{
}

router::router(std::shared_ptr<stream_registry> registry,
               std::shared_ptr<webrtc_answer_factory> answer_factory,
               std::shared_ptr<media_router> media_router)
    : registry_(std::move(registry)),
      answer_factory_(std::move(answer_factory)),
      media_router_(std::move(media_router)),
      whip_(registry_, answer_factory_),
      whep_(registry_, answer_factory_)
{
}

http_response_ptr router::handle(http_request_t& request)
{
    const auto method = request.req.method();

    const std::string_view path = request_path(request);

    WEBRTC_LOG_DEBUG("http route method={} path={}", beast_string_view_to_string(request.req.method_string()), path);

    if (method == http::verb::options)
    {
        return handle_options(request);
    }

    if (method == http::verb::get && path == "/api/health")
    {
        return handle_health(request);
    }

    if (method == http::verb::get && path == "/api/version")
    {
        return handle_version(request);
    }

    if (path == k_media_stats_path)
    {
        return handle_media_stats(request);
    }

    if (path == k_prometheus_metrics_path)
    {
        return handle_prometheus_metrics(request);
    }

    std::string_view session_id;

    if (match_single_value_path(path, k_whip_session_prefix, session_id))
    {
        return handle_whip_session(request, session_id);
    }

    if (match_single_value_path(path, k_whep_session_prefix, session_id))
    {
        return handle_whep_session(request, session_id);
    }

    std::string_view stream_id;

    if (match_single_value_path(path, k_whip_prefix, stream_id))
    {
        return handle_whip_create(request, stream_id);
    }

    if (match_single_value_path(path, k_whep_prefix, stream_id))
    {
        return handle_whep_create(request, stream_id);
    }

    return not_found(request);
}

void router::set_media_router(std::shared_ptr<media_router> media_router) { media_router_ = std::move(media_router); }

http_response_ptr router::handle_options(http_request_t& request)
{
    auto response = text_response(request, 204, "");

    response->set(http::field::access_control_allow_methods, "GET, POST, PATCH, DELETE, OPTIONS");

    response->set(http::field::access_control_allow_headers, "Content-Type, Authorization, If-Match");

    response->set(http::field::access_control_expose_headers, "Location, ETag");

    return response;
}

http_response_ptr router::handle_health(http_request_t& request) { return json_response(request, 200, R"({"status":"ok"})"); }

http_response_ptr router::handle_version(http_request_t& request)
{
    return json_response(request, 200, R"({"name":"SimpleWebrtc","version":"0.1"})");
}

http_response_ptr router::handle_media_stats(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (media_router_ == nullptr)
    {
        return json_response(request, 503, json_error_body("media router unavailable"));
    }

    const media_router_stats_snapshot snapshot = media_router_->get_stats_snapshot();

    const std::string body = media_router_stats_snapshot_to_json(snapshot);

    return json_response(request, 200, body);
}

http_response_ptr router::handle_prometheus_metrics(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (media_router_ == nullptr)
    {
        return text_response(request, 503, "media router unavailable");
    }

    const media_router_stats_snapshot snapshot = media_router_->get_stats_snapshot();

    const std::string body = media_router_stats_snapshot_to_prometheus(snapshot);

    return prometheus_response(request, 200, body);
}

http_response_ptr router::handle_whip_create(http_request_t& request, std::string_view stream_id)
{
    if (request.req.method() != http::verb::post)
    {
        return method_not_allowed(request);
    }

    if (!is_valid_resource_id(stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (!is_application_sdp(request))
    {
        return unsupported_media_type(request);
    }

    return whip_.create_publisher(request, stream_id);
}

http_response_ptr router::handle_whip_session(http_request_t& request, std::string_view session_id)
{
    if (!is_valid_resource_id(session_id))
    {
        return bad_request(request, "invalid session id");
    }

    const auto method = request.req.method();

    if (method == http::verb::patch)
    {
        return whip_.patch_session(request, session_id);
    }

    if (method == http::verb::delete_)
    {
        return whip_.delete_session(request, session_id);
    }

    return method_not_allowed(request);
}

http_response_ptr router::handle_whep_create(http_request_t& request, std::string_view stream_id)
{
    if (request.req.method() != http::verb::post)
    {
        return method_not_allowed(request);
    }

    if (!is_valid_resource_id(stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (!is_application_sdp(request))
    {
        return unsupported_media_type(request);
    }

    return whep_.create_subscriber(request, stream_id);
}

http_response_ptr router::handle_whep_session(http_request_t& request, std::string_view session_id)
{
    if (!is_valid_resource_id(session_id))
    {
        return bad_request(request, "invalid session id");
    }

    const auto method = request.req.method();

    if (method == http::verb::patch)
    {
        return whep_.patch_session(request, session_id);
    }

    if (method == http::verb::delete_)
    {
        return whep_.delete_session(request, session_id);
    }

    return method_not_allowed(request);
}

http_response_ptr router::not_found(http_request_t& request) { return json_response(request, 404, R"({"error":"not found"})"); }

http_response_ptr router::method_not_allowed(http_request_t& request)
{
    auto response = json_response(request, 405, R"({"error":"method not allowed"})");

    response->set(http::field::allow, "GET, POST, PATCH, DELETE, OPTIONS");

    return response;
}

http_response_ptr router::bad_request(http_request_t& request, std::string_view message)
{
    return json_response(request, 400, json_error_body(message));
}

http_response_ptr router::unsupported_media_type(http_request_t& request)
{
    return json_response(request, 415, R"({"error":"unsupported media type, expected application/sdp"})");
}

http_response_ptr router::not_implemented(http_request_t& request, std::string_view message)
{
    return json_response(request, 501, json_error_body(message));
}

http_response_ptr router::json_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);
    content.push_back('\n');

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "application/json; charset=utf-8");

    add_common_headers(response);

    return response;
}

http_response_ptr router::text_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    if (!content.empty() && content.back() != '\n')
    {
        content.push_back('\n');
    }

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "text/plain; charset=utf-8");

    add_common_headers(response);

    return response;
}

http_response_ptr router::prometheus_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    if (!content.empty() && content.back() != '\n')
    {
        content.push_back('\n');
    }

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "text/plain; version=0.0.4; charset=utf-8");

    add_common_headers(response);

    return response;
}

void router::add_common_headers(const http_response_ptr& response)
{
    response->set(http::field::access_control_allow_origin, "*");

    response->set(http::field::cache_control, "no-store");
}

std::string_view router::request_path(http_request_t& request)
{
    const std::string_view target = beast_string_view_to_std_string_view(request.req.target());

    const std::string_view path = remove_query(target);

    if (path.empty())
    {
        return "/";
    }

    return path;
}

bool router::is_application_sdp(http_request_t& request)
{
    const auto content_type_field = request.req[http::field::content_type];

    const std::string_view content_type = beast_string_view_to_std_string_view(content_type_field);

    if (content_type.empty())
    {
        return false;
    }

    if (boost::algorithm::iequals(content_type, k_application_sdp))
    {
        return true;
    }

    if (!boost::algorithm::istarts_with(content_type, k_application_sdp))
    {
        return false;
    }

    if (content_type.size() <= k_application_sdp.size())
    {
        return false;
    }

    return content_type[k_application_sdp.size()] == ';';
}

bool router::is_valid_resource_id(std::string_view value)
{
    if (value.empty() || value.size() > 128)
    {
        return false;
    }

    return std::ranges::all_of(value,
                               [](char c)
                               {
                                   const auto ch = static_cast<unsigned char>(c);

                                   return std::isalnum(ch) != 0 || c == '-' || c == '_' || c == '.';
                               });
}
}    // namespace webrtc
