#include "server/router.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/beast/http.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "server/http_error_response.h"
#include "server/trickle_ice_metrics.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

constexpr std::string_view k_cors_allow_methods = "GET, POST, PATCH, DELETE, OPTIONS";

constexpr std::string_view k_cors_allow_headers =
    "Content-Type, Authorization, If-Match, If-None-Match, Cache-Control, X-Requested-With, WHEP-Reconnect-Session, WHIP-Replace-Session";

constexpr std::string_view k_cors_max_age_seconds = "600";

inline constexpr std::string_view k_application_sdp = "application/sdp";

inline constexpr std::size_t k_max_sdp_offer_body_bytes = 256UL * 1024UL;

inline constexpr std::string_view k_sdp_offer_empty_error = "sdp_offer_empty";

inline constexpr std::string_view k_sdp_offer_body_too_large_error = "sdp_offer_body_too_large";

inline constexpr std::string_view k_whip_prefix = "/whip/";

inline constexpr std::string_view k_whep_prefix = "/whep/";

inline constexpr std::string_view k_whip_session_prefix = "/whip/session/";

inline constexpr std::string_view k_whep_session_prefix = "/whep/session/";

inline constexpr std::string_view k_sessions_path = "/api/sessions";

inline constexpr std::string_view k_sessions_prefix = "/api/sessions/";

inline constexpr std::string_view k_streams_prefix = "/api/streams/";

inline constexpr std::string_view k_streams_path = "/api/streams";

inline constexpr std::string_view k_api_prefix = "/api/";

inline constexpr std::string_view k_health_path = "/api/health";

inline constexpr std::string_view k_version_path = "/api/version";

inline constexpr std::string_view k_bearer_prefix = "Bearer ";

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

http_response_ptr validate_sdp_offer_body(http_request_t& request, std::string_view protocol_name, std::string_view stream_id)
{
    const std::string& body = request.req.body();

    if (body.empty())
    {
        WEBRTC_LOG_WARN("{} SDP offer body empty stream={}", protocol_name, stream_id);

        return make_json_http_error_response(request, 400, k_sdp_offer_empty_error, "sdp offer body is empty");
    }

    if (body.size() > k_max_sdp_offer_body_bytes)
    {
        WEBRTC_LOG_WARN(
            "{} SDP offer body too large stream={} body_size={} limit={}", protocol_name, stream_id, body.size(), k_max_sdp_offer_body_bytes);

        return make_json_http_error_response(request, 413, k_sdp_offer_body_too_large_error, "sdp offer body is too large");
    }

    return nullptr;
}
bool constant_time_equals(std::string_view left, std::string_view right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    unsigned char difference = 0;

    for (std::size_t index = 0; index < left.size(); ++index)
    {
        difference = static_cast<unsigned char>(
            difference | static_cast<unsigned char>(static_cast<unsigned char>(left[index]) ^ static_cast<unsigned char>(right[index])));
    }

    return difference == 0;
}

std::optional<std::string_view> bearer_token_from_authorization(std::string_view authorization)
{
    if (authorization.size() <= k_bearer_prefix.size())
    {
        return std::nullopt;
    }

    if (!authorization.starts_with(k_bearer_prefix))
    {
        return std::nullopt;
    }

    std::string_view token = authorization.substr(k_bearer_prefix.size());

    if (token.empty())
    {
        return std::nullopt;
    }

    return token;
}

bool stream_has_publisher_snapshot(std::string_view stream_id, const std::vector<stream_session_lifecycle_snapshot>& snapshots)
{
    return std::ranges::any_of(snapshots,
                               [stream_id](const stream_session_lifecycle_snapshot& snapshot)
                               { return snapshot.kind == stream_session_kind::publisher && std::string_view(snapshot.stream_id) == stream_id; });
}

std::optional<stream_session_lifecycle_snapshot> find_session_snapshot(std::string_view session_id,
                                                                       const std::vector<stream_session_lifecycle_snapshot>& snapshots)
{
    if (session_id.empty())
    {
        return std::nullopt;
    }

    for (const auto& snapshot : snapshots)
    {
        if (std::string_view(snapshot.session_id) == session_id)
        {
            return snapshot;
        }
    }

    return std::nullopt;
}

std::string_view beast_string_view_to_std_string_view(boost::beast::string_view value) { return {value.data(), value.size()}; }

std::string beast_string_view_to_string(boost::beast::string_view value) { return std::string(value.data(), value.size()); }

std::string make_trickle_ice_metrics_json(const trickle_ice_metrics_snapshot& snapshot)
{
    std::string body(R"({"trickle_ice":)");

    body.append(trickle_ice_metrics_snapshot_to_json(snapshot));
    body.push_back('}');

    return body;
}

}    // namespace

router::router(std::shared_ptr<stream_registry> registry,
               std::shared_ptr<webrtc_answer_factory> answer_factory,
               std::shared_ptr<udp_port_allocator> udp_port_allocator,
               boost::asio::io_context& io_context,
               std::string udp_bind_host,
               std::shared_ptr<dtls_context> dtls_context,
               std::uint16_t dtls_ip_mtu,
               std::string admin_token)
    : registry_(registry),
      media_fanout_router_(std::make_shared<media_fanout_router>()),
      admin_token_(std::move(admin_token)),
      whip_(registry, answer_factory, udp_port_allocator, io_context, udp_bind_host, dtls_context, dtls_ip_mtu, media_fanout_router_),
      whep_(std::move(registry),
            std::move(answer_factory),
            std::move(udp_port_allocator),
            io_context,
            std::move(udp_bind_host),
            std::move(dtls_context),
            dtls_ip_mtu,
            media_fanout_router_)
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

    if (admin_auth_required(path) && !is_admin_authorized(request))
    {
        return admin_unauthorized(request);
    }

    if (method == http::verb::get && path == k_health_path)
    {
        return handle_health(request);
    }

    if (method == http::verb::get && path == k_version_path)
    {
        return handle_version(request);
    }
    if (path == k_sessions_path)
    {
        return handle_sessions(request);
    }

    std::string_view api_session_id;

    if (match_single_value_path(path, k_sessions_prefix, api_session_id))
    {
        return handle_session(request, api_session_id);
    }

    if (path == k_streams_path)
    {
        return handle_streams(request);
    }
    std::string_view api_stream_id;

    if (match_single_value_path(path, k_streams_prefix, api_stream_id))
    {
        return handle_stream(request, api_stream_id);
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

bool router::admin_auth_required(std::string_view path) const
{
    if (admin_token_.empty())
    {
        return false;
    }

    if (!path.starts_with(k_api_prefix))
    {
        return false;
    }

    if (path == k_health_path)
    {
        return false;
    }

    if (path == k_version_path)
    {
        return false;
    }

    return true;
}

bool router::is_admin_authorized(const http_request_t& request) const
{
    if (admin_token_.empty())
    {
        return true;
    }

    const auto authorization_value = request.req[http::field::authorization];

    const std::string_view authorization(authorization_value.data(), authorization_value.size());

    const std::optional<std::string_view> token = bearer_token_from_authorization(authorization);

    if (!token.has_value())
    {
        return false;
    }

    return constant_time_equals(*token, admin_token_);
}

http_response_ptr router::admin_unauthorized(http_request_t& request)
{
    auto response = json_response(request, 401, json_error_body("unauthorized"));

    response->set(http::field::www_authenticate, "Bearer realm=\"simplewebrtc\"");

    return response;
}

http_response_ptr router::handle_options(http_request_t& request)
{
    auto response = text_response(request, 204, "");

    response->set(http::field::access_control_allow_methods, std::string(k_cors_allow_methods));

    response->set(http::field::access_control_allow_headers, std::string(k_cors_allow_headers));

    response->set(http::field::access_control_expose_headers, std::string(k_trickle_ice_expose_headers_value));

    response->set(http::field::access_control_max_age, std::string(k_cors_max_age_seconds));

    response->set(std::string(k_http_cors_private_network_header), "true");

    set_trickle_ice_patch_headers(response);

    return response;
}

http_response_ptr router::handle_health(http_request_t& request) { return json_response(request, 200, R"({"status":"ok"})"); }

http_response_ptr router::handle_version(http_request_t& request)
{
    return json_response(request, 200, R"({"name":"SimpleWebrtc","version":"0.1"})");
}

http_response_ptr router::handle_sessions(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    const std::string body = make_session_lifecycle_response_body(snapshots);

    return json_response(request, 200, body);
}
http_response_ptr router::handle_session(http_request_t& request, std::string_view session_id)
{
    if (!is_valid_resource_id(session_id))
    {
        return bad_request(request, "invalid session id");
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const auto method = request.req.method();

    if (method != http::verb::get && method != http::verb::delete_)
    {
        return method_not_allowed(request);
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    const std::optional<stream_session_lifecycle_snapshot> snapshot = find_session_snapshot(session_id, snapshots);

    if (!snapshot.has_value())
    {
        return json_response(request, 404, json_error_body("session not found"));
    }

    if (method == http::verb::get)
    {
        return json_response(request, 200, make_session_lifecycle_entry_response_body(*snapshot));
    }

    if (snapshot->kind == stream_session_kind::publisher)
    {
        auto result = registry_->remove_publisher_session(snapshot->session_id);

        if (!result)
        {
            if (result.error() == stream_registry_error::publisher_session_not_found)
            {
                return json_response(request, 404, json_error_body("session not found"));
            }

            return json_response(request, 500, json_error_body("delete publisher session failed"));
        }

        return text_response(request, 204, "");
    }

    if (snapshot->kind == stream_session_kind::subscriber)
    {
        auto result = registry_->remove_subscriber_session(snapshot->session_id);

        if (!result)
        {
            if (result.error() == stream_registry_error::subscriber_session_not_found)
            {
                return json_response(request, 404, json_error_body("session not found"));
            }

            return json_response(request, 500, json_error_body("delete subscriber session failed"));
        }

        return text_response(request, 204, "");
    }

    return json_response(request, 500, json_error_body("unsupported session kind"));
}

http_response_ptr router::handle_streams(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

    const std::string body = make_stream_list_response_body(snapshots);

    return json_response(request, 200, body);
}

http_response_ptr router::handle_stream(http_request_t& request, std::string_view stream_id)
{
    if (!is_valid_resource_id(stream_id))
    {
        return bad_request(request, "invalid stream id");
    }

    if (registry_ == nullptr)
    {
        return json_response(request, 503, json_error_body("session registry unavailable"));
    }

    const auto method = request.req.method();

    if (method == http::verb::get)
    {
        const std::vector<stream_session_lifecycle_snapshot> snapshots = registry_->session_lifecycle_snapshots();

        if (!stream_has_publisher_snapshot(stream_id, snapshots))
        {
            return json_response(request, 404, json_error_body("stream publisher not found"));
        }

        const std::string body = make_stream_detail_response_body(stream_id, snapshots);

        return json_response(request, 200, body);
    }

    if (method == http::verb::delete_)
    {
        auto publisher = registry_->find_publisher_by_stream_id(stream_id);

        if (publisher == nullptr)
        {
            return json_response(request, 404, json_error_body("stream publisher not found"));
        }

        const std::string publisher_session_id = publisher->session_id();

        auto result = registry_->remove_publisher_session(publisher_session_id);

        if (!result)
        {
            if (result.error() == stream_registry_error::publisher_session_not_found)
            {
                return json_response(request, 404, json_error_body("stream publisher not found"));
            }

            return json_response(request, 500, json_error_body("delete stream failed"));
        }

        return text_response(request, 204, "");
    }

    return method_not_allowed(request);
}

http_response_ptr router::handle_media_stats(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    return json_response(request, 200, make_trickle_ice_metrics_json(global_trickle_ice_metrics().snapshot()));
}

http_response_ptr router::handle_prometheus_metrics(http_request_t& request)
{
    if (request.req.method() != http::verb::get)
    {
        return method_not_allowed(request);
    }

    return prometheus_response(request, 200, trickle_ice_metrics_snapshot_to_prometheus(global_trickle_ice_metrics().snapshot()));
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

    auto body_validation_error = validate_sdp_offer_body(request, "WHIP", stream_id);

    if (body_validation_error != nullptr)
    {
        return body_validation_error;
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

    auto body_validation_error = validate_sdp_offer_body(request, "WHEP", stream_id);

    if (body_validation_error != nullptr)
    {
        return body_validation_error;
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

http_response_ptr router::not_found(http_request_t& request) { return make_json_http_error_response(request, 404, "not_found", "not found"); }

http_response_ptr router::method_not_allowed(http_request_t& request)
{
    auto response = make_json_http_error_response(request, 405, "method_not_allowed", "method not allowed");

    response->set(http::field::allow, "GET, POST, PATCH, DELETE, OPTIONS");

    return response;
}

http_response_ptr router::bad_request(http_request_t& request, std::string_view message)
{
    return make_json_http_error_response(request, 400, "bad_request", message);
}

http_response_ptr router::unsupported_media_type(http_request_t& request)
{
    return make_json_http_error_response(request, 415, "unsupported_media_type", "unsupported media type, expected application/sdp");
}

http_response_ptr router::json_response(http_request_t& request, int code, std::string_view body)
{
    return make_json_http_response(request, code, body);
}

http_response_ptr router::text_response(http_request_t& request, int code, std::string_view body)
{
    return make_text_http_response(request, code, body);
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

void router::add_common_headers(const http_response_ptr& response) { add_http_common_headers(response); }

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
