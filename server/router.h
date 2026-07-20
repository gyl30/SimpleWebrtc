#ifndef SIMPLE_WEBRTC_SERVER_ROUTER_H
#define SIMPLE_WEBRTC_SERVER_ROUTER_H

#include <memory>
#include <string_view>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "media/media_fanout_router.h"
#include "net/http.h"
#include "net/udp_port_allocator.h"
#include "server/whep_handler.h"
#include "server/whip_handler.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
struct webrtc_config;

class router
{
   public:
    router(std::shared_ptr<stream_registry> registry,
           std::shared_ptr<webrtc_answer_factory> answer_factory,
           std::shared_ptr<udp_port_allocator> udp_port_allocator,
           boost::asio::io_context& io_context,
           const webrtc_config& config,
           std::shared_ptr<dtls_context> dtls_context);

   public:
    [[nodiscard]]
    http_response_ptr handle(http_request_t& request);

   private:
    [[nodiscard]]
    http_response_ptr handle_options(http_request_t& request);

    [[nodiscard]]
    http_response_ptr handle_health(http_request_t& request);

    [[nodiscard]]
    http_response_ptr handle_version(http_request_t& request);

    [[nodiscard]]
    http_response_ptr handle_sessions(http_request_t& request);

    [[nodiscard]]
    http_response_ptr handle_session(http_request_t& request, std::string_view session_id);

    [[nodiscard]]
    http_response_ptr handle_stream(http_request_t& request, std::string_view stream_id);

    [[nodiscard]]
    http_response_ptr handle_streams(http_request_t& request);

    [[nodiscard]]
    http_response_ptr handle_media_stats(http_request_t& request);

    [[nodiscard]]
    http_response_ptr handle_prometheus_metrics(http_request_t& request);

    [[nodiscard]]
    http_response_ptr handle_whip_create(http_request_t& request, std::string_view stream_id);

    [[nodiscard]]
    http_response_ptr handle_whip_session(http_request_t& request, std::string_view session_id);

    [[nodiscard]]
    http_response_ptr handle_whep_create(http_request_t& request, std::string_view stream_id);

    [[nodiscard]]
    http_response_ptr handle_whep_session(http_request_t& request, std::string_view session_id);

   private:
    [[nodiscard]]
    http_response_ptr not_found(http_request_t& request);

    [[nodiscard]]
    http_response_ptr method_not_allowed(http_request_t& request);

    [[nodiscard]]
    http_response_ptr bad_request(http_request_t& request, std::string_view message);

    [[nodiscard]]
    http_response_ptr unsupported_media_type(http_request_t& request);

   private:
    [[nodiscard]]
    http_response_ptr prometheus_response(http_request_t& request, int code, std::string_view body);

   private:
    [[nodiscard]]
    static std::string_view request_path(http_request_t& request);

    [[nodiscard]]
    static bool is_application_sdp(http_request_t& request);

    [[nodiscard]]
    static bool is_valid_resource_id(std::string_view value);

   private:
    [[nodiscard]]
    bool admin_auth_required(std::string_view path) const;

    [[nodiscard]]
    bool is_admin_authorized(const http_request_t& request) const;

    [[nodiscard]]
    http_response_ptr admin_unauthorized(http_request_t& request);

   private:
    std::shared_ptr<stream_registry> registry_;

    std::shared_ptr<media_fanout_router> media_fanout_router_;

    const webrtc_config& config_;

    whip_handler whip_;

    whep_handler whep_;
};
}    // namespace webrtc

#endif
