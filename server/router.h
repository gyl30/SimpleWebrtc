#ifndef SIMPLE_WEBRTC_SERVER_ROUTER_H
#define SIMPLE_WEBRTC_SERVER_ROUTER_H

#include <memory>
#include <string_view>

#include "media/media_router.h"
#include "net/http.h"
#include "server/whip_handler.h"
#include "server/whep_handler.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
class router
{
   public:
    router(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory);

    router(std::shared_ptr<stream_registry> registry,
           std::shared_ptr<webrtc_answer_factory> answer_factory,
           std::shared_ptr<media_router> media_router);

   public:
    http_response_ptr handle(http_request_t& request);

    void set_media_router(std::shared_ptr<media_router> media_router);

   private:
    http_response_ptr handle_options(http_request_t& request);

    http_response_ptr handle_health(http_request_t& request);

    http_response_ptr handle_version(http_request_t& request);

    http_response_ptr handle_media_stats(http_request_t& request);

    http_response_ptr handle_whip_create(http_request_t& request, std::string_view stream_id);

    http_response_ptr handle_whip_session(http_request_t& request, std::string_view session_id);

    http_response_ptr handle_whep_create(http_request_t& request, std::string_view stream_id);

    http_response_ptr handle_whep_session(http_request_t& request, std::string_view session_id);

   private:
    http_response_ptr not_found(http_request_t& request);

    http_response_ptr method_not_allowed(http_request_t& request);

    http_response_ptr bad_request(http_request_t& request, std::string_view message);

    http_response_ptr unsupported_media_type(http_request_t& request);

    http_response_ptr not_implemented(http_request_t& request, std::string_view message);

   private:
    http_response_ptr json_response(http_request_t& request, int code, std::string_view body);

    http_response_ptr text_response(http_request_t& request, int code, std::string_view body);

    void add_common_headers(const http_response_ptr& response);

   private:
    [[nodiscard]] static std::string_view request_path(http_request_t& request);

    [[nodiscard]] static bool is_application_sdp(http_request_t& request);

    [[nodiscard]] static bool is_valid_resource_id(std::string_view value);

   private:
    std::shared_ptr<stream_registry> registry_;
    std::shared_ptr<webrtc_answer_factory> answer_factory_;
    std::shared_ptr<media_router> media_router_;

    whip_handler whip_;
    whep_handler whep_;
};
}    // namespace webrtc

#endif
