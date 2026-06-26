#ifndef SIMPLE_WEBRTC_SERVER_ROUTER_H
#define SIMPLE_WEBRTC_SERVER_ROUTER_H

#include <functional>
#include <memory>
#include <string_view>

#include "media/media_router.h"
#include "media/rtcp_report_service.h"
#include "net/http.h"
#include "server/whip_handler.h"
#include "server/whep_handler.h"
#include "media/keyframe_request.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
using rtcp_report_runtime_snapshot_provider = std::function<rtcp_report_service_runtime_snapshot()>;
using keyframe_request_handler = std::function<keyframe_request_expected(std::string_view stream_id)>;

class router
{
   public:
    router(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory);

    router(std::shared_ptr<stream_registry> registry,
           std::shared_ptr<webrtc_answer_factory> answer_factory,
           std::shared_ptr<media_router> media_router);

   public:
    [[nodiscard]]
    http_response_ptr handle(http_request_t& request);

    void set_media_router(std::shared_ptr<media_router> media_router);

    void set_rtcp_report_runtime_snapshot_provider(rtcp_report_runtime_snapshot_provider provider);

    void set_keyframe_request_handler(keyframe_request_handler handler);

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
    http_response_ptr handle_stream_keyframe(http_request_t& request, std::string_view stream_id);

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

    [[nodiscard]]
    http_response_ptr not_implemented(http_request_t& request, std::string_view message);

   private:
    [[nodiscard]]
    http_response_ptr json_response(http_request_t& request, int code, std::string_view body);

    [[nodiscard]]
    http_response_ptr text_response(http_request_t& request, int code, std::string_view body);

    [[nodiscard]]
    http_response_ptr prometheus_response(http_request_t& request, int code, std::string_view body);

    void add_common_headers(const http_response_ptr& response);

   private:
    [[nodiscard]]
    static std::string_view request_path(http_request_t& request);

    [[nodiscard]]
    static bool is_application_sdp(http_request_t& request);

    [[nodiscard]]
    static bool is_valid_resource_id(std::string_view value);

   private:
    std::shared_ptr<stream_registry> registry_;

    std::shared_ptr<webrtc_answer_factory> answer_factory_;

    std::shared_ptr<media_router> media_router_;

    keyframe_request_handler keyframe_request_handler_;
    rtcp_report_runtime_snapshot_provider rtcp_report_runtime_snapshot_provider_;

    whip_handler whip_;

    whep_handler whep_;
};
}    // namespace webrtc

#endif
