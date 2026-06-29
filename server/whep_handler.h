#ifndef SIMPLE_WEBRTC_SERVER_WHEP_HANDLER_H
#define SIMPLE_WEBRTC_SERVER_WHEP_HANDLER_H

#include <memory>
#include <string_view>

#include "net/http.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
class whep_handler
{
   public:
    whep_handler(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory);

   public:
    http_response_ptr create_subscriber(http_request_t& request, std::string_view stream_id);

    http_response_ptr patch_session(http_request_t& request, std::string_view session_id);

    http_response_ptr delete_session(http_request_t& request, std::string_view session_id);

   private:
    http_response_ptr patch_sdp_restart(http_request_t& request, std::string_view session_id, const std::shared_ptr<subscriber_session>& session);

    http_response_ptr json_response(http_request_t& request, int code, std::string_view body);

    http_response_ptr json_error_response(http_request_t& request, int code, std::string_view message);

    http_response_ptr sdp_response(http_request_t& request, int code, std::string_view body);

    void add_common_headers(const http_response_ptr& response);

   private:
    std::shared_ptr<stream_registry> registry_;
    std::shared_ptr<webrtc_answer_factory> answer_factory_;
};
}    // namespace webrtc

#endif
