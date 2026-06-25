#ifndef SIMPLE_WEBRTC_SERVER_WHEP_HANDLER_H
#define SIMPLE_WEBRTC_SERVER_WHEP_HANDLER_H

#include <memory>
#include <string_view>

#include "net/http.h"
#include "session/stream_registry.h"

namespace webrtc
{
class whep_handler
{
   public:
    explicit whep_handler(std::shared_ptr<stream_registry> registry);

   public:
    http_response_ptr create_subscriber(http_request_t& request, std::string_view stream_id);
    http_response_ptr patch_session(http_request_t& request, std::string_view session_id);
    http_response_ptr delete_session(http_request_t& request, std::string_view session_id);

   private:
    http_response_ptr json_response(http_request_t& request, int code, std::string_view body);
    http_response_ptr json_error_response(http_request_t& request, int code, std::string_view message);
    void add_common_headers(const http_response_ptr& response);

   private:
    std::shared_ptr<stream_registry> registry_;
};
}    // namespace webrtc

#endif
