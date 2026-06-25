#ifndef SIMPLE_WEBRTC_SERVER_WHIP_HANDLER_H
#define SIMPLE_WEBRTC_SERVER_WHIP_HANDLER_H

#include <string_view>

#include "net/http.h"

namespace webrtc
{
class whip_handler
{
   public:
    http_response_ptr create_publisher(http_request_t& request, std::string_view stream_id);
    http_response_ptr patch_session(http_request_t& request, std::string_view session_id);
    http_response_ptr delete_session(http_request_t& request, std::string_view session_id);
};
}    // namespace webrtc

#endif
