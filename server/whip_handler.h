#ifndef SIMPLE_WEBRTC_SERVER_WHIP_HANDLER_H
#define SIMPLE_WEBRTC_SERVER_WHIP_HANDLER_H

#include <memory>
#include <string>
#include <string_view>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "dtls/dtls_transport.h"
#include "media/media_fanout_router.h"
#include "net/http.h"
#include "net/udp_port_allocator.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
class whip_handler
{
   public:
    whip_handler(std::shared_ptr<stream_registry> registry,
                 std::shared_ptr<webrtc_answer_factory> answer_factory,
                 std::shared_ptr<udp_port_allocator> udp_port_allocator,
                 boost::asio::io_context& io_context,
                 std::string udp_bind_host,
                 std::shared_ptr<dtls_context> dtls_context,
                 dtls_transport_config dtls_config,
                 std::shared_ptr<media_fanout_router> media_fanout_router);

   public:
    http_response_ptr create_publisher(http_request_t& request, std::string_view stream_id);

    http_response_ptr patch_session(http_request_t& request, std::string_view session_id);

    http_response_ptr delete_session(http_request_t& request, std::string_view session_id);

   private:
    http_response_ptr patch_sdp_restart(http_request_t& request, std::string_view session_id, const std::shared_ptr<publisher_session>& session);

    http_response_ptr json_response(http_request_t& request, int code, std::string_view body);

    http_response_ptr json_error_response(http_request_t& request, int code, std::string_view message);

    http_response_ptr json_error_response(http_request_t& request, int code, std::string_view error_code, std::string_view message);

    http_response_ptr sdp_response(http_request_t& request, int code, std::string_view body);

    void add_common_headers(const http_response_ptr& response);

   private:
    std::shared_ptr<stream_registry> registry_;
    std::shared_ptr<webrtc_answer_factory> answer_factory_;
    std::shared_ptr<udp_port_allocator> udp_port_allocator_;
    std::shared_ptr<media_fanout_router> media_fanout_router_;
    boost::asio::io_context& io_context_;
    std::string udp_bind_host_;
    std::shared_ptr<dtls_context> dtls_context_;
    dtls_transport_config dtls_config_;
};
}    // namespace webrtc

#endif
