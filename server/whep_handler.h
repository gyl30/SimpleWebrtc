#ifndef SIMPLE_WEBRTC_SERVER_WHEP_HANDLER_H
#define SIMPLE_WEBRTC_SERVER_WHEP_HANDLER_H

#include <memory>
#include <string_view>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "media/media_fanout_router.h"
#include "net/http.h"
#include "net/udp_port_allocator.h"
#include "session/stream_registry.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
struct webrtc_config;

class whep_handler
{
   public:
    whep_handler(std::shared_ptr<stream_registry> registry,
                 std::shared_ptr<webrtc_answer_factory> answer_factory,
                 std::shared_ptr<udp_port_allocator> udp_port_allocator,
                 boost::asio::io_context& io_context,
                 const webrtc_config& config,
                 std::shared_ptr<dtls_context> dtls_context,
                 std::shared_ptr<media_fanout_router> media_fanout_router);

   public:
    http_response_ptr create_subscriber(http_request_t& request, std::string_view stream_id);

    http_response_ptr patch_session(http_request_t& request, std::string_view session_id);

    http_response_ptr delete_session(http_request_t& request, std::string_view session_id);

   private:
    http_response_ptr json_error_response(http_request_t& request, int code, std::string_view message);

    http_response_ptr json_error_response(http_request_t& request, int code, std::string_view error_code, std::string_view message);

   private:
    std::shared_ptr<stream_registry> registry_;
    std::shared_ptr<webrtc_answer_factory> answer_factory_;
    std::shared_ptr<udp_port_allocator> udp_port_allocator_;
    std::shared_ptr<media_fanout_router> media_fanout_router_;
    boost::asio::io_context& io_context_;
    const webrtc_config& config_;
    std::shared_ptr<dtls_context> dtls_context_;
};
}    // namespace webrtc

#endif
