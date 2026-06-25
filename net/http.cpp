#include "net/http.h"

namespace webrtc
{
http_response_ptr create_response(webrtc::http_request_t& request, int code, const std::string& content)
{
    static const char* kUserAgent = "Webrtc/0.1";
    auto status = boost::beast::http::int_to_status(static_cast<uint32_t>(code));
    auto rsp = std::make_shared<boost::beast::http::response<boost::beast::http::string_body>>(status, request.req.version());
    rsp->body().assign(content);
    rsp->keep_alive(request.req.keep_alive());
    rsp->content_length(content.size());
    rsp->set(boost::beast::http::field::server, kUserAgent);
    return rsp;
}
}    // namespace webrtc
