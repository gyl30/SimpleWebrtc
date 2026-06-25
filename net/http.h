#ifndef SIMPLE_WEBRTC_NET_HTTP_H
#define SIMPLE_WEBRTC_NET_HTTP_H

#include <memory>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>

namespace webrtc
{
using http_request_ptr = std::shared_ptr<boost::beast::http::request<boost::beast::http::string_body>>;
using http_response_ptr = std::shared_ptr<boost::beast::http::response<boost::beast::http::string_body>>;

struct http_request_t
{
    boost::beast::http::request<boost::beast::http::string_body> req;
};

struct http_handler
{
    std::function<http_response_ptr(http_request_t& req)> http;
};

http_response_ptr create_response(http_request_t& req, int code, const std::string& content);

}    // namespace webrtc
#endif
