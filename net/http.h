#ifndef SIMPLE_WEBRTC_NET_HTTP_H
#define SIMPLE_WEBRTC_NET_HTTP_H

#include <memory>

#include <boost/asio/error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/beast.hpp>
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

inline bool is_http_expected_close_error(const boost::beast::error_code& ec)
{
    return ec == boost::beast::error::timeout || ec == boost::asio::error::operation_aborted || ec == boost::asio::error::eof ||
           ec == boost::beast::http::error::end_of_stream || ec == boost::asio::ssl::error::stream_truncated;
}

http_response_ptr create_response(http_request_t& req, int code, const std::string& content);

}    // namespace webrtc
#endif
