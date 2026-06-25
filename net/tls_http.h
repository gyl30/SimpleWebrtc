#ifndef SIMPLE_WEBRTC_NET_TLS_HTTP_H
#define SIMPLE_WEBRTC_NET_TLS_HTTP_H

#include <memory>
#include <utility>

#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/optional.hpp>
#include <boost/beast/ssl.hpp>

#include "log/log.h"
#include "net/http.h"

namespace webrtc
{
class tls_http_session : public std::enable_shared_from_this<tls_http_session>
{
   public:
    tls_http_session(
        std::string id, http_handler&& handler, boost::beast::tcp_stream&& stream, boost::asio::ssl::context& ctx, boost::beast::flat_buffer&& buffer)
        : id_(std::move(id)), handler_(std::move(handler)), buffer_(std::move(buffer)), stream_(std::move(stream), ctx)
    {
        WEBRTC_LOG_DEBUG("{} created", id_);
    }
    ~tls_http_session() { WEBRTC_LOG_DEBUG("{} destroyed", id_); }

   public:
    void shutdown()
    {
        auto self = shared_from_this();
        boost::asio::post(stream_.get_executor(), [this, self]() { safe_shutdown(); });
    }

    void start()
    {
        boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        auto self = shared_from_this();
        stream_.async_handshake(boost::asio::ssl::stream_base::server,
                                buffer_.data(),
                                [self, this](boost::beast::error_code ec, std::size_t bytes_used) { on_handshake(ec, bytes_used); });
    }

   private:
    void on_handshake(boost::beast::error_code ec, std::size_t bytes_used)
    {
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} ssl handshake failed {}", id_, ec.message());
            return;
        }

        buffer_.consume(bytes_used);

        do_read();
    }

    void do_read()
    {
        parser_.emplace();
        static uint32_t body_limit = 512 * 1024;
        static uint32_t header_limit = 256 * 1024;

        parser_->body_limit(body_limit);
        parser_->header_limit(header_limit);

        auto self = shared_from_this();
        boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        boost::beast::http::async_read(
            stream_, buffer_, *parser_, [this, self](boost::beast::error_code ec, std::size_t bytes_transferred) { on_read(ec, bytes_transferred); });
    }

    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec == boost::beast::http::error::end_of_stream)
        {
            WEBRTC_LOG_DEBUG("{} read end of stream", id_);
            shutdown();
            return;
        }

        if (ec)
        {
            WEBRTC_LOG_ERROR("{} failed {}", id_, ec.message());
            return;
        }

        http_request_t req;
        req.req = parser_->release();
        auto response = handler_.http(req);
        if (response != nullptr)
        {
            write_response(req, response);
        }
    }
    void write_response(http_request_t& req, const http_response_ptr& res)
    {
        auto self = shared_from_this();
        auto req_ptr = std::make_shared<boost::beast::http::request<boost::beast::http::string_body>>(std::move(req.req));
        boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
        boost::beast::http::async_write(
            stream_, *res, [this, self, req_ptr, res](boost::beast::error_code ec, std::size_t bytes) { on_write(req_ptr, ec, bytes); });
    }

    void on_write(const http_request_ptr& req, boost::beast::error_code ec, std::size_t bytes_transferred)
    {
        writing_ = false;
        boost::ignore_unused(bytes_transferred);
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} write failed {}", id_, ec.message());
            shutdown();
            return;
        }

        if (!req->keep_alive())
        {
            WEBRTC_LOG_DEBUG("{} shutdown after write no keepalive", id_);
            shutdown();
            return;
        }
        do_read();
    }

    void safe_shutdown()
    {
        WEBRTC_LOG_DEBUG("{} safe shutdown", id_);
        boost::beast::error_code ec;
        ec = boost::beast::get_lowest_layer(stream_).socket().close(ec);
    }

   private:
    std::string id_;
    http_handler handler_;
    bool writing_ = false;
    boost::beast::flat_buffer buffer_;
    boost::asio::ssl::stream<boost::beast::tcp_stream> stream_;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser_;
};

}    // namespace webrtc
#endif
