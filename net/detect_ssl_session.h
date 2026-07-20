#ifndef SIMPLE_WEBRTC_NET_DETECT_SSL_H
#define SIMPLE_WEBRTC_NET_DETECT_SSL_H

#include <memory>
#include <utility>

#include <boost/beast.hpp>

#include "log/log.h"
#include "net/http.h"
#include "net/tls_http.h"
#include "net/plain_http.h"

namespace webrtc
{
class detect_ssl_session : public std::enable_shared_from_this<detect_ssl_session>
{
   public:
    detect_ssl_session(std::string id, http_handler&& h, boost::asio::ip::tcp::socket socket, boost::asio::ssl::context& ssl_ex)
        : id_(std::move(id)), ssl_ex_(ssl_ex), stream_(std::move(socket)), h_(std::move(h)) {};

   public:
    void run()
    {
        boost::asio::dispatch(stream_.get_executor(), boost::beast::bind_front_handler(&detect_ssl_session::on_run, this->shared_from_this()));
    }

    void on_run()
    {
        stream_.expires_after(std::chrono::seconds(30));

        boost::beast::async_detect_ssl(stream_, buffer_, boost::beast::bind_front_handler(&detect_ssl_session::on_detect, this->shared_from_this()));
    }
    void on_detect(boost::beast::error_code ec, bool result)
    {
        if (ec)
        {
            if (is_http_expected_close_error(ec))
            {
                WEBRTC_LOG_DEBUG("{} detect ssl session closed {}", id_, ec.message());
                return;
            }

            WEBRTC_LOG_ERROR("{} detect ssl session error {}", id_, ec.message());
            return;
        }

        if (result)
        {
            std::make_shared<webrtc::tls_http_session>(id_, std::move(h_), std::move(stream_), ssl_ex_, std::move(buffer_))->start();
            return;
        }
        std::make_shared<webrtc::plain_http_session>(id_, std::move(h_), std::move(stream_), std::move(buffer_))->start();
    }

   private:
    std::string id_;
    boost::asio::ssl::context& ssl_ex_;
    boost::beast::tcp_stream stream_;
    boost::beast::flat_buffer buffer_;
    webrtc::http_handler h_;
};
}    // namespace webrtc
#endif
