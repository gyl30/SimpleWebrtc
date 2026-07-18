#ifndef SIMPLE_WEBRTCP_HTTP_TCP_SERVER_H
#define SIMPLE_WEBRTCP_HTTP_TCP_SERVER_H

#include <memory>
#include <string>
#include <chrono>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>

#include "log/log.h"
#include "util/error.h"

namespace webrtc
{
struct tcp_handler
{
    std::function<boost::asio::ip::tcp::socket()> create_socket;
    std::function<void(boost::asio::ip::tcp::socket)> accept_socket;
};

class tcp_server : public std::enable_shared_from_this<tcp_server>
{
   public:
    tcp_server(uint16_t port, std::string name, boost::asio::io_context& ex, tcp_handler&& h)
        : port_(port), name_(std::move(name)), handler_(std::move(h)), io_(ex)
    {
        WEBRTC_LOG_INFO("{} server {}:{} create", name_, host_, port_);
    }
    ~tcp_server() { WEBRTC_LOG_INFO("{} server :{} destroy", name_, port_); }

   public:
    void run()
    {
        open();
        do_accept();
    }

    void stop()
    {
        auto self = shared_from_this();
        boost::asio::dispatch(io_, [this, self]() { safe_shutdown(); });
    }

   private:
    void safe_shutdown()
    {
        boost::system::error_code ec;

        accept_retry_timer_.cancel();

        if (socket_ != nullptr)
        {
            socket_.reset();
        }

        if (!acceptor_.is_open())
        {
            return;
        }

        ec = acceptor_.close(ec);
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} server address :{} close error {}", name_, port_, ec.message());
            return;
        }

        WEBRTC_LOG_INFO("{} server :{} stopped", name_, port_);
    }

   private:
    void open()
    {
        boost::asio::ip::tcp::acceptor acceptor(acceptor_.get_executor());
        boost::system::error_code ec;
        const auto addr = boost::asio::ip::make_address(host_, ec);
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} server address :{} error {}", name_, port_, ec.message());
            return;
        }
        ec = acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} server :{} open error {}", name_, port_, ec.message());
            return;
        }
        constexpr int one = 1;
        int ret = setsockopt(acceptor.native_handle(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (ret == -1)
        {
            WEBRTC_LOG_WARN("{} server :{} set SO_REUSEADDR error {}", name_, port_, errno_to_str());
        }

#ifdef __linux__
        ret = setsockopt(acceptor.native_handle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
        if (ret == -1)
        {
            WEBRTC_LOG_WARN("{} server :{} set SO_REUSEPORT error {}", name_, port_, errno_to_str());
        }
#endif
        ec = acceptor.bind(boost::asio::ip::tcp::endpoint(addr, port_), ec);
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} server :{} bind error {}", name_, port_, ec.message());
            return;
        }
        ec = acceptor.listen(boost::asio::ip::tcp::socket::max_listen_connections, ec);
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} server :{} listen error {}", name_, port_, ec.message());
            return;
        }
        acceptor_ = std::move(acceptor);
        WEBRTC_LOG_INFO("{} server :{} listen", name_, port_);
    }
    void do_accept()
    {
        if (!acceptor_.is_open())
        {
            WEBRTC_LOG_ERROR("{} server :{} accept error", name_, port_);
            return;
        }
        auto self = shared_from_this();
        WEBRTC_LOG_INFO("{} server :{} accept count {}", name_, port_, count_++);
        socket_ = std::make_shared<boost::asio::ip::tcp::socket>(handler_.create_socket());
        acceptor_.async_accept(*socket_, [this, self](const boost::system::error_code& ec) { on_accept(ec); });
    }
    void on_accept(const boost::system::error_code& ec)
    {
        if (ec == boost::asio::error::operation_aborted)
        {
            socket_.reset();
            WEBRTC_LOG_WARN("{} server :{} accept cancel", name_, port_);
            return;
        }

        if (ec)
        {
            socket_.reset();

            WEBRTC_LOG_ERROR("{} server :{} accept error {}", name_, port_, ec.message());

            retry_accept_later();

            return;
        }

        accept_retry_delay_seconds_ = 1;

        handler_.accept_socket(std::move(*socket_));

        socket_.reset();

        do_accept();
    }

   private:
    void retry_accept_later()
    {
        if (!acceptor_.is_open())
        {
            return;
        }

        auto self = shared_from_this();

        int32_t delay_seconds = accept_retry_delay_seconds_;

        accept_retry_delay_seconds_ *= 2;
        accept_retry_delay_seconds_ = std::min(accept_retry_delay_seconds_, max_accept_retry_delay_seconds_);
        WEBRTC_LOG_WARN("{} server :{} retry accept after {} seconds", name_, port_, delay_seconds);
        accept_retry_timer_.expires_after(std::chrono::seconds(delay_seconds));
        accept_retry_timer_.async_wait([this, self](const boost::system::error_code& ec) { retry_timeout_cb(ec); });
    }
    void retry_timeout_cb(const boost::system::error_code& ec)
    {
        if (ec == boost::asio::error::operation_aborted)
        {
            return;
        }
        if (ec)
        {
            WEBRTC_LOG_ERROR("{} server :{} accept retry timeout error {}", name_, port_, ec.message());
            return;
        }

        if (!acceptor_.is_open())
        {
            return;
        }

        do_accept();
    }
   private:
    std::string host_ = "0.0.0.0";
    uint16_t port_ = 0;
    uint32_t count_ = 0;
    std::string name_;
    tcp_handler handler_;
    boost::asio::io_context& io_;
    boost::asio::ip::tcp::acceptor acceptor_{io_};
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    // retry
    int32_t accept_retry_delay_seconds_ = 1;
    int32_t max_accept_retry_delay_seconds_ = 10;
    boost::asio::steady_timer accept_retry_timer_{io_};
};
}    // namespace webrtc
#endif
