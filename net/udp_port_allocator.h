#ifndef SIMPLE_WEBRTC_NET_UDP_PORT_ALLOCATOR_H
#define SIMPLE_WEBRTC_NET_UDP_PORT_ALLOCATOR_H

#include <cstdint>
#include <memory>
#include <optional>
#include <set>

namespace webrtc
{
struct udp_port_range
{
    uint16_t min_port = 0;
    uint16_t max_port = 0;
};

class udp_port_allocator
{
   public:
    explicit udp_port_allocator(udp_port_range range);

    [[nodiscard]]
    std::optional<uint16_t> acquire();

    void release(uint16_t port);

    [[nodiscard]]
    bool owns(uint16_t port) const;

   private:
    udp_port_range range_;

    uint16_t next_port_ = 0;

    std::set<uint16_t> used_ports_;
};

class udp_port_reservation
{
   public:
    udp_port_reservation(std::shared_ptr<udp_port_allocator> allocator, uint16_t port);

    ~udp_port_reservation();

    udp_port_reservation(const udp_port_reservation&) = delete;

    udp_port_reservation& operator=(const udp_port_reservation&) = delete;

    udp_port_reservation(udp_port_reservation&&) = delete;

    udp_port_reservation& operator=(udp_port_reservation&&) = delete;

    [[nodiscard]]
    uint16_t port() const;

   private:
    std::shared_ptr<udp_port_allocator> allocator_;

    uint16_t port_ = 0;
};

using udp_port_reservation_ptr = std::shared_ptr<udp_port_reservation>;

[[nodiscard]]
std::optional<udp_port_reservation_ptr> reserve_udp_port(const std::shared_ptr<udp_port_allocator>& allocator);

[[nodiscard]]
bool udp_port_range_is_valid(const udp_port_range& range);
}    // namespace webrtc

#endif
