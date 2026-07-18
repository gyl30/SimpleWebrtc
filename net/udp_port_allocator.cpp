#include "net/udp_port_allocator.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <utility>

namespace webrtc
{
bool udp_port_range_is_valid(const udp_port_range& range)
{
    if (range.min_port == 0 || range.max_port == 0)
    {
        return false;
    }

    return range.min_port <= range.max_port;
}

udp_port_allocator::udp_port_allocator(udp_port_range range) : range_(range), next_port_(range.min_port) {}

std::optional<uint16_t> udp_port_allocator::acquire()
{
    if (!udp_port_range_is_valid(range_))
    {
        return std::nullopt;
    }

    const std::size_t capacity = static_cast<std::size_t>(range_.max_port) - static_cast<std::size_t>(range_.min_port) + 1;

    if (used_ports_.size() >= capacity)
    {
        return std::nullopt;
    }

    uint16_t candidate = next_port_;

    for (std::size_t attempt = 0; attempt < capacity; ++attempt)
    {
        if (!used_ports_.contains(candidate))
        {
            used_ports_.insert(candidate);

            if (candidate == range_.max_port)
            {
                next_port_ = range_.min_port;
            }
            else
            {
                next_port_ = static_cast<uint16_t>(candidate + 1);
            }

            return candidate;
        }

        if (candidate == range_.max_port)
        {
            candidate = range_.min_port;
        }
        else
        {
            candidate = static_cast<uint16_t>(candidate + 1);
        }
    }

    return std::nullopt;
}

void udp_port_allocator::release(uint16_t port) { used_ports_.erase(port); }

udp_port_reservation::udp_port_reservation(std::shared_ptr<udp_port_allocator> allocator, uint16_t port)
    : allocator_(std::move(allocator)), port_(port)
{
}

udp_port_reservation::~udp_port_reservation()
{
    if (allocator_ == nullptr || port_ == 0)
    {
        return;
    }

    allocator_->release(port_);
}

uint16_t udp_port_reservation::port() const { return port_; }

std::optional<udp_port_reservation_ptr> reserve_udp_port(const std::shared_ptr<udp_port_allocator>& allocator)
{
    if (allocator == nullptr)
    {
        return std::nullopt;
    }

    auto port = allocator->acquire();

    if (!port)
    {
        return std::nullopt;
    }

    return std::make_shared<udp_port_reservation>(allocator, *port);
}
}    // namespace webrtc
