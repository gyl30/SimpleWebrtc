#ifndef SIMPLE_WEBRTC_MEDIA_RTP_PACKET_CACHE_H
#define SIMPLE_WEBRTC_MEDIA_RTP_PACKET_CACHE_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace webrtc
{
struct rtp_packet_cache_config
{
    std::size_t max_packets = 4096;
};

struct rtp_packet_cache_entry
{
    std::string stream_id;

    uint32_t ssrc = 0;
    uint16_t sequence_number = 0;
    uint8_t payload_type = 0;
    bool marker = false;
    uint32_t timestamp = 0;

    std::vector<uint8_t> plain_packet;
};

struct rtp_packet_cache_stream_snapshot
{
    std::string stream_id;

    uint64_t packet_count = 0;
    uint64_t byte_count = 0;

    uint32_t min_ssrc = 0;
    uint32_t max_ssrc = 0;
};

using rtp_packet_cache_result = std::expected<rtp_packet_cache_entry, std::string>;
class rtp_packet_cache
{
   public:
    rtp_packet_cache();
    explicit rtp_packet_cache(rtp_packet_cache_config config);

    ~rtp_packet_cache() = default;

    rtp_packet_cache(const rtp_packet_cache&) = delete;
    rtp_packet_cache& operator=(const rtp_packet_cache&) = delete;

    rtp_packet_cache(rtp_packet_cache&&) = delete;
    rtp_packet_cache& operator=(rtp_packet_cache&&) = delete;

   public:
    [[nodiscard]] rtp_packet_cache_result put(std::string_view stream_id, std::span<const uint8_t> plain_packet);

    [[nodiscard]] std::optional<rtp_packet_cache_entry> find(std::string_view stream_id, uint32_t ssrc, uint16_t sequence_number) const;

    void erase_stream(std::string_view stream_id);

    void clear();

    [[nodiscard]] std::size_t size() const;

    [[nodiscard]]
    std::vector<rtp_packet_cache_stream_snapshot> stream_snapshot() const;

   private:
    [[nodiscard]] static std::string make_key(std::string_view stream_id, uint32_t ssrc, uint16_t sequence_number);

    void enforce_capacity_locked();

   private:
    rtp_packet_cache_config config_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, rtp_packet_cache_entry> cache_by_key_;
    std::deque<std::string> insertion_order_;
};
}    // namespace webrtc

#endif
