#ifndef SIMPLE_WEBRTC_RTP_RTP_RETRANSMISSION_CACHE_H
#define SIMPLE_WEBRTC_RTP_RTP_RETRANSMISSION_CACHE_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace webrtc
{
struct rtp_retransmission_cache_config
{
    std::chrono::milliseconds max_age{2000};
    std::size_t max_packets = 4096;
    std::size_t max_bytes = 8U * 1024U * 1024U;
    std::chrono::milliseconds minimum_retransmit_interval{20};
};

struct rtp_retransmission_cache_packet
{
    std::vector<uint8_t> packet;
    uint32_t target_ssrc = 0;
    uint8_t target_payload_type = 0;
    uint16_t target_sequence_number = 0;
    uint32_t target_timestamp = 0;
    std::size_t payload_size = 0;
    uint64_t source_generation = 0;
    std::chrono::steady_clock::time_point stored_at;
};

enum class rtp_retransmission_cache_lookup_state
{
    hit,
    miss,
    suppressed,
};

struct rtp_retransmission_cache_lookup
{
    rtp_retransmission_cache_lookup_state state = rtp_retransmission_cache_lookup_state::miss;
    std::optional<rtp_retransmission_cache_packet> packet;
};

struct rtp_retransmission_cache_snapshot
{
    std::size_t packet_count = 0;
    std::size_t byte_count = 0;
    uint64_t inserted = 0;
    uint64_t replaced = 0;
    uint64_t evicted_age = 0;
    uint64_t evicted_capacity = 0;
};

class rtp_retransmission_cache
{
   public:
    explicit rtp_retransmission_cache(rtp_retransmission_cache_config config = {});

    void remember(rtp_retransmission_cache_packet packet,
                  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    [[nodiscard]] rtp_retransmission_cache_lookup lookup_for_retransmission(
        uint32_t target_ssrc,
        uint16_t target_sequence_number,
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void clear();

    [[nodiscard]] rtp_retransmission_cache_snapshot snapshot(
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

   private:
    struct entry
    {
        rtp_retransmission_cache_packet packet;
        uint64_t serial = 0;
        std::optional<std::chrono::steady_clock::time_point> last_retransmitted_at;
    };

    struct order_entry
    {
        uint64_t key = 0;
        uint64_t serial = 0;
    };

    [[nodiscard]] static uint64_t make_key(uint32_t target_ssrc, uint16_t target_sequence_number);
    void prune(std::chrono::steady_clock::time_point now);
    void erase_entry(uint64_t key, bool age_eviction);

   private:
    rtp_retransmission_cache_config config_;
    std::unordered_map<uint64_t, entry> entries_;
    std::deque<order_entry> order_;
    std::size_t byte_count_ = 0;
    uint64_t next_serial_ = 1;
    uint64_t inserted_ = 0;
    uint64_t replaced_ = 0;
    uint64_t evicted_age_ = 0;
    uint64_t evicted_capacity_ = 0;
};
}    // namespace webrtc

#endif
