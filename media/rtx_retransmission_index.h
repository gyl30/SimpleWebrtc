#ifndef SIMPLE_WEBRTC_MEDIA_RTX_RETRANSMISSION_INDEX_H
#define SIMPLE_WEBRTC_MEDIA_RTX_RETRANSMISSION_INDEX_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
struct rtx_retransmission_index_config
{
    std::size_t max_entries = 4096;
    uint64_t max_age_milliseconds = 60000;
};

struct rtx_retransmission_mapping
{
    std::string stream_id;
    std::string subscriber_session_id;

    std::string publisher_mid;
    std::string subscriber_mid;
    std::string kind;

    std::optional<std::string> rid;
    std::optional<std::string> repaired_rid;

    uint32_t rtx_ssrc = 0;
    uint16_t rtx_sequence_number = 0;

    uint32_t publisher_primary_ssrc = 0;
    uint32_t subscriber_primary_ssrc = 0;
    uint16_t primary_sequence_number = 0;

    uint64_t created_at_milliseconds = 0;
    uint64_t last_used_at_milliseconds = 0;
};
class rtx_retransmission_index
{
   public:
    rtx_retransmission_index();

    explicit rtx_retransmission_index(rtx_retransmission_index_config config);

    ~rtx_retransmission_index() = default;

    rtx_retransmission_index(const rtx_retransmission_index&) = delete;
    rtx_retransmission_index& operator=(const rtx_retransmission_index&) = delete;

    rtx_retransmission_index(rtx_retransmission_index&&) = delete;
    rtx_retransmission_index& operator=(rtx_retransmission_index&&) = delete;

   public:
    void remember(std::string_view stream_id,
                  std::string_view subscriber_session_id,
                  uint32_t rtx_ssrc,
                  uint16_t rtx_sequence_number,
                  uint32_t publisher_primary_ssrc,
                  uint32_t subscriber_primary_ssrc,
                  uint16_t primary_sequence_number,
                  std::string_view publisher_mid,
                  std::string_view subscriber_mid,
                  std::string_view kind,
                  const std::optional<std::string>& rid,
                  const std::optional<std::string>& repaired_rid,
                  uint64_t now_milliseconds);

    [[nodiscard]]
    std::optional<rtx_retransmission_mapping> find(std::string_view stream_id,
                                                   std::string_view subscriber_session_id,
                                                   uint32_t rtx_ssrc,
                                                   uint16_t rtx_sequence_number) const;

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    [[nodiscard]]
    std::size_t expire_old(uint64_t now_milliseconds);

    void clear();

    [[nodiscard]]
    std::size_t size() const;

   private:
    [[nodiscard]]
    static std::string make_key(std::string_view stream_id, std::string_view subscriber_session_id, uint32_t rtx_ssrc, uint16_t rtx_sequence_number);

    void enforce_capacity_locked();

    [[nodiscard]]
    std::size_t expire_old_locked(uint64_t now_milliseconds);

   private:
    rtx_retransmission_index_config config_;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, rtx_retransmission_mapping> mappings_by_key_;
    std::deque<std::string> insertion_order_;
};
}    // namespace webrtc

#endif
