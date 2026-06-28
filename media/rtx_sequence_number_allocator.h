#ifndef SIMPLE_WEBRTC_MEDIA_RTX_SEQUENCE_NUMBER_ALLOCATOR_H
#define SIMPLE_WEBRTC_MEDIA_RTX_SEQUENCE_NUMBER_ALLOCATOR_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
class rtx_sequence_number_allocator
{
   public:
    rtx_sequence_number_allocator() = default;

    ~rtx_sequence_number_allocator() = default;

    rtx_sequence_number_allocator(const rtx_sequence_number_allocator&) = delete;
    rtx_sequence_number_allocator& operator=(const rtx_sequence_number_allocator&) = delete;

    rtx_sequence_number_allocator(rtx_sequence_number_allocator&&) = delete;
    rtx_sequence_number_allocator& operator=(rtx_sequence_number_allocator&&) = delete;

   public:
    [[nodiscard]]
    uint16_t allocate(std::string_view stream_id, std::string_view subscriber_session_id, uint32_t rtx_ssrc, uint16_t seed_sequence_number);

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    void clear();

    [[nodiscard]]
    std::size_t size() const;

   private:
    struct rtx_sequence_state
    {
        std::string stream_id;
        std::string subscriber_session_id;

        uint32_t rtx_ssrc = 0;
        uint16_t next_sequence_number = 0;

        bool initialized = false;
    };

    [[nodiscard]]
    static std::string make_key(std::string_view stream_id, std::string_view subscriber_session_id, uint32_t rtx_ssrc);

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, rtx_sequence_state> states_by_key_;
};
}    // namespace webrtc

#endif
