#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_SSRC_MAPPER_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_SSRC_MAPPER_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <vector>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webrtc
{
struct media_ssrc_mapping
{
    std::string stream_id;

    std::string publisher_session_id;
    std::string subscriber_session_id;

    std::string publisher_mid;
    std::string subscriber_mid;
    std::string kind;

    bool rtx = false;
    uint32_t publisher_rtx_primary_ssrc = 0;
    uint32_t publisher_rtx_repair_ssrc = 0;

    uint32_t publisher_ssrc = 0;
    uint32_t subscriber_ssrc = 0;

    uint64_t created_at_milliseconds = 0;
    uint64_t last_used_at_milliseconds = 0;
    uint64_t packet_count = 0;
};

using media_ssrc_mapping_result = std::expected<media_ssrc_mapping, std::string>;

class media_ssrc_mapper
{
   public:
    media_ssrc_mapper() = default;
    ~media_ssrc_mapper() = default;

    media_ssrc_mapper(const media_ssrc_mapper&) = delete;

    media_ssrc_mapper& operator=(const media_ssrc_mapper&) = delete;

    media_ssrc_mapper(media_ssrc_mapper&&) = delete;

    media_ssrc_mapper& operator=(media_ssrc_mapper&&) = delete;

   public:
    [[nodiscard]]
    media_ssrc_mapping_result get_or_create_mapping(std::string_view stream_id,
                                                    std::string_view publisher_session_id,
                                                    std::string_view subscriber_session_id,
                                                    std::string_view publisher_mid,
                                                    std::string_view subscriber_mid,
                                                    std::string_view kind,
                                                    uint32_t publisher_ssrc,
                                                    uint64_t now_milliseconds,
                                                    bool rtx = false,
                                                    uint32_t publisher_rtx_primary_ssrc = 0,
                                                    uint32_t publisher_rtx_repair_ssrc = 0);
    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_by_publisher_ssrc(std::string_view stream_id,
                                                             std::string_view publisher_session_id,
                                                             std::string_view subscriber_session_id,
                                                             std::string_view publisher_mid,
                                                             uint32_t publisher_ssrc) const;

    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_by_subscriber_ssrc(std::string_view subscriber_session_id, uint32_t subscriber_ssrc) const;

    [[nodiscard]]
    std::vector<media_ssrc_mapping> find_by_subscriber_session(std::string_view subscriber_session_id) const;

    [[nodiscard]]
    std::vector<media_ssrc_mapping> find_by_stream_id(std::string_view stream_id) const;

    void forget_session(std::string_view session_id);

    void forget_stream(std::string_view stream_id);

    void clear();

    [[nodiscard]]
    std::size_t mapping_count() const;

   private:
    [[nodiscard]]
    static std::string make_publisher_key(std::string_view stream_id,
                                          std::string_view publisher_session_id,
                                          std::string_view subscriber_session_id,
                                          std::string_view publisher_mid,
                                          uint32_t publisher_ssrc);

    [[nodiscard]]
    static std::string make_subscriber_key(std::string_view subscriber_session_id, uint32_t subscriber_ssrc);

    [[nodiscard]]
    static uint64_t hash_mapping_seed(std::string_view stream_id,
                                      std::string_view publisher_session_id,
                                      std::string_view subscriber_session_id,
                                      std::string_view publisher_mid,
                                      std::string_view subscriber_mid,
                                      std::string_view kind,
                                      uint32_t publisher_ssrc);

    [[nodiscard]]
    uint32_t generate_subscriber_ssrc_locked(std::string_view stream_id,
                                             std::string_view publisher_session_id,
                                             std::string_view subscriber_session_id,
                                             std::string_view publisher_mid,
                                             std::string_view subscriber_mid,
                                             std::string_view kind,
                                             uint32_t publisher_ssrc) const;

    void erase_mapping_locked(const std::string& publisher_key);

   private:
    mutable std::mutex mutex_;

    std::unordered_map<std::string, media_ssrc_mapping> mappings_by_publisher_key_;

    std::unordered_map<std::string, std::string> publisher_key_by_subscriber_key_;
};

[[nodiscard]]
bool media_ssrc_mapping_requires_rewrite(const media_ssrc_mapping& mapping);

[[nodiscard]]
bool media_ssrc_mapping_is_rtx(const media_ssrc_mapping& mapping);

[[nodiscard]]
bool media_ssrc_mapping_is_primary_video(const media_ssrc_mapping& mapping);

[[nodiscard]]
std::string media_ssrc_mapping_to_string(const media_ssrc_mapping& mapping);
}    // namespace webrtc

#endif
