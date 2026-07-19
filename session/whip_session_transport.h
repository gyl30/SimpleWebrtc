#ifndef SIMPLE_WEBRTC_SESSION_WHIP_SESSION_TRANSPORT_H
#define SIMPLE_WEBRTC_SESSION_WHIP_SESSION_TRANSPORT_H

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "dtls/dtls_transport.h"
#include "ice/session_ice_udp_server.h"
#include "media/media_fanout_router.h"
#include "rtp/rtp_receive_statistics.h"
#include "session/session_transport_media_log.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
using whip_session_transport_result = std::expected<void, std::string>;

class whip_session_transport : public session_ice_udp_packet_handler,
                               public std::enable_shared_from_this<whip_session_transport>
{
   public:
    whip_session_transport(boost::asio::io_context& io_context,
                           std::string bind_host,
                           std::shared_ptr<dtls_context> dtls_context,
                           std::uint16_t dtls_ip_mtu,
                           std::shared_ptr<media_fanout_router> media_fanout_router);

    ~whip_session_transport();

    whip_session_transport(const whip_session_transport&) = delete;
    whip_session_transport& operator=(const whip_session_transport&) = delete;

    whip_session_transport(whip_session_transport&&) = delete;
    whip_session_transport& operator=(whip_session_transport&&) = delete;

    [[nodiscard]] whip_session_transport_result start(uint16_t local_port);

    void set_peer_context(std::string local_ice_pwd,
                          dtls_peer_identity identity,
                          const sdp::webrtc_offer_summary& remote_offer,
                          std::span<const int> accepted_remote_media_mline_indexes);

    void restart_peer_context(std::string local_ice_pwd,
                              dtls_peer_identity identity,
                              const sdp::webrtc_offer_summary& remote_offer,
                              std::span<const int> accepted_remote_media_mline_indexes);

    void set_publisher_source_generation(uint64_t source_generation);

    void send_keyframe_request(uint32_t media_ssrc);

   private:
    enum class peer_nomination_state
    {
        unchanged,
        selected_fresh,
        association_rebound,
    };

    struct pending_ice_restart
    {
        uint64_t generation = 0;
        boost::asio::ip::udp::endpoint association_endpoint;
        dtls_peer_identity association_identity;
    };

    struct inbound_payload_type_context
    {
        std::string kind;
        uint32_t clock_rate = 0;

        bool operator==(const inbound_payload_type_context&) const = default;
    };

    struct inbound_rtcp_receiver_state
    {
        std::string kind;
        uint32_t clock_rate = 0;
        rtp_receive_statistics receive_statistics;

        uint64_t sender_report_count = 0;
        uint32_t last_sender_report = 0;
        std::optional<std::chrono::steady_clock::time_point> last_sender_report_received_at;

        uint64_t receiver_report_count = 0;
        uint8_t last_fraction_lost = 0;
        int32_t last_cumulative_lost = 0;
        uint32_t last_extended_highest_sequence_number = 0;
        uint32_t last_jitter = 0;
        uint32_t last_delay_since_sender_report = 0;
        uint64_t last_expected_packet_count = 0;
        uint64_t last_received_packet_count = 0;
        bool receiver_report_logged = false;
    };

    using peer_nomination_result = std::expected<peer_nomination_state, std::string>;

    enum class media_log_event
    {
        udp_received,
        stun_received,
        dtls_received,
        rtp_published,
        rtp_bytes,
        rtp_receive_stats_unmapped,
        rtp_receive_stats_ignored,
        rtcp_received,
        rtcp_sender_report_received,
        rtcp_sender_timing_published,
        rtcp_sender_timing_rejected,
        rtcp_receiver_report_received,
        rtcp_report_block_received,
        rtcp_sdes_received,
        rtcp_bye_received,
        rtcp_pli_ignored,
        rtcp_fir_ignored,
        rtcp_generic_nack_ignored,
        rtcp_transport_cc_ignored,
        rtcp_remb_ignored,
        rtcp_other_feedback_ignored,
        rtcp_unknown_block_ignored,
        rtcp_parse_failed,
        rtcp_receiver_report_sent,
        rtcp_report_block_sent,
        rtcp_sdes_sent,
        rtcp_send_bytes,
        rtcp_build_failed,
        rtcp_protect_failed,
        rtcp_protect_ignored,
        published_targets,
        dropped_unselected,
        srtp_ignored,
        srtp_unprotect_failed,
        other_received,
        count,
    };

    struct media_log_stats
    {
        session_transport_log_counters<media_log_event> counters;
        std::atomic<bool> rtcp_parse_failure_logged{false};
        std::atomic<bool> pli_ignored_logged{false};
        std::atomic<bool> fir_ignored_logged{false};
        std::atomic<bool> generic_nack_ignored_logged{false};
        std::atomic<bool> transport_cc_ignored_logged{false};
        std::atomic<bool> remb_ignored_logged{false};
        std::atomic<bool> other_feedback_ignored_logged{false};
        std::atomic<bool> unknown_rtcp_block_ignored_logged{false};
        std::array<std::atomic<bool>, 128> unmapped_payload_type_logged{};
        std::array<std::atomic<uint32_t>, 16> logged_source_ssrcs{};
        std::array<std::atomic<uint32_t>, 16> logged_sender_timing_ssrcs{};
    };

    void clear_peer_state();
    void clear_peer_state_locked();
    void configure_remote_media_locked(
        const sdp::webrtc_offer_summary& remote_offer,
        std::span<const int> accepted_remote_media_mline_indexes);
    void record_inbound_rtp(uint32_t source_ssrc,
                            uint8_t payload_type,
                            uint16_t sequence_number,
                            uint32_t rtp_timestamp,
                            std::chrono::steady_clock::time_point arrival_time);
    void update_receiver_sender_report(uint32_t source_ssrc,
                                       uint64_t ntp_timestamp,
                                       std::chrono::steady_clock::time_point received_at);
    void schedule_ice_restart_timeout(uint64_t generation);
    void handle_ice_restart_timeout(uint64_t generation);
    void record_media_log_event(media_log_event event, uint64_t value = 1);
    void schedule_media_log_summary();
    void handle_media_log_summary(const boost::system::error_code& error);
    void log_media_summary(int64_t interval_ms);
    void log_receiver_states();
    void schedule_rtcp_receiver_reports();
    void handle_rtcp_receiver_reports(const boost::system::error_code& error);
    void send_rtcp_receiver_reports();
    void handle_inbound_rtcp(std::span<const uint8_t> plain_rtcp);
    [[nodiscard]] peer_nomination_result nominate_remote_endpoint(
        const boost::asio::ip::udp::endpoint& remote_endpoint);

    session_udp_outbound_packet_list handle_udp_packet(const session_udp_packet& packet) override;

   private:
    session_ice_udp_server udp_server_;
    boost::asio::steady_timer ice_restart_timer_;
    boost::asio::steady_timer media_log_timer_;
    boost::asio::steady_timer rtcp_receiver_report_timer_;
    std::chrono::steady_clock::time_point media_log_interval_started_at_;

    std::shared_ptr<dtls_transport> dtls_transport_;
    std::shared_ptr<srtp_transport> srtp_transport_;
    std::shared_ptr<media_fanout_router> media_fanout_router_;

    std::mutex peer_mutex_;
    std::string stream_id_;
    std::string session_id_;
    std::string local_ice_pwd_;
    std::optional<dtls_peer_identity> dtls_identity_;
    uint64_t ice_generation_ = 0;
    uint64_t publisher_source_generation_ = 0;
    std::optional<pending_ice_restart> pending_ice_restart_;

    std::unordered_map<uint8_t, inbound_payload_type_context> inbound_payload_types_;
    std::unordered_map<uint32_t, inbound_rtcp_receiver_state> inbound_rtcp_receivers_;

    std::size_t received_packet_count_ = 0;
    uint32_t rtcp_sender_ssrc_ = 0;
    std::string rtcp_cname_;
    bool rtcp_mux_enabled_ = false;

    media_log_stats media_log_stats_;

    // 仅由当前 ICE generation 中携带 USE-CANDIDATE 的完整 STUN 校验结果更新。
    std::optional<boost::asio::ip::udp::endpoint> selected_remote_endpoint_;
};
}    // namespace webrtc

#endif
