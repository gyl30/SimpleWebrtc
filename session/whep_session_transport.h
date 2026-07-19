#ifndef SIMPLE_WEBRTC_SESSION_WHEP_SESSION_TRANSPORT_H
#define SIMPLE_WEBRTC_SESSION_WHEP_SESSION_TRANSPORT_H

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
#include <unordered_set>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "dtls/dtls_transport.h"
#include "ice/session_ice_udp_server.h"
#include "media/media_fanout_router.h"
#include "media/video_keyframe_detector.h"
#include "media/whep_rtp_rewriter.h"
#include "session/session_transport_media_log.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
using whep_session_transport_result = std::expected<void, std::string>;

class whep_session_transport : public session_ice_udp_packet_handler,
                               public std::enable_shared_from_this<whep_session_transport>
{
   public:
    whep_session_transport(boost::asio::io_context& io_context,
                           std::string bind_host,
                           std::shared_ptr<dtls_context> dtls_context,
                           std::uint16_t dtls_ip_mtu,
                           std::shared_ptr<media_fanout_router> media_fanout_router);

    ~whep_session_transport();

    whep_session_transport(const whep_session_transport&) = delete;
    whep_session_transport& operator=(const whep_session_transport&) = delete;

    whep_session_transport(whep_session_transport&&) = delete;
    whep_session_transport& operator=(whep_session_transport&&) = delete;

   public:
    [[nodiscard]] whep_session_transport_result start(uint16_t local_port);

    void set_peer_context(std::string local_ice_pwd,
                          dtls_peer_identity identity,
                          whep_rtp_rewriter_target target);

    void restart_peer_context(std::string local_ice_pwd,
                              dtls_peer_identity identity,
                              whep_rtp_rewriter_target target);

    void send_rtp(uint64_t source_generation, std::span<const uint8_t> plain_rtp);

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

    struct keyframe_request_context
    {
        std::string publisher_session_id;
        uint64_t source_generation = 0;
        uint32_t source_ssrc = 0;
        uint32_t target_ssrc = 0;
    };

    struct outbound_rtcp_sender_timing
    {
        std::string publisher_session_id;
        uint64_t source_generation = 0;
        uint32_t source_ssrc = 0;
        uint64_t ntp_timestamp = 0;
        uint32_t target_rtp_timestamp = 0;
        uint32_t source_sender_packet_count = 0;
        uint32_t source_sender_octet_count = 0;

        bool operator==(const outbound_rtcp_sender_timing&) const = default;
    };

    struct outbound_rtcp_sender_state
    {
        std::string kind;
        std::string mid;
        std::string cname;
        uint32_t target_ssrc = 0;
        bool rtcp_mux = false;
        bool rtcp_rsize = false;

        uint64_t packet_count = 0;
        uint64_t octet_count = 0;
        std::optional<uint32_t> last_target_rtp_timestamp;
        std::optional<outbound_rtcp_sender_timing> sender_timing;
        bool sender_timing_logged = false;
    };

    using peer_nomination_result = std::expected<peer_nomination_state, std::string>;

    enum class media_log_event
    {
        source_rtp_received,
        rewritten,
        send_enqueued,
        send_bytes,
        send_payload_bytes,
        sender_timing_mapped,
        dropped_no_endpoint,
        dropped_stale_generation,
        rewrite_failed,
        rewrite_dropped,
        protect_failed,
        dropped_srtp_not_ready,
        protect_ignored,
        keyframe_request_submitted,
        keyframe_completed,
        rtcp_received,
        rtcp_sender_report_received,
        rtcp_receiver_report_received,
        rtcp_report_block_received,
        rtcp_sdes_received,
        rtcp_bye_received,
        rtcp_pli_received,
        rtcp_fir_received,
        rtcp_keyframe_feedback_received,
        rtcp_keyframe_feedback_forwarded,
        rtcp_generic_nack_ignored,
        rtcp_transport_cc_ignored,
        rtcp_remb_ignored,
        rtcp_other_feedback_ignored,
        rtcp_unknown_block_ignored,
        rtcp_parse_failed,
        srtp_inbound_ignored,
        srtp_unprotect_failed,
        udp_received,
        stun_received,
        dtls_received,
        dropped_unselected,
        other_received,
        count,
    };

    struct media_log_stats
    {
        session_transport_log_counters<media_log_event> counters;
        std::atomic<bool> rewrite_drop_logged{false};
        std::atomic<bool> srtp_not_ready_logged{false};
        std::atomic<bool> protect_ignore_logged{false};
        std::atomic<bool> rtcp_parse_failure_logged{false};
        std::atomic<bool> generic_nack_ignored_logged{false};
        std::atomic<bool> transport_cc_ignored_logged{false};
        std::atomic<bool> remb_ignored_logged{false};
        std::atomic<bool> other_feedback_ignored_logged{false};
        std::atomic<bool> unknown_rtcp_block_ignored_logged{false};
        std::atomic<bool> keyframe_feedback_logged{false};
        std::atomic<bool> unmapped_keyframe_feedback_logged{false};
        std::array<std::atomic<uint32_t>, 16> logged_target_ssrcs{};
    };

    void subscribe_media();
    void unsubscribe_media();
    void handle_publisher_source(media_publisher_source_update update);
    void handle_publisher_sender_timing(media_publisher_sender_timing timing);
    void configure_outbound_rtcp_senders_locked(const whep_rtp_rewriter_target& target,
                                                 bool preserve_runtime_state);
    void clear_publisher_sender_timings_locked();
    void refresh_sender_timing_locked(uint32_t source_ssrc);
    void record_outbound_rtp_sent_locked(const whep_rtp_rewrite_result& rewritten);
    void rebuild_rtp_rewriter_locked();
    void cancel_keyframe_recovery_locked();
    void reset_keyframe_recovery_locked();

    [[nodiscard]] std::optional<keyframe_request_context> prepare_keyframe_request_locked(
        uint64_t source_generation,
        uint32_t source_ssrc,
        uint32_t target_ssrc,
        bool force_dispatch);

    [[nodiscard]] bool dispatch_keyframe_request(const keyframe_request_context& context,
                                                 std::string_view reason);

    void complete_keyframe_request(const keyframe_request_context& context);
    void handle_inbound_rtcp(std::span<const uint8_t> plain_rtcp);

    void clear_peer_state();
    void clear_peer_state_locked();
    void schedule_ice_restart_timeout(uint64_t generation);
    void handle_ice_restart_timeout(uint64_t generation);
    void record_media_log_event(media_log_event event, uint64_t value = 1);
    void schedule_media_log_summary();
    void handle_media_log_summary(const boost::system::error_code& error);
    void log_media_summary(int64_t interval_ms);
    void log_outbound_rtcp_sender_state_snapshot();
    [[nodiscard]] peer_nomination_result nominate_remote_endpoint(
        const boost::asio::ip::udp::endpoint& remote_endpoint);

    session_udp_outbound_packet_list handle_udp_packet(const session_udp_packet& packet) override;

   private:
    session_ice_udp_server udp_server_;
    boost::asio::steady_timer ice_restart_timer_;
    boost::asio::steady_timer media_log_timer_;
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
    std::optional<pending_ice_restart> pending_ice_restart_;

    std::mutex rtp_rewriter_mutex_;
    whep_rtp_rewriter_target rtp_rewriter_target_;
    media_publisher_source_ptr publisher_source_;
    uint64_t publisher_source_generation_ = 0;
    std::unordered_map<uint32_t, media_publisher_sender_timing> publisher_sender_timings_;
    std::unordered_map<uint32_t, outbound_rtcp_sender_state> outbound_rtcp_senders_;
    whep_rtp_rewriter rtp_rewriter_;
    video_keyframe_tracker keyframe_tracker_;
    std::unordered_set<uint32_t> keyframe_waiting_source_ssrcs_;
    std::unordered_set<uint32_t> keyframe_ready_source_ssrcs_;
    std::unordered_set<uint32_t> unsupported_keyframe_detection_target_ssrcs_;

    std::size_t received_packet_count_ = 0;
    std::size_t rewritten_rtp_packet_count_ = 0;
    std::size_t dropped_rtp_packet_count_ = 0;

    media_log_stats media_log_stats_;

    // 仅由当前 ICE generation 中携带 USE-CANDIDATE 的完整 STUN 校验结果更新。
    std::optional<boost::asio::ip::udp::endpoint> selected_remote_endpoint_;
};
}    // namespace webrtc

#endif
