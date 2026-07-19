#ifndef SIMPLE_WEBRTC_SESSION_WHIP_SESSION_TRANSPORT_H
#define SIMPLE_WEBRTC_SESSION_WHIP_SESSION_TRANSPORT_H

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>

#include <boost/asio.hpp>

#include "dtls/dtls_context.h"
#include "dtls/dtls_transport.h"
#include "ice/session_ice_udp_server.h"
#include "media/media_fanout_router.h"
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

    void set_peer_context(std::string local_ice_pwd, dtls_peer_identity identity);

    void restart_peer_context(std::string local_ice_pwd, dtls_peer_identity identity);

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

    using peer_nomination_result = std::expected<peer_nomination_state, std::string>;

    enum class media_log_event
    {
        udp_received,
        stun_received,
        dtls_received,
        rtp_published,
        rtp_bytes,
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
        published_targets,
        dropped_unselected,
        srtp_ignored,
        srtp_unprotect_failed,
        other_received,
        count,
    };

    struct media_log_stats
    {
        session_transport_log_interval summary_interval;
        session_transport_log_counters<media_log_event> counters;
        std::atomic<bool> rtcp_parse_failure_logged{false};
        std::atomic<bool> pli_ignored_logged{false};
        std::atomic<bool> fir_ignored_logged{false};
        std::atomic<bool> generic_nack_ignored_logged{false};
        std::atomic<bool> transport_cc_ignored_logged{false};
        std::atomic<bool> remb_ignored_logged{false};
        std::atomic<bool> other_feedback_ignored_logged{false};
        std::atomic<bool> unknown_rtcp_block_ignored_logged{false};
        std::array<std::atomic<uint32_t>, 16> logged_source_ssrcs{};
        std::array<std::atomic<uint32_t>, 16> logged_sender_timing_ssrcs{};
    };

    void clear_peer_state();
    void clear_peer_state_locked();
    void schedule_ice_restart_timeout(uint64_t generation);
    void handle_ice_restart_timeout(uint64_t generation);
    void record_media_log_event(media_log_event event, uint64_t value = 1);
    void handle_inbound_rtcp(std::span<const uint8_t> plain_rtcp);
    [[nodiscard]] peer_nomination_result nominate_remote_endpoint(
        const boost::asio::ip::udp::endpoint& remote_endpoint);

    session_udp_outbound_packet_list handle_udp_packet(const session_udp_packet& packet) override;

   private:
    session_ice_udp_server udp_server_;
    boost::asio::steady_timer ice_restart_timer_;

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

    std::size_t received_packet_count_ = 0;
    uint32_t rtcp_sender_ssrc_ = 0;

    media_log_stats media_log_stats_;

    // 仅由当前 ICE generation 中携带 USE-CANDIDATE 的完整 STUN 校验结果更新。
    std::optional<boost::asio::ip::udp::endpoint> selected_remote_endpoint_;
};
}    // namespace webrtc

#endif
