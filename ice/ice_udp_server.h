#ifndef SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H
#define SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H

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
#include <string_view>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>

#include "dtls/dtls_transport.h"
#include "media/media_payload_type_mapper.h"
#include "media/media_router.h"
#include "media/keyframe_request.h"
#include "media/media_ssrc_mapper.h"
#include "media/media_track_resolver.h"
#include "media/rtcp_feedback_router.h"
#include "media/rtcp_report_service.h"
#include "media/rtp_packet_cache.h"
#include "session/stream_registry.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
using ice_udp_server_result = std::expected<void, std::string>;

class ice_udp_server : public std::enable_shared_from_this<ice_udp_server>
{
   public:
    ice_udp_server(boost::asio::io_context& io_context,
                   std::string bind_host,
                   uint16_t bind_port,
                   std::shared_ptr<stream_registry> registry,
                   std::shared_ptr<media_router> media_router);

    ~ice_udp_server() = default;

    ice_udp_server(const ice_udp_server&) = delete;

    ice_udp_server& operator=(const ice_udp_server&) = delete;

    ice_udp_server(ice_udp_server&&) = delete;

    ice_udp_server& operator=(ice_udp_server&&) = delete;

   public:
    [[nodiscard]]
    ice_udp_server_result start();

    void stop();

    void forget_session(std::string_view session_id);

    [[nodiscard]]
    uint16_t local_port() const;

    [[nodiscard]]
    keyframe_request_expected request_keyframe(std::string_view stream_id);

    [[nodiscard]]
    rtcp_report_service_runtime_snapshot rtcp_report_runtime_snapshot() const
    {
        rtcp_report_service_runtime_snapshot snapshot;

        if (rtcp_report_service_ != nullptr)
        {
            snapshot = rtcp_report_service_->runtime_snapshot();
        }

        snapshot.inbound_rtcp_observe_attempts = rtcp_report_inbound_rtcp_observe_attempts_total_.load(std::memory_order_relaxed);

        snapshot.inbound_rtcp_observe_failed = rtcp_report_inbound_rtcp_observe_failed_total_.load(std::memory_order_relaxed);

        snapshot.inbound_sender_report_sources = rtcp_report_inbound_sender_report_sources_total_.load(std::memory_order_relaxed);

        snapshot.remember_source_attempts = rtcp_report_remember_source_attempts_total_.load(std::memory_order_relaxed);

        snapshot.remember_source_success = rtcp_report_remember_source_success_total_.load(std::memory_order_relaxed);

        snapshot.remember_source_failed = rtcp_report_remember_source_failed_total_.load(std::memory_order_relaxed);

        snapshot.send_attempts = rtcp_report_send_attempts_total_.load(std::memory_order_relaxed);

        snapshot.send_success = rtcp_report_send_success_total_.load(std::memory_order_relaxed);

        snapshot.endpoint_not_found = rtcp_report_endpoint_not_found_total_.load(std::memory_order_relaxed);

        snapshot.protect_failed = rtcp_report_protect_failed_total_.load(std::memory_order_relaxed);

        snapshot.protect_ignored = rtcp_report_protect_ignored_total_.load(std::memory_order_relaxed);

        return snapshot;
    }

   private:
    using udp = boost::asio::ip::udp;

    struct ice_candidate_pair
    {
        std::string session_id;
        std::string stream_id;
        std::string remote_address;

        uint32_t remote_priority = 0;
        uint64_t remote_tie_breaker = 0;
        uint64_t last_binding_at_milliseconds = 0;

        bool nominated = false;
        bool selected = false;
    };

    struct ice_candidate_pair_selection_result
    {
        bool changed = false;

        std::string previous_remote_address;
    };

    struct media_payload_type_mapping_cache_entry
    {
        std::string publisher_session_id;
        std::string subscriber_session_id;
        std::string stream_id;

        media_payload_type_mapping_table table;
    };

   private:
    [[nodiscard]]
    ice_udp_server_result init_dtls_transport();

    void register_session_removed_callback();

    void do_receive();

    void on_receive(boost::system::error_code ec, std::size_t bytes_transferred);

    void schedule_dtls_timeout();

    void on_dtls_timeout(boost::system::error_code ec);

    void schedule_ice_consent_check();

    void on_ice_consent_check(boost::system::error_code ec);

    void schedule_rtcp_report();

    void on_rtcp_report_timer(boost::system::error_code ec);

    void send_rtcp_reports(uint64_t now_milliseconds);

    void reset_rtcp_report_runtime_counters();

    void handle_stun_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    void handle_dtls_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    void handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    [[nodiscard]]
    std::optional<media_track_resolution> resolve_media_track(const media_peer_info& peer, const srtp_packet_process_result& packet);

    void observe_inbound_rtp_stats(const media_peer_info& peer,
                                   const srtp_packet_process_result& packet,
                                   const std::optional<media_track_resolution>& track_resolution);

    void observe_inbound_rtcp_sender_reports(const media_peer_info& peer, const srtp_packet_process_result& packet);

    void observe_outbound_rtp_stats(const media_peer_info& target_peer, std::span<const uint8_t> outbound_plain_packet);

    [[nodiscard]]
    std::optional<media_payload_type_mapping_table> get_or_create_payload_type_mapping_table(const media_route_result& route,
                                                                                             const media_peer_info& target_peer);

    [[nodiscard]]
    std::optional<media_payload_type_mapping_table> get_or_create_payload_type_mapping_table_for_sessions(std::string_view stream_id,
                                                                                                          std::string_view publisher_session_id,
                                                                                                          std::string_view subscriber_session_id);

    [[nodiscard]]
    std::optional<media_payload_type_mapping> find_payload_type_mapping(const media_route_result& route,
                                                                        const media_peer_info& target_peer,
                                                                        const std::optional<media_track_resolution>& track_resolution);

    [[nodiscard]]
    std::optional<media_ssrc_mapping> get_or_create_ssrc_mapping(const media_route_result& route,
                                                                 const media_peer_info& target_peer,
                                                                 const std::optional<media_track_resolution>& track_resolution,
                                                                 const std::optional<media_payload_type_mapping>& payload_type_mapping);

    [[nodiscard]]
    std::optional<std::vector<uint8_t>> make_forward_plain_packet(const srtp_packet_process_result& packet,
                                                                  const media_route_result& route,
                                                                  const std::optional<media_track_resolution>& track_resolution,
                                                                  const std::optional<rtcp_feedback_route_event>& feedback_event,
                                                                  const media_peer_info& target_peer);

    [[nodiscard]]
    std::optional<std::vector<uint8_t>> make_retransmit_plain_packet(const rtcp_feedback_route_event& event,
                                                                     const rtp_packet_cache_entry& cached_packet,
                                                                     const std::optional<media_ssrc_mapping>& ssrc_mapping);

    void cache_inbound_rtp_packet(const srtp_packet_process_result& packet,
                                  const media_route_result& route,
                                  const std::optional<media_track_resolution>& track_resolution);

    void handle_rtcp_bye_packet(const srtp_packet_process_result& packet, const media_route_result& route);

    void handle_rtcp_feedback_event(const rtcp_feedback_route_event& event);

    void retransmit_cached_rtp_packets(const rtcp_feedback_route_event& event);

    void erase_rtp_cache(std::string_view stream_id);

    void forward_media_packet(const srtp_packet_process_result& packet,
                              const media_route_result& route,
                              const std::optional<media_track_resolution>& track_resolution,
                              const std::optional<rtcp_feedback_route_event>& feedback_event);

    void maybe_request_keyframe_from_publisher(const srtp_packet_process_result& packet,
                                               const media_route_result& route,
                                               const std::optional<media_track_resolution>& track_resolution,
                                               const media_peer_info& target_peer);

    void send_response(std::vector<uint8_t> response, const udp::endpoint& remote_endpoint);

    void remember_candidate_pair(std::string_view session_id,
                                 std::string_view stream_id,
                                 std::string_view remote_address,
                                 uint32_t remote_priority,
                                 uint64_t remote_tie_breaker,
                                 bool nominated);

    [[nodiscard]]
    std::expected<ice_candidate_pair_selection_result, std::string> select_candidate_pair(std::string_view session_id,
                                                                                          std::string_view stream_id,
                                                                                          const udp::endpoint& remote_endpoint,
                                                                                          uint32_t remote_priority,
                                                                                          uint64_t remote_tie_breaker);

    [[nodiscard]]
    std::vector<std::string> collect_expired_ice_consent_session_ids(uint64_t current_time_milliseconds);

    void cleanup_unselected_candidate_pairs(uint64_t current_time_milliseconds);

    void remove_expired_session(std::string_view session_id, std::string_view reason);

    [[nodiscard]]
    bool is_selected_endpoint(std::string_view remote_address) const;

    void forget_peer_endpoint(std::string_view remote_address);

    void forget_peer_transport_state(std::string_view remote_address);

    void touch_endpoint_activity(const boost::asio::ip::udp::endpoint& remote_endpoint);

    void schedule_endpoint_idle_cleanup();

    void schedule_pending_session_cleanup();

    void on_pending_session_cleanup(boost::system::error_code ec);

    [[nodiscard]]
    std::vector<std::string> collect_pending_session_ids(uint64_t current_time_milliseconds) const;

    void on_endpoint_idle_cleanup(boost::system::error_code ec);

    [[nodiscard]]
    std::vector<std::string> collect_idle_session_ids(uint64_t current_time_milliseconds);

    void erase_candidate_pairs_for_session_locked(std::string_view session_id);

    void erase_candidate_pairs_for_endpoint_locked(std::string_view remote_address);

    void erase_payload_type_mappings_for_session_locked(std::string_view session_id);

    [[nodiscard]]
    std::optional<udp::endpoint> find_remote_endpoint(std::string_view remote_address) const;

    [[nodiscard]]
    std::shared_ptr<publisher_session> find_publisher_for_username(std::string_view username) const;

    [[nodiscard]]
    std::shared_ptr<subscriber_session> find_subscriber_for_username(std::string_view username) const;

    [[nodiscard]]
    static std::string extract_local_ufrag(std::string_view username);

    [[nodiscard]]
    static std::string endpoint_ip(const udp::endpoint& endpoint);

    void send_rtcp_bye_for_removed_session(const stream_removed_session& removed_session);

    void send_rtcp_bye_for_removed_stream(std::string_view stream_id);

    void send_rtcp_bye_for_mappings(std::string_view stream_id, const std::vector<media_ssrc_mapping>& mappings);

    void send_rtcp_bye_to_subscriber(std::string_view stream_id,
                                     std::string_view subscriber_session_id,
                                     std::string_view remote_address,
                                     const std::vector<uint32_t>& ssrcs);

    [[nodiscard]]
    std::optional<std::string> remote_address_for_session(std::string_view session_id);

    [[nodiscard]]
    std::vector<uint32_t> collect_keyframe_request_media_ssrcs(std::string_view stream_id) const;

    void send_dtls_close_notify(std::string_view remote_address);

    void observe_outbound_track_stats(const media_peer_info& target_peer, std::span<const uint8_t> outbound_plain_packet);

   private:
    boost::asio::io_context& io_context_;

    udp::socket socket_;

    boost::asio::steady_timer dtls_timeout_timer_;

    boost::asio::steady_timer ice_consent_timer_;

    boost::asio::steady_timer rtcp_report_timer_;

    boost::asio::steady_timer endpoint_idle_cleanup_timer_;

    boost::asio::steady_timer pending_session_cleanup_timer_;

    std::string bind_host_;

    uint16_t bind_port_ = 0;

    std::shared_ptr<stream_registry> registry_;

    std::shared_ptr<dtls_transport> dtls_transport_;

    std::shared_ptr<srtp_transport> srtp_transport_;

    std::shared_ptr<media_router> media_router_;

    std::shared_ptr<media_track_resolver> track_resolver_;

    std::shared_ptr<media_ssrc_mapper> ssrc_mapper_;

    std::shared_ptr<rtcp_report_service> rtcp_report_service_;

    std::shared_ptr<rtp_packet_cache> rtp_packet_cache_;

    udp::endpoint remote_endpoint_;

    std::array<uint8_t, 4096> receive_buffer_{};

    mutable std::mutex endpoint_mutex_;

    std::unordered_map<std::string, udp::endpoint> endpoints_by_address_;

    std::unordered_map<std::string, std::string> endpoint_address_by_session_id_;

    std::unordered_map<std::string, std::string> session_id_by_endpoint_address_;

    std::unordered_map<std::string, uint64_t> endpoint_last_seen_milliseconds_by_address_;

    std::unordered_map<std::string, ice_candidate_pair> candidate_pairs_by_key_;

    std::unordered_map<std::string, media_payload_type_mapping_cache_entry> payload_type_mappings_by_key_;

    std::unordered_map<std::string, uint64_t> keyframe_request_last_time_milliseconds_by_key_;

    bool started_ = false;

    bool registry_callback_registered_ = false;

    uint64_t last_empty_rtcp_report_log_milliseconds_ = 0;

    uint64_t endpoint_idle_timeout_milliseconds_ = 120000;

    uint64_t pending_session_timeout_milliseconds_ = 60000;

    std::atomic<uint64_t> rtcp_report_inbound_rtcp_observe_attempts_total_{0};

    std::atomic<uint64_t> rtcp_report_inbound_rtcp_observe_failed_total_{0};

    std::atomic<uint64_t> rtcp_report_inbound_sender_report_sources_total_{0};

    std::atomic<uint64_t> rtcp_report_remember_source_attempts_total_{0};

    std::atomic<uint64_t> rtcp_report_remember_source_success_total_{0};

    std::atomic<uint64_t> rtcp_report_remember_source_failed_total_{0};

    std::atomic<uint64_t> rtcp_report_send_attempts_total_{0};

    std::atomic<uint64_t> rtcp_report_send_success_total_{0};

    std::atomic<uint64_t> rtcp_report_endpoint_not_found_total_{0};

    std::atomic<uint64_t> rtcp_report_protect_failed_total_{0};

    std::atomic<uint64_t> rtcp_report_protect_ignored_total_{0};
};
}    // namespace webrtc

#endif
