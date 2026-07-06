#ifndef SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H
#define SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H

#include <deque>
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
#include <utility>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>

#include "dtls/dtls_transport.h"
#include "ice/stun_message.h"
#include "server/lifecycle_debug_json.h"
#include "media/media_payload_type_mapper.h"
#include "media/media_router.h"
#include "media/keyframe_request.h"
#include "media/simulcast_rid_target.h"
#include "media/media_ssrc_mapper.h"
#include "media/media_track_resolver.h"
#include "media/rtcp_feedback_router.h"
#include "media/rtcp_report_service.h"
#include "media/rtcp_transport_cc_feedback_service.h"
#include "media/rtp_packet_cache.h"
#include "media/nack_retransmit_throttle.h"
#include "media/rtx_sequence_number_allocator.h"
#include "media/media_identity_authority.h"
#include "rtp/rtp_packet_rewriter.h"
#include "media/rtx_retransmission_index.h"
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
    void forget_session_runtime_state(std::string_view session_id);

    [[nodiscard]]
    uint16_t local_port() const;

    [[nodiscard]]
    keyframe_request_expected request_keyframe(std::string_view stream_id);

    [[nodiscard]]
    simulcast_rid_target_expected set_runtime_selected_rid_target(const simulcast_rid_target_request& request);

    [[nodiscard]]
    simulcast_rid_target_expected clear_runtime_selected_rid_target(const simulcast_rid_target_request& request);

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
    [[nodiscard]]
    lifecycle_debug_snapshot debug_state_snapshot() const;
    void schedule_subscriber_runtime_residual_check(std::string_view stream_id, std::string_view subscriber_session_id);

    [[nodiscard]]
    lifecycle_debug_subscriber_runtime_residual_entry make_subscriber_runtime_residual_entry(std::string_view stream_id,
                                                                                             std::string_view subscriber_session_id) const;

    void schedule_lifecycle_snapshot_log(std::string reason, std::string stream_id, std::string session_id);

    void log_lifecycle_snapshot(std::string_view reason, std::string_view stream_id, std::string_view session_id) const;

    void schedule_lifecycle_convergence_checks(std::string reason, std::string stream_id, std::string session_id);

    void schedule_lifecycle_convergence_check(std::string reason,
                                              std::string stream_id,
                                              std::string session_id,
                                              uint64_t delay_milliseconds,
                                              bool require_retired_endpoints_empty,
                                              uint64_t generation);

    void log_lifecycle_convergence_check(std::string_view reason,
                                         std::string_view stream_id,
                                         std::string_view session_id,
                                         uint64_t delay_milliseconds,
                                         bool require_retired_endpoints_empty,
                                         uint64_t generation);

   private:
    struct ice_candidate_pair
    {
        std::string session_id;
        std::string stream_id;
        std::string remote_address;

        uint32_t remote_priority = 0;

        uint64_t remote_tie_breaker = 0;

        uint64_t last_binding_at_milliseconds = 0;
        uint64_t last_consent_request_at_milliseconds = 0;
        uint64_t last_consent_response_at_milliseconds = 0;

        uint32_t consent_request_failures = 0;

        std::array<uint8_t, 12> pending_consent_transaction_id{};

        bool consent_request_in_flight = false;

        bool nominated = false;
        bool selected = false;
    };
    struct candidate_pair_selection_result
    {
        bool changed = false;
        std::string previous_remote_address;
        std::string replaced_session_id;
        bool remote_address_reused_by_different_session = false;
    };
    struct ice_consent_request
    {
        std::string session_id;
        std::string stream_id;
        std::string remote_address;

        boost::asio::ip::udp::endpoint remote_endpoint;

        std::string username;
        std::string message_integrity_key;

        uint64_t ice_controlled_tie_breaker = 0;
    };
    struct ice_consent_timeout_event
    {
        std::string session_id;
        std::string stream_id;
        std::string remote_address;

        uint64_t consent_age_milliseconds = 0;
        uint64_t last_binding_at_milliseconds = 0;
        uint64_t last_consent_request_at_milliseconds = 0;
        uint64_t last_consent_response_at_milliseconds = 0;

        uint32_t consent_request_failures = 0;

        bool consent_request_in_flight = false;
    };

    struct media_payload_type_mapping_cache_entry
    {
        std::string publisher_session_id;
        std::string subscriber_session_id;
        std::string stream_id;

        media_payload_type_mapping_table table;
    };

   public:
    struct retired_endpoint_state
    {
        uint64_t expires_at_milliseconds = 0;
        uint64_t suppressed_packets = 0;

        std::string session_id;
        std::string reason;
    };
    struct retired_ice_credential_state
    {
        uint64_t expires_at_milliseconds = 0;
        uint64_t suppressed_stun_packets = 0;

        std::string stream_id;
        std::string session_id;

        std::string local_ice_ufrag;
        std::string remote_ice_ufrag;

        std::string reason;
    };

    struct current_session_endpoint_state
    {
        bool allowed = false;
        bool stale_endpoint = false;

        std::string remote_address;
        std::string stream_id;
        std::string session_id;
        stream_session_kind kind = stream_session_kind::publisher;

        std::string reject_reason;
    };
    struct nack_retransmit_sequence
    {
        uint16_t feedback_sequence_number = 0;
        uint16_t cache_sequence_number = 0;
        bool rtx_feedback = false;
    };

    struct nack_retransmit_resolution
    {
        std::optional<media_ssrc_mapping> ssrc_mapping;

        uint32_t feedback_media_ssrc = 0;
        uint32_t cache_media_ssrc = 0;

        bool primary_video = false;
        bool rtx_feedback = false;

        std::size_t rtx_sequence_index_miss_count = 0;

        std::vector<nack_retransmit_sequence> sequences;
    };
    enum class retransmit_plain_packet_kind
    {
        primary,
        rtx,
    };

    struct retransmit_plain_packet_result
    {
        std::vector<uint8_t> packet;
        retransmit_plain_packet_kind kind = retransmit_plain_packet_kind::primary;
    };
    enum class keyframe_request_feedback_type
    {
        none,
        pli,
        fir,
    };
    struct keyframe_request_media_target
    {
        uint32_t sender_ssrc = 0;
        uint32_t media_ssrc = 0;

        std::string mid;
        std::string kind;

        std::optional<std::string> rid;
        std::optional<std::string> repaired_rid;
    };
    struct republish_keyframe_request_state
    {
        std::string publisher_session_id;

        uint64_t pending_since_milliseconds = 0;
        uint64_t expires_at_milliseconds = 0;

        /*
         * A republish-triggered keyframe request is scoped to the subscribers
         * that were active when the new publisher session replaced the old one.
         *
         * Do not let a later WHEP reconnect/new subscriber consume an old
         * republish pending request. That would make the old publisher switch
         * state leak into a new subscriber generation.
         */
        std::unordered_set<std::string> eligible_subscriber_session_ids;

        /*
         * This set means "this subscriber has received at least one republish
         * recovery PLI". It no longer means the request is fully completed.
         * Republish recovery may send a few bounded retries until the short
         * pending window expires or the per-subscriber attempt limit is reached.
         */
        std::unordered_set<std::string> consumed_subscriber_session_ids;

        std::unordered_map<std::string, uint64_t> last_request_milliseconds_by_subscriber_session_id;
        std::unordered_map<std::string, std::size_t> request_count_by_subscriber_session_id;
    };
    struct outbound_rtp_sequence_rewrite_state
    {
        std::string stream_id;
        std::string publisher_session_id;
        std::string subscriber_session_id;

        uint32_t subscriber_ssrc = 0;

        uint16_t last_publisher_sequence_number = 0;
        uint16_t last_subscriber_sequence_number = 0;
        uint16_t next_subscriber_sequence_number = 0;

        uint64_t packet_count = 0;
        uint64_t publisher_switch_count = 0;
    };
    struct selected_rid_layer_runtime_state
    {
        std::string stream_id;
        std::string publisher_session_id;
        std::string subscriber_session_id;
        std::string mid;
        std::string kind;
        std::string rid;

        std::string previous_rid;
        std::string target_rid;
        std::string target_policy;

        bool manual_target_active = false;

        std::string adaptive_suggested_rid;
        std::string adaptive_suggested_policy;
        std::string adaptive_suggested_reason;
        uint64_t adaptive_suggested_at_milliseconds = 0;

        uint64_t switch_count = 0;
        uint64_t last_switch_milliseconds = 0;
        std::string last_switch_reason;

        bool adaptive_enabled = false;
        std::string last_adaptive_decision;
        std::string last_adaptive_decision_reason;
        uint64_t last_adaptive_decision_milliseconds = 0;
        uint64_t last_adaptive_check_milliseconds = 0;
        uint64_t last_adaptive_primary_packet_count = 0;
        uint64_t last_adaptive_nack_sequence_count = 0;

        std::string selection_policy;
        std::vector<std::string> rid_preference;

        uint32_t primary_ssrc = 0;
        uint32_t repair_ssrc = 0;

        uint64_t packet_count = 0;
        uint64_t byte_count = 0;

        uint64_t primary_packet_count = 0;
        uint64_t primary_byte_count = 0;

        uint64_t repair_packet_count = 0;
        uint64_t repair_byte_count = 0;

        uint64_t last_packet_milliseconds = 0;

        uint64_t bitrate_window_started_milliseconds = 0;
        uint64_t bitrate_window_byte_count = 0;
        uint64_t bitrate_bps = 0;

        uint64_t nack_feedback_count = 0;
        uint64_t nack_sequence_count = 0;
        uint64_t last_nack_milliseconds = 0;

        uint64_t keyframe_request_attempt_count = 0;
        uint64_t keyframe_request_success_count = 0;
        uint64_t keyframe_request_restore_count = 0;
        uint64_t last_keyframe_request_milliseconds = 0;

        std::string last_keyframe_request_result;
        std::string last_keyframe_request_reason;
    };
    struct selected_rid_keyframe_request_pending_state
    {
        uint64_t pending_since_milliseconds = 0;
        uint64_t expires_at_milliseconds = 0;
        uint64_t restore_count = 0;
    };
    struct runtime_selected_rid_target_state
    {
        std::string stream_id;
        std::string publisher_session_id;
        std::string subscriber_session_id;
        std::string mid;
        std::string kind;
        std::string target_rid;
        std::string policy;
        std::string reason;

        uint64_t updated_at_milliseconds = 0;
        uint64_t applied_count = 0;
    };
    struct extmap_rewrite_runtime_state
    {
        std::string stream_id;
        std::string publisher_session_id;
        std::string subscriber_session_id;
        std::string subscriber_mid;
        std::string uri;

        uint8_t source_id = 0;
        uint8_t target_id = 0;

        uint64_t packet_count = 0;
    };

    struct outbound_transport_cc_packet_identity
    {
        std::string stream_id;

        std::string publisher_session_id;
        std::string subscriber_session_id;

        std::string publisher_mid;
        std::string subscriber_mid;

        std::string kind;

        uint32_t publisher_ssrc = 0;
        uint32_t subscriber_ssrc = 0;

        uint8_t publisher_payload_type = 0;
        uint8_t subscriber_payload_type = 0;

        uint16_t publisher_rtp_sequence_number = 0;
        uint16_t subscriber_rtp_sequence_number = 0;

        uint16_t publisher_transport_cc_sequence_number = 0;
        uint16_t subscriber_transport_cc_sequence_number = 0;

        uint64_t sent_at_milliseconds = 0;
    };
    struct outbound_transport_cc_feedback_observation
    {
        uint16_t subscriber_transport_cc_sequence_number = 0;

        bool lookup_hit = false;
        bool received = false;
        bool has_delta = false;

        bool feedback_packet_begin = false;
        bool small_delta = false;
        bool large_delta = false;

        int32_t delta_ticks = 0;
        int64_t delta_microseconds = 0;
        int64_t arrival_offset_microseconds = 0;

        uint64_t observed_at_milliseconds = 0;
        uint64_t sent_at_milliseconds = 0;

        uint32_t publisher_ssrc = 0;
        uint32_t subscriber_ssrc = 0;

        uint16_t publisher_rtp_sequence_number = 0;
        uint16_t subscriber_rtp_sequence_number = 0;
    };

    struct outbound_transport_cc_feedback_window_state
    {
        std::string stream_id;
        std::string subscriber_session_id;

        uint64_t first_feedback_at_milliseconds = 0;
        uint64_t last_feedback_at_milliseconds = 0;

        uint64_t feedback_count = 0;
        uint64_t feedback_packet_status_count = 0;

        uint64_t lookup_hit_count = 0;
        uint64_t lookup_miss_count = 0;

        uint64_t received_count = 0;
        uint64_t lost_count = 0;

        uint64_t small_delta_count = 0;
        uint64_t large_delta_count = 0;

        int64_t delta_microseconds_sum = 0;
        int64_t max_delta_microseconds = 0;
        int64_t min_delta_microseconds = 0;

        std::deque<outbound_transport_cc_feedback_observation> observations;
    };

    enum class subscriber_downlink_control_state
    {
        probing,
        steady,
        recovering,
        constrained,
    };

    struct subscriber_downlink_bandwidth_state
    {
        std::string stream_id;
        std::string subscriber_session_id;

        subscriber_downlink_control_state control_state = subscriber_downlink_control_state::probing;

        uint64_t created_at_milliseconds = 0;
        uint64_t updated_at_milliseconds = 0;
        uint64_t last_feedback_at_milliseconds = 0;
        uint64_t last_transition_at_milliseconds = 0;

        uint64_t transition_count = 0;

        std::string last_transition_reason;

        uint64_t target_bitrate_bps = 2000000;
        uint64_t min_bitrate_bps = 150000;
        uint64_t max_bitrate_bps = 5000000;

        uint64_t feedback_count = 0;
        uint64_t window_observation_count = 0;
        uint64_t window_packet_status_count = 0;

        uint64_t lookup_hit_rate_ppm = 0;
        uint64_t loss_rate_ppm = 0;

        uint64_t received_count = 0;
        uint64_t lost_count = 0;

        int64_t avg_delta_microseconds = 0;
        int64_t min_delta_microseconds = 0;
        int64_t max_delta_microseconds = 0;

        uint64_t bitrate_gate_last_update_milliseconds = 0;
        uint64_t bitrate_gate_budget_bytes = 0;
        uint64_t bitrate_gate_allowed_packet_count = 0;
        uint64_t bitrate_gate_dropped_packet_count = 0;
        uint64_t bitrate_gate_allowed_byte_count = 0;
        uint64_t bitrate_gate_dropped_byte_count = 0;
    };

    struct subscriber_downlink_pacing_packet
    {
        std::string stream_id;
        std::string subscriber_session_id;
        std::string remote_address;

        boost::asio::ip::udp::endpoint remote_endpoint;

        std::vector<uint8_t> protected_packet;

        uint64_t enqueued_at_milliseconds = 0;
        uint64_t protected_size = 0;
    };

    struct subscriber_downlink_pacing_state
    {
        std::string stream_id;
        std::string subscriber_session_id;

        std::deque<subscriber_downlink_pacing_packet> queue;

        uint64_t queue_byte_count = 0;
        uint64_t pacing_budget_bytes = 0;
        uint64_t pacing_last_update_milliseconds = 0;

        uint64_t enqueued_packet_count = 0;
        uint64_t enqueued_byte_count = 0;

        uint64_t sent_packet_count = 0;
        uint64_t sent_byte_count = 0;

        uint64_t dropped_packet_count = 0;
        uint64_t dropped_byte_count = 0;
    };

    struct pending_subscriber_runtime_residual_check
    {
        std::string stream_id;
        std::string subscriber_session_id;
        uint64_t scheduled_at_milliseconds = 0;
    };

   private:
    void handle_transport_cc_feedback_event(const rtcp_feedback_route_event& event);

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

    void send_rtcp_reports(uint64_t current_time_milliseconds);

    void schedule_rtcp_transport_cc_feedback();

    void on_rtcp_transport_cc_feedback_timer(boost::system::error_code ec);

    void send_rtcp_transport_cc_feedback(uint64_t current_time_milliseconds);

    void reset_rtcp_report_runtime_counters();

    void handle_stun_packet(std::span<const uint8_t> data, const boost::asio::ip::udp::endpoint& remote_endpoint);

    void handle_dtls_packet(std::span<const uint8_t> data, const boost::asio::ip::udp::endpoint& remote_endpoint);

    void handle_dtls_close_notify(std::string_view remote_address);

    void handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const boost::asio::ip::udp::endpoint& remote_endpoint);

    [[nodiscard]]
    std::optional<media_track_resolution> resolve_media_track(const media_peer_info& peer, const srtp_packet_process_result& packet);

    [[nodiscard]]
    bool publisher_rtp_identity_is_allowed(const media_route_result& route,
                                           const srtp_packet_process_result& packet,
                                           const std::optional<media_track_resolution>& track_resolution) const;

    [[nodiscard]]
    bool remember_media_identity_forward_mapping(const media_ssrc_mapping& ssrc_mapping, const media_payload_type_mapping& payload_type_mapping);

    [[nodiscard]]
    uint16_t next_outbound_transport_cc_sequence(std::string_view stream_id, std::string_view subscriber_session_id);

    [[nodiscard]]
    uint16_t next_outbound_rtp_sequence(std::string_view stream_id,
                                        std::string_view publisher_session_id,
                                        std::string_view subscriber_session_id,
                                        uint32_t subscriber_ssrc,
                                        uint16_t publisher_sequence_number);

    void forget_outbound_rtp_sequences_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_outbound_rtp_sequences_for_stream_locked(std::string_view stream_id);

    void forget_outbound_transport_cc_sequences_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_outbound_transport_cc_sequences_for_stream_locked(std::string_view stream_id);

    void remember_outbound_transport_cc_packet(const outbound_transport_cc_packet_identity& identity);
    void forget_outbound_transport_cc_packets_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_outbound_transport_cc_packets_for_stream_locked(std::string_view stream_id);

    [[nodiscard]]
    std::optional<outbound_transport_cc_packet_identity> find_outbound_transport_cc_packet(std::string_view stream_id,
                                                                                           std::string_view subscriber_session_id,
                                                                                           uint16_t subscriber_transport_cc_sequence_number) const;

    void remember_outbound_transport_cc_feedback_observation(std::string_view stream_id,
                                                             std::string_view subscriber_session_id,
                                                             const outbound_transport_cc_feedback_observation& observation);

    void forget_outbound_transport_cc_feedback_windows_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_outbound_transport_cc_feedback_windows_for_stream_locked(std::string_view stream_id);

    [[nodiscard]]
    std::size_t outbound_transport_cc_feedback_window_observation_count_locked() const;

    void remember_subscriber_downlink_bandwidth_feedback_window_locked(std::string_view stream_id,
                                                                       std::string_view subscriber_session_id,
                                                                       outbound_transport_cc_feedback_window_state& window,
                                                                       uint64_t current_time_milliseconds);
    [[nodiscard]]
    bool subscriber_downlink_bitrate_gate_allows_packet(const media_route_result& route,
                                                        const media_peer_info& target_peer,
                                                        const std::optional<media_track_resolution>& track_resolution,
                                                        const srtp_packet_process_result& packet,
                                                        std::span<const uint8_t> outbound_plain_packet,
                                                        const std::optional<media_ssrc_mapping>& outbound_mapping);

    [[nodiscard]]
    bool subscriber_downlink_pacing_should_enqueue_packet(const media_route_result& route,
                                                          const media_peer_info& target_peer,
                                                          const srtp_packet_process_result& packet,
                                                          const std::optional<media_ssrc_mapping>& outbound_mapping) const;

    void enqueue_subscriber_downlink_paced_packet(const media_route_result& route,
                                                  const media_peer_info& target_peer,
                                                  std::string_view remote_address,
                                                  const boost::asio::ip::udp::endpoint& remote_endpoint,
                                                  std::vector<uint8_t> protected_packet);

    void schedule_subscriber_downlink_pacing_timer();

    void handle_subscriber_downlink_pacing_timer();

    [[nodiscard]]
    std::vector<subscriber_downlink_pacing_packet> pop_subscriber_downlink_pacing_packets();

    void forget_subscriber_downlink_bandwidth_states_for_session(std::string_view session_id);

    void forget_subscriber_downlink_pacing_states_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_subscriber_downlink_pacing_states_for_stream_locked(std::string_view stream_id);

    [[nodiscard]]
    std::size_t subscriber_downlink_pacing_queue_packet_count_locked() const;

    [[nodiscard]]
    std::size_t subscriber_downlink_pacing_queue_byte_count_locked() const;

    [[nodiscard]]
    std::size_t erase_subscriber_downlink_bandwidth_states_for_stream_locked(std::string_view stream_id);

    [[nodiscard]]
    std::size_t subscriber_downlink_bandwidth_state_count_locked() const;

    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_identity_ssrc_mapping_by_subscriber_ssrc(std::string_view subscriber_session_id,
                                                                                    uint32_t subscriber_ssrc) const;
    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_identity_ssrc_mapping_by_publisher_ssrc(std::string_view stream_id,
                                                                                   std::string_view publisher_session_id,
                                                                                   std::string_view subscriber_session_id,
                                                                                   std::string_view publisher_mid,
                                                                                   uint32_t publisher_ssrc) const;
    [[nodiscard]]
    bool selected_media_peer_needs_refresh(std::string_view remote_address, std::string_view session_id) const;
    [[nodiscard]]
    bool selected_transport_peer_needs_refresh(std::string_view remote_address,
                                               std::string_view session_id,
                                               std::string_view local_ice_ufrag,
                                               std::string_view remote_ice_ufrag) const;

    void observe_inbound_rtp_stats(const media_peer_info& peer,
                                   const srtp_packet_process_result& packet,
                                   const std::optional<media_track_resolution>& track_resolution);

    void observe_inbound_rtcp_reports(const media_peer_info& peer, const srtp_packet_process_result& packet);
    void normalize_inbound_rtcp_report_stats(const media_peer_info& peer, srtp_packet_process_result& packet);

    void observe_outbound_rtp_stats(const media_peer_info& target_peer,
                                    std::span<const uint8_t> outbound_plain_packet,
                                    const std::optional<media_ssrc_mapping>& mapping);

    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_outbound_ssrc_mapping(const media_peer_info& target_peer,
                                                                 std::span<const uint8_t> outbound_plain_packet) const;

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
                                                                  const std::vector<rtcp_feedback_route_event>& feedback_events,
                                                                  const media_peer_info& target_peer);

    [[nodiscard]]
    std::optional<media_payload_type_mapping> find_rtx_payload_type_mapping(const media_payload_type_mapping_table& table,
                                                                            const media_payload_type_mapping& primary_mapping) const;

    [[nodiscard]]
    std::optional<media_ssrc_mapping> get_or_create_rtx_ssrc_mapping(const media_ssrc_mapping& primary_mapping,
                                                                     const media_payload_type_mapping& rtx_payload_type_mapping);

    [[nodiscard]]
    std::optional<std::vector<uint8_t>> make_rtx_retransmit_plain_packet(const rtcp_feedback_route_event& event,
                                                                         const rtp_packet_cache_entry& cached_packet,
                                                                         const media_ssrc_mapping& primary_ssrc_mapping,
                                                                         const media_payload_type_mapping& primary_payload_type_mapping);

    [[nodiscard]]
    std::optional<retransmit_plain_packet_result> make_retransmit_plain_packet(const rtcp_feedback_route_event& event,
                                                                               const rtp_packet_cache_entry& cached_packet,
                                                                               const std::optional<media_ssrc_mapping>& ssrc_mapping);

    [[nodiscard]]
    bool subscriber_feedback_targets_selected_rid_layer(const rtcp_feedback_route_event& event,
                                                        const media_ssrc_mapping& primary_mapping,
                                                        uint32_t feedback_media_ssrc,
                                                        bool allow_rtx_feedback,
                                                        std::string_view feedback_reason) const;
    [[nodiscard]]
    std::optional<nack_retransmit_resolution> resolve_nack_retransmit_resolution(const rtcp_feedback_route_event& event,
                                                                                 uint32_t feedback_media_ssrc,
                                                                                 const std::vector<uint16_t>& feedback_sequence_numbers) const;
    void cache_inbound_rtp_packet(const srtp_packet_process_result& packet,
                                  const media_route_result& route,
                                  const std::optional<media_track_resolution>& track_resolution);
    void handle_rtcp_bye_packet(const srtp_packet_process_result& packet, const media_route_result& route);

    void handle_rtcp_feedback_event(const rtcp_feedback_route_event& event);

    void retransmit_cached_rtp_packets(const rtcp_feedback_route_event& event);

    void erase_rtp_cache(std::string_view stream_id);

    void cleanup_stream_runtime_state(std::string_view stream_id);

    void forward_media_packet(const srtp_packet_process_result& packet,
                              const media_route_result& route,
                              const std::optional<media_track_resolution>& track_resolution,
                              const std::vector<rtcp_feedback_route_event>& feedback_events);

    [[nodiscard]]
    std::unordered_set<std::string> collect_republish_keyframe_eligible_subscribers(std::string_view stream_id) const;

    void mark_republish_keyframe_request_pending(std::string_view stream_id, std::string_view new_publisher_session_id);

    void forget_republish_keyframe_request_pending_for_subscriber(std::string_view stream_id, std::string_view subscriber_session_id);

    [[nodiscard]]
    bool consume_republish_keyframe_request_pending_for_subscriber(const srtp_packet_process_result& packet,
                                                                   const media_route_result& route,
                                                                   const std::optional<media_track_resolution>& track_resolution,
                                                                   const media_peer_info& target_peer);

    void complete_republish_keyframe_request_pending_for_publisher_keyframe(const srtp_packet_process_result& packet,
                                                                            const media_route_result& route,
                                                                            const std::optional<media_track_resolution>& track_resolution);

    void remember_selected_rid_layer_quality_packet_locked(selected_rid_layer_runtime_state& state,
                                                           const media_track_resolution& track_resolution,
                                                           std::size_t packet_size,
                                                           uint64_t current_time_milliseconds);
    [[nodiscard]]
    std::optional<std::string> runtime_selected_rid_target_for_subscriber(const media_route_result& route,
                                                                          const media_peer_info& target_peer,
                                                                          const media_track_resolution& track_resolution) const;

    void remember_runtime_selected_rid_target_locked(std::string_view key,
                                                     selected_rid_layer_runtime_state& state,
                                                     std::string_view target_rid,
                                                     std::string_view policy,
                                                     std::string_view reason,
                                                     uint64_t current_time_milliseconds);

    [[nodiscard]]
    bool runtime_selected_rid_target_is_manual_locked(std::string_view key) const;

    void remember_adaptive_selected_rid_suggestion_locked(selected_rid_layer_runtime_state& state,
                                                          std::string_view suggested_rid,
                                                          std::string_view policy,
                                                          std::string_view reason,
                                                          uint64_t current_time_milliseconds);

    void maybe_update_adaptive_selected_rid_target_locked(std::string_view key,
                                                          selected_rid_layer_runtime_state& state,
                                                          const std::vector<std::string>& rid_preference,
                                                          uint64_t current_time_milliseconds);

    void remember_selected_rid_layer_for_subscriber(const media_route_result& route,
                                                    const media_peer_info& target_peer,
                                                    const media_track_resolution& track_resolution,
                                                    const media_identity_rid_layer_binding& selected_layer,
                                                    std::string_view selection_policy,
                                                    const std::vector<std::string>& rid_preference,
                                                    std::size_t packet_size);
    void remember_selected_rid_layer_nack_quality(const media_ssrc_mapping& mapping, std::size_t feedback_count, std::size_t sequence_count);

    [[nodiscard]]

    bool consume_selected_rid_keyframe_request_pending_for_subscriber(const srtp_packet_process_result& packet,
                                                                      const media_route_result& route,
                                                                      const std::optional<media_track_resolution>& track_resolution,
                                                                      const media_peer_info& target_peer);

    void remember_selected_rid_keyframe_request_pending_locked(std::string_view key,
                                                               selected_rid_layer_runtime_state& state,
                                                               uint64_t current_time_milliseconds,
                                                               std::string_view reason);

    void restore_selected_rid_keyframe_request_pending_for_subscriber(const media_route_result& route,
                                                                      const std::optional<media_track_resolution>& track_resolution,
                                                                      const media_peer_info& target_peer,
                                                                      std::string_view reason);

    void remember_selected_rid_keyframe_request_result(const media_route_result& route,
                                                       const std::optional<media_track_resolution>& track_resolution,
                                                       const media_peer_info& target_peer,
                                                       std::string_view result,
                                                       std::string_view reason,
                                                       bool success);
    void forget_selected_rid_layer_states_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t expire_selected_rid_keyframe_request_pending_locked(uint64_t current_time_milliseconds);

    [[nodiscard]]
    std::size_t erase_selected_rid_layer_states_for_stream_locked(std::string_view stream_id);

    [[nodiscard]]
    bool remember_extmap_header_extension_id_rewrite(std::string_view stream_id,
                                                     std::string_view publisher_session_id,
                                                     std::string_view subscriber_session_id,
                                                     std::string_view subscriber_mid,
                                                     std::string_view uri,
                                                     const rtp_header_extension_id_rewrite& rewrite);

    void forget_extmap_rewrite_states_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_extmap_rewrite_states_for_stream_locked(std::string_view stream_id);
    void maybe_request_keyframe_from_publisher(const srtp_packet_process_result& packet,
                                               const media_route_result& route,
                                               const std::optional<media_track_resolution>& track_resolution,
                                               const media_peer_info& target_peer);

    void send_response(std::vector<uint8_t> response, const boost::asio::ip::udp::endpoint& remote_endpoint);

    void remember_candidate_pair(std::string_view session_id,
                                 std::string_view stream_id,
                                 std::string_view remote_address,
                                 uint32_t remote_priority,
                                 uint64_t remote_tie_breaker,
                                 bool nominated);

    [[nodiscard]]
    std::expected<candidate_pair_selection_result, std::string> select_candidate_pair(std::string_view session_id,
                                                                                      std::string_view stream_id,
                                                                                      const boost::asio::ip::udp::endpoint& remote_endpoint,
                                                                                      uint32_t remote_priority,
                                                                                      uint64_t remote_tie_breaker);
    [[nodiscard]]
    std::vector<ice_consent_request> collect_due_ice_consent_requests(uint64_t current_time_milliseconds);

    void send_ice_consent_requests(uint64_t current_time_milliseconds);

    void remember_ice_consent_request_sent(std::string_view session_id,
                                           std::string_view remote_address,
                                           const std::array<uint8_t, 12>& transaction_id,
                                           uint64_t current_time_milliseconds);

    [[nodiscard]]
    bool remember_ice_consent_success_locked(std::string_view remote_address,
                                             const std::array<uint8_t, 12>& transaction_id,
                                             uint64_t current_time_milliseconds);

    void handle_stun_binding_success_response(std::span<const uint8_t> data,
                                              const stun_message& message,
                                              const boost::asio::ip::udp::endpoint& remote_endpoint);

    [[nodiscard]]
    std::optional<std::string> remote_ice_password_for_session(std::string_view session_id) const;

    [[nodiscard]]
    std::vector<ice_consent_timeout_event> collect_expired_ice_consent_timeout_events(uint64_t current_time_milliseconds);

    void expire_ice_consent_session(const ice_consent_timeout_event& event);

    void cleanup_unselected_candidate_pairs(uint64_t current_time_milliseconds);
    void remove_expired_session(std::string_view session_id, std::string_view reason);

    [[nodiscard]]
    bool is_selected_endpoint(std::string_view remote_address) const;

    void forget_peer_endpoint(std::string_view remote_address);

    void forget_peer_transport_state(std::string_view remote_address);

    void forget_peer_runtime_state_without_dtls_srtp(std::string_view remote_address);

    [[nodiscard]]
    bool migrate_peer_transport_state_for_ice_restart(std::string_view old_remote_address,
                                                      std::string_view new_remote_address,
                                                      const dtls_peer_identity& identity);

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

    [[nodiscard]]
    std::vector<std::pair<std::string, boost::asio::ip::udp::endpoint>> collect_session_endpoint_snapshots_locked(std::string_view session_id) const;

    [[nodiscard]]
    std::vector<std::string> erase_endpoint_indexes_for_session_locked(std::string_view session_id);

    void erase_endpoint_indexes_for_remote_locked(std::string_view remote_address);
    void retire_endpoint_locked(std::string_view remote_address,
                                std::string_view session_id,
                                uint64_t current_time_milliseconds,
                                std::string_view reason);

    void unretire_endpoint_locked(std::string_view remote_address);

    void unretire_endpoint(std::string_view remote_address);

    [[nodiscard]]
    std::optional<retired_endpoint_state> find_retired_endpoint_state_locked(std::string_view remote_address);

    void accept_retired_endpoint_reuse_after_valid_stun(std::string_view remote_address,
                                                        std::string_view stream_id,
                                                        std::string_view session_id,
                                                        std::string_view local_ice_ufrag,
                                                        std::string_view remote_ice_ufrag);
    [[nodiscard]]
    current_session_endpoint_state find_current_session_endpoint(std::string_view remote_address, std::string_view packet_kind);

    [[nodiscard]]
    current_session_endpoint_state validate_current_session_endpoint(std::string_view remote_address,
                                                                     std::string_view expected_session_id,
                                                                     std::string_view expected_stream_id,
                                                                     std::string_view packet_kind);

    [[nodiscard]]
    bool outbound_media_runtime_ready(std::string_view remote_address,
                                      std::string_view expected_session_id,
                                      std::string_view expected_stream_id,
                                      media_peer_role expected_role,
                                      std::string_view packet_kind);

    [[nodiscard]]
    std::optional<dtls_peer_identity> current_dtls_identity_for_session(std::string_view session_id) const;

    void cleanup_stale_current_session_endpoint(std::string remote_address, std::string session_id, std::string reason);
    [[nodiscard]]
    bool retired_endpoint_matches_session(std::string_view remote_address, std::string_view session_id);
    void retire_removed_session_ice_credentials(const stream_removed_session& removed_session, std::string_view reason);
    void retire_restarted_session_ice_credentials(const stream_restarted_session& restarted_session, std::string_view reason);

    void retire_session_endpoint_for_ice_restart(const stream_restarted_session& restarted_session, std::string_view reason);

    void retire_republished_publisher_ice_credentials(const stream_republished_session& republished_session, std::string_view reason);

    void retire_old_publisher_endpoint_for_republish(const stream_republished_session& republished_session, std::string_view reason);

    void forget_publisher_runtime_state_preserving_subscribers(std::string_view stream_id,
                                                               std::string_view publisher_session_id,
                                                               std::string_view reason);
    void retire_ice_credentials_locked(std::string_view local_ice_ufrag,
                                       std::string_view remote_ice_ufrag,
                                       std::string_view stream_id,
                                       std::string_view session_id,
                                       uint64_t current_time_milliseconds,
                                       std::string_view reason);
    [[nodiscard]]
    bool suppress_retired_ice_credential_stun(std::string_view local_ice_ufrag, std::string_view remote_ice_ufrag, std::string_view remote_address);

    [[nodiscard]]
    std::size_t expire_retired_ice_credentials_locked(uint64_t current_time_milliseconds);

    [[nodiscard]]
    bool suppress_retired_endpoint_packet(std::string_view remote_address, std::string_view packet_kind);

    std::size_t expire_retired_endpoints_locked(uint64_t current_time_milliseconds);
    [[nodiscard]]
    std::size_t erase_orphan_endpoint_indexes_locked();

    void erase_payload_type_mappings_for_session_locked(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_keyframe_request_states_for_session_locked(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_payload_type_mappings_for_stream_locked(std::string_view stream_id);

    [[nodiscard]]
    std::size_t erase_keyframe_request_states_for_stream_locked(std::string_view stream_id);

    [[nodiscard]]
    std::optional<boost::asio::ip::udp::endpoint> find_remote_endpoint(std::string_view remote_address) const;

    [[nodiscard]] std::optional<std::string> find_session_id_by_endpoint(std::string_view remote_address) const;

    [[nodiscard]]
    std::shared_ptr<publisher_session> find_publisher_for_username(std::string_view username) const;

    [[nodiscard]]
    std::shared_ptr<subscriber_session> find_subscriber_for_username(std::string_view username) const;

    [[nodiscard]]
    static std::string extract_local_ufrag(std::string_view username);

    [[nodiscard]]
    static std::string endpoint_ip(const boost::asio::ip::udp::endpoint& endpoint);

    void send_rtcp_bye_for_removed_session(const stream_removed_session& removed_session);

    void send_rtcp_bye_for_removed_stream(std::string_view stream_id);

    void send_rtcp_bye_for_mappings(std::string_view stream_id, const std::vector<media_ssrc_mapping>& mappings);

    void send_rtcp_bye_to_subscriber(std::string_view stream_id,
                                     std::string_view subscriber_session_id,
                                     std::string_view remote_address,
                                     const std::vector<uint32_t>& ssrcs);

    [[nodiscard]]
    std::optional<std::string> remote_address_for_session(std::string_view session_id) const;

    void remember_publisher_video_ssrc(const media_peer_info& peer,
                                       const srtp_packet_process_result& packet,
                                       const std::optional<media_track_resolution>& track_resolution);

    [[nodiscard]]
    keyframe_request_feedback_type select_keyframe_request_feedback_type(std::string_view stream_id,
                                                                         std::string_view publisher_session_id = {},
                                                                         std::string_view mid = {},
                                                                         std::string_view kind = {}) const;

    [[nodiscard]]
    std::vector<keyframe_request_media_target> collect_keyframe_request_media_targets(std::string_view stream_id) const;
    [[nodiscard]]
    uint8_t next_fir_sequence_number(std::string_view stream_id, uint32_t media_ssrc);

    [[nodiscard]]
    std::optional<std::vector<uint8_t>> make_keyframe_request_packet(keyframe_request_feedback_type feedback_type,
                                                                     std::string_view stream_id,
                                                                     uint32_t sender_ssrc,
                                                                     uint32_t media_ssrc);

    void send_dtls_close_notify(std::string_view remote_address);
    void send_dtls_close_notify_to_endpoint(std::string_view remote_address, const boost::asio::ip::udp::endpoint& remote_endpoint);

    void observe_outbound_track_stats(const media_peer_info& target_peer,
                                      std::span<const uint8_t> outbound_plain_packet,
                                      const std::optional<media_ssrc_mapping>& mapping);

    [[nodiscard]]
    std::optional<media_ssrc_mapping> find_primary_feedback_ssrc_mapping(const media_route_result& route,
                                                                         const media_peer_info& target_peer,
                                                                         uint32_t subscriber_ssrc,
                                                                         std::string_view feedback_name,
                                                                         bool allow_rtx_repair_target) const;
    [[nodiscard]]
    std::optional<media_ssrc_mapping> resolve_keyframe_feedback_primary_mapping(const rtcp_feedback_route_event& event) const;

    [[nodiscard]]
    std::optional<std::vector<uint8_t>> make_forward_rtcp_feedback_packet(const srtp_packet_process_result& packet,
                                                                          const media_route_result& route,
                                                                          const std::vector<rtcp_feedback_route_event>& feedback_events,
                                                                          const media_peer_info& target_peer);

    void mark_subscriber_downlink_republish_grace_for_stream(std::string_view stream_id, std::string_view publisher_session_id);

    void mark_subscriber_downlink_ice_restart_grace_for_session(std::string_view stream_id, std::string_view subscriber_session_id);

    void forget_keyframe_request_states_for_session(std::string_view session_id);
    void forget_subscriber_downlink_republish_grace_for_session(std::string_view session_id);

    [[nodiscard]]
    std::size_t erase_subscriber_downlink_republish_grace_for_stream_locked(std::string_view stream_id);

   private:
    boost::asio::io_context& io_context_;

    boost::asio::ip::udp::socket socket_;

    boost::asio::steady_timer dtls_timeout_timer_;

    boost::asio::steady_timer ice_consent_timer_;

    boost::asio::steady_timer rtcp_report_timer_;

    boost::asio::steady_timer rtcp_transport_cc_feedback_timer_;
    boost::asio::steady_timer endpoint_idle_cleanup_timer_;
    boost::asio::steady_timer pending_session_cleanup_timer_;
    boost::asio::steady_timer subscriber_downlink_pacing_timer_;

    std::string bind_host_;

    uint16_t bind_port_ = 0;

    std::shared_ptr<stream_registry> registry_;

    std::shared_ptr<dtls_transport> dtls_transport_;

    std::shared_ptr<srtp_transport> srtp_transport_;

    std::shared_ptr<media_router> media_router_;

    std::shared_ptr<media_track_resolver> track_resolver_;

    std::shared_ptr<media_ssrc_mapper> ssrc_mapper_;

    std::shared_ptr<media_identity_authority> identity_authority_;

    std::shared_ptr<rtcp_report_service> rtcp_report_service_;

    std::shared_ptr<rtcp_transport_cc_feedback_service> rtcp_transport_cc_feedback_service_;

    std::shared_ptr<rtp_packet_cache> rtp_packet_cache_;

    std::shared_ptr<rtx_sequence_number_allocator> rtx_sequence_allocator_;

    std::shared_ptr<rtx_retransmission_index> rtx_retransmission_index_;
    std::shared_ptr<nack_retransmit_throttle> nack_retransmit_throttle_;

    boost::asio::ip::udp::endpoint remote_endpoint_;

    std::array<uint8_t, 4096> receive_buffer_{};

    mutable std::mutex endpoint_mutex_;
    std::vector<pending_subscriber_runtime_residual_check> pending_subscriber_runtime_residual_checks_;
    std::unordered_map<std::string, boost::asio::ip::udp::endpoint> endpoints_by_address_;
    std::unordered_map<std::string, std::string> endpoint_address_by_session_id_;
    std::unordered_map<std::string, std::string> session_id_by_endpoint_address_;
    std::unordered_map<std::string, uint64_t> endpoint_last_seen_milliseconds_by_address_;
    std::unordered_map<std::string, ice_candidate_pair> candidate_pairs_by_key_;
    std::unordered_map<std::string, media_payload_type_mapping_cache_entry> payload_type_mappings_by_key_;
    std::unordered_map<std::string, uint64_t> keyframe_request_last_time_milliseconds_by_key_;
    std::unordered_map<std::string, uint8_t> fir_sequence_number_by_key_;
    std::unordered_map<std::string, uint32_t> publisher_video_ssrc_by_stream_;
    std::unordered_map<std::string, republish_keyframe_request_state> pending_republish_keyframe_state_by_stream_;
    std::unordered_map<std::string, selected_rid_layer_runtime_state> selected_rid_layer_state_by_key_;
    std::unordered_map<std::string, runtime_selected_rid_target_state> runtime_selected_rid_targets_by_key_;
    std::unordered_set<std::string> pending_selected_rid_keyframe_request_keys_;
    std::unordered_map<std::string, selected_rid_keyframe_request_pending_state> pending_selected_rid_keyframe_request_state_by_key_;

    std::unordered_map<std::string, extmap_rewrite_runtime_state> extmap_rewrite_state_by_key_;
    std::unordered_map<std::string, outbound_rtp_sequence_rewrite_state> outbound_rtp_sequence_by_key_;
    std::unordered_map<std::string, uint16_t> outbound_transport_cc_sequence_by_key_;
    std::unordered_map<std::string, outbound_transport_cc_packet_identity> outbound_transport_cc_packets_by_key_;
    std::deque<std::string> outbound_transport_cc_packet_insertion_order_;
    std::unordered_map<std::string, outbound_transport_cc_feedback_window_state> outbound_transport_cc_feedback_windows_by_key_;

    std::unordered_map<std::string, subscriber_downlink_bandwidth_state> subscriber_downlink_bandwidth_by_key_;
    std::unordered_map<std::string, subscriber_downlink_pacing_state> subscriber_downlink_pacing_by_key_;
    std::unordered_map<std::string, uint64_t> subscriber_downlink_republish_grace_until_by_key_;

    bool subscriber_downlink_pacing_timer_scheduled_ = false;

    std::unordered_map<std::string, retired_endpoint_state> retired_endpoints_by_address_;
    std::unordered_map<std::string, retired_ice_credential_state> retired_ice_credentials_by_local_ufrag_;

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

    std::atomic<uint64_t> rtp_rtcp_drop_inbound_session_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_inbound_runtime_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_inbound_transport_missing_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_inbound_srtp_failed_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_inbound_srtp_ignored_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_inbound_unknown_peer_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_inbound_identity_gate_total_{0};

    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_no_target_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_transport_missing_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_target_endpoint_missing_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_target_peer_missing_total_{0};

    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_rewrite_failed_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_rewrite_empty_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_runtime_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_bitrate_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_pacing_queue_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_protect_failed_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_media_forward_protect_ignored_total_{0};

    std::atomic<uint64_t> rtp_rtcp_drop_rtcp_report_session_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_rtcp_report_runtime_gate_total_{0};

    std::atomic<uint64_t> rtp_rtcp_drop_twcc_session_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_twcc_identity_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_twcc_send_runtime_gate_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_twcc_endpoint_missing_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_twcc_protect_failed_total_{0};
    std::atomic<uint64_t> rtp_rtcp_drop_twcc_protect_ignored_total_{0};

    std::atomic<uint64_t> lifecycle_convergence_check_generation_{0};

    std::atomic<uint64_t> transport_cc_feedback_total_{0};
    std::atomic<uint64_t> transport_cc_feedback_packet_status_total_{0};
    std::atomic<uint64_t> transport_cc_feedback_lookup_hit_total_{0};
    std::atomic<uint64_t> transport_cc_feedback_lookup_miss_total_{0};
    std::atomic<uint64_t> transport_cc_feedback_received_packet_total_{0};
    std::atomic<uint64_t> transport_cc_feedback_not_received_packet_total_{0};
    std::atomic<uint64_t> transport_cc_feedback_small_delta_total_{0};
    std::atomic<uint64_t> transport_cc_feedback_large_delta_total_{0};
};
}    // namespace webrtc

#endif
