#ifndef SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H
#define SIMPLE_WEBRTC_ICE_ICE_UDP_SERVER_H

#include <array>
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
#include "media/media_track_resolver.h"
#include "media/rtcp_feedback_router.h"
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

    void handle_stun_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    void handle_dtls_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    void handle_rtp_or_rtcp_packet(std::span<const uint8_t> data, const udp::endpoint& remote_endpoint);

    [[nodiscard]]
    std::optional<media_track_resolution> resolve_media_track(const media_peer_info& peer, const srtp_packet_process_result& packet);

    [[nodiscard]]
    std::optional<media_payload_type_mapping_table> get_or_create_payload_type_mapping_table(const media_route_result& route,
                                                                                             const media_peer_info& target_peer);

    [[nodiscard]]
    std::optional<media_payload_type_mapping> find_payload_type_mapping(const media_route_result& route,
                                                                        const media_peer_info& target_peer,
                                                                        const std::optional<media_track_resolution>& track_resolution);

    [[nodiscard]]
    std::vector<uint8_t> make_forward_plain_packet(const srtp_packet_process_result& packet,
                                                   const media_route_result& route,
                                                   const std::optional<media_track_resolution>& track_resolution,
                                                   const media_peer_info& target_peer);

    void cache_inbound_rtp_packet(const srtp_packet_process_result& packet, const media_route_result& route);

    void handle_rtcp_feedback_event(const rtcp_feedback_route_event& event);

    void retransmit_cached_rtp_packets(const rtcp_feedback_route_event& event);

    void erase_rtp_cache(std::string_view stream_id);

    void forward_media_packet(const srtp_packet_process_result& packet,
                              const media_route_result& route,
                              const std::optional<media_track_resolution>& track_resolution);

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
    bool is_selected_endpoint(std::string_view remote_address) const;

    [[nodiscard]]
    std::vector<std::string> expire_ice_candidate_pairs(uint64_t now_milliseconds);

    void forget_peer_endpoint(std::string_view remote_address);

    void forget_peer_transport_state(std::string_view remote_address);

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

   private:
    boost::asio::io_context& io_context_;

    udp::socket socket_;

    boost::asio::steady_timer dtls_timeout_timer_;

    boost::asio::steady_timer ice_consent_timer_;

    std::string bind_host_;

    uint16_t bind_port_ = 0;

    std::shared_ptr<stream_registry> registry_;

    std::shared_ptr<dtls_transport> dtls_transport_;

    std::shared_ptr<srtp_transport> srtp_transport_;

    std::shared_ptr<media_router> media_router_;

    std::shared_ptr<media_track_resolver> track_resolver_;

    std::shared_ptr<rtp_packet_cache> rtp_packet_cache_;

    udp::endpoint remote_endpoint_;

    std::array<uint8_t, 4096> receive_buffer_{};

    mutable std::mutex endpoint_mutex_;

    std::unordered_map<std::string, udp::endpoint> endpoints_by_address_;

    std::unordered_map<std::string, std::string> endpoint_address_by_session_id_;

    std::unordered_map<std::string, std::string> session_id_by_endpoint_address_;

    std::unordered_map<std::string, ice_candidate_pair> candidate_pairs_by_key_;

    std::unordered_map<std::string, media_payload_type_mapping_cache_entry> payload_type_mappings_by_key_;

    bool started_ = false;

    bool registry_callback_registered_ = false;
};
}    // namespace webrtc

#endif
