#include "session/whep_session_transport.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "dtls/dtls_packet.h"
#include "dtls/dtls_transport.h"
#include "ice/session_ice_udp_server.h"
#include "log/log.h"
#include "media/media_fanout_router.h"
#include "media/whep_rtp_rewriter.h"
#include "net/socket.h"
#include "rtp/rtcp_compound_packet.h"
#include "rtp/rtcp_packet_builder.h"
#include "rtp/rtp_packet.h"
#include "session/session_stun_binding.h"
#include "session/session_transport_peer_rebind.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
namespace
{
using namespace std::chrono_literals;
constexpr auto k_media_log_interval = 5s;
constexpr std::size_t k_sender_report_history_size = 16;
constexpr std::size_t k_max_retransmissions_per_rtcp_compound = 256;

bool rtp_timestamp_is_newer(uint32_t value, uint32_t reference) { return static_cast<int32_t>(value - reference) > 0; }

enum class inbound_keyframe_feedback_type
{
    pli,
    fir,
};

struct inbound_keyframe_feedback
{
    inbound_keyframe_feedback_type type = inbound_keyframe_feedback_type::pli;
    uint32_t sender_ssrc = 0;
    uint32_t target_ssrc = 0;
    uint8_t fir_sequence_number = 0;
};

std::string_view keyframe_feedback_type_to_string(inbound_keyframe_feedback_type type)
{
    switch (type)
    {
        case inbound_keyframe_feedback_type::pli:
            return "pli";

        case inbound_keyframe_feedback_type::fir:
            return "fir";
    }

    return "unknown";
}

const sdp::media_summary* find_subscriber_media(const whep_rtp_rewriter_target& target, std::string_view mid)
{
    for (const auto& media : target.subscriber_offer.media)
    {
        if (media.mid == mid)
        {
            return &media;
        }
    }

    return nullptr;
}

std::string_view srtp_packet_kind_name(srtp_packet_kind kind)
{
    switch (kind)
    {
        case srtp_packet_kind::unknown:
            return "unknown";

        case srtp_packet_kind::rtp:
            return "rtp";

        case srtp_packet_kind::rtcp:
            return "rtcp";
    }

    return "unknown";
}
}    // namespace

whep_session_transport::whep_session_transport(boost::asio::io_context& io_context,
                                               std::string bind_host,
                                               std::shared_ptr<dtls_context> dtls_context,
                                               std::uint16_t dtls_ip_mtu,
                                               std::shared_ptr<media_fanout_router> media_fanout_router)
    : udp_server_(io_context, std::move(bind_host)),
      media_log_timer_(io_context),
      rtcp_sender_report_timer_(io_context),
      dtls_transport_(std::make_shared<dtls_transport>(std::move(dtls_context), dtls_ip_mtu)),
      srtp_transport_(std::make_shared<srtp_transport>(dtls_transport_)),
      media_fanout_router_(std::move(media_fanout_router))
{
}

whep_session_transport::~whep_session_transport() { close("transport_destroyed"); }

void whep_session_transport::close(std::string_view reason)
{
    if (closed_)
    {
        return;
    }

    closed_ = true;
    media_log_timer_.cancel();
    rtcp_sender_report_timer_.cancel();
    send_rtcp_bye(reason);

    if (media_log_interval_started_at_ != std::chrono::steady_clock::time_point{})
    {
        const auto interval =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - media_log_interval_started_at_);
        log_media_summary(interval.count());
    }

    log_transport_feedback_final_summary(reason);

    unsubscribe_media();
    clear_peer_state();
    udp_server_.stop();
}

whep_session_transport_result whep_session_transport::start(uint16_t local_port)
{
    auto result = udp_server_.start(local_port, *this);

    if (!result)
    {
        return result;
    }

    media_log_interval_started_at_ = std::chrono::steady_clock::now();
    schedule_media_log_summary();
    schedule_rtcp_sender_reports(true, false);
    return {};
}

void whep_session_transport::record_media_log_event(media_log_event event, uint64_t value) { media_log_stats_.counters.add(event, value); }

void whep_session_transport::schedule_media_log_summary()
{
    media_log_timer_.expires_after(k_media_log_interval);
    const std::weak_ptr<whep_session_transport> weak_transport = weak_from_this();

    media_log_timer_.async_wait(
        [weak_transport](const boost::system::error_code& error)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_media_log_summary(error);
            }
        });
}

void whep_session_transport::handle_media_log_summary(const boost::system::error_code& error)
{
    if (error)
    {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    const int64_t interval_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - media_log_interval_started_at_).count();
    media_log_interval_started_at_ = now;
    log_media_summary(interval_ms);
    schedule_media_log_summary();
}

rtcp_interval_input whep_session_transport::make_rtcp_interval_input()
{
    bool local_sender_active = false;

    for (const auto& [target_ssrc, sender] : outbound_rtcp_senders_)
    {
        (void)target_ssrc;
        local_sender_active = local_sender_active || sender.packet_count != 0;
    }

    const std::size_t remote_members = std::max<std::size_t>(remote_rtcp_participant_ssrcs_.size(), 1);

    return rtcp_interval_input{
        .member_count = 1 + remote_members,
        .sender_count = local_sender_active ? 1U : 0U,
        .local_role = local_sender_active ? rtcp_interval_role::sender : rtcp_interval_role::receiver,
    };
}

void whep_session_transport::schedule_rtcp_sender_reports(bool initial, bool packet_sent)
{
    const auto input = make_rtcp_interval_input();
    const auto now = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point deadline;
    rtcp_interval_snapshot snapshot;

    deadline =
        initial ? rtcp_interval_scheduler_.schedule_initial(now, input) : rtcp_interval_scheduler_.schedule_after_fire(now, input, packet_sent);
    snapshot = rtcp_interval_scheduler_.snapshot();

    rtcp_sender_report_timer_.expires_at(deadline);
    const std::weak_ptr<whep_session_transport> weak_transport = weak_from_this();

    rtcp_sender_report_timer_.async_wait(
        [weak_transport](const boost::system::error_code& error)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_rtcp_sender_reports(error);
            }
        });

    if (packet_sent && !rtcp_interval_logged_)
    {
        rtcp_interval_logged_ = true;
        WEBRTC_LOG_INFO("WHEP RTCP interval activated stream={} session={} role={} members={} senders={} average_packet_size={} next_interval_ms={}",
                        stream_id_,
                        session_id_,
                        input.local_role == rtcp_interval_role::sender ? "sender" : "receiver",
                        input.member_count,
                        input.sender_count,
                        snapshot.average_packet_size,
                        snapshot.last_interval.count());
    }

    WEBRTC_LOG_TRACE(
        "WHEP RTCP interval scheduled stream={} session={} initial={} role={} members={} senders={} average_packet_size={} interval_ms={}",
        stream_id_,
        session_id_,
        snapshot.initial ? 1 : 0,
        input.local_role == rtcp_interval_role::sender ? "sender" : "receiver",
        input.member_count,
        input.sender_count,
        snapshot.average_packet_size,
        snapshot.last_interval.count());
}

void whep_session_transport::handle_rtcp_sender_reports(const boost::system::error_code& error)
{
    if (error)
    {
        return;
    }

    const std::size_t wire_bytes = send_rtcp_sender_reports();

    if (wire_bytes != 0)
    {
        rtcp_interval_scheduler_.note_transmission(wire_bytes);
    }

    schedule_rtcp_sender_reports(false, wire_bytes != 0);
}

std::size_t whep_session_transport::send_rtcp_sender_reports()
{
    std::size_t wire_bytes = 0;

    if (closed_ || !selected_remote_endpoint_.has_value())
    {
        return 0;
    }

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);
    auto peer_ready = srtp_transport_->peer_ready(remote_address);

    if (!peer_ready)
    {
        record_media_log_event(media_log_event::rtcp_protect_failed);
        WEBRTC_LOG_WARN("WHEP RTCP SR readiness check failed stream={} session={} remote={} error={}",
                        stream_id_,
                        session_id_,
                        remote_address,
                        peer_ready.error());
        return 0;
    }

    if (!*peer_ready)
    {
        return 0;
    }

    for (auto& [target_ssrc, sender] : outbound_rtcp_senders_)
    {
        (void)target_ssrc;

        if (!sender.rtcp_mux || sender.cname.empty() || sender.packet_count == 0 || !sender.sender_timing.has_value() ||
            sender.sender_timing->source_generation != publisher_source_generation_)
        {
            continue;
        }

        // 同一份 NTP/RTP 映射只发送一次，避免重复 LSR 让 RR 往返时间无法唯一关联。
        if (sender.last_sender_report_ntp_timestamp == sender.sender_timing->ntp_timestamp &&
            sender.last_sender_report_rtp_timestamp == sender.sender_timing->target_rtp_timestamp)
        {
            continue;
        }

        // SR 中的 NTP 与 RTP timestamp 必须来自同一份 publisher timing 快照。
        // last_target_rtp_timestamp 只表示最近已发送 RTP，不能与旧 NTP 时间戳拼成新的时间对。
        rtcp_sender_report_data report{
            .sender_ssrc = sender.target_ssrc,
            .ntp_timestamp = sender.sender_timing->ntp_timestamp,
            .rtp_timestamp = sender.sender_timing->target_rtp_timestamp,
            .sender_packet_count = static_cast<uint32_t>(sender.packet_count),
            .sender_octet_count = static_cast<uint32_t>(sender.octet_count),
            .report_blocks = {},
        };

        auto sender_report = build_rtcp_sender_report(report);
        auto sdes = build_rtcp_sdes_cname(sender.target_ssrc, sender.cname);

        if (!sender_report || !sdes)
        {
            record_media_log_event(media_log_event::rtcp_build_failed);
            WEBRTC_LOG_WARN("WHEP RTCP SR build failed stream={} session={} kind={} target_ssrc={} error={}",
                            stream_id_,
                            session_id_,
                            sender.kind,
                            sender.target_ssrc,
                            !sender_report ? sender_report.error() : sdes.error());
            continue;
        }

        std::array<std::vector<uint8_t>, 2> members{
            std::move(*sender_report),
            std::move(*sdes),
        };
        auto compound = build_rtcp_compound_packet(members);

        if (!compound)
        {
            record_media_log_event(media_log_event::rtcp_build_failed);
            WEBRTC_LOG_WARN("WHEP RTCP compound build failed stream={} session={} kind={} target_ssrc={} error={}",
                            stream_id_,
                            session_id_,
                            sender.kind,
                            sender.target_ssrc,
                            compound.error());
            continue;
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(*compound, remote_address, srtp_packet_kind::rtcp);

        if (!protected_packet)
        {
            record_media_log_event(media_log_event::rtcp_protect_failed);
            WEBRTC_LOG_WARN("WHEP RTCP SR protect failed stream={} session={} kind={} target_ssrc={} remote={} error={}",
                            stream_id_,
                            session_id_,
                            sender.kind,
                            sender.target_ssrc,
                            remote_address,
                            protected_packet.error());
            continue;
        }

        if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
        {
            record_media_log_event(media_log_event::rtcp_protect_ignored);
            WEBRTC_LOG_DEBUG("WHEP RTCP SR protect ignored stream={} session={} kind={} target_ssrc={} remote={} state={} reason={}",
                             stream_id_,
                             session_id_,
                             sender.kind,
                             sender.target_ssrc,
                             remote_address,
                             srtp_packet_process_state_to_string(protected_packet->state),
                             protected_packet->reason);
            continue;
        }

        const auto sent_at = std::chrono::steady_clock::now();
        const uint32_t compact_ntp = static_cast<uint32_t>((sender.sender_timing->ntp_timestamp >> 16U) & 0xFFFFFFFFU);
        const std::size_t protected_size = protected_packet->protected_packet.size();

        sender.sender_report_count += 1;
        sender.sender_report_bytes += protected_size;
        sender.last_sender_report_source_generation = sender.sender_timing->source_generation;
        sender.last_sender_report_ntp_timestamp = sender.sender_timing->ntp_timestamp;
        sender.last_sender_report_rtp_timestamp = sender.sender_timing->target_rtp_timestamp;
        sender.sent_sender_reports.push_back(sent_rtcp_sender_report{
            .compact_ntp = compact_ntp,
            .source_generation = sender.sender_timing->source_generation,
            .sent_at = sent_at,
        });

        while (sender.sent_sender_reports.size() > k_sender_report_history_size)
        {
            sender.sent_sender_reports.pop_front();
        }

        record_media_log_event(media_log_event::rtcp_sender_report_sent);
        record_media_log_event(media_log_event::rtcp_sdes_sent);
        record_media_log_event(media_log_event::rtcp_send_bytes, protected_size);
        wire_bytes += protected_size + (remote_endpoint.address().is_v6() ? k_ipv6_udp_overhead : k_ipv4_udp_overhead);
        udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

        if (!sender.sender_report_logged)
        {
            sender.sender_report_logged = true;
            WEBRTC_LOG_DEBUG(
                "WHEP first sender report sent stream={} session={} kind={} mid={} rtx={} associated_primary_ssrc={} target_ssrc={} "
                "cname={} source_generation={} ntp_timestamp={} rtp_timestamp={} sender_packets={} sender_octets={} compact_ntp={} bytes={}",
                stream_id_,
                session_id_,
                sender.kind,
                sender.mid,
                sender.rtx ? 1 : 0,
                sender.associated_primary_ssrc,
                sender.target_ssrc,
                sender.cname,
                sender.last_sender_report_source_generation,
                sender.last_sender_report_ntp_timestamp,
                sender.last_sender_report_rtp_timestamp,
                sender.packet_count,
                sender.octet_count,
                compact_ntp,
                protected_size);
        }

        WEBRTC_LOG_TRACE(
            "WHEP sender report sent stream={} session={} kind={} rtx={} target_ssrc={} source_generation={} ntp_timestamp={} "
            "rtp_timestamp={} sender_packets={} sender_octets={} reports={} bytes={}",
            stream_id_,
            session_id_,
            sender.kind,
            sender.rtx ? 1 : 0,
            sender.target_ssrc,
            sender.last_sender_report_source_generation,
            sender.last_sender_report_ntp_timestamp,
            sender.last_sender_report_rtp_timestamp,
            sender.packet_count,
            sender.octet_count,
            sender.sender_report_count,
            protected_size);
    }

    return wire_bytes;
}

void whep_session_transport::log_media_summary(int64_t interval_ms)
{
    const uint64_t source_rtp_received = media_log_stats_.counters.take(media_log_event::source_rtp_received);
    const uint64_t source_padding_dropped = media_log_stats_.counters.take(media_log_event::source_padding_dropped);
    const uint64_t source_empty_payload_dropped = media_log_stats_.counters.take(media_log_event::source_empty_payload_dropped);
    const uint64_t source_layout_invalid = media_log_stats_.counters.take(media_log_event::source_layout_invalid);
    const uint64_t rewritten = media_log_stats_.counters.take(media_log_event::rewritten);
    const uint64_t send_enqueued = media_log_stats_.counters.take(media_log_event::send_enqueued);
    const uint64_t send_bytes = media_log_stats_.counters.take(media_log_event::send_bytes);
    const uint64_t send_payload_bytes = media_log_stats_.counters.take(media_log_event::send_payload_bytes);
    const uint64_t sender_timing_mapped = media_log_stats_.counters.take(media_log_event::sender_timing_mapped);
    const uint64_t dropped_no_endpoint = media_log_stats_.counters.take(media_log_event::dropped_no_endpoint);
    const uint64_t dropped_stale_generation = media_log_stats_.counters.take(media_log_event::dropped_stale_generation);
    const uint64_t rewrite_failed = media_log_stats_.counters.take(media_log_event::rewrite_failed);
    const uint64_t rewrite_dropped = media_log_stats_.counters.take(media_log_event::rewrite_dropped);
    const uint64_t protect_failed = media_log_stats_.counters.take(media_log_event::protect_failed);
    const uint64_t dropped_srtp_not_ready = media_log_stats_.counters.take(media_log_event::dropped_srtp_not_ready);
    const uint64_t protect_ignored = media_log_stats_.counters.take(media_log_event::protect_ignored);
    const uint64_t keyframe_request_submitted = media_log_stats_.counters.take(media_log_event::keyframe_request_submitted);
    const uint64_t keyframe_completed = media_log_stats_.counters.take(media_log_event::keyframe_completed);
    const uint64_t rtcp_received = media_log_stats_.counters.take(media_log_event::rtcp_received);
    const uint64_t rtcp_sender_report_received = media_log_stats_.counters.take(media_log_event::rtcp_sender_report_received);
    const uint64_t rtcp_receiver_report_received = media_log_stats_.counters.take(media_log_event::rtcp_receiver_report_received);
    const uint64_t rtcp_report_block_received = media_log_stats_.counters.take(media_log_event::rtcp_report_block_received);
    const uint64_t rtcp_sdes_received = media_log_stats_.counters.take(media_log_event::rtcp_sdes_received);
    const uint64_t rtcp_bye_received = media_log_stats_.counters.take(media_log_event::rtcp_bye_received);
    const uint64_t rtcp_bye_participant_ended = media_log_stats_.counters.take(media_log_event::rtcp_bye_participant_ended);
    const uint64_t rtcp_bye_unknown_ssrc = media_log_stats_.counters.take(media_log_event::rtcp_bye_unknown_ssrc);
    const uint64_t rtcp_bye_sent = media_log_stats_.counters.take(media_log_event::rtcp_bye_sent);
    const uint64_t rtcp_bye_ssrc_sent = media_log_stats_.counters.take(media_log_event::rtcp_bye_ssrc_sent);
    const uint64_t rtcp_bye_send_bytes = media_log_stats_.counters.take(media_log_event::rtcp_bye_send_bytes);
    const uint64_t publisher_source_bye_received = media_log_stats_.counters.take(media_log_event::publisher_source_bye_received);
    const uint64_t rtcp_pli_received = media_log_stats_.counters.take(media_log_event::rtcp_pli_received);
    const uint64_t rtcp_fir_received = media_log_stats_.counters.take(media_log_event::rtcp_fir_received);
    const uint64_t rtcp_keyframe_feedback_received = media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_received);
    const uint64_t rtcp_keyframe_feedback_forwarded = media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_forwarded);
    const uint64_t rtcp_keyframe_feedback_coalesced = media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_coalesced);
    const uint64_t rtcp_keyframe_feedback_target_ignored = media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_target_ignored);
    const uint64_t rtcp_fir_duplicate_ignored = media_log_stats_.counters.take(media_log_event::rtcp_fir_duplicate_ignored);
    const uint64_t rtcp_generic_nack_received = media_log_stats_.counters.take(media_log_event::rtcp_generic_nack_received);
    const uint64_t rtcp_nack_sequence_requested = media_log_stats_.counters.take(media_log_event::rtcp_nack_sequence_requested);
    const uint64_t rtcp_nack_sequence_unique = media_log_stats_.counters.take(media_log_event::rtcp_nack_sequence_unique);
    const uint64_t rtcp_nack_target_ignored = media_log_stats_.counters.take(media_log_event::rtcp_nack_target_ignored);
    const uint64_t rtp_retransmission_cache_hit = media_log_stats_.counters.take(media_log_event::rtp_retransmission_cache_hit);
    const uint64_t rtp_retransmission_cache_miss = media_log_stats_.counters.take(media_log_event::rtp_retransmission_cache_miss);
    const uint64_t rtp_retransmission_suppressed = media_log_stats_.counters.take(media_log_event::rtp_retransmission_suppressed);
    const uint64_t rtp_retransmission_limited = media_log_stats_.counters.take(media_log_event::rtp_retransmission_limited);
    const uint64_t rtp_retransmission_original_sent = media_log_stats_.counters.take(media_log_event::rtp_retransmission_original_sent);
    const uint64_t rtp_retransmission_rtx_sent = media_log_stats_.counters.take(media_log_event::rtp_retransmission_rtx_sent);
    const uint64_t rtp_retransmission_send_bytes = media_log_stats_.counters.take(media_log_event::rtp_retransmission_send_bytes);
    const uint64_t rtp_retransmission_payload_bytes = media_log_stats_.counters.take(media_log_event::rtp_retransmission_payload_bytes);
    const uint64_t rtp_retransmission_build_failed = media_log_stats_.counters.take(media_log_event::rtp_retransmission_build_failed);
    const uint64_t rtp_retransmission_protect_failed = media_log_stats_.counters.take(media_log_event::rtp_retransmission_protect_failed);
    const uint64_t rtp_retransmission_srtp_not_ready = media_log_stats_.counters.take(media_log_event::rtp_retransmission_srtp_not_ready);
    const uint64_t rtp_retransmission_protect_ignored = media_log_stats_.counters.take(media_log_event::rtp_retransmission_protect_ignored);
    const uint64_t rtcp_transport_feedback_received = media_log_stats_.counters.take(media_log_event::rtcp_transport_feedback_received);
    const uint64_t rtcp_remb_ignored = media_log_stats_.counters.take(media_log_event::rtcp_remb_ignored);
    const uint64_t rtcp_other_feedback_ignored = media_log_stats_.counters.take(media_log_event::rtcp_other_feedback_ignored);
    const uint64_t rtcp_unknown_block_ignored = media_log_stats_.counters.take(media_log_event::rtcp_unknown_block_ignored);
    const uint64_t rtcp_parse_failed = media_log_stats_.counters.take(media_log_event::rtcp_parse_failed);
    const uint64_t rtcp_sender_report_sent = media_log_stats_.counters.take(media_log_event::rtcp_sender_report_sent);
    const uint64_t rtcp_sdes_sent = media_log_stats_.counters.take(media_log_event::rtcp_sdes_sent);
    const uint64_t rtcp_send_bytes = media_log_stats_.counters.take(media_log_event::rtcp_send_bytes);
    const uint64_t rtcp_build_failed = media_log_stats_.counters.take(media_log_event::rtcp_build_failed);
    const uint64_t rtcp_protect_failed = media_log_stats_.counters.take(media_log_event::rtcp_protect_failed);
    const uint64_t rtcp_protect_ignored = media_log_stats_.counters.take(media_log_event::rtcp_protect_ignored);
    const uint64_t rtcp_receiver_report_lsr_matched = media_log_stats_.counters.take(media_log_event::rtcp_receiver_report_lsr_matched);
    const uint64_t srtp_inbound_ignored = media_log_stats_.counters.take(media_log_event::srtp_inbound_ignored);
    const uint64_t srtp_unprotect_failed = media_log_stats_.counters.take(media_log_event::srtp_unprotect_failed);
    const uint64_t udp_received = media_log_stats_.counters.take(media_log_event::udp_received);
    const uint64_t stun_received = media_log_stats_.counters.take(media_log_event::stun_received);
    const uint64_t dtls_received = media_log_stats_.counters.take(media_log_event::dtls_received);
    const uint64_t dropped_unselected = media_log_stats_.counters.take(media_log_event::dropped_unselected);
    const uint64_t other_received = media_log_stats_.counters.take(media_log_event::other_received);

    const bool has_activity =
        source_rtp_received != 0 || source_padding_dropped != 0 || source_empty_payload_dropped != 0 || source_layout_invalid != 0 ||
        rewritten != 0 || send_enqueued != 0 || send_bytes != 0 || send_payload_bytes != 0 || sender_timing_mapped != 0 || dropped_no_endpoint != 0 ||
        dropped_stale_generation != 0 || rewrite_failed != 0 || rewrite_dropped != 0 || protect_failed != 0 || dropped_srtp_not_ready != 0 ||
        protect_ignored != 0 || keyframe_request_submitted != 0 || keyframe_completed != 0 || rtcp_received != 0 ||
        rtcp_sender_report_received != 0 || rtcp_receiver_report_received != 0 || rtcp_report_block_received != 0 || rtcp_sdes_received != 0 ||
        rtcp_bye_received != 0 || rtcp_bye_participant_ended != 0 || rtcp_bye_unknown_ssrc != 0 || rtcp_bye_sent != 0 || rtcp_bye_ssrc_sent != 0 ||
        rtcp_bye_send_bytes != 0 || publisher_source_bye_received != 0 || rtcp_pli_received != 0 || rtcp_fir_received != 0 ||
        rtcp_keyframe_feedback_received != 0 || rtcp_keyframe_feedback_forwarded != 0 || rtcp_keyframe_feedback_coalesced != 0 ||
        rtcp_keyframe_feedback_target_ignored != 0 || rtcp_fir_duplicate_ignored != 0 || rtcp_generic_nack_received != 0 ||
        rtcp_nack_sequence_requested != 0 || rtcp_nack_sequence_unique != 0 || rtcp_nack_target_ignored != 0 || rtp_retransmission_cache_hit != 0 ||
        rtp_retransmission_cache_miss != 0 || rtp_retransmission_suppressed != 0 || rtp_retransmission_limited != 0 ||
        rtp_retransmission_original_sent != 0 || rtp_retransmission_rtx_sent != 0 || rtp_retransmission_send_bytes != 0 ||
        rtp_retransmission_payload_bytes != 0 || rtp_retransmission_build_failed != 0 || rtp_retransmission_protect_failed != 0 ||
        rtp_retransmission_srtp_not_ready != 0 || rtp_retransmission_protect_ignored != 0 || rtcp_transport_feedback_received != 0 ||
        rtcp_remb_ignored != 0 || rtcp_other_feedback_ignored != 0 || rtcp_unknown_block_ignored != 0 || rtcp_parse_failed != 0 ||
        rtcp_sender_report_sent != 0 || rtcp_sdes_sent != 0 || rtcp_send_bytes != 0 || rtcp_build_failed != 0 || rtcp_protect_failed != 0 ||
        rtcp_protect_ignored != 0 || rtcp_receiver_report_lsr_matched != 0 || srtp_inbound_ignored != 0 || srtp_unprotect_failed != 0 ||
        udp_received != 0 || stun_received != 0 || dtls_received != 0 || dropped_unselected != 0 || other_received != 0;

    if (!has_activity)
    {
        return;
    }

    WEBRTC_LOG_DEBUG(
        "WHEP media summary stream={} session={} interval_ms={} source_rtp={} source_padding_dropped={} "
        "source_empty_payload_dropped={} source_layout_invalid={} rewritten={} send_enqueued={} send_bytes={} "
        "send_payload_bytes={} sender_timing_mapped={} dropped_no_endpoint={} dropped_stale_source_generation={} rewrite_failed={} "
        "rewrite_dropped={} protect_failed={} "
        "dropped_srtp_not_ready={} protect_ignored={} keyframe_request_submitted={} keyframe_completed={} rtcp_received={} rtcp_sr={} rtcp_rr={} "
        "rtcp_report_blocks={} rtcp_sdes={} rtcp_bye={} rtcp_bye_participant_ended={} rtcp_bye_unknown_ssrc={} "
        "rtcp_bye_sent={} rtcp_bye_ssrcs_sent={} rtcp_bye_send_bytes={} publisher_source_bye={} "
        "rtcp_pli={} rtcp_fir={} rtcp_keyframe_feedback_received={} "
        "rtcp_keyframe_feedback_forwarded={} rtcp_keyframe_feedback_coalesced={} rtcp_keyframe_feedback_target_ignored={} "
        "rtcp_fir_duplicate_ignored={} rtcp_generic_nack={} rtcp_nack_sequences_requested={} rtcp_nack_sequences_unique={} "
        "rtcp_nack_target_ignored={} retransmission_cache_hit={} retransmission_cache_miss={} retransmission_suppressed={} "
        "retransmission_limited={} retransmission_original_sent={} retransmission_rtx_sent={} retransmission_send_bytes={} "
        "retransmission_payload_bytes={} "
        "retransmission_build_failed={} retransmission_protect_failed={} retransmission_srtp_not_ready={} retransmission_protect_ignored={} "
        "rtcp_transport_feedback={} rtcp_remb_ignored={} rtcp_other_feedback_ignored={} rtcp_unknown_block_ignored={} "
        "rtcp_parse_failed={} rtcp_sr_sent={} rtcp_sdes_sent={} "
        "rtcp_send_bytes={} rtcp_build_failed={} rtcp_protect_failed={} rtcp_protect_ignored={} rtcp_rr_lsr_matched={} "
        "srtp_inbound_ignored={} srtp_unprotect_failed={} udp_received={} stun={} dtls={} dropped_unselected={} other_received={}",
        stream_id_,
        session_id_,
        interval_ms,
        source_rtp_received,
        source_padding_dropped,
        source_empty_payload_dropped,
        source_layout_invalid,
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
        rtcp_bye_participant_ended,
        rtcp_bye_unknown_ssrc,
        rtcp_bye_sent,
        rtcp_bye_ssrc_sent,
        rtcp_bye_send_bytes,
        publisher_source_bye_received,
        rtcp_pli_received,
        rtcp_fir_received,
        rtcp_keyframe_feedback_received,
        rtcp_keyframe_feedback_forwarded,
        rtcp_keyframe_feedback_coalesced,
        rtcp_keyframe_feedback_target_ignored,
        rtcp_fir_duplicate_ignored,
        rtcp_generic_nack_received,
        rtcp_nack_sequence_requested,
        rtcp_nack_sequence_unique,
        rtcp_nack_target_ignored,
        rtp_retransmission_cache_hit,
        rtp_retransmission_cache_miss,
        rtp_retransmission_suppressed,
        rtp_retransmission_limited,
        rtp_retransmission_original_sent,
        rtp_retransmission_rtx_sent,
        rtp_retransmission_send_bytes,
        rtp_retransmission_payload_bytes,
        rtp_retransmission_build_failed,
        rtp_retransmission_protect_failed,
        rtp_retransmission_srtp_not_ready,
        rtp_retransmission_protect_ignored,
        rtcp_transport_feedback_received,
        rtcp_remb_ignored,
        rtcp_other_feedback_ignored,
        rtcp_unknown_block_ignored,
        rtcp_parse_failed,
        rtcp_sender_report_sent,
        rtcp_sdes_sent,
        rtcp_send_bytes,
        rtcp_build_failed,
        rtcp_protect_failed,
        rtcp_protect_ignored,
        rtcp_receiver_report_lsr_matched,
        srtp_inbound_ignored,
        srtp_unprotect_failed,
        udp_received,
        stun_received,
        dtls_received,
        dropped_unselected,
        other_received);

    log_outbound_rtcp_sender_state_snapshot();
    log_retransmission_cache_state();
    log_transport_feedback_state();
    log_rtcp_interval_state();
}

void whep_session_transport::log_retransmission_cache_state()
{
    const rtp_retransmission_cache_snapshot snapshot = retransmission_cache_.snapshot();

    WEBRTC_LOG_DEBUG(
        "WHEP retransmission cache state stream={} session={} packets={} bytes={} inserted={} replaced={} "
        "evicted_age={} evicted_capacity={}",
        stream_id_,
        session_id_,
        snapshot.packet_count,
        snapshot.byte_count,
        snapshot.inserted,
        snapshot.replaced,
        snapshot.evicted_age,
        snapshot.evicted_capacity);
}

void whep_session_transport::log_transport_feedback_state()
{
    transport_feedback_history_.expire(std::chrono::steady_clock::now());
    const auto snapshot = transport_feedback_history_.snapshot();

    WEBRTC_LOG_DEBUG(
        "WHEP transport-cc shadow state stream={} session={} history_packets={} sent_packets={} sent_bytes={} "
        "sent_retransmissions={} sent_retransmission_bytes={} feedback_packets={} feedback_statuses={} "
        "lookup_hit={} lookup_miss={} received={} not_received={} received_bytes={} not_received_bytes={} "
        "received_retransmissions={} not_received_retransmissions={} feedback_duplicates={} feedback_gaps={} "
        "feedback_reordered={} evicted_age={} evicted_capacity={} maximum_feedback_delay_ms={}",
        stream_id_,
        session_id_,
        snapshot.history_packets,
        snapshot.sent_packets,
        snapshot.sent_bytes,
        snapshot.sent_retransmissions,
        snapshot.sent_retransmission_bytes,
        snapshot.feedback_packets,
        snapshot.feedback_statuses,
        snapshot.lookup_hit,
        snapshot.lookup_miss,
        snapshot.received,
        snapshot.not_received,
        snapshot.received_bytes,
        snapshot.not_received_bytes,
        snapshot.received_retransmissions,
        snapshot.not_received_retransmissions,
        snapshot.feedback_duplicates,
        snapshot.feedback_gaps,
        snapshot.feedback_reordered,
        snapshot.evicted_age,
        snapshot.evicted_capacity,
        snapshot.maximum_feedback_delay_ms);
}

void whep_session_transport::log_transport_feedback_final_summary(std::string_view reason)
{
    transport_feedback_history_.expire(std::chrono::steady_clock::now());
    const auto snapshot = transport_feedback_history_.snapshot();

    WEBRTC_LOG_INFO(
        "WHEP transport-cc shadow final stream={} session={} reason={} history_packets={} sent_packets={} sent_bytes={} "
        "sent_retransmissions={} sent_retransmission_bytes={} feedback_packets={} feedback_statuses={} "
        "lookup_hit={} lookup_miss={} received={} not_received={} received_bytes={} not_received_bytes={} "
        "received_retransmissions={} not_received_retransmissions={} feedback_duplicates={} feedback_gaps={} "
        "feedback_reordered={} evicted_age={} evicted_capacity={} maximum_feedback_delay_ms={}",
        stream_id_,
        session_id_,
        reason,
        snapshot.history_packets,
        snapshot.sent_packets,
        snapshot.sent_bytes,
        snapshot.sent_retransmissions,
        snapshot.sent_retransmission_bytes,
        snapshot.feedback_packets,
        snapshot.feedback_statuses,
        snapshot.lookup_hit,
        snapshot.lookup_miss,
        snapshot.received,
        snapshot.not_received,
        snapshot.received_bytes,
        snapshot.not_received_bytes,
        snapshot.received_retransmissions,
        snapshot.not_received_retransmissions,
        snapshot.feedback_duplicates,
        snapshot.feedback_gaps,
        snapshot.feedback_reordered,
        snapshot.evicted_age,
        snapshot.evicted_capacity,
        snapshot.maximum_feedback_delay_ms);
}

void whep_session_transport::log_rtcp_interval_state()
{
    const rtcp_interval_snapshot snapshot = rtcp_interval_scheduler_.snapshot();

    WEBRTC_LOG_DEBUG("WHEP RTCP interval state stream={} session={} initial={} members={} senders={} average_packet_size={} last_interval_ms={}",
                     stream_id_,
                     session_id_,
                     snapshot.initial ? 1 : 0,
                     snapshot.member_count,
                     snapshot.sender_count,
                     snapshot.average_packet_size,
                     snapshot.last_interval.count());
}

void whep_session_transport::log_outbound_rtcp_sender_state_snapshot()
{
    std::vector<outbound_rtcp_sender_state> senders;

    {
        senders.reserve(outbound_rtcp_senders_.size());

        for (const auto& [target_ssrc, sender] : outbound_rtcp_senders_)
        {
            (void)target_ssrc;
            senders.push_back(sender);
        }
    }

    std::sort(senders.begin(),
              senders.end(),
              [](const outbound_rtcp_sender_state& left, const outbound_rtcp_sender_state& right) { return left.target_ssrc < right.target_ssrc; });

    for (const auto& sender : senders)
    {
        if (sender.packet_count == 0 && !sender.sender_timing.has_value())
        {
            continue;
        }

        const std::string publisher_session_id = sender.sender_timing.has_value() ? sender.sender_timing->publisher_session_id : std::string{};
        const uint64_t source_generation = sender.sender_timing.has_value() ? sender.sender_timing->source_generation : 0;
        const uint32_t source_ssrc = sender.sender_timing.has_value() ? sender.sender_timing->source_ssrc : 0;
        const uint64_t ntp_timestamp = sender.sender_timing.has_value() ? sender.sender_timing->ntp_timestamp : 0;
        const uint32_t timing_target_rtp_timestamp = sender.sender_timing.has_value() ? sender.sender_timing->target_rtp_timestamp : 0;

        WEBRTC_LOG_DEBUG(
            "WHEP sender state stream={} session={} kind={} mid={} rtx={} associated_primary_ssrc={} target_ssrc={} cname={} "
            "packets={} octets={} last_target_rtp_timestamp={} timing_ready={} publisher_session={} source_generation={} "
            "source_ssrc={} ntp_timestamp={} "
            "timing_target_rtp_timestamp={} sr_sent={} sr_bytes={} last_sr_source_generation={} last_sr_ntp_timestamp={} "
            "last_sr_rtp_timestamp={} rr_received={} last_rr_lsr={} last_rr_dlsr={} last_fraction_lost={} "
            "last_cumulative_lost={} last_jitter={} last_rtt_ms={} rtcp_mux={} rtcp_rsize={}",
            stream_id_,
            session_id_,
            sender.kind,
            sender.mid,
            sender.rtx ? 1 : 0,
            sender.associated_primary_ssrc,
            sender.target_ssrc,
            sender.cname,
            sender.packet_count,
            sender.octet_count,
            sender.last_target_rtp_timestamp.value_or(0),
            sender.sender_timing.has_value() ? 1 : 0,
            publisher_session_id,
            source_generation,
            source_ssrc,
            ntp_timestamp,
            timing_target_rtp_timestamp,
            sender.sender_report_count,
            sender.sender_report_bytes,
            sender.last_sender_report_source_generation,
            sender.last_sender_report_ntp_timestamp,
            sender.last_sender_report_rtp_timestamp,
            sender.receiver_report_count,
            sender.last_receiver_report_lsr,
            sender.last_receiver_report_dlsr,
            sender.last_fraction_lost,
            sender.last_cumulative_lost,
            sender.last_jitter,
            sender.last_round_trip_time_ms.value_or(0),
            sender.rtcp_mux ? 1 : 0,
            sender.rtcp_rsize ? 1 : 0);
    }
}

void whep_session_transport::set_peer_context(std::string local_ice_pwd, dtls_peer_identity identity, whep_rtp_rewriter_target target)
{
    unsubscribe_media();
    clear_peer_state();

    stream_id_ = identity.stream_id;
    session_id_ = identity.session_id;
    local_ice_pwd_ = std::move(local_ice_pwd);
    dtls_identity_ = std::move(identity);
    configure_outbound_rtcp_senders(target);
    rtp_rewriter_target_ = std::move(target);
    publisher_source_.reset();
    publisher_source_generation_ = 0;
    clear_publisher_sender_timings();
    clear_keyframe_feedback_state();
    retransmission_cache_.clear();
    transport_feedback_history_.reset();
    remote_rtcp_participant_ssrcs_.clear();
    reset_keyframe_recovery();
    rebuild_rtp_rewriter();

    subscribe_media();
}

void whep_session_transport::send_rtp(uint64_t source_generation, std::span<const uint8_t> plain_rtp)
{
    if (plain_rtp.empty())
    {
        return;
    }

    auto layout = inspect_rtp_packet_layout(plain_rtp);

    if (!layout)
    {
        record_media_log_event(media_log_event::source_layout_invalid);

        if (!std::exchange(media_log_stats_.source_layout_invalid_logged, true))
        {
            WEBRTC_LOG_WARN("WHEP source RTP layout invalid stream={} session={} error={}", stream_id_, session_id_, layout.error());
        }

        return;
    }

    if (layout->padding_only())
    {
        record_media_log_event(media_log_event::source_padding_dropped);
        return;
    }

    if (layout->media_payload_size == 0)
    {
        record_media_log_event(media_log_event::source_empty_payload_dropped);

        if (!std::exchange(media_log_stats_.source_empty_payload_logged, true))
        {
            WEBRTC_LOG_WARN("WHEP source RTP empty media payload dropped stream={} session={}", stream_id_, session_id_);
        }

        return;
    }

    record_media_log_event(media_log_event::source_rtp_received);

    if (closed_)
    {
        return;
    }

    if (!selected_remote_endpoint_.has_value())
    {
        record_media_log_event(media_log_event::dropped_no_endpoint);
        return;
    }

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);
    auto peer_ready = srtp_transport_->peer_ready(remote_address);

    if (!peer_ready)
    {
        record_media_log_event(media_log_event::protect_failed);
        WEBRTC_LOG_WARN(
            "WHEP SRTP readiness check failed stream={} session={} remote={} error={}", stream_id_, session_id_, remote_address, peer_ready.error());
        return;
    }

    if (!*peer_ready)
    {
        record_media_log_event(media_log_event::dropped_srtp_not_ready);

        if (!std::exchange(media_log_stats_.srtp_not_ready_logged, true))
        {
            WEBRTC_LOG_DEBUG("WHEP media send waiting for SRTP stream={} session={} remote={}", stream_id_, session_id_, remote_address);
        }

        return;
    }

    if (source_generation != publisher_source_generation_)
    {
        record_media_log_event(media_log_event::dropped_stale_generation);
        return;
    }

    whep_rtp_rewrite_packet_result rewritten = rtp_rewriter_.rewrite(plain_rtp, transport_feedback_history_.next_sequence_number());

    if (!rewritten)
    {
        record_media_log_event(media_log_event::rewrite_failed);
        WEBRTC_LOG_WARN("WHEP RTP rewrite failed stream={} session={} error={}", stream_id_, session_id_, rewritten.error());
        return;
    }

    if (rewritten->state != whep_rtp_rewrite_state::rewritten || rewritten->packet.empty())
    {
        ++dropped_rtp_packet_count_;
        record_media_log_event(media_log_event::rewrite_dropped);

        if (!std::exchange(media_log_stats_.rewrite_drop_logged, true))
        {
            WEBRTC_LOG_DEBUG("WHEP first RTP rewrite drop stream={} session={} source_ssrc={} source_pt={} source_seq={} reason={}",
                             stream_id_,
                             session_id_,
                             rewritten->source_ssrc,
                             rewritten->source_payload_type,
                             rewritten->source_sequence_number,
                             rewritten->reason);
        }

        WEBRTC_LOG_TRACE("WHEP RTP rewrite dropped stream={} session={} source_ssrc={} source_pt={} source_seq={} reason={} dropped={}",
                         stream_id_,
                         session_id_,
                         rewritten->source_ssrc,
                         rewritten->source_payload_type,
                         rewritten->source_sequence_number,
                         rewritten->reason,
                         dropped_rtp_packet_count_);
        return;
    }

    ++rewritten_rtp_packet_count_;
    record_media_log_event(media_log_event::rewritten);

    auto protected_packet = srtp_transport_->protect_outbound_packet(rewritten->packet, remote_address, srtp_packet_kind::rtp);

    if (!protected_packet)
    {
        record_media_log_event(media_log_event::protect_failed);
        WEBRTC_LOG_WARN(
            "WHEP RTP protect failed stream={} session={} remote={} error={}", stream_id_, session_id_, remote_address, protected_packet.error());
        return;
    }

    if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
    {
        record_media_log_event(media_log_event::protect_ignored);

        if (!std::exchange(media_log_stats_.protect_ignore_logged, true))
        {
            WEBRTC_LOG_DEBUG("WHEP first RTP protect ignore stream={} session={} remote={} state={} reason={}",
                             stream_id_,
                             session_id_,
                             remote_address,
                             srtp_packet_process_state_to_string(protected_packet->state),
                             protected_packet->reason);
        }

        WEBRTC_LOG_TRACE("WHEP RTP protect ignored stream={} session={} remote={} state={} reason={}",
                         stream_id_,
                         session_id_,
                         remote_address,
                         srtp_packet_process_state_to_string(protected_packet->state),
                         protected_packet->reason);
        return;
    }

    if (mark_session_transport_value_once(media_log_stats_.logged_target_ssrcs, rewritten->target_ssrc))
    {
        WEBRTC_LOG_DEBUG(
            "WHEP first RTP rewritten stream={} session={} kind={} codec={} rtx={} source_ssrc={} target_ssrc={} source_pt={} target_pt={} "
            "source_seq={} target_seq={} source_timestamp={} target_timestamp={}",
            stream_id_,
            session_id_,
            rewritten->kind,
            rewritten->codec_name,
            rewritten->rtx ? 1 : 0,
            rewritten->source_ssrc,
            rewritten->target_ssrc,
            rewritten->source_payload_type,
            rewritten->target_payload_type,
            rewritten->source_sequence_number,
            rewritten->target_sequence_number,
            rewritten->source_timestamp,
            rewritten->target_timestamp);
    }

    WEBRTC_LOG_TRACE(
        "WHEP RTP rewritten stream={} session={} kind={} codec={} rtx={} source_ssrc={} target_ssrc={} source_pt={} target_pt={} "
        "source_seq={} target_seq={} source_timestamp={} target_timestamp={} packets={}",
        stream_id_,
        session_id_,
        rewritten->kind,
        rewritten->codec_name,
        rewritten->rtx ? 1 : 0,
        rewritten->source_ssrc,
        rewritten->target_ssrc,
        rewritten->source_payload_type,
        rewritten->target_payload_type,
        rewritten->source_sequence_number,
        rewritten->target_sequence_number,
        rewritten->source_timestamp,
        rewritten->target_timestamp,
        rewritten_rtp_packet_count_);

    if (source_generation != publisher_source_generation_)
    {
        record_media_log_event(media_log_event::dropped_stale_generation);
        return;
    }

    const std::size_t protected_size = protected_packet->protected_packet.size();
    udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

    if (rewritten->transport_sequence_number.has_value())
    {
        transport_feedback_history_.remember_sent(transport_feedback_sent_packet{
            .packet_size = protected_size,
            .retransmission = rewritten->rtx,
            .sent_at = std::chrono::steady_clock::now(),
        });
    }

    cache_rewritten_rtp(source_generation, *rewritten);
    record_outbound_rtp_sent(*rewritten);

    record_media_log_event(media_log_event::send_enqueued);
    record_media_log_event(media_log_event::send_bytes, protected_size);
    record_media_log_event(media_log_event::send_payload_bytes, rewritten->payload_size);

    std::optional<keyframe_request_context> request_context;
    std::optional<keyframe_request_context> completed_context;

    if (rewritten->kind == "video" && !rewritten->rtx)
    {
        if (source_generation == publisher_source_generation_ && publisher_source_ != nullptr)
        {
            if (rewritten->keyframe_request_needed)
            {
                // 源 SSRC 发生切换时，旧源上的等待任务已经失去意义。
                // 仅取消当前 WHEP 的等待集合，其他订阅者仍由共享协调器独立维护。
                cancel_keyframe_recovery();
            }

            auto observation = keyframe_tracker_.observe(rewritten->codec_name, rewritten->packet);

            if (!observation)
            {
                keyframe_tracker_.reset(rewritten->target_ssrc);
                WEBRTC_LOG_WARN("WHEP keyframe detection failed stream={} session={} codec={} target_ssrc={} error={}",
                                stream_id_,
                                session_id_,
                                rewritten->codec_name,
                                rewritten->target_ssrc,
                                observation.error());
            }
            else if (observation->state == video_keyframe_observation_state::started)
            {
                WEBRTC_LOG_DEBUG("WHEP keyframe started stream={} session={} codec={} source_ssrc={} target_ssrc={} timestamp={}",
                                 stream_id_,
                                 session_id_,
                                 rewritten->codec_name,
                                 rewritten->source_ssrc,
                                 rewritten->target_ssrc,
                                 rewritten->target_timestamp);
            }
            else if (observation->state == video_keyframe_observation_state::completed)
            {
                const bool became_ready = keyframe_ready_source_ssrcs_.insert(rewritten->source_ssrc).second;
                keyframe_waiting_source_ssrcs_.erase(rewritten->source_ssrc);

                if (became_ready)
                {
                    completed_context = keyframe_request_context{
                        .publisher_session_id = publisher_source_->session_id,
                        .source_generation = source_generation,
                        .source_ssrc = rewritten->source_ssrc,
                        .target_ssrc = rewritten->target_ssrc,
                    };
                }
            }
            else if (observation->state == video_keyframe_observation_state::aborted)
            {
                request_context = prepare_keyframe_request(source_generation, rewritten->source_ssrc, rewritten->target_ssrc, true, false);
            }
            else if (observation->state == video_keyframe_observation_state::unsupported_codec &&
                     unsupported_keyframe_detection_target_ssrcs_.insert(rewritten->target_ssrc).second)
            {
                WEBRTC_LOG_WARN("WHEP keyframe completion detection unsupported stream={} session={} codec={} source_ssrc={} target_ssrc={}",
                                stream_id_,
                                session_id_,
                                rewritten->codec_name,
                                rewritten->source_ssrc,
                                rewritten->target_ssrc);
            }

            if (!keyframe_ready_source_ssrcs_.contains(rewritten->source_ssrc) && !request_context.has_value())
            {
                request_context = prepare_keyframe_request(source_generation, rewritten->source_ssrc, rewritten->target_ssrc, false, false);
            }
        }
    }

    if (completed_context.has_value())
    {
        complete_keyframe_request(*completed_context);
    }

    if (request_context.has_value())
    {
        (void)dispatch_keyframe_request(*request_context, "media_start_or_gap");
    }
}

void whep_session_transport::subscribe_media()
{
    const std::weak_ptr<whep_session_transport> weak_transport = weak_from_this();

    media_fanout_router_->subscribe(
        stream_id_,
        session_id_,
        [weak_transport](uint64_t source_generation, std::span<const uint8_t> packet)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->send_rtp(source_generation, packet);
            }
        },
        [weak_transport](media_publisher_source_update update)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_publisher_source(std::move(update));
            }
        },
        [weak_transport](media_publisher_sender_timing timing)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_publisher_sender_timing(std::move(timing));
            }
        },
        [weak_transport](media_publisher_source_bye bye)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_publisher_source_bye(std::move(bye));
            }
        });
}

void whep_session_transport::unsubscribe_media()
{
    if (!session_id_.empty())
    {
        media_fanout_router_->unsubscribe(session_id_);
    }
}

void whep_session_transport::handle_publisher_source(media_publisher_source_update update)
{
    if (update.generation < publisher_source_generation_)
    {
        WEBRTC_LOG_DEBUG("WHEP ignored stale publisher source update stream={} session={} source_generation={} current_source_generation={}",
                         stream_id_,
                         session_id_,
                         update.generation,
                         publisher_source_generation_);
        return;
    }

    cancel_keyframe_recovery();

    if (update.generation != publisher_source_generation_)
    {
        clear_publisher_sender_timings();
        clear_keyframe_feedback_state();
    }

    publisher_source_generation_ = update.generation;
    publisher_source_ = std::move(update.source);
    rebuild_rtp_rewriter();
}

void whep_session_transport::handle_publisher_sender_timing(media_publisher_sender_timing timing)
{
    if (publisher_source_ == nullptr || timing.source_generation != publisher_source_generation_ ||
        timing.publisher_session_id != publisher_source_->session_id)
    {
        WEBRTC_LOG_TRACE(
            "WHEP ignored stale publisher sender timing stream={} session={} publisher_session={} source_generation={} source_ssrc={} "
            "current_publisher_session={} current_source_generation={}",
            stream_id_,
            session_id_,
            timing.publisher_session_id,
            timing.source_generation,
            timing.source_ssrc,
            publisher_source_ != nullptr ? publisher_source_->session_id : std::string{},
            publisher_source_generation_);
        return;
    }

    const uint32_t source_ssrc = timing.source_ssrc;
    publisher_sender_timings_.insert_or_assign(source_ssrc, std::move(timing));
    refresh_sender_timing(source_ssrc);
}

void whep_session_transport::configure_outbound_rtcp_senders(const whep_rtp_rewriter_target& target)
{
    outbound_rtcp_senders_.clear();
    outbound_rtcp_senders_.reserve(target.accepted_media_sources.size() * 2U);

    const auto make_state = [&](const sdp::sdp_answer_media_source& source, uint32_t target_ssrc, bool rtx, uint32_t associated_primary_ssrc)
    {
        outbound_rtcp_sender_state state;
        state.kind = source.kind;
        state.mid = source.mid;
        state.cname = source.cname;
        state.target_ssrc = target_ssrc;
        state.rtx = rtx;
        state.associated_primary_ssrc = associated_primary_ssrc;
        state.rtcp_mux = false;
        state.rtcp_rsize = false;

        if (const auto* media = find_subscriber_media(target, source.mid); media != nullptr)
        {
            state.rtcp_mux = true;
            state.rtcp_rsize = media->rtcp_rsize;
        }

        return state;
    };

    for (const auto& source : target.accepted_media_sources)
    {
        if (source.ssrc == 0)
        {
            continue;
        }

        outbound_rtcp_senders_.insert_or_assign(source.ssrc, make_state(source, source.ssrc, false, 0));

        if (source.rtx_repair_ssrc != 0)
        {
            outbound_rtcp_senders_.insert_or_assign(source.rtx_repair_ssrc, make_state(source, source.rtx_repair_ssrc, true, source.ssrc));
        }
    }
}

void whep_session_transport::clear_publisher_sender_timings()
{
    publisher_sender_timings_.clear();

    for (auto& [target_ssrc, state] : outbound_rtcp_senders_)
    {
        (void)target_ssrc;
        state.sender_timing.reset();
        state.sender_timing_logged = false;
    }
}

void whep_session_transport::refresh_sender_timing(uint32_t source_ssrc)
{
    const auto timing_iterator = publisher_sender_timings_.find(source_ssrc);

    if (timing_iterator == publisher_sender_timings_.end())
    {
        return;
    }

    const auto mapped = rtp_rewriter_.map_source_timestamp(source_ssrc, timing_iterator->second.source_rtp_timestamp);

    if (!mapped.has_value())
    {
        return;
    }

    for (auto& [target_ssrc, sender] : outbound_rtcp_senders_)
    {
        const bool matches_primary = !sender.rtx && target_ssrc == mapped->target_ssrc;
        const bool matches_rtx = sender.rtx && sender.associated_primary_ssrc == mapped->target_ssrc;

        if (!matches_primary && !matches_rtx)
        {
            continue;
        }

        outbound_rtcp_sender_timing next_timing{
            .publisher_session_id = timing_iterator->second.publisher_session_id,
            .source_generation = timing_iterator->second.source_generation,
            .source_ssrc = timing_iterator->second.source_ssrc,
            .ntp_timestamp = timing_iterator->second.ntp_timestamp,
            .target_rtp_timestamp = mapped->target_timestamp,
            .source_sender_packet_count = timing_iterator->second.sender_packet_count,
            .source_sender_octet_count = timing_iterator->second.sender_octet_count,
        };

        if (sender.sender_timing.has_value() && *sender.sender_timing == next_timing)
        {
            continue;
        }

        sender.sender_timing = std::move(next_timing);
        record_media_log_event(media_log_event::sender_timing_mapped);

        if (!sender.sender_timing_logged)
        {
            sender.sender_timing_logged = true;
            WEBRTC_LOG_DEBUG(
                "WHEP sender timing mapped stream={} session={} kind={} mid={} rtx={} publisher_session={} source_generation={} "
                "source_ssrc={} target_ssrc={} ntp_timestamp={} target_rtp_timestamp={} rtcp_mux={} rtcp_rsize={}",
                stream_id_,
                session_id_,
                sender.kind,
                sender.mid,
                sender.rtx ? 1 : 0,
                sender.sender_timing->publisher_session_id,
                sender.sender_timing->source_generation,
                sender.sender_timing->source_ssrc,
                sender.target_ssrc,
                sender.sender_timing->ntp_timestamp,
                sender.sender_timing->target_rtp_timestamp,
                sender.rtcp_mux ? 1 : 0,
                sender.rtcp_rsize ? 1 : 0);
        }
    }
}

void whep_session_transport::record_outbound_rtp_sent(const whep_rtp_rewrite_result& rewritten)
{
    record_outbound_rtp_sent(rewritten.target_ssrc, rewritten.payload_size, rewritten.target_timestamp);

    const auto sender_iterator = outbound_rtcp_senders_.find(rewritten.target_ssrc);

    if (sender_iterator != outbound_rtcp_senders_.end() && !sender_iterator->second.sender_timing.has_value() &&
        publisher_sender_timings_.contains(rewritten.source_ssrc))
    {
        refresh_sender_timing(rewritten.source_ssrc);
    }
}

void whep_session_transport::record_outbound_rtp_sent(uint32_t target_ssrc, std::size_t payload_size, uint32_t target_timestamp)
{
    const auto sender_iterator = outbound_rtcp_senders_.find(target_ssrc);

    if (sender_iterator == outbound_rtcp_senders_.end())
    {
        return;
    }

    auto& sender = sender_iterator->second;
    sender.packet_count += 1;
    sender.octet_count += payload_size;

    if (!sender.last_target_rtp_timestamp.has_value() || rtp_timestamp_is_newer(target_timestamp, *sender.last_target_rtp_timestamp))
    {
        sender.last_target_rtp_timestamp = target_timestamp;
    }
}

void whep_session_transport::cache_rewritten_rtp(uint64_t source_generation, const whep_rtp_rewrite_result& rewritten)
{
    if (rewritten.rtx || rewritten.packet.empty() || !rtp_rewriter_.nack_enabled(rewritten.target_ssrc, rewritten.target_payload_type))
    {
        return;
    }

    retransmission_cache_.remember(rtp_retransmission_cache_packet{
        .packet = rewritten.packet,
        .target_ssrc = rewritten.target_ssrc,
        .target_payload_type = rewritten.target_payload_type,
        .target_sequence_number = rewritten.target_sequence_number,
        .target_timestamp = rewritten.target_timestamp,
        .payload_size = rewritten.payload_size,
        .source_generation = source_generation,
        .stored_at = std::chrono::steady_clock::now(),
    });
}

void whep_session_transport::rebuild_rtp_rewriter()
{
    if (publisher_source_ == nullptr)
    {
        reset_keyframe_recovery();
        rtp_rewriter_.clear_source();
        WEBRTC_LOG_INFO(
            "WHEP RTP publisher source unavailable stream={} session={} source_generation={}", stream_id_, session_id_, publisher_source_generation_);
        return;
    }

    auto config = make_whep_rtp_rewriter_config(publisher_source_->session_id, publisher_source_->offer, rtp_rewriter_target_);

    if (!config)
    {
        reset_keyframe_recovery();
        rtp_rewriter_.clear_source();
        WEBRTC_LOG_WARN("WHEP RTP publisher source rejected stream={} session={} publisher_session={} source_generation={} error={}",
                        stream_id_,
                        session_id_,
                        publisher_source_->session_id,
                        publisher_source_generation_,
                        config.error());
        return;
    }

    rtp_rewriter_.set_config(std::move(*config));

    WEBRTC_LOG_INFO("WHEP RTP publisher source updated stream={} session={} publisher_session={} source_generation={}",
                    stream_id_,
                    session_id_,
                    publisher_source_->session_id,
                    publisher_source_generation_);
}

void whep_session_transport::reset_keyframe_recovery()
{
    keyframe_tracker_.reset();
    keyframe_waiting_source_ssrcs_.clear();
    keyframe_ready_source_ssrcs_.clear();
    unsupported_keyframe_detection_target_ssrcs_.clear();
}

void whep_session_transport::clear_keyframe_feedback_state() { fir_sequence_tracker_.clear(); }

void whep_session_transport::cancel_keyframe_recovery()
{
    media_fanout_router_->cancel_keyframe_requests(session_id_);
    reset_keyframe_recovery();
}

std::optional<whep_session_transport::keyframe_request_context> whep_session_transport::prepare_keyframe_request(
    uint64_t source_generation, uint32_t source_ssrc, uint32_t target_ssrc, bool force_dispatch, bool coalesce_if_waiting)
{
    if (source_generation == 0 || source_ssrc == 0 || target_ssrc == 0 || source_generation != publisher_source_generation_ ||
        publisher_source_ == nullptr)
    {
        return std::nullopt;
    }

    const bool already_waiting = keyframe_waiting_source_ssrcs_.contains(source_ssrc);

    if (coalesce_if_waiting && already_waiting)
    {
        return std::nullopt;
    }

    if (force_dispatch)
    {
        keyframe_ready_source_ssrcs_.erase(source_ssrc);
        keyframe_tracker_.reset(target_ssrc);
    }
    else if (keyframe_ready_source_ssrcs_.contains(source_ssrc))
    {
        return std::nullopt;
    }

    const bool inserted = keyframe_waiting_source_ssrcs_.insert(source_ssrc).second;

    if (!inserted && !force_dispatch)
    {
        return std::nullopt;
    }

    return keyframe_request_context{
        .publisher_session_id = publisher_source_->session_id,
        .source_generation = source_generation,
        .source_ssrc = source_ssrc,
        .target_ssrc = target_ssrc,
    };
}

bool whep_session_transport::dispatch_keyframe_request(const keyframe_request_context& context, std::string_view reason)
{
    if (context.source_generation != publisher_source_generation_ || publisher_source_ == nullptr ||
        publisher_source_->session_id != context.publisher_session_id || !keyframe_waiting_source_ssrcs_.contains(context.source_ssrc))
    {
        return false;
    }

    const bool requested =
        media_fanout_router_->request_keyframe(stream_id_, session_id_, context.publisher_session_id, context.source_generation, context.source_ssrc);

    if (requested)
    {
        record_media_log_event(media_log_event::keyframe_request_submitted);
        WEBRTC_LOG_TRACE("WHEP keyframe request submitted stream={} session={} publisher_session={} source_generation={} media_ssrc={} reason={}",
                         stream_id_,
                         session_id_,
                         context.publisher_session_id,
                         context.source_generation,
                         context.source_ssrc,
                         reason);
        return true;
    }

    keyframe_waiting_source_ssrcs_.erase(context.source_ssrc);

    WEBRTC_LOG_DEBUG(
        "WHEP publisher keyframe request rejected stream={} session={} publisher_session={} source_generation={} media_ssrc={} reason={}",
        stream_id_,
        session_id_,
        context.publisher_session_id,
        context.source_generation,
        context.source_ssrc,
        reason);
    return false;
}

void whep_session_transport::complete_keyframe_request(const keyframe_request_context& context)
{
    if (context.source_generation != publisher_source_generation_ || publisher_source_ == nullptr ||
        publisher_source_->session_id != context.publisher_session_id || !keyframe_ready_source_ssrcs_.contains(context.source_ssrc))
    {
        return;
    }

    media_fanout_router_->complete_keyframe_request(
        stream_id_, session_id_, context.publisher_session_id, context.source_generation, context.source_ssrc);
    record_media_log_event(media_log_event::keyframe_completed);
    WEBRTC_LOG_INFO("WHEP keyframe completed stream={} session={} publisher_session={} source_generation={} source_ssrc={} target_ssrc={}",
                    stream_id_,
                    session_id_,
                    context.publisher_session_id,
                    context.source_generation,
                    context.source_ssrc,
                    context.target_ssrc);
}

void whep_session_transport::handle_publisher_source_bye(media_publisher_source_bye bye)
{
    if (publisher_source_ == nullptr || bye.publisher_session_id != publisher_source_->session_id ||
        bye.source_generation != publisher_source_generation_ || bye.source_ssrc == 0)
    {
        return;
    }

    publisher_sender_timings_.erase(bye.source_ssrc);
    keyframe_waiting_source_ssrcs_.erase(bye.source_ssrc);
    keyframe_ready_source_ssrcs_.erase(bye.source_ssrc);
    std::size_t affected_senders = 0;

    for (auto& [target_ssrc, sender] : outbound_rtcp_senders_)
    {
        const auto source_ssrc = rtp_rewriter_.source_ssrc_for_target_ssrc(target_ssrc);

        if (!source_ssrc.has_value() || *source_ssrc != bye.source_ssrc)
        {
            continue;
        }

        sender.sender_timing.reset();
        keyframe_tracker_.reset(target_ssrc);
        ++affected_senders;
    }

    record_media_log_event(media_log_event::publisher_source_bye_received);
    WEBRTC_LOG_INFO(
        "WHEP publisher source BYE applied stream={} session={} publisher_session={} source_generation={} source_ssrc={} reason={} "
        "affected_senders={}",
        stream_id_,
        session_id_,
        bye.publisher_session_id,
        bye.source_generation,
        bye.source_ssrc,
        bye.reason,
        affected_senders);
}

void whep_session_transport::record_receiver_byes(std::span<const rtcp_bye_packet> bye_packets)
{
    for (const auto& bye : bye_packets)
    {
        for (const uint32_t ssrc : bye.ssrcs)
        {
            if (ssrc != 0 && remote_rtcp_participant_ssrcs_.erase(ssrc) != 0)
            {
                record_media_log_event(media_log_event::rtcp_bye_participant_ended);
                WEBRTC_LOG_INFO(
                    "WHEP remote RTCP participant BYE stream={} session={} participant_ssrc={} reason={}", stream_id_, session_id_, ssrc, bye.reason);
            }
            else
            {
                record_media_log_event(media_log_event::rtcp_bye_unknown_ssrc);
                WEBRTC_LOG_DEBUG("WHEP remote RTCP BYE unknown SSRC stream={} session={} participant_ssrc={} reason={}",
                                 stream_id_,
                                 session_id_,
                                 ssrc,
                                 bye.reason);
            }
        }
    }
}

void whep_session_transport::send_rtcp_bye(std::string_view reason)
{
    if (!selected_remote_endpoint_.has_value())
    {
        return;
    }

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);
    auto peer_ready = srtp_transport_->peer_ready(remote_address);

    if (!peer_ready || !*peer_ready)
    {
        if (!peer_ready)
        {
            record_media_log_event(media_log_event::rtcp_protect_failed);
            WEBRTC_LOG_WARN("WHEP RTCP BYE readiness check failed stream={} session={} remote={} error={}",
                            stream_id_,
                            session_id_,
                            remote_address,
                            peer_ready.error());
        }
        return;
    }

    for (auto& [target_ssrc, sender] : outbound_rtcp_senders_)
    {
        (void)target_ssrc;

        if (!sender.rtcp_mux || sender.cname.empty() || sender.packet_count == 0)
        {
            continue;
        }

        rtcp_packet_build_result report_packet = build_rtcp_receiver_report(rtcp_receiver_report_data{
            .sender_ssrc = sender.target_ssrc,
            .report_blocks = {},
        });
        bool sender_report = false;

        if (sender.sender_timing.has_value() && sender.sender_timing->source_generation == publisher_source_generation_)
        {
            report_packet = build_rtcp_sender_report(rtcp_sender_report_data{
                .sender_ssrc = sender.target_ssrc,
                .ntp_timestamp = sender.sender_timing->ntp_timestamp,
                .rtp_timestamp = sender.sender_timing->target_rtp_timestamp,
                .sender_packet_count = static_cast<uint32_t>(sender.packet_count),
                .sender_octet_count = static_cast<uint32_t>(sender.octet_count),
                .report_blocks = {},
            });
            sender_report = true;
        }

        if (!report_packet)
        {
            record_media_log_event(media_log_event::rtcp_build_failed);
            WEBRTC_LOG_WARN("WHEP RTCP BYE report build failed stream={} session={} kind={} target_ssrc={} error={}",
                            stream_id_,
                            session_id_,
                            sender.kind,
                            sender.target_ssrc,
                            report_packet.error());
            continue;
        }

        const std::array<uint32_t, 1> bye_ssrcs{sender.target_ssrc};
        auto compound = build_rtcp_bye_datagram(*report_packet, sender.target_ssrc, sender.cname, bye_ssrcs, reason);

        if (!compound)
        {
            record_media_log_event(media_log_event::rtcp_build_failed);
            WEBRTC_LOG_WARN("WHEP RTCP BYE compound build failed stream={} session={} kind={} target_ssrc={} error={}",
                            stream_id_,
                            session_id_,
                            sender.kind,
                            sender.target_ssrc,
                            compound.error());
            continue;
        }

        auto protected_packet = srtp_transport_->protect_outbound_packet(*compound, remote_address, srtp_packet_kind::rtcp);

        if (!protected_packet)
        {
            record_media_log_event(media_log_event::rtcp_protect_failed);
            WEBRTC_LOG_WARN("WHEP RTCP BYE protect failed stream={} session={} kind={} target_ssrc={} remote={} error={}",
                            stream_id_,
                            session_id_,
                            sender.kind,
                            sender.target_ssrc,
                            remote_address,
                            protected_packet.error());
            continue;
        }

        if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
        {
            record_media_log_event(media_log_event::rtcp_protect_ignored);
            WEBRTC_LOG_DEBUG("WHEP RTCP BYE protect ignored stream={} session={} kind={} target_ssrc={} remote={} state={} reason={}",
                             stream_id_,
                             session_id_,
                             sender.kind,
                             sender.target_ssrc,
                             remote_address,
                             srtp_packet_process_state_to_string(protected_packet->state),
                             protected_packet->reason);
            continue;
        }

        const std::size_t protected_size = protected_packet->protected_packet.size();
        udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

        record_media_log_event(media_log_event::rtcp_bye_sent);
        record_media_log_event(media_log_event::rtcp_bye_ssrc_sent);
        record_media_log_event(media_log_event::rtcp_bye_send_bytes, protected_size);
        record_media_log_event(media_log_event::rtcp_sdes_sent);
        record_media_log_event(media_log_event::rtcp_send_bytes, protected_size);

        if (sender_report)
        {
            record_media_log_event(media_log_event::rtcp_sender_report_sent);
            sender.sender_report_count += 1;
            sender.sender_report_bytes += protected_size;
            sender.last_sender_report_source_generation = sender.sender_timing->source_generation;
            sender.last_sender_report_ntp_timestamp = sender.sender_timing->ntp_timestamp;
            sender.last_sender_report_rtp_timestamp = sender.sender_timing->target_rtp_timestamp;
        }

        WEBRTC_LOG_INFO(
            "WHEP RTCP BYE sent stream={} session={} kind={} rtx={} associated_primary_ssrc={} target_ssrc={} report={} reason={} "
            "plain_bytes={} protected_bytes={}",
            stream_id_,
            session_id_,
            sender.kind,
            sender.rtx ? 1 : 0,
            sender.associated_primary_ssrc,
            sender.target_ssrc,
            sender_report ? "sr" : "rr",
            reason,
            compound->size(),
            protected_size);
    }
}

void whep_session_transport::record_receiver_reports(std::span<const rtcp_report_packet> reports)
{
    const auto now = std::chrono::steady_clock::now();

    for (const auto& report : reports)
    {
        if (report.sender_ssrc != 0)
        {
            remote_rtcp_participant_ssrcs_.insert(report.sender_ssrc);
        }

        for (const auto& block : report.report_blocks)
        {
            const auto sender_iterator = outbound_rtcp_senders_.find(block.source_ssrc);

            if (sender_iterator == outbound_rtcp_senders_.end())
            {
                continue;
            }

            auto& sender = sender_iterator->second;
            sender.receiver_report_count += 1;
            sender.last_receiver_report_lsr = block.last_sender_report;
            sender.last_receiver_report_dlsr = block.delay_since_last_sender_report;
            sender.last_fraction_lost = block.fraction_lost;
            sender.last_cumulative_lost = block.cumulative_lost;
            sender.last_jitter = block.jitter;

            if (block.last_sender_report == 0)
            {
                continue;
            }

            const auto sent_report =
                std::find_if(sender.sent_sender_reports.rbegin(),
                             sender.sent_sender_reports.rend(),
                             [&block](const sent_rtcp_sender_report& sent) { return sent.compact_ntp == block.last_sender_report; });

            if (sent_report == sender.sent_sender_reports.rend())
            {
                continue;
            }

            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - sent_report->sent_at);
            const auto receiver_delay = std::chrono::microseconds(
                static_cast<int64_t>((static_cast<uint64_t>(block.delay_since_last_sender_report) * 1'000'000ULL) / 65'536ULL));

            if (elapsed < receiver_delay)
            {
                continue;
            }

            const uint64_t round_trip_time_ms =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed - receiver_delay).count());
            sender.last_round_trip_time_ms = round_trip_time_ms;
            record_media_log_event(media_log_event::rtcp_receiver_report_lsr_matched);

            if (!sender.receiver_report_match_logged)
            {
                sender.receiver_report_match_logged = true;
                WEBRTC_LOG_DEBUG(
                    "WHEP receiver report matched sender report stream={} session={} kind={} target_ssrc={} source_generation={} "
                    "compact_ntp={} dlsr={} rtt_ms={} fraction_lost={} cumulative_lost={} jitter={}",
                    stream_id_,
                    session_id_,
                    sender.kind,
                    sender.target_ssrc,
                    sent_report->source_generation,
                    block.last_sender_report,
                    block.delay_since_last_sender_report,
                    round_trip_time_ms,
                    block.fraction_lost,
                    block.cumulative_lost,
                    block.jitter);
            }
        }
    }
}

void whep_session_transport::handle_generic_nacks(const rtcp_compound_packet& compound)
{
    std::vector<rtp_retransmission_cache_packet> retransmissions;
    std::unordered_set<uint64_t> unique_requests;
    std::size_t nack_blocks = 0;
    std::size_t requested_sequences = 0;
    std::size_t target_ignored = 0;
    std::size_t retransmission_limited = 0;

    {
        for (const auto& block : compound.blocks)
        {
            if (!block.has_generic_nack)
            {
                continue;
            }

            nack_blocks += 1;
            requested_sequences += block.nack_sequence_numbers.size();
            const auto sender_iterator = outbound_rtcp_senders_.find(block.feedback_media_ssrc);
            const bool target_valid =
                block.feedback_media_ssrc != 0 && sender_iterator != outbound_rtcp_senders_.end() && !sender_iterator->second.rtx;

            for (const uint16_t sequence_number : block.nack_sequence_numbers)
            {
                const uint64_t request_key = (static_cast<uint64_t>(block.feedback_media_ssrc) << 16U) | static_cast<uint64_t>(sequence_number);

                if (!unique_requests.insert(request_key).second)
                {
                    continue;
                }

                if (!target_valid)
                {
                    target_ignored += 1;
                    continue;
                }

                if (retransmissions.size() >= k_max_retransmissions_per_rtcp_compound)
                {
                    retransmission_limited += 1;
                    continue;
                }

                auto lookup = retransmission_cache_.lookup_for_retransmission(block.feedback_media_ssrc, sequence_number);

                switch (lookup.state)
                {
                    case rtp_retransmission_cache_lookup_state::hit:
                        record_media_log_event(media_log_event::rtp_retransmission_cache_hit);

                        if (lookup.packet.has_value())
                        {
                            retransmissions.push_back(std::move(*lookup.packet));
                        }
                        break;

                    case rtp_retransmission_cache_lookup_state::miss:
                        record_media_log_event(media_log_event::rtp_retransmission_cache_miss);
                        break;

                    case rtp_retransmission_cache_lookup_state::suppressed:
                        record_media_log_event(media_log_event::rtp_retransmission_suppressed);
                        break;
                }
            }
        }
    }

    if (nack_blocks == 0)
    {
        return;
    }

    record_media_log_event(media_log_event::rtcp_generic_nack_received, nack_blocks);
    record_media_log_event(media_log_event::rtcp_nack_sequence_requested, requested_sequences);
    record_media_log_event(media_log_event::rtcp_nack_sequence_unique, unique_requests.size());
    record_media_log_event(media_log_event::rtcp_nack_target_ignored, target_ignored);
    record_media_log_event(media_log_event::rtp_retransmission_limited, retransmission_limited);

    if (!std::exchange(media_log_stats_.generic_nack_logged, true))
    {
        WEBRTC_LOG_DEBUG(
            "WHEP first Generic NACK processed stream={} session={} blocks={} requested={} unique={} target_ignored={} "
            "limited={} retransmissions={}",
            stream_id_,
            session_id_,
            nack_blocks,
            requested_sequences,
            unique_requests.size(),
            target_ignored,
            retransmission_limited,
            retransmissions.size());
    }

    for (auto& cached : retransmissions)
    {
        send_retransmission(std::move(cached));
    }
}

void whep_session_transport::send_retransmission(rtp_retransmission_cache_packet cached)
{
    whep_rtp_retransmission_result_type retransmission =
        rtp_rewriter_.build_retransmission(cached.packet, transport_feedback_history_.next_sequence_number());

    if (!retransmission)
    {
        record_media_log_event(media_log_event::rtp_retransmission_build_failed);
        WEBRTC_LOG_WARN("WHEP RTP retransmission build failed stream={} session={} target_ssrc={} target_seq={} source_generation={} error={}",
                        stream_id_,
                        session_id_,
                        cached.target_ssrc,
                        cached.target_sequence_number,
                        cached.source_generation,
                        retransmission.error());
        return;
    }

    if (closed_ || !selected_remote_endpoint_.has_value())
    {
        record_media_log_event(media_log_event::rtp_retransmission_srtp_not_ready);
        return;
    }

    const auto remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);
    auto protected_packet = srtp_transport_->protect_outbound_packet(retransmission->packet, remote_address, srtp_packet_kind::rtp);

    if (!protected_packet)
    {
        record_media_log_event(media_log_event::rtp_retransmission_protect_failed);
        WEBRTC_LOG_WARN(
            "WHEP RTP retransmission protect failed stream={} session={} remote={} original_ssrc={} original_seq={} "
            "target_ssrc={} target_seq={} rtx={} error={}",
            stream_id_,
            session_id_,
            remote_address,
            retransmission->original_target_ssrc,
            retransmission->original_target_sequence_number,
            retransmission->target_ssrc,
            retransmission->target_sequence_number,
            retransmission->rtx ? 1 : 0,
            protected_packet.error());
        return;
    }

    if (protected_packet->state != srtp_packet_process_state::protected_packet || protected_packet->protected_packet.empty())
    {
        record_media_log_event(media_log_event::rtp_retransmission_protect_ignored);
        return;
    }

    const std::size_t protected_size = protected_packet->protected_packet.size();
    udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

    if (retransmission->transport_sequence_number.has_value())
    {
        transport_feedback_history_.remember_sent(transport_feedback_sent_packet{
            .packet_size = protected_size,
            .retransmission = true,
            .sent_at = std::chrono::steady_clock::now(),
        });
    }

    record_outbound_rtp_sent(retransmission->target_ssrc, retransmission->payload_size, retransmission->target_timestamp);

    record_media_log_event(retransmission->rtx ? media_log_event::rtp_retransmission_rtx_sent : media_log_event::rtp_retransmission_original_sent);
    record_media_log_event(media_log_event::rtp_retransmission_send_bytes, protected_size);
    record_media_log_event(media_log_event::rtp_retransmission_payload_bytes, retransmission->payload_size);

    if (!std::exchange(media_log_stats_.retransmission_logged, true))
    {
        WEBRTC_LOG_DEBUG(
            "WHEP first RTP retransmission sent stream={} session={} kind={} codec={} mode={} original_ssrc={} "
            "original_pt={} original_seq={} target_ssrc={} target_pt={} target_seq={} timestamp={} plain_bytes={} protected_bytes={}",
            stream_id_,
            session_id_,
            retransmission->kind,
            retransmission->codec_name,
            retransmission->rtx ? "rtx" : "original",
            retransmission->original_target_ssrc,
            retransmission->original_target_payload_type,
            retransmission->original_target_sequence_number,
            retransmission->target_ssrc,
            retransmission->target_payload_type,
            retransmission->target_sequence_number,
            retransmission->target_timestamp,
            retransmission->packet.size(),
            protected_size);
    }
}

void whep_session_transport::handle_transport_feedback(const rtcp_compound_packet& compound)
{
    for (const auto& block : compound.blocks)
    {
        if (!block.transport_feedback.has_value())
        {
            continue;
        }

        const auto observation = transport_feedback_history_.observe(*block.transport_feedback, std::chrono::steady_clock::now());
        record_media_log_event(media_log_event::rtcp_transport_feedback_received);

        if (!std::exchange(media_log_stats_.transport_feedback_logged, true))
        {
            WEBRTC_LOG_DEBUG(
                "WHEP first transport-cc feedback observed stream={} session={} sender_ssrc={} media_ssrc={} "
                "feedback_count={} base_sequence={} statuses={} lookup_hit={} lookup_miss={} received={} "
                "not_received={} maximum_feedback_delay_ms={} action=shadow",
                stream_id_,
                session_id_,
                block.transport_feedback->sender_ssrc,
                block.transport_feedback->media_ssrc,
                block.transport_feedback->feedback_packet_count,
                block.transport_feedback->base_sequence_number,
                observation.packet_status_count,
                observation.lookup_hit,
                observation.lookup_miss,
                observation.received,
                observation.not_received,
                observation.maximum_feedback_delay_ms);
        }

        WEBRTC_LOG_TRACE(
            "WHEP transport-cc feedback observed stream={} session={} feedback_count={} base_sequence={} statuses={} "
            "lookup_hit={} lookup_miss={} received={} not_received={} action=shadow",
            stream_id_,
            session_id_,
            block.transport_feedback->feedback_packet_count,
            block.transport_feedback->base_sequence_number,
            observation.packet_status_count,
            observation.lookup_hit,
            observation.lookup_miss,
            observation.received,
            observation.not_received);
    }
}

void whep_session_transport::handle_inbound_rtcp(std::span<const uint8_t> plain_rtcp)
{
    record_media_log_event(media_log_event::rtcp_received);

    auto compound = parse_rtcp_compound_packet(plain_rtcp);

    if (!compound)
    {
        record_media_log_event(media_log_event::rtcp_parse_failed);

        if (!std::exchange(media_log_stats_.rtcp_parse_failure_logged, true))
        {
            WEBRTC_LOG_WARN("WHEP first inbound RTCP parse failure stream={} session={} error={}", stream_id_, session_id_, compound.error());
        }

        WEBRTC_LOG_TRACE("WHEP inbound RTCP parse failed stream={} session={} error={}", stream_id_, session_id_, compound.error());
        return;
    }

    record_media_log_event(media_log_event::rtcp_sender_report_received, compound->sender_report_count);
    record_media_log_event(media_log_event::rtcp_receiver_report_received, compound->receiver_report_count);
    record_media_log_event(media_log_event::rtcp_report_block_received, compound->report_block_count);
    record_media_log_event(media_log_event::rtcp_sdes_received, compound->sdes_packet_count);
    record_media_log_event(media_log_event::rtcp_bye_received, compound->bye_packets.size());
    record_media_log_event(media_log_event::rtcp_pli_received, compound->pli_count);
    record_media_log_event(media_log_event::rtcp_fir_received, compound->fir_block_count);
    record_media_log_event(media_log_event::rtcp_remb_ignored, compound->remb_block_count);
    record_media_log_event(media_log_event::rtcp_other_feedback_ignored, compound->other_feedback_block_count);
    record_media_log_event(media_log_event::rtcp_unknown_block_ignored, compound->unknown_block_count);

    {
        for (const auto& chunk : compound->sdes_chunks)
        {
            if (chunk.ssrc != 0)
            {
                remote_rtcp_participant_ssrcs_.insert(chunk.ssrc);
            }
        }

        record_receiver_reports(compound->report_packets);
        record_receiver_byes(compound->bye_packets);
    }

    handle_generic_nacks(*compound);
    handle_transport_feedback(*compound);

    for (const auto& block : compound->blocks)
    {
        if (block.has_remb && !std::exchange(media_log_stats_.remb_ignored_logged, true))
        {
            WEBRTC_LOG_DEBUG("WHEP first REMB ignored stream={} session={} sender_ssrc={} media_ssrc={} bitrate_bps={} action=ignored",
                             stream_id_,
                             session_id_,
                             block.feedback_sender_ssrc,
                             block.feedback_media_ssrc,
                             block.remb_bitrate_bps);
        }

        const bool other_feedback = block.is_feedback && block.feedback_name != "pli" && block.feedback_name != "fir" && !block.has_generic_nack &&
                                    !block.transport_feedback.has_value() && !block.has_remb;

        if (other_feedback && !std::exchange(media_log_stats_.other_feedback_ignored_logged, true))
        {
            WEBRTC_LOG_DEBUG("WHEP first other RTCP feedback ignored stream={} session={} type={} sender_ssrc={} media_ssrc={} action=ignored",
                             stream_id_,
                             session_id_,
                             block.feedback_name,
                             block.feedback_sender_ssrc,
                             block.feedback_media_ssrc);
        }

        if (block.is_unknown && !std::exchange(media_log_stats_.unknown_rtcp_block_ignored_logged, true))
        {
            WEBRTC_LOG_DEBUG("WHEP first unknown RTCP block ignored stream={} session={} packet_type={} packet_type_name={} count={} action=ignored",
                             stream_id_,
                             session_id_,
                             block.packet_type,
                             block.packet_type_name,
                             block.count);
        }
    }

    std::vector<inbound_keyframe_feedback> feedback_requests;

    for (const auto& block : compound->blocks)
    {
        if (block.feedback_name == "pli" && block.has_keyframe_request)
        {
            feedback_requests.push_back(inbound_keyframe_feedback{
                .type = inbound_keyframe_feedback_type::pli,
                .sender_ssrc = block.feedback_sender_ssrc,
                .target_ssrc = block.feedback_media_ssrc,
            });
            continue;
        }

        if (block.feedback_name != "fir")
        {
            continue;
        }

        for (const auto& entry : block.fir_entries)
        {
            feedback_requests.push_back(inbound_keyframe_feedback{
                .type = inbound_keyframe_feedback_type::fir,
                .sender_ssrc = block.feedback_sender_ssrc,
                .target_ssrc = entry.media_ssrc,
                .fir_sequence_number = entry.sequence_number,
            });
        }
    }

    if (feedback_requests.empty())
    {
        WEBRTC_LOG_TRACE(
            "WHEP inbound RTCP stream={} session={} blocks={} sr={} rr={} report_blocks={} sdes={} bye={} pli={} fir={} "
            "generic_nack_blocks={} transport_feedback={} remb_ignored={} other_feedback_ignored={} unknown_ignored={} summary={}",
            stream_id_,
            session_id_,
            compound->blocks.size(),
            compound->sender_report_count,
            compound->receiver_report_count,
            compound->report_block_count,
            compound->sdes_packet_count,
            compound->bye_packets.size(),
            compound->pli_count,
            compound->fir_block_count,
            compound->generic_nack_block_count,
            compound->transport_cc_block_count,
            compound->remb_block_count,
            compound->other_feedback_block_count,
            compound->unknown_block_count,
            rtcp_compound_feedback_summary_to_string(*compound));
        return;
    }

    record_media_log_event(media_log_event::rtcp_keyframe_feedback_received, feedback_requests.size());
    std::vector<keyframe_request_context> requests;
    std::unordered_set<uint32_t> requested_source_ssrcs;
    std::size_t coalesced = 0;
    std::size_t target_ignored = 0;
    std::size_t duplicate_fir = 0;

    {
        for (const auto& feedback : feedback_requests)
        {
            std::string_view rejection_reason;

            if (feedback.target_ssrc == 0)
            {
                rejection_reason = "zero_target_ssrc";
            }
            else
            {
                const auto sender_iterator = outbound_rtcp_senders_.find(feedback.target_ssrc);

                if (sender_iterator == outbound_rtcp_senders_.end())
                {
                    rejection_reason = "unknown_or_non_primary_target_ssrc";
                }
                else if (sender_iterator->second.rtx)
                {
                    rejection_reason = "rtx_target_ssrc";
                }
                else if (sender_iterator->second.kind != "video")
                {
                    rejection_reason = "non_video_target_ssrc";
                }
            }

            std::optional<uint32_t> source_ssrc;

            if (rejection_reason.empty())
            {
                source_ssrc = rtp_rewriter_.source_ssrc_for_target_ssrc(feedback.target_ssrc);

                if (!source_ssrc.has_value())
                {
                    rejection_reason = "source_ssrc_unmapped";
                }
            }

            if (!rejection_reason.empty())
            {
                target_ignored += 1;

                if (!std::exchange(media_log_stats_.invalid_keyframe_feedback_target_logged, true))
                {
                    WEBRTC_LOG_DEBUG(
                        "WHEP first keyframe feedback target ignored stream={} session={} type={} sender_ssrc={} target_ssrc={} "
                        "source_generation={} reason={}",
                        stream_id_,
                        session_id_,
                        keyframe_feedback_type_to_string(feedback.type),
                        feedback.sender_ssrc,
                        feedback.target_ssrc,
                        publisher_source_generation_,
                        rejection_reason);
                }

                WEBRTC_LOG_TRACE(
                    "WHEP keyframe feedback target ignored stream={} session={} type={} sender_ssrc={} target_ssrc={} "
                    "source_generation={} reason={}",
                    stream_id_,
                    session_id_,
                    keyframe_feedback_type_to_string(feedback.type),
                    feedback.sender_ssrc,
                    feedback.target_ssrc,
                    publisher_source_generation_,
                    rejection_reason);
                continue;
            }

            if (feedback.type == inbound_keyframe_feedback_type::fir)
            {
                if (!fir_sequence_tracker_.accept(feedback.sender_ssrc, feedback.target_ssrc, feedback.fir_sequence_number))
                {
                    duplicate_fir += 1;

                    if (!std::exchange(media_log_stats_.duplicate_fir_logged, true))
                    {
                        WEBRTC_LOG_DEBUG(
                            "WHEP first duplicate FIR ignored stream={} session={} sender_ssrc={} target_ssrc={} "
                            "sequence_number={} source_generation={}",
                            stream_id_,
                            session_id_,
                            feedback.sender_ssrc,
                            feedback.target_ssrc,
                            feedback.fir_sequence_number,
                            publisher_source_generation_);
                    }

                    WEBRTC_LOG_TRACE(
                        "WHEP duplicate FIR ignored stream={} session={} sender_ssrc={} target_ssrc={} sequence_number={} "
                        "source_generation={}",
                        stream_id_,
                        session_id_,
                        feedback.sender_ssrc,
                        feedback.target_ssrc,
                        feedback.fir_sequence_number,
                        publisher_source_generation_);
                    continue;
                }
            }

            if (!requested_source_ssrcs.insert(*source_ssrc).second)
            {
                coalesced += 1;
                continue;
            }

            const bool already_waiting = keyframe_waiting_source_ssrcs_.contains(*source_ssrc);
            auto request = prepare_keyframe_request(publisher_source_generation_, *source_ssrc, feedback.target_ssrc, true, true);

            if (!request.has_value())
            {
                if (already_waiting)
                {
                    coalesced += 1;
                }
                else
                {
                    target_ignored += 1;
                }
                continue;
            }

            requests.push_back(std::move(*request));
        }
    }

    record_media_log_event(media_log_event::rtcp_keyframe_feedback_coalesced, coalesced);
    record_media_log_event(media_log_event::rtcp_keyframe_feedback_target_ignored, target_ignored);
    record_media_log_event(media_log_event::rtcp_fir_duplicate_ignored, duplicate_fir);

    std::size_t forwarded = 0;

    for (const auto& request : requests)
    {
        if (dispatch_keyframe_request(request, "receiver_feedback"))
        {
            forwarded += 1;
        }
    }

    record_media_log_event(media_log_event::rtcp_keyframe_feedback_forwarded, forwarded);

    if (!std::exchange(media_log_stats_.keyframe_feedback_logged, true))
    {
        WEBRTC_LOG_DEBUG(
            "WHEP first inbound keyframe feedback stream={} session={} requested={} forwarded={} coalesced={} target_ignored={} "
            "fir_duplicate_ignored={} pli={} fir={} summary={}",
            stream_id_,
            session_id_,
            feedback_requests.size(),
            forwarded,
            coalesced,
            target_ignored,
            duplicate_fir,
            compound->pli_count,
            compound->fir_block_count,
            rtcp_compound_feedback_summary_to_string(*compound));
    }

    WEBRTC_LOG_TRACE(
        "WHEP inbound keyframe feedback stream={} session={} requested={} forwarded={} coalesced={} target_ignored={} "
        "fir_duplicate_ignored={} pli={} fir={} summary={}",
        stream_id_,
        session_id_,
        feedback_requests.size(),
        forwarded,
        coalesced,
        target_ignored,
        duplicate_fir,
        compound->pli_count,
        compound->fir_block_count,
        rtcp_compound_feedback_summary_to_string(*compound));
}

void whep_session_transport::clear_peer_state()
{
    if (selected_remote_endpoint_.has_value())
    {
        const std::string remote_address = format_udp_endpoint(*selected_remote_endpoint_);
        srtp_transport_->forget_peer(remote_address);
        dtls_transport_->forget_peer(remote_address);
    }

    selected_remote_endpoint_.reset();
}

whep_session_transport::peer_nomination_result whep_session_transport::nominate_remote_endpoint(const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    if (!dtls_identity_.has_value())
    {
        return std::unexpected(std::string("WHEP DTLS identity is unavailable"));
    }

    if (selected_remote_endpoint_.has_value() && *selected_remote_endpoint_ == remote_endpoint)
    {
        return peer_nomination_state::unchanged;
    }

    std::optional<boost::asio::ip::udp::endpoint> association_endpoint;
    std::optional<dtls_peer_identity> association_identity;

    if (selected_remote_endpoint_.has_value())
    {
        association_endpoint = selected_remote_endpoint_;
        association_identity = dtls_identity_;
    }

    peer_nomination_state state = peer_nomination_state::selected_fresh;

    if (association_endpoint.has_value() && association_identity.has_value())
    {
        auto rebound = rebind_session_transport_peer(
            dtls_transport_, srtp_transport_, *association_endpoint, remote_endpoint, *association_identity, *dtls_identity_);

        if (!rebound)
        {
            return std::unexpected(rebound.error());
        }

        if (*rebound)
        {
            state = peer_nomination_state::association_rebound;
        }
    }

    selected_remote_endpoint_ = remote_endpoint;

    WEBRTC_LOG_INFO("WHEP ICE endpoint nominated stream={} session={} remote={} association_reused={}",
                    stream_id_,
                    session_id_,
                    format_udp_endpoint(remote_endpoint),
                    state == peer_nomination_state::association_rebound ? 1 : 0);

    return state;
}

session_udp_outbound_packet_list whep_session_transport::handle_udp_packet(const session_udp_packet& packet)
{
    ++received_packet_count_;
    record_media_log_event(media_log_event::udp_received);

    std::string local_ice_ufrag;
    std::string local_ice_pwd;
    std::string remote_ice_ufrag;

    {
        if (dtls_identity_.has_value())
        {
            local_ice_ufrag = dtls_identity_->local_ice_ufrag;
            remote_ice_ufrag = dtls_identity_->remote_ice_ufrag;
        }

        local_ice_pwd = local_ice_pwd_;
    }

    session_stun_binding_context context;
    context.log_prefix = "WHEP";
    context.stream_id = stream_id_;
    context.session_id = session_id_;
    context.local_ice_ufrag = local_ice_ufrag;
    context.local_ice_pwd = local_ice_pwd;
    context.remote_ice_ufrag = remote_ice_ufrag;

    auto stun_result = handle_session_stun_binding(packet.data, packet.remote_endpoint, context);

    if (stun_result.handled)
    {
        record_media_log_event(media_log_event::stun_received);
        session_udp_outbound_packet_list result;

        if (stun_result.response.has_value())
        {
            if (stun_result.nominated)
            {
                auto nomination = nominate_remote_endpoint(packet.remote_endpoint);

                if (!nomination)
                {
                    WEBRTC_LOG_WARN("WHEP ICE endpoint nomination failed stream={} session={} remote={} error={}",
                                    stream_id_,
                                    session_id_,
                                    format_udp_endpoint(packet.remote_endpoint),
                                    nomination.error());
                }
                else if (*nomination != peer_nomination_state::unchanged)
                {
                    cancel_keyframe_recovery();
                }
            }

            result.push_back(std::move(*stun_result.response));
        }

        return result;
    }

    if (!selected_remote_endpoint_.has_value() || *selected_remote_endpoint_ != packet.remote_endpoint)
    {
        record_media_log_event(media_log_event::dropped_unselected);
        WEBRTC_LOG_TRACE("WHEP session transport ignored packet from unselected endpoint stream={} session={} remote={} size={}",
                         stream_id_,
                         session_id_,
                         format_udp_endpoint(packet.remote_endpoint),
                         packet.data.size());

        return {};
    }

    if (is_dtls_packet(packet.data))
    {
        record_media_log_event(media_log_event::dtls_received);
        session_udp_outbound_packet_list result;

        if (!dtls_identity_.has_value())
        {
            WEBRTC_LOG_WARN("WHEP session transport dtls identity unavailable stream={} session={}", stream_id_, session_id_);
            return result;
        }

        const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
        const dtls_network_family network_family = packet.remote_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

        dtls_transport_->remember_peer(remote_address, *dtls_identity_);

        auto outbound_packets = dtls_transport_->handle_udp_packet(packet.data, remote_address, network_family);

        if (!outbound_packets)
        {
            WEBRTC_LOG_WARN("WHEP session transport dtls packet failed stream={} session={} remote={} error={}",
                            stream_id_,
                            session_id_,
                            remote_address,
                            outbound_packets.error());
            return result;
        }

        for (auto& outbound_packet : *outbound_packets)
        {
            result.push_back({std::move(outbound_packet), packet.remote_endpoint});
        }

        return result;
    }

    const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
    auto inbound = srtp_transport_->handle_inbound_packet(packet.data, remote_address);

    if (!inbound)
    {
        record_media_log_event(media_log_event::srtp_unprotect_failed);
        WEBRTC_LOG_WARN(
            "WHEP inbound SRTP packet failed stream={} session={} remote={} error={}", stream_id_, session_id_, remote_address, inbound.error());
        return {};
    }

    if (inbound->state != srtp_packet_process_state::unprotected || inbound->plain_packet.empty())
    {
        record_media_log_event(media_log_event::srtp_inbound_ignored);
        WEBRTC_LOG_TRACE("WHEP inbound SRTP packet ignored stream={} session={} remote={} kind={} state={} reason={}",
                         stream_id_,
                         session_id_,
                         remote_address,
                         srtp_packet_kind_name(inbound->kind),
                         srtp_packet_process_state_to_string(inbound->state),
                         inbound->reason);
        return {};
    }

    if (inbound->kind == srtp_packet_kind::rtcp)
    {
        handle_inbound_rtcp(inbound->plain_packet);
        return {};
    }

    record_media_log_event(media_log_event::other_received);
    WEBRTC_LOG_TRACE("WHEP session transport received non-RTCP media packet remote={} size={} count={}",
                     packet.remote_endpoint.address().to_string(),
                     packet.data.size(),
                     received_packet_count_);

    return {};
}

}    // namespace webrtc
