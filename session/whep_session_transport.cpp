#include "session/whep_session_transport.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
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
#include "session/session_stun_binding.h"
#include "session/session_transport_peer_rebind.h"
#include "srtp/srtp_transport.h"

namespace webrtc
{
namespace
{
using namespace std::chrono_literals;
constexpr auto k_ice_restart_timeout = 30s;
constexpr auto k_media_log_interval = 5s;

const sdp::media_summary* find_subscriber_media(const whep_rtp_rewriter_target& target,
                                                std::string_view mid)
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
      ice_restart_timer_(io_context),
      media_log_timer_(io_context),
      dtls_transport_(std::make_shared<dtls_transport>(std::move(dtls_context), dtls_ip_mtu)),
      srtp_transport_(std::make_shared<srtp_transport>(dtls_transport_)),
      media_fanout_router_(std::move(media_fanout_router))
{
}

whep_session_transport::~whep_session_transport()
{
    media_log_timer_.cancel();
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
    return {};
}

void whep_session_transport::record_media_log_event(media_log_event event, uint64_t value)
{
    media_log_stats_.counters.add(event, value);
}

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
    const int64_t interval_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    now - media_log_interval_started_at_)
                                    .count();
    media_log_interval_started_at_ = now;
    log_media_summary(interval_ms);
    schedule_media_log_summary();
}

void whep_session_transport::log_media_summary(int64_t interval_ms)
{
    const uint64_t source_rtp_received = media_log_stats_.counters.take(media_log_event::source_rtp_received);
    const uint64_t rewritten = media_log_stats_.counters.take(media_log_event::rewritten);
    const uint64_t send_enqueued = media_log_stats_.counters.take(media_log_event::send_enqueued);
    const uint64_t send_bytes = media_log_stats_.counters.take(media_log_event::send_bytes);
    const uint64_t send_payload_bytes = media_log_stats_.counters.take(media_log_event::send_payload_bytes);
    const uint64_t sender_timing_mapped = media_log_stats_.counters.take(media_log_event::sender_timing_mapped);
    const uint64_t dropped_no_endpoint = media_log_stats_.counters.take(media_log_event::dropped_no_endpoint);
    const uint64_t dropped_stale_generation =
        media_log_stats_.counters.take(media_log_event::dropped_stale_generation);
    const uint64_t rewrite_failed = media_log_stats_.counters.take(media_log_event::rewrite_failed);
    const uint64_t rewrite_dropped = media_log_stats_.counters.take(media_log_event::rewrite_dropped);
    const uint64_t protect_failed = media_log_stats_.counters.take(media_log_event::protect_failed);
    const uint64_t dropped_srtp_not_ready =
        media_log_stats_.counters.take(media_log_event::dropped_srtp_not_ready);
    const uint64_t protect_ignored = media_log_stats_.counters.take(media_log_event::protect_ignored);
    const uint64_t keyframe_request_submitted =
        media_log_stats_.counters.take(media_log_event::keyframe_request_submitted);
    const uint64_t keyframe_completed = media_log_stats_.counters.take(media_log_event::keyframe_completed);
    const uint64_t rtcp_received = media_log_stats_.counters.take(media_log_event::rtcp_received);
    const uint64_t rtcp_sender_report_received =
        media_log_stats_.counters.take(media_log_event::rtcp_sender_report_received);
    const uint64_t rtcp_receiver_report_received =
        media_log_stats_.counters.take(media_log_event::rtcp_receiver_report_received);
    const uint64_t rtcp_report_block_received =
        media_log_stats_.counters.take(media_log_event::rtcp_report_block_received);
    const uint64_t rtcp_sdes_received = media_log_stats_.counters.take(media_log_event::rtcp_sdes_received);
    const uint64_t rtcp_bye_received = media_log_stats_.counters.take(media_log_event::rtcp_bye_received);
    const uint64_t rtcp_pli_received = media_log_stats_.counters.take(media_log_event::rtcp_pli_received);
    const uint64_t rtcp_fir_received = media_log_stats_.counters.take(media_log_event::rtcp_fir_received);
    const uint64_t rtcp_keyframe_feedback_received =
        media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_received);
    const uint64_t rtcp_keyframe_feedback_forwarded =
        media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_forwarded);
    const uint64_t rtcp_generic_nack_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_generic_nack_ignored);
    const uint64_t rtcp_transport_cc_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_transport_cc_ignored);
    const uint64_t rtcp_remb_ignored = media_log_stats_.counters.take(media_log_event::rtcp_remb_ignored);
    const uint64_t rtcp_other_feedback_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_other_feedback_ignored);
    const uint64_t rtcp_unknown_block_ignored =
        media_log_stats_.counters.take(media_log_event::rtcp_unknown_block_ignored);
    const uint64_t rtcp_parse_failed = media_log_stats_.counters.take(media_log_event::rtcp_parse_failed);
    const uint64_t srtp_inbound_ignored = media_log_stats_.counters.take(media_log_event::srtp_inbound_ignored);
    const uint64_t srtp_unprotect_failed = media_log_stats_.counters.take(media_log_event::srtp_unprotect_failed);
    const uint64_t udp_received = media_log_stats_.counters.take(media_log_event::udp_received);
    const uint64_t stun_received = media_log_stats_.counters.take(media_log_event::stun_received);
    const uint64_t dtls_received = media_log_stats_.counters.take(media_log_event::dtls_received);
    const uint64_t dropped_unselected = media_log_stats_.counters.take(media_log_event::dropped_unselected);
    const uint64_t other_received = media_log_stats_.counters.take(media_log_event::other_received);

    const bool has_activity =
        source_rtp_received != 0 || rewritten != 0 || send_enqueued != 0 || send_bytes != 0 ||
        send_payload_bytes != 0 || sender_timing_mapped != 0 || dropped_no_endpoint != 0 ||
        dropped_stale_generation != 0 || rewrite_failed != 0 || rewrite_dropped != 0 ||
        protect_failed != 0 || dropped_srtp_not_ready != 0 || protect_ignored != 0 ||
        keyframe_request_submitted != 0 || keyframe_completed != 0 || rtcp_received != 0 ||
        rtcp_sender_report_received != 0 || rtcp_receiver_report_received != 0 ||
        rtcp_report_block_received != 0 || rtcp_sdes_received != 0 || rtcp_bye_received != 0 ||
        rtcp_pli_received != 0 || rtcp_fir_received != 0 || rtcp_keyframe_feedback_received != 0 ||
        rtcp_keyframe_feedback_forwarded != 0 || rtcp_generic_nack_ignored != 0 ||
        rtcp_transport_cc_ignored != 0 || rtcp_remb_ignored != 0 ||
        rtcp_other_feedback_ignored != 0 || rtcp_unknown_block_ignored != 0 ||
        rtcp_parse_failed != 0 || srtp_inbound_ignored != 0 || srtp_unprotect_failed != 0 ||
        udp_received != 0 || stun_received != 0 || dtls_received != 0 || dropped_unselected != 0 ||
        other_received != 0;

    if (!has_activity)
    {
        return;
    }

    WEBRTC_LOG_DEBUG(
        "WHEP media summary stream={} session={} interval_ms={} source_rtp={} rewritten={} send_enqueued={} send_bytes={} "
        "send_payload_bytes={} sender_timing_mapped={} dropped_no_endpoint={} dropped_stale_source_generation={} rewrite_failed={} rewrite_dropped={} protect_failed={} "
        "dropped_srtp_not_ready={} protect_ignored={} keyframe_request_submitted={} keyframe_completed={} rtcp_received={} rtcp_sr={} rtcp_rr={} "
        "rtcp_report_blocks={} rtcp_sdes={} rtcp_bye={} rtcp_pli={} rtcp_fir={} rtcp_keyframe_feedback_received={} "
        "rtcp_keyframe_feedback_forwarded={} rtcp_generic_nack_ignored={} rtcp_transport_cc_ignored={} rtcp_remb_ignored={} "
        "rtcp_other_feedback_ignored={} rtcp_unknown_block_ignored={} rtcp_parse_failed={} srtp_inbound_ignored={} "
        "srtp_unprotect_failed={} udp_received={} stun={} dtls={} dropped_unselected={} other_received={}",
        stream_id_,
        session_id_,
        interval_ms,
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
        other_received);

    log_outbound_rtcp_sender_state_snapshot();
}

void whep_session_transport::log_outbound_rtcp_sender_state_snapshot()
{
    std::vector<outbound_rtcp_sender_state> senders;

    {
        std::lock_guard lock(rtp_rewriter_mutex_);
        senders.reserve(outbound_rtcp_senders_.size());

        for (const auto& [target_ssrc, sender] : outbound_rtcp_senders_)
        {
            (void)target_ssrc;
            senders.push_back(sender);
        }
    }

    std::sort(
        senders.begin(),
        senders.end(),
        [](const outbound_rtcp_sender_state& left, const outbound_rtcp_sender_state& right)
        {
            return left.target_ssrc < right.target_ssrc;
        });

    for (const auto& sender : senders)
    {
        if (sender.packet_count == 0 && !sender.sender_timing.has_value())
        {
            continue;
        }

        const std::string publisher_session_id = sender.sender_timing.has_value()
                                                     ? sender.sender_timing->publisher_session_id
                                                     : std::string{};
        const uint64_t source_generation = sender.sender_timing.has_value()
                                               ? sender.sender_timing->source_generation
                                               : 0;
        const uint32_t source_ssrc = sender.sender_timing.has_value()
                                         ? sender.sender_timing->source_ssrc
                                         : 0;
        const uint64_t ntp_timestamp = sender.sender_timing.has_value()
                                           ? sender.sender_timing->ntp_timestamp
                                           : 0;
        const uint32_t timing_target_rtp_timestamp = sender.sender_timing.has_value()
                                                         ? sender.sender_timing->target_rtp_timestamp
                                                         : 0;

        WEBRTC_LOG_DEBUG(
            "WHEP sender state stream={} session={} kind={} mid={} target_ssrc={} cname={} packets={} octets={} "
            "last_target_rtp_timestamp={} timing_ready={} publisher_session={} source_generation={} source_ssrc={} ntp_timestamp={} "
            "timing_target_rtp_timestamp={} rtcp_mux={} rtcp_rsize={}",
            stream_id_,
            session_id_,
            sender.kind,
            sender.mid,
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
            sender.rtcp_mux ? 1 : 0,
            sender.rtcp_rsize ? 1 : 0);
    }
}

void whep_session_transport::set_peer_context(std::string local_ice_pwd,
                                              dtls_peer_identity identity,
                                              whep_rtp_rewriter_target target)
{
    unsubscribe_media();
    clear_peer_state();

    {
        std::lock_guard lock(peer_mutex_);
        stream_id_ = identity.stream_id;
        session_id_ = identity.session_id;
        local_ice_pwd_ = std::move(local_ice_pwd);
        dtls_identity_ = std::move(identity);
        ++ice_generation_;
    }

    {
        std::lock_guard lock(rtp_rewriter_mutex_);
        configure_outbound_rtcp_senders_locked(target, false);
        rtp_rewriter_target_ = std::move(target);
        publisher_source_.reset();
        publisher_source_generation_ = 0;
        clear_publisher_sender_timings_locked();
        reset_keyframe_recovery_locked();
        rebuild_rtp_rewriter_locked();
    }

    subscribe_media();
}

void whep_session_transport::restart_peer_context(std::string local_ice_pwd,
                                                  dtls_peer_identity identity,
                                                  whep_rtp_rewriter_target target)
{
    uint64_t generation = 0;
    bool has_pending_association = false;

    {
        std::lock_guard lock(peer_mutex_);

        std::optional<boost::asio::ip::udp::endpoint> association_endpoint;
        std::optional<dtls_peer_identity> association_identity;

        if (pending_ice_restart_.has_value())
        {
            association_endpoint = pending_ice_restart_->association_endpoint;
            association_identity = pending_ice_restart_->association_identity;
        }
        else if (selected_remote_endpoint_.has_value() && dtls_identity_.has_value())
        {
            association_endpoint = selected_remote_endpoint_;
            association_identity = dtls_identity_;
        }

        selected_remote_endpoint_.reset();
        local_ice_pwd_ = std::move(local_ice_pwd);
        dtls_identity_ = std::move(identity);
        generation = ++ice_generation_;

        if (association_endpoint.has_value() && association_identity.has_value())
        {
            pending_ice_restart_ = pending_ice_restart{
                .generation = generation,
                .association_endpoint = *association_endpoint,
                .association_identity = std::move(*association_identity),
            };
            has_pending_association = true;
        }
        else
        {
            pending_ice_restart_.reset();
        }
    }

    ice_restart_timer_.cancel();

    if (has_pending_association)
    {
        schedule_ice_restart_timeout(generation);
    }

    std::lock_guard lock(rtp_rewriter_mutex_);
    cancel_keyframe_recovery_locked();
    configure_outbound_rtcp_senders_locked(target, true);
    rtp_rewriter_target_ = std::move(target);
    rebuild_rtp_rewriter_locked();
}

void whep_session_transport::send_rtp(uint64_t source_generation, std::span<const uint8_t> plain_rtp)
{
    if (plain_rtp.empty())
    {
        return;
    }

    record_media_log_event(media_log_event::source_rtp_received);
    std::unique_lock peer_lock(peer_mutex_);

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
        WEBRTC_LOG_WARN("WHEP SRTP readiness check failed stream={} session={} remote={} error={}",
                        stream_id_,
                        session_id_,
                        remote_address,
                        peer_ready.error());
        return;
    }

    if (!*peer_ready)
    {
        record_media_log_event(media_log_event::dropped_srtp_not_ready);

        if (!media_log_stats_.srtp_not_ready_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG("WHEP media send waiting for SRTP stream={} session={} remote={}",
                             stream_id_,
                             session_id_,
                             remote_address);
        }

        return;
    }

    whep_rtp_rewrite_packet_result rewritten;

    {
        std::lock_guard lock(rtp_rewriter_mutex_);

        if (source_generation != publisher_source_generation_)
        {
            record_media_log_event(media_log_event::dropped_stale_generation);
            return;
        }

        rewritten = rtp_rewriter_.rewrite(plain_rtp);
    }

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

        if (!media_log_stats_.rewrite_drop_logged.exchange(true, std::memory_order_relaxed))
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

    auto protected_packet =
        srtp_transport_->protect_outbound_packet(rewritten->packet, remote_address, srtp_packet_kind::rtp);

    if (!protected_packet)
    {
        record_media_log_event(media_log_event::protect_failed);
        WEBRTC_LOG_WARN("WHEP RTP protect failed stream={} session={} remote={} error={}",
                        stream_id_,
                        session_id_,
                        remote_address,
                        protected_packet.error());
        return;
    }

    if (protected_packet->state != srtp_packet_process_state::protected_packet ||
        protected_packet->protected_packet.empty())
    {
        record_media_log_event(media_log_event::protect_ignored);

        if (!media_log_stats_.protect_ignore_logged.exchange(true, std::memory_order_relaxed))
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

    {
        std::lock_guard lock(rtp_rewriter_mutex_);

        if (source_generation != publisher_source_generation_)
        {
            record_media_log_event(media_log_event::dropped_stale_generation);
            return;
        }

        record_outbound_rtp_sent_locked(*rewritten);
    }

    const std::size_t protected_size = protected_packet->protected_packet.size();
    record_media_log_event(media_log_event::send_enqueued);
    record_media_log_event(media_log_event::send_bytes, protected_size);
    record_media_log_event(media_log_event::send_payload_bytes, rewritten->payload_size);
    udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);
    peer_lock.unlock();

    std::optional<keyframe_request_context> request_context;
    std::optional<keyframe_request_context> completed_context;

    if (rewritten->kind == "video" && !rewritten->rtx)
    {
        std::lock_guard lock(rtp_rewriter_mutex_);

        if (source_generation == publisher_source_generation_ && publisher_source_ != nullptr)
        {
            if (rewritten->keyframe_request_needed)
            {
                // 源 SSRC 发生切换时，旧源上的等待任务已经失去意义。
                // 仅取消当前 WHEP 的等待集合，其他订阅者仍由共享协调器独立维护。
                cancel_keyframe_recovery_locked();
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
                request_context = prepare_keyframe_request_locked(source_generation,
                                                                  rewritten->source_ssrc,
                                                                  rewritten->target_ssrc,
                                                                  true);
            }
            else if (observation->state == video_keyframe_observation_state::unsupported_codec &&
                     unsupported_keyframe_detection_target_ssrcs_.insert(rewritten->target_ssrc).second)
            {
                WEBRTC_LOG_WARN(
                    "WHEP keyframe completion detection unsupported stream={} session={} codec={} source_ssrc={} target_ssrc={}",
                    stream_id_,
                    session_id_,
                    rewritten->codec_name,
                    rewritten->source_ssrc,
                    rewritten->target_ssrc);
            }

            if (!keyframe_ready_source_ssrcs_.contains(rewritten->source_ssrc) && !request_context.has_value())
            {
                request_context = prepare_keyframe_request_locked(source_generation,
                                                                  rewritten->source_ssrc,
                                                                  rewritten->target_ssrc,
                                                                  false);
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
    std::lock_guard lock(rtp_rewriter_mutex_);

    if (update.generation < publisher_source_generation_)
    {
        WEBRTC_LOG_DEBUG("WHEP ignored stale publisher source update stream={} session={} source_generation={} current_source_generation={}",
                         stream_id_,
                         session_id_,
                         update.generation,
                         publisher_source_generation_);
        return;
    }

    cancel_keyframe_recovery_locked();

    if (update.generation != publisher_source_generation_)
    {
        clear_publisher_sender_timings_locked();
    }

    publisher_source_generation_ = update.generation;
    publisher_source_ = std::move(update.source);
    rebuild_rtp_rewriter_locked();
}

void whep_session_transport::handle_publisher_sender_timing(media_publisher_sender_timing timing)
{
    std::lock_guard lock(rtp_rewriter_mutex_);

    if (publisher_source_ == nullptr ||
        timing.source_generation != publisher_source_generation_ ||
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
    refresh_sender_timing_locked(source_ssrc);
}

void whep_session_transport::configure_outbound_rtcp_senders_locked(
    const whep_rtp_rewriter_target& target,
    bool preserve_runtime_state)
{
    std::unordered_map<uint32_t, outbound_rtcp_sender_state> previous_states =
        preserve_runtime_state ? std::move(outbound_rtcp_senders_)
                               : std::unordered_map<uint32_t, outbound_rtcp_sender_state>{};

    outbound_rtcp_senders_.clear();
    outbound_rtcp_senders_.reserve(target.accepted_media_sources.size());

    for (const auto& source : target.accepted_media_sources)
    {
        if (source.ssrc == 0)
        {
            continue;
        }

        outbound_rtcp_sender_state state;
        state.kind = source.kind;
        state.mid = source.mid;
        state.cname = source.cname;
        state.target_ssrc = source.ssrc;

        if (const auto* media = find_subscriber_media(target, source.mid); media != nullptr)
        {
            state.rtcp_mux = true;
            state.rtcp_rsize = media->rtcp_rsize;
        }

        const auto previous = previous_states.find(source.ssrc);

        if (previous != previous_states.end() && previous->second.cname == source.cname)
        {
            state.packet_count = previous->second.packet_count;
            state.octet_count = previous->second.octet_count;
            state.last_target_rtp_timestamp = previous->second.last_target_rtp_timestamp;
            state.sender_timing = previous->second.sender_timing;
            state.sender_timing_logged = previous->second.sender_timing_logged;
        }

        outbound_rtcp_senders_.insert_or_assign(source.ssrc, std::move(state));
    }
}

void whep_session_transport::clear_publisher_sender_timings_locked()
{
    publisher_sender_timings_.clear();

    for (auto& [target_ssrc, state] : outbound_rtcp_senders_)
    {
        (void)target_ssrc;
        state.sender_timing.reset();
        state.sender_timing_logged = false;
    }
}

void whep_session_transport::refresh_sender_timing_locked(uint32_t source_ssrc)
{
    const auto timing_iterator = publisher_sender_timings_.find(source_ssrc);

    if (timing_iterator == publisher_sender_timings_.end())
    {
        return;
    }

    const auto mapped = rtp_rewriter_.map_source_timestamp(
        source_ssrc,
        timing_iterator->second.source_rtp_timestamp);

    if (!mapped.has_value())
    {
        return;
    }

    const auto sender_iterator = outbound_rtcp_senders_.find(mapped->target_ssrc);

    if (sender_iterator == outbound_rtcp_senders_.end())
    {
        return;
    }

    auto& sender = sender_iterator->second;
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
        return;
    }

    sender.sender_timing = std::move(next_timing);
    record_media_log_event(media_log_event::sender_timing_mapped);

    if (!sender.sender_timing_logged)
    {
        sender.sender_timing_logged = true;
        WEBRTC_LOG_DEBUG(
            "WHEP sender timing mapped stream={} session={} kind={} mid={} publisher_session={} source_generation={} "
            "source_ssrc={} target_ssrc={} ntp_timestamp={} target_rtp_timestamp={} rtcp_mux={} rtcp_rsize={}",
            stream_id_,
            session_id_,
            sender.kind,
            sender.mid,
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

void whep_session_transport::record_outbound_rtp_sent_locked(
    const whep_rtp_rewrite_result& rewritten)
{
    const auto sender_iterator = outbound_rtcp_senders_.find(rewritten.target_ssrc);

    if (sender_iterator == outbound_rtcp_senders_.end())
    {
        return;
    }

    auto& sender = sender_iterator->second;
    sender.packet_count += 1;
    sender.octet_count += rewritten.payload_size;
    sender.last_target_rtp_timestamp = rewritten.target_timestamp;

    if (!sender.sender_timing.has_value() && publisher_sender_timings_.contains(rewritten.source_ssrc))
    {
        refresh_sender_timing_locked(rewritten.source_ssrc);
    }
}

void whep_session_transport::rebuild_rtp_rewriter_locked()
{
    if (publisher_source_ == nullptr)
    {
        reset_keyframe_recovery_locked();
        rtp_rewriter_.clear_source();
        WEBRTC_LOG_INFO("WHEP RTP publisher source unavailable stream={} session={} source_generation={}",
                        stream_id_,
                        session_id_,
                        publisher_source_generation_);
        return;
    }

    auto config = make_whep_rtp_rewriter_config(publisher_source_->session_id,
                                                 publisher_source_->offer,
                                                 rtp_rewriter_target_);

    if (!config)
    {
        reset_keyframe_recovery_locked();
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

void whep_session_transport::reset_keyframe_recovery_locked()
{
    keyframe_tracker_.reset();
    keyframe_waiting_source_ssrcs_.clear();
    keyframe_ready_source_ssrcs_.clear();
    unsupported_keyframe_detection_target_ssrcs_.clear();
}

void whep_session_transport::cancel_keyframe_recovery_locked()
{
    media_fanout_router_->cancel_keyframe_requests(session_id_);
    reset_keyframe_recovery_locked();
}

std::optional<whep_session_transport::keyframe_request_context>
whep_session_transport::prepare_keyframe_request_locked(uint64_t source_generation,
                                                        uint32_t source_ssrc,
                                                        uint32_t target_ssrc,
                                                        bool force_dispatch)
{
    if (source_generation == 0 || source_ssrc == 0 || target_ssrc == 0 ||
        source_generation != publisher_source_generation_ || publisher_source_ == nullptr)
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

bool whep_session_transport::dispatch_keyframe_request(const keyframe_request_context& context,
                                                       std::string_view reason)
{
    std::lock_guard lock(rtp_rewriter_mutex_);

    if (context.source_generation != publisher_source_generation_ || publisher_source_ == nullptr ||
        publisher_source_->session_id != context.publisher_session_id ||
        !keyframe_waiting_source_ssrcs_.contains(context.source_ssrc))
    {
        return false;
    }

    const bool requested = media_fanout_router_->request_keyframe(stream_id_,
                                                                  session_id_,
                                                                  context.publisher_session_id,
                                                                  context.source_generation,
                                                                  context.source_ssrc);

    if (requested)
    {
        record_media_log_event(media_log_event::keyframe_request_submitted);
        WEBRTC_LOG_TRACE(
            "WHEP keyframe request submitted stream={} session={} publisher_session={} source_generation={} media_ssrc={} reason={}",
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
    std::lock_guard lock(rtp_rewriter_mutex_);

    if (context.source_generation != publisher_source_generation_ || publisher_source_ == nullptr ||
        publisher_source_->session_id != context.publisher_session_id ||
        !keyframe_ready_source_ssrcs_.contains(context.source_ssrc))
    {
        return;
    }

    media_fanout_router_->complete_keyframe_request(stream_id_,
                                                     session_id_,
                                                     context.publisher_session_id,
                                                     context.source_generation,
                                                     context.source_ssrc);
    record_media_log_event(media_log_event::keyframe_completed);
    WEBRTC_LOG_INFO(
        "WHEP keyframe completed stream={} session={} publisher_session={} source_generation={} source_ssrc={} target_ssrc={}",
        stream_id_,
        session_id_,
        context.publisher_session_id,
        context.source_generation,
        context.source_ssrc,
        context.target_ssrc);
}

void whep_session_transport::handle_inbound_rtcp(std::span<const uint8_t> plain_rtcp)
{
    record_media_log_event(media_log_event::rtcp_received);

    auto compound = parse_rtcp_compound_packet(plain_rtcp);

    if (!compound)
    {
        record_media_log_event(media_log_event::rtcp_parse_failed);

        if (!media_log_stats_.rtcp_parse_failure_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_WARN("WHEP first inbound RTCP parse failure stream={} session={} error={}",
                            stream_id_,
                            session_id_,
                            compound.error());
        }

        WEBRTC_LOG_TRACE("WHEP inbound RTCP parse failed stream={} session={} error={}",
                         stream_id_,
                         session_id_,
                         compound.error());
        return;
    }

    record_media_log_event(media_log_event::rtcp_sender_report_received, compound->sender_report_count);
    record_media_log_event(media_log_event::rtcp_receiver_report_received, compound->receiver_report_count);
    record_media_log_event(media_log_event::rtcp_report_block_received, compound->report_block_count);
    record_media_log_event(media_log_event::rtcp_sdes_received, compound->sdes_packet_count);
    record_media_log_event(media_log_event::rtcp_bye_received, compound->bye_packets.size());
    record_media_log_event(media_log_event::rtcp_pli_received, compound->pli_count);
    record_media_log_event(media_log_event::rtcp_fir_received, compound->fir_block_count);
    record_media_log_event(media_log_event::rtcp_generic_nack_ignored, compound->generic_nack_block_count);
    record_media_log_event(media_log_event::rtcp_transport_cc_ignored, compound->transport_cc_block_count);
    record_media_log_event(media_log_event::rtcp_remb_ignored, compound->remb_block_count);
    record_media_log_event(media_log_event::rtcp_other_feedback_ignored, compound->other_feedback_block_count);
    record_media_log_event(media_log_event::rtcp_unknown_block_ignored, compound->unknown_block_count);

    for (const auto& block : compound->blocks)
    {
        if (block.has_generic_nack &&
            !media_log_stats_.generic_nack_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHEP first Generic NACK ignored stream={} session={} sender_ssrc={} media_ssrc={} fci_entries={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc,
                block.nack_count);
        }

        if (block.has_transport_cc &&
            !media_log_stats_.transport_cc_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHEP first transport-cc feedback ignored stream={} session={} sender_ssrc={} media_ssrc={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc);
        }

        if (block.has_remb &&
            !media_log_stats_.remb_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHEP first REMB ignored stream={} session={} sender_ssrc={} media_ssrc={} bitrate_bps={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc,
                block.remb_bitrate_bps);
        }

        const bool other_feedback = block.is_feedback && block.feedback_name != "pli" &&
                                    block.feedback_name != "fir" && !block.has_generic_nack &&
                                    !block.has_transport_cc && !block.has_remb;

        if (other_feedback &&
            !media_log_stats_.other_feedback_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHEP first other RTCP feedback ignored stream={} session={} type={} sender_ssrc={} media_ssrc={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_name,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc);
        }

        if (block.is_unknown &&
            !media_log_stats_.unknown_rtcp_block_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHEP first unknown RTCP block ignored stream={} session={} packet_type={} packet_type_name={} count={} action=ignored",
                stream_id_,
                session_id_,
                block.packet_type,
                block.packet_type_name,
                block.count);
        }
    }

    if (compound->keyframe_request_media_ssrcs.empty())
    {
        WEBRTC_LOG_TRACE(
            "WHEP inbound RTCP stream={} session={} blocks={} sr={} rr={} report_blocks={} sdes={} bye={} pli={} fir={} "
            "generic_nack_ignored={} transport_cc_ignored={} remb_ignored={} other_feedback_ignored={} unknown_ignored={} summary={}",
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

    record_media_log_event(media_log_event::rtcp_keyframe_feedback_received,
                           compound->keyframe_request_media_ssrcs.size());
    std::vector<keyframe_request_context> requests;
    std::unordered_set<uint32_t> requested_source_ssrcs;

    {
        std::lock_guard lock(rtp_rewriter_mutex_);

        for (const uint32_t target_ssrc : compound->keyframe_request_media_ssrcs)
        {
            const auto source_ssrc = rtp_rewriter_.source_ssrc_for_target_ssrc(target_ssrc);

            if (!source_ssrc.has_value())
            {
                if (!media_log_stats_.unmapped_keyframe_feedback_logged.exchange(true,
                                                                                  std::memory_order_relaxed))
                {
                    WEBRTC_LOG_DEBUG(
                        "WHEP first keyframe feedback target unmapped stream={} session={} target_ssrc={} source_generation={}",
                        stream_id_,
                        session_id_,
                        target_ssrc,
                        publisher_source_generation_);
                }

                WEBRTC_LOG_TRACE(
                    "WHEP keyframe feedback target unmapped stream={} session={} target_ssrc={} source_generation={}",
                    stream_id_,
                    session_id_,
                    target_ssrc,
                    publisher_source_generation_);
                continue;
            }

            if (!requested_source_ssrcs.insert(*source_ssrc).second)
            {
                continue;
            }

            auto request = prepare_keyframe_request_locked(publisher_source_generation_,
                                                           *source_ssrc,
                                                           target_ssrc,
                                                           true);

            if (request.has_value())
            {
                requests.push_back(std::move(*request));
            }
        }
    }

    std::size_t forwarded = 0;

    for (const auto& request : requests)
    {
        if (dispatch_keyframe_request(request, "receiver_feedback"))
        {
            forwarded += 1;
        }
    }

    record_media_log_event(media_log_event::rtcp_keyframe_feedback_forwarded, forwarded);

    if (!media_log_stats_.keyframe_feedback_logged.exchange(true, std::memory_order_relaxed))
    {
        WEBRTC_LOG_DEBUG(
            "WHEP first inbound keyframe feedback stream={} session={} requested={} forwarded={} pli={} fir={} summary={}",
            stream_id_,
            session_id_,
            compound->keyframe_request_media_ssrcs.size(),
            forwarded,
            compound->pli_count,
            compound->fir_block_count,
            rtcp_compound_feedback_summary_to_string(*compound));
    }

    WEBRTC_LOG_TRACE(
        "WHEP inbound keyframe feedback stream={} session={} requested={} forwarded={} pli={} fir={} summary={}",
        stream_id_,
        session_id_,
        compound->keyframe_request_media_ssrcs.size(),
        forwarded,
        compound->pli_count,
        compound->fir_block_count,
        rtcp_compound_feedback_summary_to_string(*compound));
}

void whep_session_transport::clear_peer_state()
{
    std::lock_guard lock(peer_mutex_);
    clear_peer_state_locked();
}

void whep_session_transport::clear_peer_state_locked()
{
    ice_restart_timer_.cancel();

    std::optional<boost::asio::ip::udp::endpoint> pending_endpoint;

    if (pending_ice_restart_.has_value())
    {
        pending_endpoint = pending_ice_restart_->association_endpoint;
    }

    if (selected_remote_endpoint_.has_value())
    {
        const std::string remote_address = format_udp_endpoint(*selected_remote_endpoint_);
        srtp_transport_->forget_peer(remote_address);
        dtls_transport_->forget_peer(remote_address);
    }

    if (pending_endpoint.has_value() &&
        (!selected_remote_endpoint_.has_value() || *pending_endpoint != *selected_remote_endpoint_))
    {
        const std::string remote_address = format_udp_endpoint(*pending_endpoint);
        srtp_transport_->forget_peer(remote_address);
        dtls_transport_->forget_peer(remote_address);
    }

    selected_remote_endpoint_.reset();
    pending_ice_restart_.reset();
}

void whep_session_transport::schedule_ice_restart_timeout(uint64_t generation)
{
    ice_restart_timer_.expires_after(k_ice_restart_timeout);
    const std::weak_ptr<whep_session_transport> weak_transport = weak_from_this();

    ice_restart_timer_.async_wait(
        [weak_transport, generation](const boost::system::error_code& error)
        {
            if (error == boost::asio::error::operation_aborted)
            {
                return;
            }

            if (const auto transport = weak_transport.lock())
            {
                transport->handle_ice_restart_timeout(generation);
            }
        });
}

void whep_session_transport::handle_ice_restart_timeout(uint64_t generation)
{
    std::lock_guard lock(peer_mutex_);

    if (!pending_ice_restart_.has_value() || pending_ice_restart_->generation != generation)
    {
        return;
    }

    const std::string remote_address = format_udp_endpoint(pending_ice_restart_->association_endpoint);
    srtp_transport_->forget_peer(remote_address);
    dtls_transport_->forget_peer(remote_address);
    pending_ice_restart_.reset();

    WEBRTC_LOG_WARN("WHEP ICE restart timed out stream={} session={} ice_generation={} association_remote={}",
                    stream_id_,
                    session_id_,
                    generation,
                    remote_address);
}

whep_session_transport::peer_nomination_result whep_session_transport::nominate_remote_endpoint(
    const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    std::lock_guard lock(peer_mutex_);

    if (!dtls_identity_.has_value())
    {
        return std::unexpected(std::string("WHEP DTLS identity is unavailable"));
    }

    if (!pending_ice_restart_.has_value() && selected_remote_endpoint_.has_value() &&
        *selected_remote_endpoint_ == remote_endpoint)
    {
        return peer_nomination_state::unchanged;
    }

    std::optional<boost::asio::ip::udp::endpoint> association_endpoint;
    std::optional<dtls_peer_identity> association_identity;

    if (pending_ice_restart_.has_value())
    {
        association_endpoint = pending_ice_restart_->association_endpoint;
        association_identity = pending_ice_restart_->association_identity;
    }
    else if (selected_remote_endpoint_.has_value())
    {
        association_endpoint = selected_remote_endpoint_;
        association_identity = dtls_identity_;
    }

    peer_nomination_state state = peer_nomination_state::selected_fresh;

    if (association_endpoint.has_value() && association_identity.has_value())
    {
        auto rebound = rebind_session_transport_peer(dtls_transport_,
                                                     srtp_transport_,
                                                     *association_endpoint,
                                                     remote_endpoint,
                                                     *association_identity,
                                                     *dtls_identity_);

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
    pending_ice_restart_.reset();
    ice_restart_timer_.cancel();

    WEBRTC_LOG_INFO("WHEP ICE endpoint nominated stream={} session={} ice_generation={} remote={} association_reused={}",
                    stream_id_,
                    session_id_,
                    ice_generation_,
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
        std::lock_guard lock(peer_mutex_);

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
                    std::lock_guard lock(rtp_rewriter_mutex_);
                    cancel_keyframe_recovery_locked();
                }
            }

            result.push_back(std::move(*stun_result.response));
        }

        return result;
    }

    std::unique_lock peer_lock(peer_mutex_);

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
        const dtls_network_family network_family =
            packet.remote_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

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
    peer_lock.unlock();

    if (!inbound)
    {
        record_media_log_event(media_log_event::srtp_unprotect_failed);
        WEBRTC_LOG_WARN("WHEP inbound SRTP packet failed stream={} session={} remote={} error={}",
                        stream_id_,
                        session_id_,
                        remote_address,
                        inbound.error());
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
