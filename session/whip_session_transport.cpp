#include "session/whip_session_transport.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
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
#include "net/socket.h"
#include "rtp/rtcp_compound_packet.h"
#include "rtp/rtcp_feedback.h"
#include "rtp/rtcp_packet_builder.h"
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
constexpr auto k_rtcp_receiver_report_interval = 1s;
constexpr std::size_t k_maximum_rtp_sources = 64;
constexpr std::size_t k_maximum_rtcp_report_blocks = 31;

uint32_t make_rtcp_sender_ssrc(std::string_view session_id)
{
    uint32_t hash = 2166136261U;

    for (const char value : session_id)
    {
        hash ^= static_cast<uint8_t>(value);
        hash *= 16777619U;
    }

    return hash == 0 ? 1U : hash;
}

std::string make_rtcp_cname(std::string_view session_id)
{
    std::string cname("sw-rx-");
    cname.append(session_id);
    return cname;
}

uint32_t make_compact_ntp(uint64_t ntp_timestamp)
{
    return static_cast<uint32_t>((ntp_timestamp >> 16U) & 0xFFFFFFFFU);
}

uint32_t make_delay_since_last_sender_report(
    std::chrono::steady_clock::time_point now,
    const std::optional<std::chrono::steady_clock::time_point>& received_at)
{
    if (!received_at.has_value() || now <= *received_at)
    {
        return 0;
    }

    const auto elapsed_microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(now - *received_at).count();
    const uint64_t delay = static_cast<uint64_t>(elapsed_microseconds) * 65536U / 1000000U;
    return static_cast<uint32_t>(std::min<uint64_t>(delay, std::numeric_limits<uint32_t>::max()));
}
}    // namespace

whip_session_transport::whip_session_transport(boost::asio::io_context& io_context,
                                               std::string bind_host,
                                               std::shared_ptr<dtls_context> dtls_context,
                                               std::uint16_t dtls_ip_mtu,
                                               std::shared_ptr<media_fanout_router> media_fanout_router)
    : udp_server_(io_context, std::move(bind_host)),
      ice_restart_timer_(io_context),
      media_log_timer_(io_context),
      rtcp_receiver_report_timer_(io_context),
      dtls_transport_(std::make_shared<dtls_transport>(std::move(dtls_context), dtls_ip_mtu)),
      srtp_transport_(std::make_shared<srtp_transport>(dtls_transport_)),
      media_fanout_router_(std::move(media_fanout_router))
{
}

whip_session_transport::~whip_session_transport()
{
    media_log_timer_.cancel();
    rtcp_receiver_report_timer_.cancel();
    clear_peer_state();
    udp_server_.stop();
}

whip_session_transport_result whip_session_transport::start(uint16_t local_port)
{
    auto result = udp_server_.start(local_port, *this);

    if (!result)
    {
        return result;
    }

    media_log_interval_started_at_ = std::chrono::steady_clock::now();
    schedule_media_log_summary();
    schedule_rtcp_receiver_reports();
    return {};
}

void whip_session_transport::record_media_log_event(media_log_event event, uint64_t value)
{
    media_log_stats_.counters.add(event, value);
}

void whip_session_transport::schedule_media_log_summary()
{
    media_log_timer_.expires_after(k_media_log_interval);
    const std::weak_ptr<whip_session_transport> weak_transport = weak_from_this();

    media_log_timer_.async_wait(
        [weak_transport](const boost::system::error_code& error)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_media_log_summary(error);
            }
        });
}

void whip_session_transport::handle_media_log_summary(const boost::system::error_code& error)
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

void whip_session_transport::schedule_rtcp_receiver_reports()
{
    rtcp_receiver_report_timer_.expires_after(k_rtcp_receiver_report_interval);
    const std::weak_ptr<whip_session_transport> weak_transport = weak_from_this();

    rtcp_receiver_report_timer_.async_wait(
        [weak_transport](const boost::system::error_code& error)
        {
            if (const auto transport = weak_transport.lock())
            {
                transport->handle_rtcp_receiver_reports(error);
            }
        });
}

void whip_session_transport::handle_rtcp_receiver_reports(const boost::system::error_code& error)
{
    if (error)
    {
        return;
    }

    send_rtcp_receiver_reports();
    schedule_rtcp_receiver_reports();
}

void whip_session_transport::configure_remote_media_locked(
    const sdp::webrtc_offer_summary& remote_offer,
    std::span<const int> accepted_remote_media_mline_indexes)
{
    std::unordered_map<uint8_t, inbound_payload_type_context> payload_types;
    std::unordered_set<uint8_t> ambiguous_payload_types;
    bool has_media = false;
    bool all_media_rtcp_mux = true;

    for (const int mline_index : accepted_remote_media_mline_indexes)
    {
        if (mline_index < 0 || static_cast<std::size_t>(mline_index) >= remote_offer.media.size())
        {
            continue;
        }

        const auto& media = remote_offer.media[static_cast<std::size_t>(mline_index)];

        if (media.codecs.empty())
        {
            continue;
        }

        has_media = true;
        all_media_rtcp_mux = all_media_rtcp_mux && media.rtcp_mux;

        for (const auto& codec : media.codecs)
        {
            if (codec.payload_type > 127 || codec.clock_rate == 0)
            {
                continue;
            }

            const uint8_t payload_type = static_cast<uint8_t>(codec.payload_type);
            const inbound_payload_type_context context{
                .kind = media.kind,
                .clock_rate = codec.clock_rate,
                .rtcp_rsize = media.rtcp_rsize,
            };

            if (ambiguous_payload_types.contains(payload_type))
            {
                continue;
            }

            const auto iterator = payload_types.find(payload_type);

            if (iterator == payload_types.end())
            {
                payload_types.emplace(payload_type, context);
                continue;
            }

            if (iterator->second != context)
            {
                payload_types.erase(iterator);
                ambiguous_payload_types.insert(payload_type);
            }
        }
    }

    inbound_payload_types_ = std::move(payload_types);
    rtcp_mux_enabled_ = has_media && all_media_rtcp_mux;
}

void whip_session_transport::record_inbound_rtp(
    uint32_t source_ssrc,
    uint8_t payload_type,
    uint16_t sequence_number,
    uint32_t rtp_timestamp,
    std::chrono::steady_clock::time_point arrival_time)
{
    std::lock_guard lock(peer_mutex_);
    const auto payload_iterator = inbound_payload_types_.find(payload_type);

    if (payload_iterator == inbound_payload_types_.end())
    {
        record_media_log_event(media_log_event::rtp_receive_stats_unmapped);

        if (!media_log_stats_.unmapped_payload_type_logged[payload_type].exchange(
                true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP RTP receive statistics unavailable stream={} session={} source_ssrc={} payload_type={} reason=unmapped_or_ambiguous",
                stream_id_,
                session_id_,
                source_ssrc,
                payload_type);
        }

        return;
    }

    auto receiver_iterator = inbound_rtcp_receivers_.find(source_ssrc);

    if (receiver_iterator == inbound_rtcp_receivers_.end())
    {
        if (inbound_rtcp_receivers_.size() >= k_maximum_rtp_sources)
        {
            record_media_log_event(media_log_event::rtp_receive_stats_ignored);
            return;
        }

        inbound_rtcp_receiver_state receiver;
        receiver.kind = payload_iterator->second.kind;
        receiver.clock_rate = payload_iterator->second.clock_rate;
        receiver.rtcp_rsize = payload_iterator->second.rtcp_rsize;
        receiver_iterator = inbound_rtcp_receivers_.emplace(source_ssrc, std::move(receiver)).first;
    }

    auto& receiver = receiver_iterator->second;

    if (!receiver.kind.empty() && receiver.kind != payload_iterator->second.kind)
    {
        record_media_log_event(media_log_event::rtp_receive_stats_ignored);
        WEBRTC_LOG_WARN(
            "WHIP RTP receive statistics media kind changed stream={} session={} source_ssrc={} previous_kind={} next_kind={} payload_type={}",
            stream_id_,
            session_id_,
            source_ssrc,
            receiver.kind,
            payload_iterator->second.kind,
            payload_type);
        return;
    }

    receiver.kind = payload_iterator->second.kind;
    receiver.clock_rate = payload_iterator->second.clock_rate;
    receiver.rtcp_rsize = payload_iterator->second.rtcp_rsize;

    if (!receiver.receive_statistics.observe(sequence_number,
                                              rtp_timestamp,
                                              receiver.clock_rate,
                                              arrival_time))
    {
        record_media_log_event(media_log_event::rtp_receive_stats_ignored);
    }
}

void whip_session_transport::update_receiver_sender_report(
    uint32_t source_ssrc,
    uint64_t ntp_timestamp,
    std::chrono::steady_clock::time_point received_at)
{
    std::lock_guard lock(peer_mutex_);
    auto receiver_iterator = inbound_rtcp_receivers_.find(source_ssrc);

    if (receiver_iterator == inbound_rtcp_receivers_.end())
    {
        if (inbound_rtcp_receivers_.size() >= k_maximum_rtp_sources)
        {
            return;
        }

        receiver_iterator = inbound_rtcp_receivers_.emplace(source_ssrc,
                                                             inbound_rtcp_receiver_state{}).first;
    }

    auto& receiver = receiver_iterator->second;
    ++receiver.sender_report_count;
    receiver.last_sender_report = make_compact_ntp(ntp_timestamp);
    receiver.last_sender_report_received_at = received_at;
}

void whip_session_transport::send_rtcp_receiver_reports()
{
    std::lock_guard lock(peer_mutex_);

    if (!rtcp_mux_enabled_ || rtcp_sender_ssrc_ == 0 || rtcp_cname_.empty() ||
        !selected_remote_endpoint_.has_value())
    {
        return;
    }

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);
    auto peer_ready = srtp_transport_->peer_ready(remote_address);

    if (!peer_ready)
    {
        record_media_log_event(media_log_event::rtcp_protect_failed);
        WEBRTC_LOG_WARN("WHIP RTCP RR readiness check failed stream={} session={} remote={} error={}",
                        stream_id_,
                        session_id_,
                        remote_address,
                        peer_ready.error());
        return;
    }

    if (!*peer_ready)
    {
        return;
    }

    std::vector<uint32_t> source_ssrcs;
    source_ssrcs.reserve(inbound_rtcp_receivers_.size());

    for (const auto& [source_ssrc, receiver] : inbound_rtcp_receivers_)
    {
        if (receiver.receive_statistics.initialized())
        {
            source_ssrcs.push_back(source_ssrc);
        }
    }

    if (source_ssrcs.empty())
    {
        return;
    }

    std::ranges::sort(source_ssrcs);
    const auto now = std::chrono::steady_clock::now();

    for (std::size_t offset = 0; offset < source_ssrcs.size(); offset += k_maximum_rtcp_report_blocks)
    {
        const std::size_t block_count =
            std::min(k_maximum_rtcp_report_blocks, source_ssrcs.size() - offset);
        std::vector<rtcp_report_block> report_blocks;
        report_blocks.reserve(block_count);

        for (std::size_t index = 0; index < block_count; ++index)
        {
            const uint32_t source_ssrc = source_ssrcs[offset + index];
            auto& receiver = inbound_rtcp_receivers_.at(source_ssrc);
            const auto snapshot = receiver.receive_statistics.preview_report();
            const uint32_t delay_since_sender_report =
                receiver.last_sender_report == 0
                    ? 0
                    : make_delay_since_last_sender_report(now, receiver.last_sender_report_received_at);

            report_blocks.push_back(rtcp_report_block{
                .source_ssrc = source_ssrc,
                .fraction_lost = snapshot.fraction_lost,
                .cumulative_lost = snapshot.cumulative_lost,
                .extended_highest_sequence_number = snapshot.extended_highest_sequence_number,
                .jitter = snapshot.jitter,
                .last_sender_report = receiver.last_sender_report,
                .delay_since_last_sender_report = delay_since_sender_report,
            });
        }

        auto receiver_report = build_rtcp_receiver_report(rtcp_receiver_report_data{
            .sender_ssrc = rtcp_sender_ssrc_,
            .report_blocks = report_blocks,
        });
        auto sdes = build_rtcp_sdes_cname(rtcp_sender_ssrc_, rtcp_cname_);

        if (!receiver_report || !sdes)
        {
            record_media_log_event(media_log_event::rtcp_build_failed);
            WEBRTC_LOG_WARN("WHIP RTCP RR build failed stream={} session={} report_blocks={} error={}",
                            stream_id_,
                            session_id_,
                            report_blocks.size(),
                            !receiver_report ? receiver_report.error() : sdes.error());
            continue;
        }

        std::array<std::vector<uint8_t>, 2> members{
            std::move(*receiver_report),
            std::move(*sdes),
        };
        auto compound = build_rtcp_compound_packet(members);

        if (!compound)
        {
            record_media_log_event(media_log_event::rtcp_build_failed);
            WEBRTC_LOG_WARN("WHIP RTCP RR compound build failed stream={} session={} report_blocks={} error={}",
                            stream_id_,
                            session_id_,
                            report_blocks.size(),
                            compound.error());
            continue;
        }

        auto protected_packet =
            srtp_transport_->protect_outbound_packet(*compound, remote_address, srtp_packet_kind::rtcp);

        if (!protected_packet)
        {
            record_media_log_event(media_log_event::rtcp_protect_failed);
            WEBRTC_LOG_WARN("WHIP RTCP RR protect failed stream={} session={} remote={} report_blocks={} error={}",
                            stream_id_,
                            session_id_,
                            remote_address,
                            report_blocks.size(),
                            protected_packet.error());
            continue;
        }

        if (protected_packet->state != srtp_packet_process_state::protected_packet ||
            protected_packet->protected_packet.empty())
        {
            record_media_log_event(media_log_event::rtcp_protect_ignored);
            WEBRTC_LOG_DEBUG(
                "WHIP RTCP RR protect ignored stream={} session={} remote={} report_blocks={} state={} reason={}",
                stream_id_,
                session_id_,
                remote_address,
                report_blocks.size(),
                srtp_packet_process_state_to_string(protected_packet->state),
                protected_packet->reason);
            continue;
        }

        const std::size_t protected_size = protected_packet->protected_packet.size();

        for (std::size_t index = 0; index < block_count; ++index)
        {
            const uint32_t source_ssrc = source_ssrcs[offset + index];
            auto& receiver = inbound_rtcp_receivers_.at(source_ssrc);
            const auto& block = report_blocks[index];
            const auto snapshot = receiver.receive_statistics.preview_report();

            receiver.receive_statistics.commit_report();
            ++receiver.receiver_report_count;
            receiver.last_fraction_lost = block.fraction_lost;
            receiver.last_cumulative_lost = block.cumulative_lost;
            receiver.last_extended_highest_sequence_number = block.extended_highest_sequence_number;
            receiver.last_jitter = block.jitter;
            receiver.last_delay_since_sender_report = block.delay_since_last_sender_report;
            receiver.last_expected_packet_count = snapshot.expected_packet_count;
            receiver.last_received_packet_count = snapshot.received_packet_count;

            if (!receiver.receiver_report_logged)
            {
                receiver.receiver_report_logged = true;
                WEBRTC_LOG_DEBUG(
                    "WHIP first receiver report block sent stream={} session={} kind={} source_ssrc={} clock_rate={} fraction_lost={} "
                    "cumulative_lost={} extended_highest_sequence={} jitter={} lsr={} dlsr={}",
                    stream_id_,
                    session_id_,
                    receiver.kind,
                    source_ssrc,
                    receiver.clock_rate,
                    block.fraction_lost,
                    block.cumulative_lost,
                    block.extended_highest_sequence_number,
                    block.jitter,
                    block.last_sender_report,
                    block.delay_since_last_sender_report);
            }
        }

        record_media_log_event(media_log_event::rtcp_receiver_report_sent);
        record_media_log_event(media_log_event::rtcp_report_block_sent, report_blocks.size());
        record_media_log_event(media_log_event::rtcp_sdes_sent);
        record_media_log_event(media_log_event::rtcp_send_bytes, protected_size);
        udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

        WEBRTC_LOG_TRACE(
            "WHIP receiver report sent stream={} session={} remote={} sender_ssrc={} cname={} report_blocks={} bytes={}",
            stream_id_,
            session_id_,
            remote_address,
            rtcp_sender_ssrc_,
            rtcp_cname_,
            report_blocks.size(),
            protected_size);
    }
}

void whip_session_transport::log_media_summary(int64_t interval_ms)
{
    const uint64_t udp_received = media_log_stats_.counters.take(media_log_event::udp_received);
    const uint64_t stun_received = media_log_stats_.counters.take(media_log_event::stun_received);
    const uint64_t dtls_received = media_log_stats_.counters.take(media_log_event::dtls_received);
    const uint64_t rtp_published = media_log_stats_.counters.take(media_log_event::rtp_published);
    const uint64_t rtp_bytes = media_log_stats_.counters.take(media_log_event::rtp_bytes);
    const uint64_t rtp_receive_stats_unmapped =
        media_log_stats_.counters.take(media_log_event::rtp_receive_stats_unmapped);
    const uint64_t rtp_receive_stats_ignored =
        media_log_stats_.counters.take(media_log_event::rtp_receive_stats_ignored);
    const uint64_t rtcp_received = media_log_stats_.counters.take(media_log_event::rtcp_received);
    const uint64_t rtcp_sender_report_received =
        media_log_stats_.counters.take(media_log_event::rtcp_sender_report_received);
    const uint64_t rtcp_sender_timing_published =
        media_log_stats_.counters.take(media_log_event::rtcp_sender_timing_published);
    const uint64_t rtcp_sender_timing_rejected =
        media_log_stats_.counters.take(media_log_event::rtcp_sender_timing_rejected);
    const uint64_t rtcp_receiver_report_received =
        media_log_stats_.counters.take(media_log_event::rtcp_receiver_report_received);
    const uint64_t rtcp_report_block_received =
        media_log_stats_.counters.take(media_log_event::rtcp_report_block_received);
    const uint64_t rtcp_sdes_received = media_log_stats_.counters.take(media_log_event::rtcp_sdes_received);
    const uint64_t rtcp_bye_received = media_log_stats_.counters.take(media_log_event::rtcp_bye_received);
    const uint64_t rtcp_pli_ignored = media_log_stats_.counters.take(media_log_event::rtcp_pli_ignored);
    const uint64_t rtcp_fir_ignored = media_log_stats_.counters.take(media_log_event::rtcp_fir_ignored);
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
    const uint64_t rtcp_receiver_report_sent =
        media_log_stats_.counters.take(media_log_event::rtcp_receiver_report_sent);
    const uint64_t rtcp_report_block_sent =
        media_log_stats_.counters.take(media_log_event::rtcp_report_block_sent);
    const uint64_t rtcp_sdes_sent = media_log_stats_.counters.take(media_log_event::rtcp_sdes_sent);
    const uint64_t rtcp_send_bytes = media_log_stats_.counters.take(media_log_event::rtcp_send_bytes);
    const uint64_t rtcp_build_failed = media_log_stats_.counters.take(media_log_event::rtcp_build_failed);
    const uint64_t rtcp_protect_failed = media_log_stats_.counters.take(media_log_event::rtcp_protect_failed);
    const uint64_t rtcp_protect_ignored = media_log_stats_.counters.take(media_log_event::rtcp_protect_ignored);
    const uint64_t rtcp_keyframe_feedback_sent =
        media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_sent);
    const uint64_t rtcp_keyframe_feedback_reduced_size_sent =
        media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_reduced_size_sent);
    const uint64_t rtcp_keyframe_feedback_compound_sent =
        media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_compound_sent);
    const uint64_t rtcp_keyframe_feedback_send_bytes =
        media_log_stats_.counters.take(media_log_event::rtcp_keyframe_feedback_send_bytes);
    const uint64_t published_targets = media_log_stats_.counters.take(media_log_event::published_targets);
    const uint64_t dropped_unselected = media_log_stats_.counters.take(media_log_event::dropped_unselected);
    const uint64_t srtp_ignored = media_log_stats_.counters.take(media_log_event::srtp_ignored);
    const uint64_t srtp_unprotect_failed = media_log_stats_.counters.take(media_log_event::srtp_unprotect_failed);
    const uint64_t other_received = media_log_stats_.counters.take(media_log_event::other_received);

    const bool has_activity =
        udp_received != 0 || stun_received != 0 || dtls_received != 0 || rtp_published != 0 ||
        rtp_bytes != 0 || rtp_receive_stats_unmapped != 0 || rtp_receive_stats_ignored != 0 ||
        rtcp_received != 0 || rtcp_sender_report_received != 0 ||
        rtcp_sender_timing_published != 0 || rtcp_sender_timing_rejected != 0 ||
        rtcp_receiver_report_received != 0 || rtcp_report_block_received != 0 ||
        rtcp_sdes_received != 0 || rtcp_bye_received != 0 || rtcp_pli_ignored != 0 ||
        rtcp_fir_ignored != 0 || rtcp_generic_nack_ignored != 0 || rtcp_transport_cc_ignored != 0 ||
        rtcp_remb_ignored != 0 || rtcp_other_feedback_ignored != 0 ||
        rtcp_unknown_block_ignored != 0 || rtcp_parse_failed != 0 ||
        rtcp_receiver_report_sent != 0 || rtcp_report_block_sent != 0 || rtcp_sdes_sent != 0 ||
        rtcp_send_bytes != 0 || rtcp_build_failed != 0 || rtcp_protect_failed != 0 ||
        rtcp_protect_ignored != 0 || rtcp_keyframe_feedback_sent != 0 ||
        rtcp_keyframe_feedback_reduced_size_sent != 0 ||
        rtcp_keyframe_feedback_compound_sent != 0 || rtcp_keyframe_feedback_send_bytes != 0 ||
        published_targets != 0 || dropped_unselected != 0 ||
        srtp_ignored != 0 || srtp_unprotect_failed != 0 || other_received != 0;

    if (!has_activity)
    {
        return;
    }

    WEBRTC_LOG_DEBUG(
        "WHIP media summary stream={} session={} interval_ms={} udp_received={} stun={} dtls={} rtp_published={} rtp_bytes={} "
        "rtp_receive_stats_unmapped={} rtp_receive_stats_ignored={} rtcp_received={} rtcp_sr={} "
        "rtcp_sender_timing_published={} rtcp_sender_timing_rejected={} rtcp_rr={} rtcp_report_blocks={} rtcp_sdes={} "
        "rtcp_bye={} rtcp_pli_ignored={} rtcp_fir_ignored={} rtcp_generic_nack_ignored={} rtcp_transport_cc_ignored={} "
        "rtcp_remb_ignored={} rtcp_other_feedback_ignored={} rtcp_unknown_block_ignored={} rtcp_parse_failed={} "
        "rtcp_rr_sent={} rtcp_report_blocks_sent={} rtcp_sdes_sent={} rtcp_send_bytes={} rtcp_build_failed={} "
        "rtcp_protect_failed={} rtcp_protect_ignored={} rtcp_keyframe_feedback_sent={} "
        "rtcp_keyframe_feedback_reduced_size_sent={} rtcp_keyframe_feedback_compound_sent={} "
        "rtcp_keyframe_feedback_send_bytes={} published_targets={} dropped_unselected={} srtp_ignored={} "
        "srtp_unprotect_failed={} other_received={}",
        stream_id_,
        session_id_,
        interval_ms,
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
        rtcp_keyframe_feedback_sent,
        rtcp_keyframe_feedback_reduced_size_sent,
        rtcp_keyframe_feedback_compound_sent,
        rtcp_keyframe_feedback_send_bytes,
        published_targets,
        dropped_unselected,
        srtp_ignored,
        srtp_unprotect_failed,
        other_received);

    log_receiver_states();
}

void whip_session_transport::log_receiver_states()
{
    std::lock_guard lock(peer_mutex_);
    std::vector<uint32_t> source_ssrcs;
    source_ssrcs.reserve(inbound_rtcp_receivers_.size());

    for (const auto& [source_ssrc, receiver] : inbound_rtcp_receivers_)
    {
        if (receiver.receive_statistics.initialized())
        {
            source_ssrcs.push_back(source_ssrc);
        }
    }

    std::ranges::sort(source_ssrcs);

    for (const uint32_t source_ssrc : source_ssrcs)
    {
        const auto& receiver = inbound_rtcp_receivers_.at(source_ssrc);
        const auto current = receiver.receive_statistics.preview_report();

        WEBRTC_LOG_DEBUG(
            "WHIP receiver state stream={} session={} source_generation={} kind={} source_ssrc={} clock_rate={} expected_packets={} "
            "received_packets={} current_cumulative_lost={} current_extended_highest_sequence={} current_jitter={} sr_received={} "
            "last_sr_lsr={} last_sr_dlsr={} rr_sent={} last_fraction_lost={} last_cumulative_lost={} "
            "last_extended_highest_sequence={} last_jitter={} last_rr_expected_packets={} last_rr_received_packets={} "
            "rtcp_sender_ssrc={} cname={} rtcp_mux={} rtcp_rsize={}",
            stream_id_,
            session_id_,
            publisher_source_generation_,
            receiver.kind,
            source_ssrc,
            receiver.clock_rate,
            current.expected_packet_count,
            current.received_packet_count,
            current.cumulative_lost,
            current.extended_highest_sequence_number,
            current.jitter,
            receiver.sender_report_count,
            receiver.last_sender_report,
            receiver.last_delay_since_sender_report,
            receiver.receiver_report_count,
            receiver.last_fraction_lost,
            receiver.last_cumulative_lost,
            receiver.last_extended_highest_sequence_number,
            receiver.last_jitter,
            receiver.last_expected_packet_count,
            receiver.last_received_packet_count,
            rtcp_sender_ssrc_,
            rtcp_cname_,
            rtcp_mux_enabled_ ? 1 : 0,
            receiver.rtcp_rsize ? 1 : 0);
    }
}

void whip_session_transport::handle_inbound_rtcp(std::span<const uint8_t> plain_rtcp)
{
    record_media_log_event(media_log_event::rtcp_received);

    auto compound = parse_rtcp_compound_packet(plain_rtcp);

    if (!compound)
    {
        record_media_log_event(media_log_event::rtcp_parse_failed);

        if (!media_log_stats_.rtcp_parse_failure_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_WARN("WHIP first inbound RTCP parse failure stream={} session={} error={}",
                            stream_id_,
                            session_id_,
                            compound.error());
        }

        WEBRTC_LOG_TRACE("WHIP inbound RTCP parse failed stream={} session={} error={}",
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
    record_media_log_event(media_log_event::rtcp_pli_ignored, compound->pli_count);
    record_media_log_event(media_log_event::rtcp_fir_ignored, compound->fir_block_count);
    record_media_log_event(media_log_event::rtcp_generic_nack_ignored, compound->generic_nack_block_count);
    record_media_log_event(media_log_event::rtcp_transport_cc_ignored, compound->transport_cc_block_count);
    record_media_log_event(media_log_event::rtcp_remb_ignored, compound->remb_block_count);
    record_media_log_event(media_log_event::rtcp_other_feedback_ignored, compound->other_feedback_block_count);
    record_media_log_event(media_log_event::rtcp_unknown_block_ignored, compound->unknown_block_count);

    uint64_t publisher_source_generation = 0;

    {
        std::lock_guard lock(peer_mutex_);
        publisher_source_generation = publisher_source_generation_;
    }

    const auto sender_report_received_at = std::chrono::steady_clock::now();

    for (const auto& report : compound->report_packets)
    {
        if (!report.sender_info.has_value())
        {
            continue;
        }

        const auto& sender_info = *report.sender_info;
        const uint64_t ntp_timestamp =
            (static_cast<uint64_t>(sender_info.ntp_timestamp_msw) << 32U) |
            static_cast<uint64_t>(sender_info.ntp_timestamp_lsw);
        update_receiver_sender_report(report.sender_ssrc, ntp_timestamp, sender_report_received_at);
        const bool published = media_fanout_router_->publish_sender_timing(stream_id_,
                                                                           session_id_,
                                                                           publisher_source_generation,
                                                                           report.sender_ssrc,
                                                                           ntp_timestamp,
                                                                           sender_info.rtp_timestamp,
                                                                           sender_info.sender_packet_count,
                                                                           sender_info.sender_octet_count);

        record_media_log_event(published ? media_log_event::rtcp_sender_timing_published
                                         : media_log_event::rtcp_sender_timing_rejected);

        if (published &&
            mark_session_transport_value_once(media_log_stats_.logged_sender_timing_ssrcs,
                                              report.sender_ssrc))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first sender timing published stream={} session={} source_generation={} source_ssrc={} ntp_timestamp={} rtp_timestamp={} "
                "sender_packets={} sender_octets={}",
                stream_id_,
                session_id_,
                publisher_source_generation,
                report.sender_ssrc,
                ntp_timestamp,
                sender_info.rtp_timestamp,
                sender_info.sender_packet_count,
                sender_info.sender_octet_count);
        }
    }

    for (const auto& block : compound->blocks)
    {
        if (block.feedback_name == "pli" &&
            !media_log_stats_.pli_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first inbound PLI ignored stream={} session={} sender_ssrc={} media_ssrc={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc);
        }

        if (block.feedback_name == "fir" &&
            !media_log_stats_.fir_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first inbound FIR ignored stream={} session={} sender_ssrc={} media_ssrc={} fir_entries={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc,
                block.fir_count);
        }

        if (block.has_generic_nack &&
            !media_log_stats_.generic_nack_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first Generic NACK ignored stream={} session={} sender_ssrc={} media_ssrc={} fci_entries={} action=ignored",
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
                "WHIP first transport-cc feedback ignored stream={} session={} sender_ssrc={} media_ssrc={} action=ignored",
                stream_id_,
                session_id_,
                block.feedback_sender_ssrc,
                block.feedback_media_ssrc);
        }

        if (block.has_remb &&
            !media_log_stats_.remb_ignored_logged.exchange(true, std::memory_order_relaxed))
        {
            WEBRTC_LOG_DEBUG(
                "WHIP first REMB ignored stream={} session={} sender_ssrc={} media_ssrc={} bitrate_bps={} action=ignored",
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
                "WHIP first other RTCP feedback ignored stream={} session={} type={} sender_ssrc={} media_ssrc={} action=ignored",
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
                "WHIP first unknown RTCP block ignored stream={} session={} packet_type={} packet_type_name={} count={} action=ignored",
                stream_id_,
                session_id_,
                block.packet_type,
                block.packet_type_name,
                block.count);
        }
    }

    WEBRTC_LOG_TRACE(
        "WHIP inbound RTCP stream={} session={} blocks={} sr={} rr={} report_blocks={} sdes={} bye={} pli_ignored={} fir_ignored={} "
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
}

void whip_session_transport::set_peer_context(
    std::string local_ice_pwd,
    dtls_peer_identity identity,
    const sdp::webrtc_offer_summary& remote_offer,
    std::span<const int> accepted_remote_media_mline_indexes)
{
    clear_peer_state();

    std::lock_guard lock(peer_mutex_);
    stream_id_ = identity.stream_id;
    session_id_ = identity.session_id;
    local_ice_pwd_ = std::move(local_ice_pwd);
    rtcp_sender_ssrc_ = make_rtcp_sender_ssrc(identity.session_id);
    rtcp_cname_ = make_rtcp_cname(identity.session_id);
    publisher_source_generation_ = 0;
    inbound_rtcp_receivers_.clear();
    configure_remote_media_locked(remote_offer, accepted_remote_media_mline_indexes);
    dtls_identity_ = std::move(identity);
    ++ice_generation_;
}

void whip_session_transport::restart_peer_context(
    std::string local_ice_pwd,
    dtls_peer_identity identity,
    const sdp::webrtc_offer_summary& remote_offer,
    std::span<const int> accepted_remote_media_mline_indexes)
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
        configure_remote_media_locked(remote_offer, accepted_remote_media_mline_indexes);
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
}

void whip_session_transport::set_publisher_source_generation(uint64_t source_generation)
{
    std::lock_guard lock(peer_mutex_);
    publisher_source_generation_ = source_generation;
}

void whip_session_transport::send_keyframe_request(uint32_t media_ssrc)
{
    std::lock_guard lock(peer_mutex_);

    if (media_ssrc == 0 || rtcp_sender_ssrc_ == 0 || rtcp_cname_.empty() ||
        !rtcp_mux_enabled_ || !selected_remote_endpoint_.has_value())
    {
        return;
    }

    const auto receiver = inbound_rtcp_receivers_.find(media_ssrc);
    const bool source_state_known = receiver != inbound_rtcp_receivers_.end();
    const bool reduced_size = source_state_known && receiver->second.rtcp_rsize;
    auto pli = build_rtcp_picture_loss_indication(rtcp_sender_ssrc_, media_ssrc);

    if (!pli)
    {
        record_media_log_event(media_log_event::rtcp_build_failed);
        WEBRTC_LOG_WARN("WHIP keyframe request PLI build failed stream={} session={} media_ssrc={} error={}",
                        stream_id_,
                        session_id_,
                        media_ssrc,
                        pli.error());
        return;
    }

    auto feedback_packet = build_rtcp_feedback_datagram(
        *pli, rtcp_sender_ssrc_, rtcp_cname_, reduced_size);

    if (!feedback_packet)
    {
        record_media_log_event(media_log_event::rtcp_build_failed);
        WEBRTC_LOG_WARN(
            "WHIP keyframe request datagram build failed stream={} session={} media_ssrc={} format={} error={}",
            stream_id_,
            session_id_,
            media_ssrc,
            reduced_size ? "reduced_size" : "compound",
            feedback_packet.error());
        return;
    }

    const boost::asio::ip::udp::endpoint remote_endpoint = *selected_remote_endpoint_;
    const std::string remote_address = format_udp_endpoint(remote_endpoint);
    const std::size_t plain_size = feedback_packet->size();
    auto protected_packet =
        srtp_transport_->protect_outbound_packet(*feedback_packet, remote_address, srtp_packet_kind::rtcp);

    if (!protected_packet)
    {
        record_media_log_event(media_log_event::rtcp_protect_failed);
        WEBRTC_LOG_WARN(
            "WHIP keyframe request protect failed stream={} session={} remote={} media_ssrc={} format={} error={}",
            stream_id_,
            session_id_,
            remote_address,
            media_ssrc,
            reduced_size ? "reduced_size" : "compound",
            protected_packet.error());
        return;
    }

    if (protected_packet->state != srtp_packet_process_state::protected_packet ||
        protected_packet->protected_packet.empty())
    {
        record_media_log_event(media_log_event::rtcp_protect_ignored);
        WEBRTC_LOG_DEBUG(
            "WHIP keyframe request protect ignored stream={} session={} remote={} media_ssrc={} format={} state={} reason={}",
            stream_id_,
            session_id_,
            remote_address,
            media_ssrc,
            reduced_size ? "reduced_size" : "compound",
            srtp_packet_process_state_to_string(protected_packet->state),
            protected_packet->reason);
        return;
    }

    const std::size_t protected_size = protected_packet->protected_packet.size();
    record_media_log_event(media_log_event::rtcp_keyframe_feedback_sent);
    record_media_log_event(reduced_size
                               ? media_log_event::rtcp_keyframe_feedback_reduced_size_sent
                               : media_log_event::rtcp_keyframe_feedback_compound_sent);
    record_media_log_event(media_log_event::rtcp_keyframe_feedback_send_bytes, protected_size);
    udp_server_.send(std::move(protected_packet->protected_packet), remote_endpoint);

    if (!media_log_stats_.keyframe_feedback_sent_logged.exchange(true, std::memory_order_relaxed))
    {
        WEBRTC_LOG_INFO(
            "WHIP first keyframe request sent stream={} session={} remote={} media_ssrc={} format={} rtcp_rsize={} "
            "source_state_known={} plain_bytes={} protected_bytes={}",
            stream_id_,
            session_id_,
            remote_address,
            media_ssrc,
            reduced_size ? "reduced_size" : "compound",
            reduced_size ? 1 : 0,
            source_state_known ? 1 : 0,
            plain_size,
            protected_size);
    }
    else
    {
        WEBRTC_LOG_INFO(
            "WHIP keyframe request sent stream={} session={} remote={} media_ssrc={} format={} rtcp_rsize={} "
            "plain_bytes={} protected_bytes={}",
            stream_id_,
            session_id_,
            remote_address,
            media_ssrc,
            reduced_size ? "reduced_size" : "compound",
            reduced_size ? 1 : 0,
            plain_size,
            protected_size);
    }
}

void whip_session_transport::clear_peer_state()
{
    std::lock_guard lock(peer_mutex_);
    clear_peer_state_locked();
}

void whip_session_transport::clear_peer_state_locked()
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

void whip_session_transport::schedule_ice_restart_timeout(uint64_t generation)
{
    ice_restart_timer_.expires_after(k_ice_restart_timeout);
    const std::weak_ptr<whip_session_transport> weak_transport = weak_from_this();

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

void whip_session_transport::handle_ice_restart_timeout(uint64_t generation)
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

    WEBRTC_LOG_WARN("WHIP ICE restart timed out stream={} session={} ice_generation={} association_remote={}",
                    stream_id_,
                    session_id_,
                    generation,
                    remote_address);
}

whip_session_transport::peer_nomination_result whip_session_transport::nominate_remote_endpoint(
    const boost::asio::ip::udp::endpoint& remote_endpoint)
{
    std::lock_guard lock(peer_mutex_);

    if (!dtls_identity_.has_value())
    {
        return std::unexpected(std::string("WHIP DTLS identity is unavailable"));
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

    WEBRTC_LOG_INFO("WHIP ICE endpoint nominated stream={} session={} ice_generation={} remote={} association_reused={}",
                    stream_id_,
                    session_id_,
                    ice_generation_,
                    format_udp_endpoint(remote_endpoint),
                    state == peer_nomination_state::association_rebound ? 1 : 0);

    return state;
}

session_udp_outbound_packet_list whip_session_transport::handle_udp_packet(const session_udp_packet& packet)
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
    context.log_prefix = "WHIP";
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
                    WEBRTC_LOG_WARN("WHIP ICE endpoint nomination failed stream={} session={} remote={} error={}",
                                    stream_id_,
                                    session_id_,
                                    format_udp_endpoint(packet.remote_endpoint),
                                    nomination.error());
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
        WEBRTC_LOG_TRACE("WHIP session transport ignored packet from unselected endpoint stream={} session={} remote={} size={}",
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
            WEBRTC_LOG_WARN("WHIP session transport dtls identity unavailable stream={} session={}", stream_id_, session_id_);
            return result;
        }

        const std::string remote_address = format_udp_endpoint(packet.remote_endpoint);
        const dtls_network_family network_family =
            packet.remote_endpoint.address().is_v6() ? dtls_network_family::ipv6 : dtls_network_family::ipv4;

        dtls_transport_->remember_peer(remote_address, *dtls_identity_);

        auto outbound_packets = dtls_transport_->handle_udp_packet(packet.data, remote_address, network_family);

        if (!outbound_packets)
        {
            WEBRTC_LOG_WARN("WHIP session transport dtls packet failed stream={} session={} remote={} error={}",
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
    auto srtp_packet = srtp_transport_->handle_inbound_packet(packet.data, remote_address);
    peer_lock.unlock();

    if (!srtp_packet)
    {
        record_media_log_event(media_log_event::srtp_unprotect_failed);
        WEBRTC_LOG_WARN("WHIP session transport srtp unprotect failed stream={} session={} remote={} error={}",
                        stream_id_,
                        session_id_,
                        remote_address,
                        srtp_packet.error());
        return {};
    }

    if (srtp_packet->state == srtp_packet_process_state::unprotected && srtp_packet->kind == srtp_packet_kind::rtp)
    {
        record_inbound_rtp(srtp_packet->ssrc,
                           srtp_packet->payload_type,
                           srtp_packet->sequence_number,
                           srtp_packet->timestamp,
                           std::chrono::steady_clock::now());
        const std::span<const uint8_t> plain_packet(srtp_packet->plain_packet.data(), srtp_packet->plain_packet.size());
        const std::size_t target_count = media_fanout_router_->publish_rtp(stream_id_, session_id_, plain_packet);
        record_media_log_event(media_log_event::rtp_published);
        record_media_log_event(media_log_event::rtp_bytes, srtp_packet->plain_packet.size());
        record_media_log_event(media_log_event::published_targets, target_count);

        if (mark_session_transport_value_once(media_log_stats_.logged_source_ssrcs, srtp_packet->ssrc))
        {
            WEBRTC_LOG_DEBUG("WHIP first RTP published stream={} session={} remote={} ssrc={} pt={} seq={} timestamp={} size={} targets={}",
                             stream_id_,
                             session_id_,
                             remote_address,
                             srtp_packet->ssrc,
                             srtp_packet->payload_type,
                             srtp_packet->sequence_number,
                             srtp_packet->timestamp,
                             srtp_packet->plain_packet.size(),
                             target_count);
        }

        WEBRTC_LOG_TRACE("WHIP RTP published stream={} session={} remote={} ssrc={} pt={} seq={} timestamp={} size={} targets={}",
                         stream_id_,
                         session_id_,
                         remote_address,
                         srtp_packet->ssrc,
                         srtp_packet->payload_type,
                         srtp_packet->sequence_number,
                         srtp_packet->timestamp,
                         srtp_packet->plain_packet.size(),
                         target_count);
        return {};
    }

    if (srtp_packet->state == srtp_packet_process_state::unprotected && srtp_packet->kind == srtp_packet_kind::rtcp)
    {
        handle_inbound_rtcp(srtp_packet->plain_packet);
        return {};
    }
    else if (srtp_packet->state == srtp_packet_process_state::ignored)
    {
        record_media_log_event(media_log_event::srtp_ignored);
    }
    else
    {
        record_media_log_event(media_log_event::other_received);
    }

    WEBRTC_LOG_TRACE("WHIP session transport received udp packet remote={} size={} count={}",
                     packet.remote_endpoint.address().to_string(),
                     packet.data.size(),
                     received_packet_count_);

    return {};
}
}    // namespace webrtc
