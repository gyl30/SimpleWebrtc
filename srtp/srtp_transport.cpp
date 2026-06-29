#include "srtp/srtp_transport.h"

#include <algorithm>
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
#include <utility>
#include <vector>

#include "dtls/dtls_srtp_keying_material.h"
#include "log/log.h"
#include "rtp/rtcp_compound_packet.h"
#include "rtp/rtp_packet.h"
#include "srtp/srtp_session.h"

namespace webrtc
{
namespace
{
inline constexpr std::size_t k_srtp_protect_extra_capacity = 64;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

srtp_packet_kind classify_packet(std::span<const uint8_t> data)
{
    if (!is_rtp_or_rtcp_packet(data))
    {
        return srtp_packet_kind::unknown;
    }

    if (is_rtcp_packet(data))
    {
        return srtp_packet_kind::rtcp;
    }

    return srtp_packet_kind::rtp;
}

srtp_packet_process_result make_ignored_result(srtp_packet_kind kind, std::size_t packet_size, std::string_view reason)
{
    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::ignored;
    result.kind = kind;
    result.packet_size = packet_size;
    result.reason = std::string(reason);
    return result;
}

srtp_transport_result make_unprotected_rtp_result(std::size_t packet_size, std::vector<uint8_t> packet)
{
    auto header = parse_rtp_packet_header(packet);

    if (!header)
    {
        std::string message = "rtp header parse failed after srtp unprotect: ";

        message.append(header.error());

        return std::unexpected(std::move(message));
    }

    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::unprotected;
    result.kind = srtp_packet_kind::rtp;
    result.packet_size = packet_size;
    result.unprotected_size = packet.size();
    result.ssrc = header->ssrc;
    result.payload_type = header->payload_type;
    result.marker = header->marker;
    result.sequence_number = header->sequence_number;
    result.timestamp = header->timestamp;
    result.packet_type_name = "rtp";
    result.plain_packet = std::move(packet);

    return result;
}

void fill_rtcp_report_fields_from_compound(const rtcp_compound_packet& compound, srtp_packet_process_result& result)
{
    result.rtcp_report_packet_count = compound.report_packet_count;
    result.rtcp_report_block_count = compound.report_block_count;
    result.rtcp_has_sender_report = compound.has_sender_report;
    result.rtcp_has_receiver_report = compound.has_receiver_report;
    result.rtcp_has_sender_info = compound.has_sender_info;
    result.rtcp_report_sender_ssrc = compound.report_sender_ssrc;
    result.rtcp_sender_info_data = compound.sender_info;
    result.rtcp_report_blocks = compound.report_blocks;

    if (!compound.report_blocks.empty())
    {
        const rtcp_report_block& last_block = compound.report_blocks.back();

        result.rtcp_last_fraction_lost = last_block.fraction_lost;
        result.rtcp_last_cumulative_lost = last_block.cumulative_lost;
        result.rtcp_last_jitter = last_block.jitter;
    }
}

void fill_rtcp_fields_from_compound(const rtcp_compound_packet& compound, srtp_packet_process_result& result)
{
    result.rtcp_block_count = compound.blocks.size();

    result.rtcp_feedback_block_count = compound.feedback_block_count;

    if (!compound.blocks.empty())
    {
        const rtcp_compound_block& first_block = compound.blocks.front();

        result.payload_type = first_block.packet_type;
        result.rtcp_count = first_block.count;
        result.rtcp_length = first_block.length;
        result.packet_type_name = first_block.packet_type_name;

        if (first_block.has_ssrc)
        {
            result.ssrc = first_block.ssrc;
        }
    }

    result.rtcp_is_feedback = compound.has_feedback;
    result.rtcp_feedback_name = rtcp_compound_feedback_summary_to_string(compound);
    result.rtcp_nack_count = compound.nack_count;
    result.rtcp_fir_count = compound.fir_count;
    result.rtcp_nack_items = compound.nack_items;
    result.rtcp_fir_items = compound.fir_items;

    result.rtcp_feedback_blocks.clear();
    result.rtcp_feedback_blocks.reserve(compound.feedback_block_count);

    for (const auto& block : compound.blocks)
    {
        if (!block.is_feedback)
        {
            continue;
        }

        result.rtcp_feedback_blocks.push_back(block);
    }

    result.rtcp_has_generic_nack = compound.has_generic_nack;
    result.rtcp_has_keyframe_request = compound.has_keyframe_request;
    result.rtcp_has_transport_cc = compound.has_transport_cc;
    result.rtcp_has_remb = compound.has_remb;
    result.rtcp_remb_bitrate_bps = compound.remb_bitrate_bps;

    for (const auto& block : compound.blocks)
    {
        if (!block.is_feedback)
        {
            continue;
        }

        result.rtcp_feedback_format = block.feedback_format;
        result.rtcp_sender_ssrc = block.feedback_sender_ssrc;
        result.rtcp_media_ssrc = block.feedback_media_ssrc;

        if (!block.feedback_name.empty() && result.rtcp_feedback_name == "feedback")
        {
            result.rtcp_feedback_name = block.feedback_name;
        }

        break;
    }
    result.rtcp_bye_packet_count = compound.bye_packet_count;
    result.rtcp_has_bye = compound.has_bye;
    result.rtcp_bye_ssrcs = compound.bye_ssrcs;
    result.rtcp_bye_reason = compound.bye_reason;
    fill_rtcp_report_fields_from_compound(compound, result);
}

srtp_transport_result make_unprotected_rtcp_result(std::size_t packet_size, std::vector<uint8_t> packet)
{
    auto compound = parse_rtcp_compound_packet(packet);

    if (!compound)
    {
        std::string message = "rtcp compound parse failed after srtp unprotect: ";

        message.append(compound.error());

        return std::unexpected(std::move(message));
    }

    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::unprotected;
    result.kind = srtp_packet_kind::rtcp;
    result.packet_size = packet_size;
    result.unprotected_size = packet.size();

    fill_rtcp_fields_from_compound(*compound, result);

    result.plain_packet = std::move(packet);

    return result;
}

srtp_transport_result make_unprotected_result(srtp_packet_kind kind, std::size_t packet_size, std::vector<uint8_t> packet)
{
    if (kind == srtp_packet_kind::rtp)
    {
        return make_unprotected_rtp_result(packet_size, std::move(packet));
    }

    if (kind == srtp_packet_kind::rtcp)
    {
        return make_unprotected_rtcp_result(packet_size, std::move(packet));
    }

    return make_error("srtp packet kind is unknown");
}

srtp_transport_result make_protected_result(srtp_packet_kind kind, std::size_t plain_size, std::vector<uint8_t> packet)
{
    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::protected_packet;
    result.kind = kind;
    result.packet_size = plain_size;
    result.protected_size = packet.size();
    result.protected_packet = std::move(packet);
    return result;
}
}    // namespace

struct srtp_transport::impl
{
    explicit impl(std::shared_ptr<dtls_transport> dtls_transport) : dtls_transport_(std::move(dtls_transport)) {}

    struct srtp_peer_context
    {
        bool sessions_ready = false;

        std::string session_id;
        std::string stream_id;
        std::string local_ice_ufrag;
        std::string remote_ice_ufrag;
        std::string generation;

        std::optional<srtp_session> inbound_session;
        std::optional<srtp_session> outbound_session;

        uint64_t inbound_packet_count = 0;
        uint64_t inbound_byte_count = 0;
        uint64_t inbound_rtp_count = 0;
        uint64_t inbound_rtcp_count = 0;

        uint64_t outbound_packet_count = 0;
        uint64_t outbound_byte_count = 0;
        uint64_t outbound_rtp_count = 0;
        uint64_t outbound_rtcp_count = 0;
    };
    static bool peer_identity_matches(const srtp_peer_context& peer, const dtls_peer_identity& identity)
    {
        return peer.session_id == identity.session_id && peer.stream_id == identity.stream_id && peer.local_ice_ufrag == identity.local_ice_ufrag &&
               peer.remote_ice_ufrag == identity.remote_ice_ufrag && peer.generation == identity.generation;
    }

    static void bind_peer_identity(srtp_peer_context& peer, const dtls_peer_identity& identity)
    {
        peer.session_id = identity.session_id;

        peer.stream_id = identity.stream_id;

        peer.local_ice_ufrag = identity.local_ice_ufrag;

        peer.remote_ice_ufrag = identity.remote_ice_ufrag;

        peer.generation = identity.generation;
    }

    static void reset_peer_for_identity(srtp_peer_context& peer, const dtls_peer_identity& identity)
    {
        peer = srtp_peer_context{};

        bind_peer_identity(peer, identity);
    }
    srtp_transport_result handle_inbound_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
    {
        const srtp_packet_kind kind = classify_packet(data);

        if (kind == srtp_packet_kind::unknown)
        {
            return make_ignored_result(kind, data.size(), "packet is not rtp or rtcp");
        }

        std::lock_guard lock(mutex_);

        auto& peer = peers_by_endpoint_[std::string(remote_endpoint)];

        auto ready_result = ensure_sessions_ready_locked(peer, remote_endpoint);

        if (!ready_result)
        {
            return std::unexpected(ready_result.error());
        }

        if (!*ready_result)
        {
            return make_ignored_result(kind, data.size(), "dtls handshake is not complete");
        }

        if (!peer.inbound_session.has_value())
        {
            return make_error("srtp inbound session is empty");
        }

        std::vector<uint8_t> packet(data.begin(), data.end());

        srtp_packet_result unprotect_result = kind == srtp_packet_kind::rtcp ? peer.inbound_session->unprotect_rtcp(packet, packet.size())
                                                                             : peer.inbound_session->unprotect_rtp(packet, packet.size());

        if (!unprotect_result)
        {
            std::string message = "srtp inbound unprotect failed remote=";

            message.append(std::string(remote_endpoint));
            message.append(" kind=");
            message.append(srtp_packet_kind_to_string(kind));
            message.append(" error=");
            message.append(unprotect_result.error());

            return std::unexpected(std::move(message));
        }

        const std::size_t unprotected_size = *unprotect_result;

        packet.resize(unprotected_size);

        auto result = make_unprotected_result(kind, data.size(), std::move(packet));

        if (!result)
        {
            return std::unexpected(result.error());
        }

        peer.inbound_packet_count += 1;
        peer.inbound_byte_count += static_cast<uint64_t>(unprotected_size);

        if (kind == srtp_packet_kind::rtp)
        {
            peer.inbound_rtp_count += 1;

            WEBRTC_LOG_DEBUG(
                "srtp inbound rtp unprotected remote={} size={} plain_size={} ssrc={} payload_type={} marker={} sequence={} timestamp={} packets={}",
                remote_endpoint,
                data.size(),
                unprotected_size,
                result->ssrc,
                static_cast<unsigned int>(result->payload_type),
                result->marker ? 1 : 0,
                result->sequence_number,
                result->timestamp,
                peer.inbound_packet_count);
        }
        else
        {
            peer.inbound_rtcp_count += 1;

            if (result->rtcp_is_feedback)
            {
                WEBRTC_LOG_DEBUG(
                    "srtp inbound rtcp compound feedback unprotected remote={} size={} plain_size={} blocks={} feedback_blocks={} reports={} "
                    "report_blocks={} ssrc={} first_packet_type={} feedback={} sender_ssrc={} media_ssrc={} nack_count={} fir_count={} "
                    "keyframe_request={} generic_nack={} transport_cc={} remb={} remb_bitrate={} packets={}",
                    remote_endpoint,
                    data.size(),
                    unprotected_size,
                    result->rtcp_block_count,
                    result->rtcp_feedback_block_count,
                    result->rtcp_report_packet_count,
                    result->rtcp_report_block_count,
                    result->ssrc,
                    static_cast<unsigned int>(result->payload_type),
                    result->rtcp_feedback_name,
                    result->rtcp_sender_ssrc,
                    result->rtcp_media_ssrc,
                    result->rtcp_nack_count,
                    result->rtcp_fir_count,
                    result->rtcp_has_keyframe_request ? 1 : 0,
                    result->rtcp_has_generic_nack ? 1 : 0,
                    result->rtcp_has_transport_cc ? 1 : 0,
                    result->rtcp_has_remb ? 1 : 0,
                    result->rtcp_remb_bitrate_bps,
                    peer.inbound_packet_count);
            }
            else
            {
                WEBRTC_LOG_DEBUG(
                    "srtp inbound rtcp compound unprotected remote={} size={} plain_size={} blocks={} reports={} report_blocks={} ssrc={} "
                    "packet_type={} packet_type_name={} count={} length={} fraction_lost={} cumulative_lost={} jitter={} packets={}",
                    remote_endpoint,
                    data.size(),
                    unprotected_size,
                    result->rtcp_block_count,
                    result->rtcp_report_packet_count,
                    result->rtcp_report_block_count,
                    result->ssrc,
                    static_cast<unsigned int>(result->payload_type),
                    result->packet_type_name,
                    static_cast<unsigned int>(result->rtcp_count),
                    result->rtcp_length,
                    static_cast<unsigned int>(result->rtcp_last_fraction_lost),
                    result->rtcp_last_cumulative_lost,
                    result->rtcp_last_jitter,
                    peer.inbound_packet_count);
            }
        }

        return std::move(*result);
    }

    srtp_transport_result protect_outbound_packet(std::span<const uint8_t> plain_packet, std::string_view remote_endpoint, srtp_packet_kind kind)
    {
        if (kind == srtp_packet_kind::unknown)
        {
            return make_ignored_result(kind, plain_packet.size(), "packet kind is unknown");
        }

        if (plain_packet.empty())
        {
            return make_ignored_result(kind, 0, "plain packet is empty");
        }

        std::lock_guard lock(mutex_);

        auto& peer = peers_by_endpoint_[std::string(remote_endpoint)];

        auto ready_result = ensure_sessions_ready_locked(peer, remote_endpoint);

        if (!ready_result)
        {
            return std::unexpected(ready_result.error());
        }

        if (!*ready_result)
        {
            return make_ignored_result(kind, plain_packet.size(), "dtls handshake is not complete");
        }

        if (!peer.outbound_session.has_value())
        {
            return make_error("srtp outbound session is empty");
        }

        std::vector<uint8_t> packet(plain_packet.size() + k_srtp_protect_extra_capacity);

        std::copy(plain_packet.begin(), plain_packet.end(), packet.begin());

        srtp_packet_result protect_result = kind == srtp_packet_kind::rtcp ? peer.outbound_session->protect_rtcp(packet, plain_packet.size())
                                                                           : peer.outbound_session->protect_rtp(packet, plain_packet.size());

        if (!protect_result)
        {
            std::string message = "srtp outbound protect failed remote=";

            message.append(std::string(remote_endpoint));
            message.append(" kind=");
            message.append(srtp_packet_kind_to_string(kind));
            message.append(" error=");
            message.append(protect_result.error());

            return std::unexpected(std::move(message));
        }

        packet.resize(*protect_result);

        peer.outbound_packet_count += 1;
        peer.outbound_byte_count += static_cast<uint64_t>(packet.size());

        if (kind == srtp_packet_kind::rtp)
        {
            peer.outbound_rtp_count += 1;
        }
        else
        {
            peer.outbound_rtcp_count += 1;
        }

        WEBRTC_LOG_DEBUG("srtp outbound packet protected remote={} kind={} plain_size={} protected_size={} packets={}",
                         remote_endpoint,
                         srtp_packet_kind_to_string(kind),
                         plain_packet.size(),
                         packet.size(),
                         peer.outbound_packet_count);

        return make_protected_result(kind, plain_packet.size(), std::move(packet));
    }

    void forget_peer(std::string_view remote_endpoint)
    {
        if (remote_endpoint.empty())
        {
            return;
        }

        std::lock_guard lock(mutex_);

        peers_by_endpoint_.erase(std::string(remote_endpoint));
    }

    std::size_t peer_count() const
    {
        std::lock_guard lock(mutex_);

        return peers_by_endpoint_.size();
    }

    std::expected<bool, std::string> ensure_sessions_ready_locked(srtp_peer_context& peer, std::string_view remote_endpoint)
    {
        if (dtls_transport_ == nullptr)
        {
            return make_error("dtls transport is null");
        }

        auto identity = dtls_transport_->get_peer_identity(remote_endpoint);

        if (!identity.has_value())
        {
            if (peer.sessions_ready)
            {
                WEBRTC_LOG_INFO("srtp sessions reset because dtls identity is missing remote={} old_session={} old_generation={}",
                                remote_endpoint,
                                peer.session_id,
                                peer.generation);

                peer = srtp_peer_context{};
            }

            return false;
        }

        if (peer.sessions_ready && peer_identity_matches(peer, *identity))
        {
            return true;
        }

        if (!peer.generation.empty() && !peer_identity_matches(peer, *identity))
        {
            WEBRTC_LOG_INFO(
                "srtp generation changed reset sessions remote={} old_session={} new_session={} old_generation={} new_generation={} "
                "old_local_ufrag={} new_local_ufrag={} old_remote_ufrag={} new_remote_ufrag={}",
                remote_endpoint,
                peer.session_id,
                identity->session_id,
                peer.generation,
                identity->generation,
                peer.local_ice_ufrag,
                identity->local_ice_ufrag,
                peer.remote_ice_ufrag,
                identity->remote_ice_ufrag);

            reset_peer_for_identity(peer, *identity);
        }
        else if (peer.generation.empty())
        {
            bind_peer_identity(peer, *identity);
        }

        auto material = dtls_transport_->get_srtp_keying_material(remote_endpoint);

        if (!material.has_value())
        {
            if (!dtls_transport_->is_handshake_done(remote_endpoint))
            {
                return false;
            }

            return make_error("dtls handshake is complete but srtp keying material is empty");
        }

        auto material_identity = dtls_transport_->get_peer_identity(remote_endpoint);

        if (!material_identity.has_value() || material_identity->generation != peer.generation)
        {
            WEBRTC_LOG_DEBUG("srtp session create skipped because dtls generation changed remote={} expected_generation={} current_generation={}",
                             remote_endpoint,
                             peer.generation,
                             material_identity.has_value() ? material_identity->generation : "");

            return false;
        }

        auto inbound_config = make_inbound_srtp_session_config(*material);

        auto outbound_config = make_outbound_srtp_session_config(*material);

        auto inbound = make_srtp_session(inbound_config);

        if (!inbound)
        {
            return std::unexpected(inbound.error());
        }

        auto outbound = make_srtp_session(outbound_config);

        if (!outbound)
        {
            return std::unexpected(outbound.error());
        }

        peer.inbound_session.emplace(std::move(*inbound));

        peer.outbound_session.emplace(std::move(*outbound));

        peer.sessions_ready = true;

        WEBRTC_LOG_INFO(
            "srtp sessions created remote={} session={} stream={} generation={} profile={} local_ufrag={} remote_ufrag={} inbound={} outbound={}",
            remote_endpoint,
            peer.session_id,
            peer.stream_id,
            peer.generation,
            srtp_profile_id_to_string(material->profile),
            peer.local_ice_ufrag,
            peer.remote_ice_ufrag,
            srtp_direction_to_string(srtp_direction::inbound),
            srtp_direction_to_string(srtp_direction::outbound));

        return true;
    }
    std::shared_ptr<dtls_transport> dtls_transport_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, srtp_peer_context> peers_by_endpoint_;
};

srtp_transport::srtp_transport(std::shared_ptr<dtls_transport> dtls_transport) : impl_(std::make_unique<impl>(std::move(dtls_transport))) {}

srtp_transport::~srtp_transport() = default;

srtp_transport_result srtp_transport::handle_inbound_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
{
    return impl_->handle_inbound_packet(data, remote_endpoint);
}

srtp_transport_result srtp_transport::protect_outbound_packet(std::span<const uint8_t> plain_packet,
                                                              std::string_view remote_endpoint,
                                                              srtp_packet_kind kind)
{
    return impl_->protect_outbound_packet(plain_packet, remote_endpoint, kind);
}

void srtp_transport::forget_peer(std::string_view remote_endpoint) { impl_->forget_peer(remote_endpoint); }

std::size_t srtp_transport::peer_count() const { return impl_->peer_count(); }

std::string srtp_packet_kind_to_string(srtp_packet_kind kind)
{
    switch (kind)
    {
        case srtp_packet_kind::rtp:
            return "rtp";

        case srtp_packet_kind::rtcp:
            return "rtcp";

        case srtp_packet_kind::unknown:
            return "unknown";
    }

    return "unknown";
}

std::string srtp_packet_process_state_to_string(srtp_packet_process_state state)
{
    switch (state)
    {
        case srtp_packet_process_state::ignored:
            return "ignored";

        case srtp_packet_process_state::unprotected:
            return "unprotected";

        case srtp_packet_process_state::protected_packet:
            return "protected";
    }

    return "unknown";
}
}    // namespace webrtc
