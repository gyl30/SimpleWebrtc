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

srtp_packet_process_result make_ignored_result(srtp_packet_kind kind, std::string_view reason)
{
    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::ignored;
    result.kind = kind;
    result.reason = std::string(reason);
    return result;
}

void log_unprotected_rtp_packet(std::string_view remote_endpoint,
                                  std::size_t protected_size,
                                  std::size_t unprotected_size,
                                  const rtp_packet_header& header,
                                  uint64_t packet_count)
{
    WEBRTC_LOG_TRACE(
        "srtp inbound rtp unprotected remote={} size={} plain_size={} ssrc={} payload_type={} marker={} sequence={} timestamp={} packets={}",
        remote_endpoint,
        protected_size,
        unprotected_size,
        header.ssrc,
        static_cast<unsigned int>(header.payload_type),
        header.marker ? 1 : 0,
        header.sequence_number,
        header.timestamp,
        packet_count);
}

void log_unprotected_rtcp_packet(std::string_view remote_endpoint,
                                 std::size_t protected_size,
                                 std::size_t unprotected_size,
                                 const rtcp_compound_packet& compound,
                                 uint64_t packet_count)
{
    const rtcp_compound_block* first_block = compound.blocks.empty() ? nullptr : &compound.blocks.front();
    const uint32_t first_ssrc = first_block != nullptr && first_block->has_ssrc ? first_block->ssrc : 0;
    const uint8_t first_packet_type = first_block != nullptr ? first_block->packet_type : 0;

    if (compound.has_feedback)
    {
        std::string feedback_name = rtcp_compound_feedback_summary_to_string(compound);
        uint32_t feedback_sender_ssrc = 0;
        uint32_t feedback_media_ssrc = 0;

        for (const auto& block : compound.blocks)
        {
            if (!block.is_feedback)
            {
                continue;
            }

            feedback_sender_ssrc = block.feedback_sender_ssrc;
            feedback_media_ssrc = block.feedback_media_ssrc;

            if (!block.feedback_name.empty() && feedback_name == "feedback")
            {
                feedback_name = block.feedback_name;
            }

            break;
        }

        WEBRTC_LOG_TRACE(
            "srtp inbound rtcp compound feedback unprotected remote={} size={} plain_size={} blocks={} feedback_blocks={} reports={} "
            "report_blocks={} ssrc={} first_packet_type={} feedback={} sender_ssrc={} media_ssrc={} nack_count={} fir_count={} "
            "keyframe_request={} generic_nack={} transport_cc={} remb={} remb_bitrate={} packets={}",
            remote_endpoint,
            protected_size,
            unprotected_size,
            compound.blocks.size(),
            compound.feedback_block_count,
            compound.report_packet_count,
            compound.report_block_count,
            first_ssrc,
            static_cast<unsigned int>(first_packet_type),
            feedback_name,
            feedback_sender_ssrc,
            feedback_media_ssrc,
            compound.nack_count,
            compound.fir_count,
            compound.has_keyframe_request ? 1 : 0,
            compound.has_generic_nack ? 1 : 0,
            compound.has_transport_cc ? 1 : 0,
            compound.has_remb ? 1 : 0,
            compound.remb_bitrate_bps,
            packet_count);

        return;
    }

    const uint8_t first_count = first_block != nullptr ? first_block->count : 0;
    const uint16_t first_length = first_block != nullptr ? first_block->length : 0;
    const std::string_view first_packet_type_name = first_block != nullptr ? first_block->packet_type_name : std::string_view{};
    const uint8_t fraction_lost = compound.last_report_block.has_value() ? compound.last_report_block->fraction_lost : 0;
    const int32_t cumulative_lost = compound.last_report_block.has_value() ? compound.last_report_block->cumulative_lost : 0;
    const uint32_t jitter = compound.last_report_block.has_value() ? compound.last_report_block->jitter : 0;

    WEBRTC_LOG_TRACE(
        "srtp inbound rtcp compound unprotected remote={} size={} plain_size={} blocks={} reports={} report_blocks={} ssrc={} "
        "packet_type={} packet_type_name={} count={} length={} fraction_lost={} cumulative_lost={} jitter={} packets={}",
        remote_endpoint,
        protected_size,
        unprotected_size,
        compound.blocks.size(),
        compound.report_packet_count,
        compound.report_block_count,
        first_ssrc,
        static_cast<unsigned int>(first_packet_type),
        first_packet_type_name,
        static_cast<unsigned int>(first_count),
        first_length,
        static_cast<unsigned int>(fraction_lost),
        cumulative_lost,
        jitter,
        packet_count);
}

srtp_transport_result make_protected_result(srtp_packet_kind kind, std::vector<uint8_t> packet)
{
    srtp_packet_process_result result;
    result.state = srtp_packet_process_state::protected_packet;
    result.kind = kind;
    result.protected_packet = std::move(packet);
    return result;
}

struct srtp_peer_state
{
    std::string session_id;
    std::string stream_id;
    std::string local_ice_ufrag;
    std::string remote_ice_ufrag;

    std::optional<srtp_session> inbound_session;
    std::optional<srtp_session> outbound_session;

    uint64_t inbound_packet_count = 0;
    uint64_t outbound_packet_count = 0;
};
}    // namespace

struct srtp_transport::impl
{
    explicit impl(std::shared_ptr<dtls_transport> dtls_transport) : dtls_transport_(std::move(dtls_transport)) {}

    static bool peer_identity_matches(const srtp_peer_state& peer, const dtls_peer_identity& identity)
    {
        return peer.session_id == identity.session_id && peer.stream_id == identity.stream_id && peer.local_ice_ufrag == identity.local_ice_ufrag &&
               peer.remote_ice_ufrag == identity.remote_ice_ufrag;
    }

    static void bind_peer_identity(srtp_peer_state& peer, const dtls_peer_identity& identity)
    {
        peer.session_id = identity.session_id;

        peer.stream_id = identity.stream_id;

        peer.local_ice_ufrag = identity.local_ice_ufrag;

        peer.remote_ice_ufrag = identity.remote_ice_ufrag;
    }

    static void reset_peer_for_identity(srtp_peer_state& peer, const dtls_peer_identity& identity)
    {
        peer = srtp_peer_state{};

        bind_peer_identity(peer, identity);
    }

    std::expected<srtp_peer_state*, std::string> find_ready_peer_locked(std::string_view remote_endpoint, std::string& ignored_reason)
    {
        if (dtls_transport_ == nullptr)
        {
            return make_error("dtls transport is null");
        }

        auto identity = dtls_transport_->get_peer_identity(remote_endpoint);

        if (!identity.has_value())
        {
            const auto iterator = peers_by_endpoint_.find(std::string(remote_endpoint));

            if (iterator == peers_by_endpoint_.end())
            {
                ignored_reason = "dtls identity is missing";
                return static_cast<srtp_peer_state*>(nullptr);
            }

            if (iterator->second.inbound_session.has_value() || iterator->second.outbound_session.has_value())
            {
                WEBRTC_LOG_INFO(
                    "srtp sessions reset because dtls identity is missing remote={} old_session={} old_local_ufrag={} old_remote_ufrag={}",
                    remote_endpoint,
                    iterator->second.session_id,
                    iterator->second.local_ice_ufrag,
                    iterator->second.remote_ice_ufrag);
            }

            peers_by_endpoint_.erase(iterator);
            ignored_reason = "dtls handshake is not complete";
            return static_cast<srtp_peer_state*>(nullptr);
        }

        const std::string endpoint_key(remote_endpoint);
        auto [iterator, inserted] = peers_by_endpoint_.try_emplace(endpoint_key);
        auto& peer = iterator->second;

        if (inserted)
        {
            bind_peer_identity(peer, *identity);
        }

        auto ready_result = ensure_sessions_ready_locked(peer, remote_endpoint, *identity);

        if (!ready_result)
        {
            return std::unexpected(ready_result.error());
        }

        if (!*ready_result)
        {
            ignored_reason = "dtls handshake is not complete";
            return static_cast<srtp_peer_state*>(nullptr);
        }

        return &peer;
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

    srtp_peer_rebind_result rebind_peer(std::string_view previous_remote_endpoint,
                                        std::string_view next_remote_endpoint,
                                        const dtls_peer_identity& identity)
    {
        if (previous_remote_endpoint.empty() || next_remote_endpoint.empty())
        {
            return std::unexpected("srtp peer rebind endpoint is empty");
        }

        std::lock_guard lock(mutex_);

        const std::string previous_key(previous_remote_endpoint);
        const std::string next_key(next_remote_endpoint);
        auto previous = peers_by_endpoint_.find(previous_key);

        if (previous == peers_by_endpoint_.end())
        {
            return false;
        }

        if (previous->second.session_id != identity.session_id ||
            previous->second.stream_id != identity.stream_id)
        {
            return std::unexpected("srtp peer rebind session identity changed");
        }

        if (previous_key != next_key && peers_by_endpoint_.contains(next_key))
        {
            return std::unexpected("srtp peer rebind destination already exists");
        }

        if (previous_key == next_key)
        {
            bind_peer_identity(previous->second, identity);

            WEBRTC_LOG_INFO("srtp peer rebound remote={} session={} stream={} local_ufrag={} remote_ufrag={} same_endpoint=1",
                            next_remote_endpoint,
                            previous->second.session_id,
                            previous->second.stream_id,
                            previous->second.local_ice_ufrag,
                            previous->second.remote_ice_ufrag);

            return true;
        }

        auto node = peers_by_endpoint_.extract(previous);
        node.key() = next_key;
        bind_peer_identity(node.mapped(), identity);
        auto inserted = peers_by_endpoint_.insert(std::move(node));

        if (!inserted.inserted)
        {
            return std::unexpected("srtp peer rebind destination insertion failed");
        }

        WEBRTC_LOG_INFO("srtp peer rebound previous_remote={} remote={} session={} stream={} local_ufrag={} remote_ufrag={} same_endpoint=0",
                        previous_remote_endpoint,
                        next_remote_endpoint,
                        inserted.position->second.session_id,
                        inserted.position->second.stream_id,
                        inserted.position->second.local_ice_ufrag,
                        inserted.position->second.remote_ice_ufrag);

        return true;
    }

    srtp_peer_ready_result peer_ready(std::string_view remote_endpoint)
    {
        if (remote_endpoint.empty())
        {
            return false;
        }

        std::lock_guard lock(mutex_);
        std::string ignored_reason;
        auto peer_result = find_ready_peer_locked(remote_endpoint, ignored_reason);

        if (!peer_result)
        {
            return std::unexpected(peer_result.error());
        }

        return *peer_result != nullptr;
    }

    srtp_transport_result handle_inbound_packet(std::span<const uint8_t> data, std::string_view remote_endpoint)
    {
        const srtp_packet_kind kind = classify_packet(data);

        if (kind == srtp_packet_kind::unknown)
        {
            return make_ignored_result(kind, "packet is not rtp or rtcp");
        }

        std::lock_guard lock(mutex_);

        std::string ignored_reason;
        auto peer_result = find_ready_peer_locked(remote_endpoint, ignored_reason);

        if (!peer_result)
        {
            return std::unexpected(peer_result.error());
        }

        if (*peer_result == nullptr)
        {
            return make_ignored_result(kind, ignored_reason);
        }

        auto& peer = **peer_result;

        std::vector<uint8_t> packet(data.begin(), data.end());

        srtp_packet_result unprotect_result = kind == srtp_packet_kind::rtcp ? peer.inbound_session->unprotect_rtcp(packet, packet.size())
                                                                             : peer.inbound_session->unprotect_rtp(packet, packet.size());

        if (!unprotect_result)
        {
            std::string reason;

            if (is_srtp_replay_error(unprotect_result.error()))
            {
                reason = "srtp replay ignored kind=";
            }
            else
            {
                reason = "srtp unprotect failed ignored kind=";
            }

            reason.append(srtp_packet_kind_to_string(kind));
            reason.append(" error=");
            reason.append(unprotect_result.error());

            return make_ignored_result(kind, reason);
        }

        const std::size_t unprotected_size = *unprotect_result;
        packet.resize(unprotected_size);

        srtp_packet_process_result result;
        result.state = srtp_packet_process_state::unprotected;
        result.kind = kind;

        if (kind == srtp_packet_kind::rtp)
        {
            auto header = parse_rtp_packet_header(packet);

            if (!header)
            {
                std::string message = "rtp header parse failed after srtp unprotect: ";

                message.append(header.error());

                return std::unexpected(std::move(message));
            }

            result.ssrc = header->ssrc;
            result.payload_type = header->payload_type;
            result.sequence_number = header->sequence_number;
            result.timestamp = header->timestamp;
            result.plain_packet = std::move(packet);

            peer.inbound_packet_count += 1;

            log_unprotected_rtp_packet(remote_endpoint, data.size(), unprotected_size, *header, peer.inbound_packet_count);

            return result;
        }

        auto compound = parse_rtcp_compound_packet(packet);

        if (!compound)
        {
            std::string message = "rtcp compound parse failed after srtp unprotect: ";

            message.append(compound.error());

            return std::unexpected(std::move(message));
        }

        result.plain_packet = std::move(packet);

        peer.inbound_packet_count += 1;

        log_unprotected_rtcp_packet(remote_endpoint, data.size(), unprotected_size, *compound, peer.inbound_packet_count);

        return result;
    }

    srtp_transport_result protect_outbound_packet(std::span<const uint8_t> plain_packet, std::string_view remote_endpoint, srtp_packet_kind kind)
    {
        if (kind == srtp_packet_kind::unknown)
        {
            return make_ignored_result(kind, "packet kind is unknown");
        }

        if (plain_packet.empty())
        {
            return make_ignored_result(kind, "plain packet is empty");
        }

        std::lock_guard lock(mutex_);

        std::string ignored_reason;
        auto peer_result = find_ready_peer_locked(remote_endpoint, ignored_reason);

        if (!peer_result)
        {
            return std::unexpected(peer_result.error());
        }

        if (*peer_result == nullptr)
        {
            return make_ignored_result(kind, ignored_reason);
        }

        auto& peer = **peer_result;
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
        WEBRTC_LOG_TRACE("srtp outbound packet protected remote={} kind={} plain_size={} protected_size={} packets={}",
                         remote_endpoint,
                         srtp_packet_kind_to_string(kind),
                         plain_packet.size(),
                         packet.size(),
                         peer.outbound_packet_count);

        return make_protected_result(kind, std::move(packet));
    }

    std::expected<bool, std::string> ensure_sessions_ready_locked(srtp_peer_state& peer,
                                                                  std::string_view remote_endpoint,
                                                                  const dtls_peer_identity& identity)
    {
        const bool identity_matches = peer_identity_matches(peer, identity);

        if (peer.inbound_session.has_value() && peer.outbound_session.has_value() && identity_matches)
        {
            return true;
        }

        if (!peer.session_id.empty() && !identity_matches)
        {
            WEBRTC_LOG_INFO(
                "srtp ice generation changed reset sessions remote={} old_session={} new_session={} old_local_ufrag={} new_local_ufrag={} "
                "old_remote_ufrag={} new_remote_ufrag={}",
                remote_endpoint,
                peer.session_id,
                identity.session_id,
                peer.local_ice_ufrag,
                identity.local_ice_ufrag,
                peer.remote_ice_ufrag,
                identity.remote_ice_ufrag);

            reset_peer_for_identity(peer, identity);
        }
        else if (peer.session_id.empty())
        {
            bind_peer_identity(peer, identity);
        }

        auto material = dtls_transport_->get_srtp_keying_material(remote_endpoint, identity);

        if (!material.has_value())
        {
            return false;
        }

        auto inbound = make_inbound_srtp_session(*material);

        if (!inbound)
        {
            return std::unexpected(inbound.error());
        }

        auto outbound = make_outbound_srtp_session(*material);

        if (!outbound)
        {
            return std::unexpected(outbound.error());
        }

        peer.inbound_session.emplace(std::move(*inbound));

        peer.outbound_session.emplace(std::move(*outbound));

        WEBRTC_LOG_INFO(
            "srtp sessions created remote={} session={} stream={} profile={} local_ufrag={} remote_ufrag={} inbound={} outbound={}",
            remote_endpoint,
            peer.session_id,
            peer.stream_id,
            srtp_profile_id_to_string(material->profile),
            peer.local_ice_ufrag,
            peer.remote_ice_ufrag,
            srtp_direction_to_string(srtp_direction::inbound),
            srtp_direction_to_string(srtp_direction::outbound));

        return true;
    }
    std::shared_ptr<dtls_transport> dtls_transport_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, srtp_peer_state> peers_by_endpoint_;
};

srtp_transport::srtp_transport(std::shared_ptr<dtls_transport> dtls_transport) : impl_(std::make_unique<impl>(std::move(dtls_transport))) {}

srtp_transport::~srtp_transport() = default;

void srtp_transport::forget_peer(std::string_view remote_endpoint)
{
    impl_->forget_peer(remote_endpoint);
}

srtp_peer_rebind_result srtp_transport::rebind_peer(std::string_view previous_remote_endpoint,
                                                     std::string_view next_remote_endpoint,
                                                     const dtls_peer_identity& identity)
{
    return impl_->rebind_peer(previous_remote_endpoint, next_remote_endpoint, identity);
}

srtp_peer_ready_result srtp_transport::peer_ready(std::string_view remote_endpoint)
{
    return impl_->peer_ready(remote_endpoint);
}

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
