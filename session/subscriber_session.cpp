#include "session/subscriber_session.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

#include "log/log.h"
#include "session/peer_transport.h"
#include "util/timestamp.h"
#include "ice/ice_candidate.h"

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_remote_ice_candidates = 256;

uint64_t now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

}    // namespace

subscriber_session::subscriber_session(std::string session_id,
                                       std::string stream_id,
                                       sdp::webrtc_offer_summary remote_offer_summary,
                                       uint64_t created_at_milliseconds)
    : session_id_(std::move(session_id)),
      stream_id_(std::move(stream_id)),
      remote_offer_summary_(std::move(remote_offer_summary)),
      created_at_milliseconds_(created_at_milliseconds),
      updated_at_milliseconds_(created_at_milliseconds)
{
}

const std::string& subscriber_session::session_id() const { return session_id_; }

const std::string& subscriber_session::stream_id() const { return stream_id_; }

const sdp::webrtc_offer_summary& subscriber_session::remote_offer_summary() const { return remote_offer_summary_; }

const ice_credentials& subscriber_session::local_ice() const { return local_ice_; }

uint16_t subscriber_session::local_udp_port() const { return local_udp_port_->port(); }

uint64_t subscriber_session::sdp_session_id() const { return sdp_session_id_; }

uint64_t subscriber_session::sdp_session_version() const { return sdp_session_version_; }

const std::vector<remote_ice_candidate>& subscriber_session::remote_ice_candidates() const { return remote_ice_candidates_; }

bool subscriber_session::remote_ice_completed() const
{
    return !remote_ice_candidates_.empty() && remote_ice_candidates_.back().end_of_candidates;
}
const std::vector<int>& subscriber_session::accepted_remote_media_mline_indexes() const { return accepted_remote_media_mline_indexes_; }

const std::vector<sdp::sdp_answer_media_source>& subscriber_session::outbound_media_sources() const { return outbound_media_sources_; }

uint64_t subscriber_session::created_at_milliseconds() const { return created_at_milliseconds_; }

uint64_t subscriber_session::updated_at_milliseconds() const { return updated_at_milliseconds_; }

void subscriber_session::complete_initial_setup(ice_credentials local_ice,
                                                uint64_t sdp_session_id,
                                                uint64_t sdp_session_version,
                                                std::vector<int> accepted_remote_media_mline_indexes,
                                                std::vector<sdp::sdp_answer_media_source> outbound_media_sources,
                                                udp_port_reservation_ptr local_udp_port,
                                                std::shared_ptr<whep_session_transport> transport)
{
    local_ice_ = std::move(local_ice);
    sdp_session_id_ = sdp_session_id;
    sdp_session_version_ = sdp_session_version;
    accepted_remote_media_mline_indexes_ = std::move(accepted_remote_media_mline_indexes);
    outbound_media_sources_ = std::move(outbound_media_sources);
    local_udp_port_ = std::move(local_udp_port);

    transport->set_peer_context(local_ice_.pwd, make_dtls_peer_identity(*this));
    transport_ = std::move(transport);

    updated_at_milliseconds_ = now_milliseconds();
}

void subscriber_session::apply_remote_ice_restart(sdp::webrtc_offer_summary remote_offer_summary,
                                                  std::vector<int> accepted_remote_media_mline_indexes,
                                                  ice_credentials local_ice,
                                                  uint64_t sdp_session_id,
                                                  uint64_t sdp_session_version)
{
    remote_offer_summary_ = std::move(remote_offer_summary);
    remote_ice_candidates_.clear();
    accepted_remote_media_mline_indexes_ = std::move(accepted_remote_media_mline_indexes);
    local_ice_ = std::move(local_ice);
    sdp_session_id_ = sdp_session_id;
    sdp_session_version_ = sdp_session_version;

    updated_at_milliseconds_ = now_milliseconds();
}

std::expected<void, std::string> subscriber_session::add_remote_ice_candidate(remote_ice_candidate candidate)
{
    if (!candidate.end_of_candidates)
    {
        WEBRTC_LOG_INFO("subscriber remote ice candidate session={} stream={} mid={} mline={} address={} port={} hostname={} mdns={}",
                        session_id_,
                        stream_id_,
                        candidate.sdp_mid,
                        candidate.sdp_mline_index,
                        candidate.address,
                        candidate.port,
                        candidate.address_is_hostname,
                        candidate.address_is_mdns_hostname);
    }
    if (candidate.end_of_candidates)
    {
        remote_ice_candidates_.push_back(std::move(candidate));

        updated_at_milliseconds_ = now_milliseconds();

        return {};
    }

    if (remote_ice_completed())
    {
        return make_error("remote ice candidates already completed");
    }

    if (remote_ice_candidates_.size() >= k_max_remote_ice_candidates)
    {
        return make_error("too many remote ice candidates");
    }

    remote_ice_candidates_.push_back(std::move(candidate));

    updated_at_milliseconds_ = now_milliseconds();

    return {};
}
}    // namespace webrtc
