#include "session/publisher_session.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

#include "ice/ice_candidate.h"
#include "util/timestamp.h"

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_remote_ice_candidates = 256;

uint64_t now_milliseconds() { return static_cast<uint64_t>(timestamp::now().milliseconds()); }

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool remote_ice_candidates_equal(const remote_ice_candidate& left, const remote_ice_candidate& right)
{
    return left.candidate == right.candidate && left.sdp_mid == right.sdp_mid && left.sdp_mline_index == right.sdp_mline_index &&
           left.end_of_candidates == right.end_of_candidates;
}

bool contains_remote_ice_candidate(const std::vector<remote_ice_candidate>& candidates, const remote_ice_candidate& candidate)
{
    for (const auto& current : candidates)
    {
        if (remote_ice_candidates_equal(current, candidate))
        {
            return true;
        }
    }

    return false;
}

std::size_t count_remote_ice_candidates(const std::vector<remote_ice_candidate>& candidates)
{
    std::size_t count = 0;

    for (const auto& candidate : candidates)
    {
        if (!candidate.end_of_candidates)
        {
            count += 1;
        }
    }

    return count;
}
}    // namespace

publisher_session::publisher_session(std::string session_id,
                                     std::string stream_id,
                                     std::string remote_sdp_offer,
                                     sdp::webrtc_offer_summary remote_offer_summary,
                                     uint64_t created_at_milliseconds)
    : session_id_(std::move(session_id)),
      stream_id_(std::move(stream_id)),
      remote_sdp_offer_(std::move(remote_sdp_offer)),
      remote_offer_summary_(std::move(remote_offer_summary)),
      state_(session_state::sdp_received),
      created_at_milliseconds_(created_at_milliseconds),
      updated_at_milliseconds_(created_at_milliseconds)
{
}

const std::string& publisher_session::session_id() const { return session_id_; }

const std::string& publisher_session::stream_id() const { return stream_id_; }

const std::string& publisher_session::remote_sdp_offer() const { return remote_sdp_offer_; }

const sdp::webrtc_offer_summary& publisher_session::remote_offer_summary() const { return remote_offer_summary_; }

const std::string& publisher_session::local_sdp_answer() const { return local_sdp_answer_; }

const ice_credentials& publisher_session::local_ice() const { return local_ice_; }

const sdp::fingerprint_info& publisher_session::local_fingerprint() const { return local_fingerprint_; }

uint64_t publisher_session::sdp_session_id() const { return sdp_session_id_; }

uint64_t publisher_session::sdp_session_version() const { return sdp_session_version_; }

const std::vector<remote_ice_candidate>& publisher_session::remote_ice_candidates() const { return remote_ice_candidates_; }

bool publisher_session::remote_ice_completed() const { return remote_ice_completed_; }

const std::vector<int>& publisher_session::accepted_remote_media_mline_indexes() const { return accepted_remote_media_mline_indexes_; }

session_state publisher_session::state() const { return state_; }

std::string publisher_session::state_string() const { return std::string(session_state_to_string(state_)); }

uint64_t publisher_session::created_at_milliseconds() const { return created_at_milliseconds_; }

uint64_t publisher_session::updated_at_milliseconds() const { return updated_at_milliseconds_; }

void publisher_session::set_state(session_state state)
{
    state_ = state;
    updated_at_milliseconds_ = now_milliseconds();
}

void publisher_session::set_local_sdp_answer(std::string local_sdp_answer)
{
    local_sdp_answer_ = std::move(local_sdp_answer);

    state_ = session_state::sdp_answered;

    updated_at_milliseconds_ = now_milliseconds();
}

void publisher_session::set_local_answer(std::string local_sdp_answer,
                                         ice_credentials local_ice,
                                         sdp::fingerprint_info local_fingerprint,
                                         uint64_t sdp_session_id,
                                         uint64_t sdp_session_version)
{
    local_sdp_answer_ = std::move(local_sdp_answer);

    local_ice_ = std::move(local_ice);

    local_fingerprint_ = std::move(local_fingerprint);

    sdp_session_id_ = sdp_session_id;

    sdp_session_version_ = sdp_session_version;

    state_ = session_state::sdp_answered;

    updated_at_milliseconds_ = now_milliseconds();
}
void publisher_session::set_accepted_remote_media_mline_indexes(std::vector<int> accepted_remote_media_mline_indexes)
{
    accepted_remote_media_mline_indexes_ = std::move(accepted_remote_media_mline_indexes);

    updated_at_milliseconds_ = now_milliseconds();
}

std::expected<void, std::string> publisher_session::add_remote_ice_candidate(remote_ice_candidate candidate)
{
    if (contains_remote_ice_candidate(remote_ice_candidates_, candidate))
    {
        return {};
    }

    if (candidate.end_of_candidates)
    {
        if (remote_ice_completed_)
        {
            return {};
        }

        remote_ice_completed_ = true;

        remote_ice_candidates_.push_back(std::move(candidate));

        updated_at_milliseconds_ = now_milliseconds();

        return {};
    }

    if (remote_ice_completed_)
    {
        return make_error("remote ice candidates already completed");
    }

    const std::size_t candidate_count = count_remote_ice_candidates(remote_ice_candidates_);

    if (candidate_count >= k_max_remote_ice_candidates)
    {
        return make_error("too many remote ice candidates");
    }

    remote_ice_candidates_.push_back(std::move(candidate));

    updated_at_milliseconds_ = now_milliseconds();

    return {};
}
}    // namespace webrtc
