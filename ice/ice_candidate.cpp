#include "ice/ice_candidate.h"

#include <cctype>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_candidate_size = 4096;
constexpr std::size_t k_max_sdp_mid_size = 128;
constexpr int k_max_sdp_mline_index = 1024;

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool contains_line_break(std::string_view value)
{
    for (const auto ch : value)
    {
        if (ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

bool contains_whitespace(std::string_view value)
{
    for (const auto ch : value)
    {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

std::string_view trim_left(std::string_view value)
{
    const auto position = value.find_first_not_of(" \t");
    if (position == std::string_view::npos)
    {
        return {};
    }

    return value.substr(position);
}

std::string_view trim_right(std::string_view value)
{
    const auto position = value.find_last_not_of(" \t");
    if (position == std::string_view::npos)
    {
        return {};
    }

    return value.substr(0, position + 1);
}

std::string_view trim(std::string_view value) { return trim_right(trim_left(value)); }

bool is_end_of_candidates_text(std::string_view candidate)
{
    return candidate.empty() || candidate == "end-of-candidates" || candidate == "a=end-of-candidates";
}

std::expected<std::string, std::string> normalize_candidate_text(std::string_view candidate)
{
    if (candidate.size() > k_max_candidate_size)
    {
        return make_error("ice candidate is too large");
    }

    if (contains_line_break(candidate))
    {
        return make_error("ice candidate must not contain line breaks");
    }

    candidate = trim(candidate);

    if (is_end_of_candidates_text(candidate))
    {
        return std::string();
    }

    if (candidate.starts_with("a=candidate:"))
    {
        candidate.remove_prefix(2);
    }

    if (!candidate.starts_with("candidate:"))
    {
        return make_error("ice candidate must start with candidate:");
    }

    return std::string(candidate);
}

std::expected<std::string, std::string> normalize_sdp_mid(std::string_view sdp_mid)
{
    if (sdp_mid.size() > k_max_sdp_mid_size)
    {
        return make_error("sdpMid is too large");
    }

    if (contains_whitespace(sdp_mid))
    {
        return make_error("sdpMid must not contain whitespace");
    }

    return std::string(sdp_mid);
}

std::expected<void, std::string> validate_sdp_mline_index(int sdp_mline_index)
{
    if (sdp_mline_index < -1)
    {
        return make_error("sdpMLineIndex is invalid");
    }

    if (sdp_mline_index > k_max_sdp_mline_index)
    {
        return make_error("sdpMLineIndex is too large");
    }

    return {};
}
}    // namespace

remote_ice_candidate_result make_remote_ice_candidate(std::string_view candidate,
                                                      std::string_view sdp_mid,
                                                      int sdp_mline_index,
                                                      uint64_t received_at_milliseconds)
{
    auto normalized_candidate = normalize_candidate_text(candidate);

    if (!normalized_candidate)
    {
        return std::unexpected(normalized_candidate.error());
    }

    auto normalized_sdp_mid = normalize_sdp_mid(sdp_mid);

    if (!normalized_sdp_mid)
    {
        return std::unexpected(normalized_sdp_mid.error());
    }

    auto mline_index_result = validate_sdp_mline_index(sdp_mline_index);

    if (!mline_index_result)
    {
        return std::unexpected(mline_index_result.error());
    }

    if (normalized_sdp_mid->empty() && sdp_mline_index < 0)
    {
        return make_error("sdpMid or sdpMLineIndex is required");
    }

    remote_ice_candidate value;
    value.candidate = std::move(*normalized_candidate);
    value.sdp_mid = std::move(*normalized_sdp_mid);
    value.sdp_mline_index = sdp_mline_index;
    value.received_at_milliseconds = received_at_milliseconds;
    value.end_of_candidates = value.candidate.empty();

    return value;
}
}    // namespace webrtc
