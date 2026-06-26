#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_SDPFRAG_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_SDPFRAG_H

#include <cctype>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "ice/ice_candidate.h"

namespace webrtc
{
using trickle_ice_sdpfrag_result = std::expected<std::vector<remote_ice_candidate>, std::string>;

namespace detail
{
inline bool starts_with(std::string_view value, std::string_view prefix)
{
    if (value.size() < prefix.size())
    {
        return false;
    }

    return value.substr(0, prefix.size()) == prefix;
}

inline std::string_view trim_ascii(std::string_view value)
{
    while (!value.empty())
    {
        const auto item = static_cast<unsigned char>(value.front());

        if (std::isspace(item) == 0)
        {
            break;
        }

        value.remove_prefix(1);
    }

    while (!value.empty())
    {
        const auto item = static_cast<unsigned char>(value.back());

        if (std::isspace(item) == 0)
        {
            break;
        }

        value.remove_suffix(1);
    }

    return value;
}

inline std::string make_sdpfrag_error(std::size_t line_number, std::string_view message)
{
    std::string error;

    error.reserve(message.size() + 64);

    error.append("trickle ice sdpfrag line ");

    error.append(std::to_string(line_number));

    error.append(" ");

    error.append(message);

    return error;
}

inline std::expected<remote_ice_candidate, std::string> make_candidate_from_sdpfrag_line(
    std::string_view candidate_line, std::string_view sdp_mid, int sdp_mline_index, uint64_t received_at_milliseconds, std::size_t line_number)
{
    if (sdp_mid.empty())
    {
        return std::unexpected(make_sdpfrag_error(line_number, "candidate mid is missing"));
    }

    std::string candidate;

    if (starts_with(candidate_line, "a="))
    {
        candidate = std::string(candidate_line.substr(2));
    }
    else
    {
        candidate = std::string(candidate_line);
    }

    auto result = make_remote_ice_candidate(candidate, sdp_mid, sdp_mline_index, received_at_milliseconds);

    if (!result)
    {
        std::string error = make_sdpfrag_error(line_number, "candidate is invalid: ");

        error.append(result.error());

        return std::unexpected(std::move(error));
    }

    return result;
}

inline std::expected<remote_ice_candidate, std::string> make_end_of_candidates_from_sdpfrag_line(std::string_view sdp_mid,
                                                                                                 int sdp_mline_index,
                                                                                                 uint64_t received_at_milliseconds,
                                                                                                 std::size_t line_number)
{
    if (sdp_mid.empty())
    {
        return std::unexpected(make_sdpfrag_error(line_number, "end-of-candidates mid is missing"));
    }

    auto result = make_remote_ice_candidate("", sdp_mid, sdp_mline_index, received_at_milliseconds);

    if (!result)
    {
        std::string error = make_sdpfrag_error(line_number, "end-of-candidates is invalid: ");

        error.append(result.error());

        return std::unexpected(std::move(error));
    }

    return result;
}
}    // namespace detail

inline trickle_ice_sdpfrag_result parse_trickle_ice_sdpfrag(std::string_view body, uint64_t received_at_milliseconds)
{
    if (body.empty())
    {
        return std::unexpected(std::string("empty trickle ice sdpfrag"));
    }

    std::vector<remote_ice_candidate> candidates;

    std::string current_mid;
    int current_mline_index = 0;
    int next_mline_index = 0;

    std::size_t line_number = 0;
    std::size_t offset = 0;

    while (offset <= body.size())
    {
        const std::size_t line_start = offset;

        const std::size_t line_end = body.find('\n', line_start);

        if (line_end == std::string_view::npos)
        {
            offset = body.size() + 1;
        }
        else
        {
            offset = line_end + 1;
        }

        std::string_view line;

        if (line_end == std::string_view::npos)
        {
            line = body.substr(line_start);
        }
        else
        {
            line = body.substr(line_start, line_end - line_start);
        }

        line_number += 1;

        line = detail::trim_ascii(line);

        if (line.empty())
        {
            continue;
        }

        if (detail::starts_with(line, "m="))
        {
            current_mline_index = next_mline_index;

            next_mline_index += 1;

            current_mid.clear();

            continue;
        }

        if (detail::starts_with(line, "a=mid:"))
        {
            current_mid = std::string(detail::trim_ascii(line.substr(6)));

            if (current_mid.empty())
            {
                return std::unexpected(detail::make_sdpfrag_error(line_number, "mid is empty"));
            }

            continue;
        }

        if (detail::starts_with(line, "a=candidate:") || detail::starts_with(line, "candidate:"))
        {
            auto candidate = detail::make_candidate_from_sdpfrag_line(line, current_mid, current_mline_index, received_at_milliseconds, line_number);

            if (!candidate)
            {
                return std::unexpected(candidate.error());
            }

            candidates.push_back(std::move(*candidate));

            continue;
        }

        if (line == "a=end-of-candidates" || line == "end-of-candidates")
        {
            auto candidate =
                detail::make_end_of_candidates_from_sdpfrag_line(current_mid, current_mline_index, received_at_milliseconds, line_number);

            if (!candidate)
            {
                return std::unexpected(candidate.error());
            }

            candidates.push_back(std::move(*candidate));

            continue;
        }
    }

    if (candidates.empty())
    {
        return std::unexpected(std::string("trickle ice sdpfrag has no candidates"));
    }

    return candidates;
}
}    // namespace webrtc

#endif
