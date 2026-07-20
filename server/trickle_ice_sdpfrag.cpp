#include "server/trickle_ice_sdpfrag.h"

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

#include <boost/algorithm/string.hpp>

namespace webrtc
{
namespace
{
std::string make_sdpfrag_error(std::size_t line_number, std::string_view message)
{
    std::string error;
    error.reserve(message.size() + 64);
    error.append("trickle ice sdpfrag line ");
    error.append(std::to_string(line_number));
    error.push_back(' ');
    error.append(message);
    return error;
}

std::expected<void, std::string> set_attribute_once(std::string& target, std::string_view value, std::string_view name, std::size_t line_number)
{
    const std::string trimmed_value = boost::algorithm::trim_copy(std::string(value));
    if (trimmed_value.empty())
    {
        return std::unexpected(make_sdpfrag_error(line_number, std::string(name) + " is empty"));
    }

    if (!target.empty() && target != trimmed_value)
    {
        return std::unexpected(make_sdpfrag_error(line_number, std::string(name) + " is duplicated with different value"));
    }

    target = trimmed_value;
    return {};
}

std::expected<remote_ice_candidate, std::string> parse_candidate(std::string_view line,
                                                                 std::string_view mid,
                                                                 int mline_index,
                                                                 std::size_t line_number)
{
    if (mid.empty())
    {
        return std::unexpected(make_sdpfrag_error(line_number, "candidate mid is missing"));
    }

    if (line.starts_with("a="))
    {
        line.remove_prefix(2);
    }

    auto candidate = make_remote_ice_candidate(line, mid, mline_index);
    if (!candidate)
    {
        return std::unexpected(make_sdpfrag_error(line_number, "candidate is invalid: ") + candidate.error());
    }

    return candidate;
}

std::expected<remote_ice_candidate, std::string> parse_end_of_candidates(std::string_view mid, int mline_index, std::size_t line_number)
{
    if (mid.empty())
    {
        return std::unexpected(make_sdpfrag_error(line_number, "end-of-candidates mid is missing"));
    }

    auto candidate = make_remote_ice_candidate("", mid, mline_index);
    if (!candidate)
    {
        return std::unexpected(make_sdpfrag_error(line_number, "end-of-candidates is invalid: ") + candidate.error());
    }

    return candidate;
}

struct sdpfrag_parser
{
    std::expected<void, std::string> parse_line(std::string_view input, std::size_t line_number)
    {
        const std::string line = boost::algorithm::trim_copy(std::string(input));
        if (line.empty())
        {
            return {};
        }

        if (line.starts_with("m="))
        {
            current_mline_index = next_mline_index++;
            current_mid.clear();
            return {};
        }

        if (line.starts_with("a=mid:"))
        {
            current_mid = boost::algorithm::trim_copy(line.substr(6));
            if (current_mid.empty())
            {
                return std::unexpected(make_sdpfrag_error(line_number, "mid is empty"));
            }
            return {};
        }

        if (line.starts_with("a=ice-ufrag:"))
        {
            return set_attribute_once(result.ice_ufrag, std::string_view(line).substr(12), "ice-ufrag", line_number);
        }

        if (line.starts_with("a=ice-pwd:"))
        {
            return set_attribute_once(result.ice_pwd, std::string_view(line).substr(10), "ice-pwd", line_number);
        }

        if (line.starts_with("a=candidate:") || line.starts_with("candidate:"))
        {
            auto candidate = parse_candidate(line, current_mid, current_mline_index, line_number);
            if (!candidate)
            {
                return std::unexpected(candidate.error());
            }
            result.candidates.push_back(std::move(*candidate));
            return {};
        }

        if (line == "a=end-of-candidates" || line == "end-of-candidates")
        {
            auto candidate = parse_end_of_candidates(current_mid, current_mline_index, line_number);
            if (!candidate)
            {
                return std::unexpected(candidate.error());
            }
            result.candidates.push_back(std::move(*candidate));
        }

        return {};
    }

    trickle_ice_sdpfrag_parse_result result;
    std::string current_mid;
    int current_mline_index = 0;
    int next_mline_index = 0;
};
}    // namespace

trickle_ice_sdpfrag_parse_result_type parse_trickle_ice_sdpfrag(std::string_view body)
{
    if (body.empty())
    {
        return std::unexpected(std::string("empty trickle ice sdpfrag"));
    }

    sdpfrag_parser parser;
    std::size_t line_number = 0;
    std::size_t offset = 0;

    while (offset <= body.size())
    {
        const std::size_t line_end = body.find('\n', offset);
        const std::string_view line = line_end == std::string_view::npos ? body.substr(offset) : body.substr(offset, line_end - offset);
        ++line_number;

        auto line_result = parser.parse_line(line, line_number);
        if (!line_result)
        {
            return std::unexpected(line_result.error());
        }

        if (line_end == std::string_view::npos)
        {
            break;
        }
        offset = line_end + 1;
    }

    if (parser.result.candidates.empty())
    {
        return std::unexpected(std::string("trickle ice sdpfrag has no candidates"));
    }

    if (parser.result.ice_ufrag.empty() != parser.result.ice_pwd.empty())
    {
        return std::unexpected(std::string("trickle ice sdpfrag must include both ice-ufrag and ice-pwd when either is present"));
    }

    return std::move(parser.result);
}
}    // namespace webrtc
