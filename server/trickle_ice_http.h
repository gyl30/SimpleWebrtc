#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <sstream>
#include <string>
#include <string_view>

#include "net/http.h"

namespace webrtc
{
inline constexpr std::string_view k_trickle_ice_patch_accept_patch_value = "application/trickle-ice-sdpfrag, application/json";

inline constexpr std::string_view k_trickle_ice_expose_headers_value = "Location, ETag, Accept-Patch";

inline constexpr std::size_t k_trickle_ice_max_patch_body_bytes = 64L * 1024;

inline constexpr std::size_t k_trickle_ice_max_candidates_per_patch = 32;

namespace trickle_ice_http_detail
{
inline uint64_t fnv1a_append(uint64_t hash, std::string_view value)
{
    constexpr uint64_t k_fnv_prime = 1099511628211ULL;

    for (char item : value)
    {
        hash ^= static_cast<unsigned char>(item);

        hash *= k_fnv_prime;
    }

    return hash;
}

inline std::string_view string_like_view(const std::string& value) { return {value.data(), value.size()}; }

inline std::string_view string_like_view(std::string_view value) { return value; }

inline std::string_view string_like_view(const char* value)
{
    if (value == nullptr)
    {
        return {};
    }

    return {value};
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

inline bool etag_list_contains(std::string_view if_match, std::string_view current_etag)
{
    std::size_t offset = 0;

    while (offset <= if_match.size())
    {
        const std::size_t comma = if_match.find(',', offset);

        std::string_view token;

        if (comma == std::string_view::npos)
        {
            token = if_match.substr(offset);

            offset = if_match.size() + 1;
        }
        else
        {
            token = if_match.substr(offset, comma - offset);

            offset = comma + 1;
        }

        token = trim_ascii(token);

        if (token == "*")
        {
            return true;
        }

        if (token == current_etag)
        {
            return true;
        }
    }

    return false;
}
}    // namespace trickle_ice_http_detail

inline void set_trickle_ice_patch_headers(const http_response_ptr& response)
{
    if (response == nullptr)
    {
        return;
    }

    response->set("Accept-Patch", std::string(k_trickle_ice_patch_accept_patch_value));
}

inline bool trickle_ice_patch_body_too_large(std::size_t body_size) { return body_size > k_trickle_ice_max_patch_body_bytes; }

inline bool trickle_ice_candidate_batch_too_large(std::size_t candidate_count) { return candidate_count > k_trickle_ice_max_candidates_per_patch; }

template <typename session_type>
[[nodiscard]]
std::string make_session_resource_etag(const session_type& session)
{
    constexpr uint64_t k_fnv_offset_basis = 1469598103934665603ULL;

    uint64_t hash = k_fnv_offset_basis;

    const auto session_id_value = session.session_id();

    const auto stream_id_value = session.stream_id();

    hash = trickle_ice_http_detail::fnv1a_append(hash, trickle_ice_http_detail::string_like_view(session_id_value));

    hash = trickle_ice_http_detail::fnv1a_append(hash, "|");

    hash = trickle_ice_http_detail::fnv1a_append(hash, trickle_ice_http_detail::string_like_view(stream_id_value));

    hash = trickle_ice_http_detail::fnv1a_append(hash, session.remote_ice_completed() ? "|completed" : "|open");

    std::ostringstream output;

    output << "\"swrtc-" << std::hex << hash << "-" << std::dec << session.remote_ice_candidates().size() << "-"
           << (session.remote_ice_completed() ? 1 : 0) << "\"";

    return output.str();
}

template <typename session_type>
void set_session_resource_headers(const http_response_ptr& response, const session_type& session)
{
    if (response == nullptr)
    {
        return;
    }

    set_trickle_ice_patch_headers(response);

    response->set(boost::beast::http::field::etag, make_session_resource_etag(session));
}

template <typename session_type>
[[nodiscard]]
std::expected<void, std::string> validate_session_if_match(http_request_t& request, const session_type& session)
{
    const auto if_match_field = request.req[boost::beast::http::field::if_match];

    const std::string_view if_match(if_match_field.data(), if_match_field.size());

    if (if_match.empty())
    {
        return std::unexpected(std::string("missing if-match header"));
    }

    const std::string current_etag = make_session_resource_etag(session);

    if (!trickle_ice_http_detail::etag_list_contains(if_match, current_etag))
    {
        return std::unexpected(std::string("if-match does not match current session etag"));
    }

    return {};
}
}    // namespace webrtc

#endif
