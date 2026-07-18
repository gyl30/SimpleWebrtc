#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "net/http.h"
#include "session/session_state.h"

namespace webrtc
{
inline constexpr std::string_view k_trickle_ice_patch_accept_patch_value = "application/sdp, application/trickle-ice-sdpfrag, application/json";

inline constexpr std::string_view k_session_resource_state_header = "X-Session-Resource-State";
inline constexpr std::string_view k_session_resource_updated_at_header = "X-Session-Resource-Updated-At";
inline constexpr std::string_view k_session_resource_ice_completed_header = "X-Session-Resource-Ice-Completed";
inline constexpr std::string_view k_session_resource_candidate_count_header = "X-Session-Resource-Candidate-Count";

inline constexpr std::string_view k_trickle_ice_expose_headers_value =
    "Location, ETag, Link, Accept-Patch, X-Session-Resource-State, X-Session-Resource-Updated-At, X-Session-Resource-Ice-Completed, "
    "X-Session-Resource-Candidate-Count";

inline constexpr std::string_view k_ice_server_urls_env_name = "WEBRTC_ICE_SERVER_URLS";
inline constexpr std::string_view k_ice_server_username_env_name = "WEBRTC_ICE_SERVER_USERNAME";
inline constexpr std::string_view k_ice_server_credential_env_name = "WEBRTC_ICE_SERVER_CREDENTIAL";

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

inline uint64_t fnv1a_append_separator(uint64_t hash) { return fnv1a_append(hash, "|"); }

inline uint64_t fnv1a_append_uint64(uint64_t hash, uint64_t value) { return fnv1a_append(hash, std::to_string(value)); }

inline uint64_t fnv1a_append_string(uint64_t hash, std::string_view value) { return fnv1a_append(hash, value); }

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

inline std::string get_env_string(std::string_view name)
{
    std::string env_name(name);

    const char* value = std::getenv(env_name.c_str());

    if (value == nullptr || value[0] == '\0')
    {
        return {};
    }

    return value;
}

inline bool contains_header_unsafe_character(std::string_view value)
{
    for (const char ch : value)
    {
        if (ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

inline bool is_configured_ice_server_url(std::string_view url)
{
    return url.starts_with("stun:") || url.starts_with("stuns:") || url.starts_with("turn:") || url.starts_with("turns:");
}

inline std::vector<std::string> split_configured_ice_server_urls(std::string_view value)
{
    std::vector<std::string> urls;

    std::size_t offset = 0;

    while (offset <= value.size())
    {
        const std::size_t separator = value.find_first_of(", \t\r\n", offset);

        std::string_view item;

        if (separator == std::string_view::npos)
        {
            item = value.substr(offset);

            offset = value.size() + 1;
        }
        else
        {
            item = value.substr(offset, separator - offset);

            offset = separator + 1;
        }

        item = trim_ascii(item);

        if (item.empty())
        {
            continue;
        }

        if (contains_header_unsafe_character(item))
        {
            continue;
        }

        if (!is_configured_ice_server_url(item))
        {
            continue;
        }

        urls.emplace_back(item);
    }

    return urls;
}

inline void append_link_quoted_parameter(std::string& output, std::string_view name, std::string_view value)
{
    if (name.empty() || value.empty())
    {
        return;
    }

    if (contains_header_unsafe_character(value))
    {
        return;
    }

    output.append("; ");

    output.append(name);

    output.append("=\"");

    for (const char ch : value)
    {
        if (ch == '"' || ch == '\\')
        {
            output.push_back('\\');
        }

        output.push_back(ch);
    }

    output.push_back('"');
}

inline std::string make_configured_ice_server_link_header()
{
    const std::string urls_value = get_env_string(k_ice_server_urls_env_name);

    if (urls_value.empty())
    {
        return {};
    }

    const std::vector<std::string> urls = split_configured_ice_server_urls(urls_value);

    if (urls.empty())
    {
        return {};
    }

    const std::string username = get_env_string(k_ice_server_username_env_name);

    const std::string credential = get_env_string(k_ice_server_credential_env_name);

    std::string header;

    for (const auto& url : urls)
    {
        if (!header.empty())
        {
            header.append(", ");
        }

        header.push_back('<');

        header.append(url);

        header.append(">; rel=\"ice-server\"");

        if (!username.empty() && !credential.empty())
        {
            append_link_quoted_parameter(header, "username", username);

            append_link_quoted_parameter(header, "credential", credential);
        }
    }

    return header;
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

    /*
     * ETag represents the HTTP session resource version, not transient transport
     * runtime state.
     *
     * Do not include:
     *   - session state
     *   - session.updated_at_milliseconds()
     *   - ICE selected pair / DTLS / SRTP / media runtime state
     *
     */
    hash = trickle_ice_http_detail::fnv1a_append_string(hash, trickle_ice_http_detail::string_like_view(session.session_id()));

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_string(hash, trickle_ice_http_detail::string_like_view(session.stream_id()));

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_uint64(hash, session.created_at_milliseconds());

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_string(hash, trickle_ice_http_detail::string_like_view(session.local_ice().ufrag));

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_string(hash, trickle_ice_http_detail::string_like_view(session.remote_offer_summary().ice_ufrag));

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_uint64(hash, session.sdp_session_id());

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_uint64(hash, session.sdp_session_version());

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_uint64(hash, static_cast<uint64_t>(session.remote_ice_candidates().size()));

    hash = trickle_ice_http_detail::fnv1a_append_separator(hash);

    hash = trickle_ice_http_detail::fnv1a_append_string(hash, session.remote_ice_completed() ? "completed" : "open");

    std::ostringstream output;

    output << "\"swrtc-" << std::hex << hash << "-" << std::dec << session.created_at_milliseconds() << "-" << session.remote_ice_candidates().size()
           << "-" << (session.remote_ice_completed() ? 1 : 0) << "\"";

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

    const std::string ice_server_link_header = trickle_ice_http_detail::make_configured_ice_server_link_header();

    if (!ice_server_link_header.empty())
    {
        response->set("Link", ice_server_link_header);
    }

    response->set(std::string(k_session_resource_state_header), std::string(session_state_to_string(session.state())));

    response->set(std::string(k_session_resource_updated_at_header), std::to_string(session.updated_at_milliseconds()));

    response->set(std::string(k_session_resource_ice_completed_header), session.remote_ice_completed() ? "1" : "0");

    response->set(std::string(k_session_resource_candidate_count_header), std::to_string(session.remote_ice_candidates().size()));
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
        std::string message = "if-match does not match current session etag current=";

        message.append(current_etag);

        return std::unexpected(std::move(message));
    }

    return {};
}
}    // namespace webrtc

#endif
