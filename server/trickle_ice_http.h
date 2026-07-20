#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H

#include <cstddef>
#include <cstdlib>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "net/http.h"

namespace webrtc
{
inline constexpr std::string_view k_trickle_ice_patch_accept_patch_value = "application/trickle-ice-sdpfrag";

inline constexpr std::string_view k_trickle_ice_expose_headers_value = "Location, ETag, Link, Accept-Patch";

inline constexpr std::size_t k_trickle_ice_max_patch_body_bytes = 64L * 1024;
inline constexpr std::size_t k_trickle_ice_max_candidates_per_patch = 32;

namespace trickle_ice_http_detail
{
inline std::string get_env_string(const char* name)
{
    const char* value = std::getenv(name);

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
    std::vector<std::string_view> items;
    boost::algorithm::split(items,
                            value,
                            boost::algorithm::is_any_of(", \t\r\n"),
                            boost::algorithm::token_compress_on);

    for (std::string_view item : items)
    {
        item = boost::algorithm::trim_copy(item);

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
    const std::string urls_value = get_env_string("WEBRTC_ICE_SERVER_URLS");

    if (urls_value.empty())
    {
        return {};
    }

    const std::vector<std::string> urls = split_configured_ice_server_urls(urls_value);

    if (urls.empty())
    {
        return {};
    }

    const std::string username = get_env_string("WEBRTC_ICE_SERVER_USERNAME");

    const std::string credential = get_env_string("WEBRTC_ICE_SERVER_CREDENTIAL");

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

inline const std::string k_configured_ice_server_link_header = make_configured_ice_server_link_header();

}    // namespace trickle_ice_http_detail

inline void set_trickle_ice_patch_headers(const http_response_ptr& response)
{
    response->set("Accept-Patch", std::string(k_trickle_ice_patch_accept_patch_value));
}

template <typename session_type>
[[nodiscard]]
std::string make_session_resource_etag(const session_type& session)
{
    std::string etag;
    etag.reserve(session.session_id().size() + 2);
    etag.push_back('"');
    etag.append(session.session_id());
    etag.push_back('"');
    return etag;
}
template <typename session_type>
void set_session_resource_headers(const http_response_ptr& response, const session_type& session)
{
    set_trickle_ice_patch_headers(response);

    response->set(boost::beast::http::field::etag, make_session_resource_etag(session));

    if (!trickle_ice_http_detail::k_configured_ice_server_link_header.empty())
    {
        response->set("Link", trickle_ice_http_detail::k_configured_ice_server_link_header);
    }
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

    if (boost::algorithm::trim_copy(if_match) != current_etag)
    {
        std::string message = "if-match does not match current session etag current=";

        message.append(current_etag);

        return std::unexpected(std::move(message));
    }

    return {};
}
}    // namespace webrtc

#endif
