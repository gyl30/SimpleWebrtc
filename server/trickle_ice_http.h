#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_HTTP_H

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>

#include <boost/algorithm/string.hpp>

#include "net/http.h"

namespace webrtc
{
inline constexpr std::string_view k_trickle_ice_patch_accept_patch_value = "application/trickle-ice-sdpfrag";

inline constexpr std::string_view k_trickle_ice_expose_headers_value = "Location, ETag, Link, Accept-Patch";

inline constexpr std::size_t k_trickle_ice_max_patch_body_bytes = 64L * 1024;
inline constexpr std::size_t k_trickle_ice_max_candidates_per_patch = 32;

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
void set_session_resource_headers(const http_response_ptr& response, const session_type& session, std::string_view ice_server_link_header)
{
    set_trickle_ice_patch_headers(response);

    response->set(boost::beast::http::field::etag, make_session_resource_etag(session));

    if (!ice_server_link_header.empty())
    {
        response->set("Link", std::string(ice_server_link_header));
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
