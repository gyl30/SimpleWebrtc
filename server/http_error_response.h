#ifndef SIMPLE_WEBRTC_SERVER_HTTP_ERROR_RESPONSE_H
#define SIMPLE_WEBRTC_SERVER_HTTP_ERROR_RESPONSE_H

#include <string>
#include <string_view>

#include <boost/beast/http.hpp>

#include "net/http.h"
#include "util/reflect.h"
#include "server/trickle_ice_http.h"

namespace webrtc
{
inline constexpr std::string_view k_http_json_content_type = "application/json; charset=utf-8";
inline constexpr std::string_view k_http_text_content_type = "text/plain; charset=utf-8";
inline constexpr std::string_view k_http_sdp_content_type = "application/sdp";
inline constexpr std::string_view k_http_cache_control_no_store = "no-store";
inline constexpr std::string_view k_http_cors_private_network_header = "Access-Control-Allow-Private-Network";

namespace http_error_response_detail
{
inline void append_json_escaped_string(std::string& output, std::string_view value)
{
    for (const char ch : value)
    {
        switch (ch)
        {
            case '"':
                output.append("\\\"");

                break;

            case '\\':
                output.append("\\\\");

                break;

            case '\b':
                output.append("\\b");

                break;

            case '\f':
                output.append("\\f");

                break;

            case '\n':
                output.append("\\n");

                break;

            case '\r':
                output.append("\\r");

                break;

            case '\t':
                output.append("\\t");

                break;

            default:
                if (static_cast<unsigned char>(ch) < 0x20U)
                {
                    output.append("\\u00");

                    constexpr char k_hex_digits[] = "0123456789abcdef";

                    const auto value_byte = static_cast<unsigned char>(ch);

                    output.push_back(k_hex_digits[(value_byte >> 4U) & 0x0FU]);

                    output.push_back(k_hex_digits[value_byte & 0x0FU]);

                    break;
                }

                output.push_back(ch);

                break;
        }
    }
}

inline std::string normalize_error_code(std::string_view error_code)
{
    if (!error_code.empty())
    {
        return std::string(error_code);
    }

    return "error";
}

inline void append_trailing_newline(std::string& content)
{
    if (content.empty() || content.back() != '\n')
    {
        content.push_back('\n');
    }
}
}    // namespace http_error_response_detail

struct http_error_response_body
{
    std::string error;
    std::string code;
};

REFLECT_STRUCT(webrtc::http_error_response_body, (error)(code));    // NOLINT

inline std::string make_http_error_response_body(std::string_view error_code, std::string_view message)
{
    http_error_response_body response;

    response.error = std::string(message);

    response.code = http_error_response_detail::normalize_error_code(error_code);

    return serialize_struct(response);
}

inline std::string make_http_error_response_body(std::string_view message) { return make_http_error_response_body("error", message); }

inline void add_http_common_headers(const http_response_ptr& response)
{
    if (response == nullptr)
    {
        return;
    }

    response->set(boost::beast::http::field::access_control_allow_origin, "*");

    response->set(boost::beast::http::field::access_control_expose_headers, std::string(k_trickle_ice_expose_headers_value));

    response->set(std::string(k_http_cors_private_network_header), "true");

    response->set(boost::beast::http::field::cache_control, std::string(k_http_cache_control_no_store));

    set_trickle_ice_patch_headers(response);
}

inline http_response_ptr make_json_http_response(http_request_t& request, int status_code, std::string_view body)
{
    std::string content(body);

    http_error_response_detail::append_trailing_newline(content);

    auto response = create_response(request, status_code, content);

    response->set(boost::beast::http::field::content_type, std::string(k_http_json_content_type));

    add_http_common_headers(response);

    return response;
}

inline http_response_ptr make_json_http_error_response(http_request_t& request,
                                                       int status_code,
                                                       std::string_view error_code,
                                                       std::string_view message)
{
    return make_json_http_response(request, status_code, make_http_error_response_body(error_code, message));
}

inline http_response_ptr make_json_http_error_response(http_request_t& request, int status_code, std::string_view message)
{
    return make_json_http_error_response(request, status_code, "error", message);
}

inline http_response_ptr make_text_http_response(http_request_t& request, int status_code, std::string_view body)
{
    std::string content(body);

    http_error_response_detail::append_trailing_newline(content);

    auto response = create_response(request, status_code, content);

    response->set(boost::beast::http::field::content_type, std::string(k_http_text_content_type));

    add_http_common_headers(response);

    return response;
}

inline http_response_ptr make_sdp_http_response(http_request_t& request, int status_code, std::string_view body)
{
    std::string content(body);

    auto response = create_response(request, status_code, content);

    response->set(boost::beast::http::field::content_type, std::string(k_http_sdp_content_type));

    add_http_common_headers(response);

    return response;
}
}    // namespace webrtc

#endif
