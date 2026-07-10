#ifndef SIMPLE_WEBRTC_UTIL_NUMBER_PARSE_H
#define SIMPLE_WEBRTC_UTIL_NUMBER_PARSE_H

#include <concepts>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

#include <boost/charconv/from_chars.hpp>

namespace webrtc
{
namespace detail
{
inline std::string make_number_parse_error(std::string_view field_name, std::string_view message)
{
    std::string error;

    error.reserve(field_name.size() + message.size() + 2);

    if (!field_name.empty())
    {
        error.append(field_name);
        error.append(": ");
    }

    error.append(message);

    return error;
}
}    // namespace detail

template <std::integral Integer>
    requires(!std::same_as<std::remove_cv_t<Integer>, bool>)
[[nodiscard]] std::expected<Integer, std::string> parse_integer(std::string_view text,
                                                                Integer minimum,
                                                                Integer maximum,
                                                                std::string_view field_name = {})
{
    if (minimum > maximum)
    {
        return std::unexpected(detail::make_number_parse_error(field_name, "integer range is invalid"));
    }

    if (text.empty())
    {
        return std::unexpected(detail::make_number_parse_error(field_name, "value is empty"));
    }

    Integer value{};

    const char* first = text.data();
    const char* last = text.data() + text.size();

    const auto result = boost::charconv::from_chars(first, last, value, 10);

    if (result.ec == std::errc::invalid_argument)
    {
        return std::unexpected(detail::make_number_parse_error(field_name, "value is not a valid base-10 integer"));
    }

    if (result.ec == std::errc::result_out_of_range)
    {
        return std::unexpected(detail::make_number_parse_error(field_name, "value is outside the integer type range"));
    }

    if (result.ec != std::errc{})
    {
        return std::unexpected(detail::make_number_parse_error(field_name, "integer conversion failed"));
    }

    if (result.ptr != last)
    {
        return std::unexpected(detail::make_number_parse_error(field_name, "value contains trailing characters"));
    }

    if (value < minimum || value > maximum)
    {
        return std::unexpected(detail::make_number_parse_error(field_name, "value is outside the allowed range"));
    }

    return value;
}
}    // namespace webrtc

#endif
