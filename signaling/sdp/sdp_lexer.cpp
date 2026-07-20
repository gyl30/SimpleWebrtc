#include "signaling/sdp/sdp_lexer.h"

#include <charconv>
#include <string>
#include <system_error>

namespace webrtc::sdp
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message)
{
    return std::unexpected(std::string(message));
}

bool is_line_break(char ch) { return ch == '\n' || ch == '\r'; }

std::string escape_char_for_error(char ch)
{
    switch (ch)
    {
        case '\n':
            return "\\n";
        case '\r':
            return "\\r";
        case '\t':
            return "\\t";
        case '\\':
            return "\\\\";
        case '"':
            return "\\\"";
        case '\0':
            return "\\0";
        default:
            return std::string(1, ch);
    }
}
}    // namespace

sdp_lexer::sdp_lexer(std::string_view text) : text_(text) {}

bool sdp_lexer::eof() const
{
    return position_ >= text_.size();
}

void sdp_lexer::skip_line_breaks()
{
    while (!eof())
    {
        const char ch = text_[position_];

        if (ch == '\r')
        {
            ++position_;

            if (!eof() && text_[position_] == '\n')
            {
                ++position_;
            }

            continue;
        }

        if (ch == '\n')
        {
            ++position_;
            continue;
        }

        return;
    }
}

std::expected<std::string_view, std::string> sdp_lexer::read_line()
{
    const std::size_t start = position_;

    while (!eof())
    {
        const char ch = text_[position_];

        if (ch == '\n')
        {
            std::size_t end = position_;
            if (end > start && text_[end - 1] == '\r')
            {
                --end;
            }

            ++position_;
            return text_.substr(start, end - start);
        }

        if (ch == '\r')
        {
            const std::size_t end = position_;
            ++position_;

            if (!eof() && text_[position_] == '\n')
            {
                ++position_;
            }

            return text_.substr(start, end - start);
        }

        ++position_;
    }

    return text_.substr(start, position_ - start);
}

std::expected<char, std::string> sdp_lexer::read_type()
{
    while (!eof())
    {
        const char first = text_[position_];

        if (is_line_break(first))
        {
            skip_line_breaks();
            continue;
        }

        ++position_;

        if (eof())
        {
            return make_error(make_syntax_error(position_ - 1));
        }

        const char second = text_[position_];
        ++position_;

        if (second != '=')
        {
            return make_error(make_syntax_error(position_ - 1));
        }

        return first;
    }

    return make_error("unexpected end of sdp");
}

std::string sdp_lexer::make_syntax_error(std::size_t position) const
{
    if (text_.empty())
    {
        return "sdp syntax error at position 0: \"\"";
    }

    if (position >= text_.size())
    {
        position = text_.size() - 1;
    }

    std::string message;
    message.reserve(64);
    message += "sdp syntax error at position ";
    message += std::to_string(position);
    message += ": \"";
    message += escape_char_for_error(text_[position]);
    message += "\"";

    return message;
}

bool is_any_of(std::string_view value, std::initializer_list<std::string_view> candidates)
{
    for (const auto candidate : candidates)
    {
        if (value == candidate)
        {
            return true;
        }
    }

    return false;
}

std::expected<int64_t, std::string> parse_time_units(std::string_view value)
{
    if (value.empty())
    {
        return make_error("empty sdp time value");
    }

    int64_t multiplier = 1;
    std::string_view number_text = value;

    const char last = value.back();
    switch (last)
    {
        case 'd':
            multiplier = 86400;
            number_text = value.substr(0, value.size() - 1);
            break;
        case 'h':
            multiplier = 3600;
            number_text = value.substr(0, value.size() - 1);
            break;
        case 'm':
            multiplier = 60;
            number_text = value.substr(0, value.size() - 1);
            break;
        case 's':
            multiplier = 1;
            number_text = value.substr(0, value.size() - 1);
            break;
        default:
            multiplier = 1;
            break;
    }

    if (number_text.empty())
    {
        return make_error("invalid sdp time value");
    }

    int64_t number = 0;
    const auto result = std::from_chars(number_text.data(), number_text.data() + number_text.size(), number);
    if (result.ec != std::errc() || result.ptr != number_text.data() + number_text.size())
    {
        return make_error("invalid sdp time value");
    }

    return number * multiplier;
}

std::expected<int, std::string> parse_port(std::string_view value)
{
    int port = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), port);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size())
    {
        return make_error("invalid port");
    }

    if (port < 0 || port > 65535)
    {
        return make_error("port out of range");
    }

    return port;
}
}    // namespace webrtc::sdp
