#include "signaling/sdp/sdp_lexer.h"

#include <charconv>
#include <string>

namespace webrtc::sdp
{
namespace
{
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

sdp_syntax_error::sdp_syntax_error(std::string_view text, std::size_t position)
    : std::runtime_error(make_message(text, position)), position_(position)
{
}

std::size_t sdp_syntax_error::position() const { return position_; }

std::string sdp_syntax_error::make_message(std::string_view text, std::size_t position)
{
    if (text.empty())
    {
        return "sdp syntax error at position 0: \"\"";
    }

    if (position >= text.size())
    {
        position = text.size() - 1;
    }

    const char ch = text[position];

    std::string message;
    message.reserve(64);
    message += "sdp syntax error at position ";
    message += std::to_string(position);
    message += ": \"";
    message += escape_char_for_error(ch);
    message += "\"";

    return message;
}

sdp_document_start_error::sdp_document_start_error() : std::runtime_error("already at document start") {}

sdp_field_missing_error::sdp_field_missing_error() : std::runtime_error("sdp field missing") {}

sdp_lexer::sdp_lexer(std::string_view text) : text_(text) {}

void sdp_lexer::reset(std::string_view text)
{
    text_ = text;
    position_ = 0;
}

std::string_view sdp_lexer::text() const { return text_; }

std::size_t sdp_lexer::position() const { return position_; }

bool sdp_lexer::eof() const { return position_ >= text_.size(); }

char sdp_lexer::read_byte()
{
    if (eof())
    {
        return '\0';
    }

    const char ch = text_[position_];
    ++position_;
    return ch;
}

void sdp_lexer::unread_byte()
{
    if (position_ == 0)
    {
        throw sdp_document_start_error();
    }

    --position_;
}

void sdp_lexer::skip_line_breaks()
{
    while (!eof())
    {
        const char ch = read_byte();
        if (!is_line_break(ch))
        {
            unread_byte();
            return;
        }
    }
}

void sdp_lexer::skip_whitespace()
{
    while (!eof())
    {
        const char ch = read_byte();
        if (!is_whitespace(ch))
        {
            unread_byte();
            return;
        }
    }
}

uint64_t sdp_lexer::read_uint64_field()
{
    uint64_t value = 0;
    bool has_digit = false;

    while (!eof())
    {
        const char ch = read_byte();

        if (is_line_break(ch))
        {
            unread_byte();
            break;
        }

        if (is_whitespace(ch))
        {
            skip_whitespace();
            break;
        }

        if (ch < '0' || ch > '9')
        {
            throw sdp_syntax_error(text_, position_ == 0 ? 0 : position_ - 1);
        }

        value = value * 10 + static_cast<uint64_t>(ch - '0');
        has_digit = true;
    }

    if (!has_digit)
    {
        throw sdp_syntax_error(text_, position_);
    }

    return value;
}

std::string_view sdp_lexer::read_field()
{
    const std::size_t start = position_;
    std::size_t stop = position_;

    while (!eof())
    {
        stop = position_;

        const char ch = read_byte();

        if (is_line_break(ch))
        {
            unread_byte();
            break;
        }

        if (is_whitespace(ch))
        {
            skip_whitespace();
            break;
        }
    }

    if (eof())
    {
        stop = position_;
    }

    if (stop < start)
    {
        return {};
    }

    return text_.substr(start, stop - start);
}

std::string_view sdp_lexer::read_required_field()
{
    auto field = read_field();
    if (field.empty())
    {
        throw sdp_field_missing_error();
    }

    return field;
}

std::string_view sdp_lexer::read_line()
{
    const std::size_t start = position_;

    while (!eof())
    {
        const char ch = read_byte();

        if (ch == '\n')
        {
            std::size_t end = position_ - 1;
            if (end > start && text_[end - 1] == '\r')
            {
                --end;
            }

            return text_.substr(start, end - start);
        }

        if (ch == '\r')
        {
            if (!eof() && text_[position_] == '\n')
            {
                ++position_;
            }

            const std::size_t end = position_ >= 2 && text_[position_ - 2] == '\r' ? position_ - 2 : position_ - 1;
            return text_.substr(start, end - start);
        }
    }

    std::size_t end = position_;
    if (end > start && text_[end - 1] == '\r')
    {
        --end;
    }

    return text_.substr(start, end - start);
}

char sdp_lexer::read_type()
{
    while (!eof())
    {
        const char first = read_byte();

        if (is_line_break(first))
        {
            continue;
        }

        if (eof())
        {
            throw sdp_syntax_error(text_, position_ == 0 ? 0 : position_ - 1);
        }

        const char second = read_byte();
        if (second != '=')
        {
            unread_byte();
            throw sdp_syntax_error(text_, position_ == 0 ? 0 : position_ - 1);
        }

        return first;
    }

    throw sdp_syntax_error(text_, position_);
}

bool is_line_break(char ch) { return ch == '\n' || ch == '\r'; }

bool is_whitespace(char ch) { return ch == ' ' || ch == '\t'; }

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

int64_t parse_time_units(std::string_view value)
{
    if (value.empty())
    {
        return 0;
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
        throw std::invalid_argument("invalid sdp time value");
    }

    int64_t number = 0;
    const auto result = std::from_chars(number_text.data(), number_text.data() + number_text.size(), number);
    if (result.ec != std::errc())
    {
        throw std::invalid_argument("invalid sdp time value");
    }

    return number * multiplier;
}

int parse_port(std::string_view value)
{
    int port = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), port);
    if (result.ec != std::errc())
    {
        return -1;
    }

    if (port < 0 || port > 65535)
    {
        return -1;
    }

    return port;
}
}    // namespace webrtc::sdp
