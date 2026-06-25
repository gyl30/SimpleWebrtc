#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_LEXER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_LEXER_H

#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <string_view>

namespace webrtc::sdp
{
class sdp_syntax_error : public std::runtime_error
{
   public:
    sdp_syntax_error(std::string_view text, std::size_t position);

   public:
    std::size_t position() const;

   private:
    static std::string make_message(std::string_view text, std::size_t position);

   private:
    std::size_t position_ = 0;
};

class sdp_document_start_error : public std::runtime_error
{
   public:
    sdp_document_start_error();
};

class sdp_field_missing_error : public std::runtime_error
{
   public:
    sdp_field_missing_error();
};

class sdp_lexer
{
   public:
    sdp_lexer() = default;
    explicit sdp_lexer(std::string_view text);

   public:
    void reset(std::string_view text);

    std::string_view text() const;
    std::size_t position() const;
    bool eof() const;

   public:
    char read_byte();
    void unread_byte();

    void skip_line_breaks();
    void skip_whitespace();

    uint64_t read_uint64_field();
    std::string_view read_field();
    std::string_view read_required_field();
    std::string_view read_line();
    char read_type();

   private:
    std::string_view text_;
    std::size_t position_ = 0;
};

bool is_line_break(char ch);
bool is_whitespace(char ch);
bool is_any_of(std::string_view value, std::initializer_list<std::string_view> candidates);

int64_t parse_time_units(std::string_view value);
int parse_port(std::string_view value);
}    // namespace webrtc::sdp

#endif
