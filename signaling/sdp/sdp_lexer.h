#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_LEXER_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_LEXER_H

#include <cstdint>
#include <expected>
#include <initializer_list>
#include <string>
#include <string_view>

namespace webrtc::sdp
{
class sdp_lexer
{
   public:
    explicit sdp_lexer(std::string_view text);

   public:
    [[nodiscard]] bool eof() const;

   public:
    void skip_line_breaks();
    [[nodiscard]] std::expected<std::string_view, std::string> read_line();
    [[nodiscard]] std::expected<char, std::string> read_type();

   private:
    std::string make_syntax_error(std::size_t position) const;

   private:
    std::string_view text_;
    std::size_t position_ = 0;
};

[[nodiscard]] bool is_any_of(std::string_view value, std::initializer_list<std::string_view> candidates);

[[nodiscard]] std::expected<int64_t, std::string> parse_time_units(std::string_view value);
[[nodiscard]] std::expected<int, std::string> parse_port(std::string_view value);
}    // namespace webrtc::sdp

#endif
