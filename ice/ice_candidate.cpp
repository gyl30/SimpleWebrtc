#include "ice/ice_candidate.h"

#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

namespace webrtc
{
namespace
{
constexpr std::size_t k_max_candidate_size = 4096;
constexpr std::size_t k_max_candidate_token_count = 64;
constexpr std::size_t k_max_foundation_size = 32;
constexpr std::size_t k_max_sdp_mid_size = 128;
constexpr std::size_t k_max_candidate_address_size = 253;
constexpr std::size_t k_max_extension_name_size = 64;
constexpr std::size_t k_max_extension_value_size = 512;

constexpr int k_max_sdp_mline_index = 1024;

constexpr uint32_t k_min_component_id = 1;
constexpr uint32_t k_max_component_id = 256;

constexpr std::string_view k_candidate_prefix = "candidate:";

enum class ice_candidate_transport
{
    udp,
    tcp,
};

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_field_error(std::string_view field, std::string_view message)
{
    std::string error;
    error.reserve(field.size() + message.size() + 2);

    error.append(field);
    error.push_back(' ');
    error.append(message);

    return std::unexpected(std::move(error));
}

bool contains_line_break(std::string_view value)
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

bool contains_whitespace(std::string_view value)
{
    for (const char ch : value)
    {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

bool contains_control_character(std::string_view value)
{
    for (const char ch : value)
    {
        const auto value_byte = static_cast<unsigned char>(ch);

        if (std::iscntrl(value_byte) != 0)
        {
            return true;
        }
    }

    return false;
}

bool is_end_of_candidates_text(std::string_view candidate)
{
    return candidate.empty() || candidate == "end-of-candidates" || candidate == "a=end-of-candidates";
}

std::expected<std::string, std::string> normalize_candidate_text(std::string_view candidate)
{
    if (candidate.size() > k_max_candidate_size)
    {
        return make_error("ice candidate is too large");
    }

    if (contains_line_break(candidate))
    {
        return make_error("ice candidate must not contain line breaks");
    }

    candidate = boost::algorithm::trim_copy_if(candidate, boost::algorithm::is_any_of(" \t"));

    if (is_end_of_candidates_text(candidate))
    {
        return std::string();
    }

    if (candidate.starts_with("a=candidate:"))
    {
        candidate.remove_prefix(2);
    }

    if (!candidate.starts_with(k_candidate_prefix))
    {
        return make_error("ice candidate must start with candidate:");
    }

    return std::string(candidate);
}

std::expected<std::string, std::string> normalize_sdp_mid(std::string_view sdp_mid)
{
    if (sdp_mid.size() > k_max_sdp_mid_size)
    {
        return make_error("sdpMid is too large");
    }

    if (contains_whitespace(sdp_mid))
    {
        return make_error("sdpMid must not contain whitespace");
    }

    if (contains_control_character(sdp_mid))
    {
        return make_error("sdpMid contains control characters");
    }

    return std::string(sdp_mid);
}

std::expected<void, std::string> validate_sdp_mline_index(int sdp_mline_index)
{
    if (sdp_mline_index < -1)
    {
        return make_error("sdpMLineIndex is invalid");
    }

    if (sdp_mline_index > k_max_sdp_mline_index)
    {
        return make_error("sdpMLineIndex is too large");
    }

    return {};
}

std::expected<std::vector<std::string_view>, std::string> split_candidate_tokens(std::string_view candidate)
{
    std::vector<std::string_view> tokens;

    tokens.reserve(16);

    std::size_t position = 0;

    while (position < candidate.size())
    {
        position = candidate.find_first_not_of(" \t", position);

        if (position == std::string_view::npos)
        {
            break;
        }

        const std::size_t token_end = candidate.find_first_of(" \t", position);

        if (token_end == std::string_view::npos)
        {
            tokens.push_back(candidate.substr(position));

            break;
        }

        tokens.push_back(candidate.substr(position, token_end - position));

        position = token_end;

        if (tokens.size() > k_max_candidate_token_count)
        {
            return make_error("ice candidate has too many tokens");
        }
    }

    if (tokens.size() > k_max_candidate_token_count)
    {
        return make_error("ice candidate has too many tokens");
    }

    return tokens;
}

template <typename value_type>
std::expected<value_type, std::string> parse_unsigned_integer(std::string_view text, uint64_t minimum, uint64_t maximum, std::string_view field_name)
{
    if (text.empty())
    {
        return make_field_error(field_name, "is empty");
    }

    uint64_t value = 0;

    const char* begin = text.data();

    const char* end = text.data() + text.size();

    const auto result = std::from_chars(begin, end, value, 10);

    if (result.ec != std::errc{} || result.ptr != end)
    {
        return make_field_error(field_name, "is invalid");
    }

    if (value < minimum || value > maximum)
    {
        return make_field_error(field_name, "is out of range");
    }

    return static_cast<value_type>(value);
}

bool is_valid_foundation_character(char ch)
{
    const auto value = static_cast<unsigned char>(ch);

    return std::isalnum(value) != 0 || ch == '+' || ch == '/';
}

std::expected<void, std::string> validate_foundation(std::string_view first_token)
{
    if (!first_token.starts_with(k_candidate_prefix))
    {
        return make_error("ice candidate foundation prefix is invalid");
    }

    const std::string_view foundation = first_token.substr(k_candidate_prefix.size());

    if (foundation.empty())
    {
        return make_error("ice candidate foundation is empty");
    }

    if (foundation.size() > k_max_foundation_size)
    {
        return make_error("ice candidate foundation is too large");
    }

    for (const char ch : foundation)
    {
        if (!is_valid_foundation_character(ch))
        {
            return make_error("ice candidate foundation contains invalid characters");
        }
    }

    return {};
}

std::expected<ice_candidate_transport, std::string> parse_transport(std::string_view value)
{
    if (boost::algorithm::iequals(value, "udp"))
    {
        return ice_candidate_transport::udp;
    }

    if (boost::algorithm::iequals(value, "tcp"))
    {
        return ice_candidate_transport::tcp;
    }

    return make_error("ice candidate transport is unsupported");
}

std::expected<void, std::string> validate_candidate_type(std::string_view value)
{
    if (boost::algorithm::iequals(value, "host") || boost::algorithm::iequals(value, "srflx") ||
        boost::algorithm::iequals(value, "prflx") || boost::algorithm::iequals(value, "relay"))
    {
        return {};
    }

    return make_error("ice candidate type is unsupported");
}

std::expected<void, std::string> validate_tcp_candidate_type(std::string_view value)
{
    if (boost::algorithm::iequals(value, "active") || boost::algorithm::iequals(value, "passive") ||
        boost::algorithm::iequals(value, "so"))
    {
        return {};
    }

    return make_error("ice candidate tcp type is unsupported");
}

bool looks_like_ipv4_literal(std::string_view value)
{
    if (value.empty())
    {
        return false;
    }

    bool has_dot = false;

    for (const char ch : value)
    {
        if (ch == '.')
        {
            has_dot = true;

            continue;
        }

        const auto value_byte = static_cast<unsigned char>(ch);

        if (std::isdigit(value_byte) == 0)
        {
            return false;
        }
    }

    return has_dot;
}

bool is_valid_hostname_label(std::string_view label)
{
    if (label.empty() || label.size() > 63)
    {
        return false;
    }

    const auto first = static_cast<unsigned char>(label.front());

    const auto last = static_cast<unsigned char>(label.back());

    if (std::isalnum(first) == 0 || std::isalnum(last) == 0)
    {
        return false;
    }

    for (const char ch : label)
    {
        const auto value = static_cast<unsigned char>(ch);

        if (std::isalnum(value) == 0 && ch != '-')
        {
            return false;
        }
    }

    return true;
}

bool is_valid_hostname(std::string_view value)
{
    if (value.empty() || value.size() > k_max_candidate_address_size)
    {
        return false;
    }

    if (value.back() == '.')
    {
        value.remove_suffix(1);
    }

    if (value.empty())
    {
        return false;
    }

    std::size_t position = 0;

    while (position < value.size())
    {
        const std::size_t separator = value.find('.', position);

        const std::size_t label_end = separator == std::string_view::npos ? value.size() : separator;

        const std::string_view label = value.substr(position, label_end - position);

        if (!is_valid_hostname_label(label))
        {
            return false;
        }

        if (separator == std::string_view::npos)
        {
            break;
        }

        position = separator + 1;
    }

    return true;
}

bool is_valid_candidate_address(std::string_view value)
{
    if (value.empty() || value.size() > k_max_candidate_address_size)
    {
        return false;
    }

    if (contains_whitespace(value) || contains_control_character(value))
    {
        return false;
    }

    boost::system::error_code ec;

    const auto address = boost::asio::ip::make_address(std::string(value), ec);

    (void)address;

    if (!ec)
    {
        return true;
    }

    if (looks_like_ipv4_literal(value))
    {
        return false;
    }

    return is_valid_hostname(value);
}
bool is_ip_literal(std::string_view value)
{
    boost::system::error_code ec;

    const auto address = boost::asio::ip::make_address(std::string(value), ec);

    (void)address;

    return !ec;
}

bool is_mdns_hostname(std::string_view value)
{
    if (value.empty())
    {
        return false;
    }

    std::string lowered(value);
    boost::algorithm::to_lower(lowered);

    if (lowered.ends_with(".local"))
    {
        return true;
    }

    return lowered.ends_with(".local.");
}

std::expected<std::string, std::string> parse_candidate_address(std::string_view value, std::string_view field_name)
{
    if (!is_valid_candidate_address(value))
    {
        return make_field_error(field_name, "is invalid");
    }

    return std::string(value);
}

std::expected<void, std::string> validate_extension_token(std::string_view value, std::string_view field_name, std::size_t maximum_size)
{
    if (value.empty())
    {
        return make_field_error(field_name, "is empty");
    }

    if (value.size() > maximum_size)
    {
        return make_field_error(field_name, "is too large");
    }

    if (contains_whitespace(value) || contains_control_character(value))
    {
        return make_field_error(field_name, "contains invalid characters");
    }

    return {};
}

std::expected<void, std::string> parse_candidate_extensions(const std::vector<std::string_view>& tokens, ice_candidate_transport transport)
{
    if ((tokens.size() - 8) % 2 != 0)
    {
        return make_error("ice candidate extension is missing a value");
    }

    bool has_related_address = false;
    bool has_related_port = false;
    bool has_tcp_type = false;
    bool has_generation = false;
    bool has_network_id = false;
    bool has_network_cost = false;

    for (std::size_t index = 8; index < tokens.size(); index += 2)
    {
        const std::string_view raw_name = tokens[index];

        const std::string_view raw_value = tokens[index + 1];

        auto name_validation = validate_extension_token(raw_name, "ice candidate extension name", k_max_extension_name_size);

        if (!name_validation)
        {
            return std::unexpected(name_validation.error());
        }

        auto value_validation = validate_extension_token(raw_value, "ice candidate extension value", k_max_extension_value_size);

        if (!value_validation)
        {
            return std::unexpected(value_validation.error());
        }

        std::string name(raw_name);
        boost::algorithm::to_lower(name);

        if (name == "raddr")
        {
            if (has_related_address)
            {
                return make_error("ice candidate related address is duplicated");
            }

            auto related_address = parse_candidate_address(raw_value, "ice candidate related address");

            if (!related_address)
            {
                return std::unexpected(related_address.error());
            }

            has_related_address = true;

            continue;
        }

        if (name == "rport")
        {
            if (has_related_port)
            {
                return make_error("ice candidate related port is duplicated");
            }

            auto related_port = parse_unsigned_integer<uint16_t>(raw_value, 1, std::numeric_limits<uint16_t>::max(), "ice candidate related port");

            if (!related_port)
            {
                return std::unexpected(related_port.error());
            }

            has_related_port = true;

            continue;
        }

        if (name == "tcptype")
        {
            if (has_tcp_type)
            {
                return make_error("ice candidate tcp type is duplicated");
            }

            auto tcp_type = validate_tcp_candidate_type(raw_value);

            if (!tcp_type)
            {
                return std::unexpected(tcp_type.error());
            }

            has_tcp_type = true;

            continue;
        }

        if (name == "generation")
        {
            if (has_generation)
            {
                return make_error("ice candidate generation is duplicated");
            }

            auto generation = parse_unsigned_integer<uint32_t>(raw_value, 0, std::numeric_limits<uint32_t>::max(), "ice candidate generation");

            if (!generation)
            {
                return std::unexpected(generation.error());
            }

            has_generation = true;

            continue;
        }

        if (name == "network-id")
        {
            if (has_network_id)
            {
                return make_error("ice candidate network id is duplicated");
            }

            auto network_id = parse_unsigned_integer<uint32_t>(raw_value, 0, std::numeric_limits<uint32_t>::max(), "ice candidate network id");

            if (!network_id)
            {
                return std::unexpected(network_id.error());
            }

            has_network_id = true;

            continue;
        }

        if (name == "network-cost")
        {
            if (has_network_cost)
            {
                return make_error("ice candidate network cost is duplicated");
            }

            auto network_cost = parse_unsigned_integer<uint32_t>(raw_value, 0, std::numeric_limits<uint32_t>::max(), "ice candidate network cost");

            if (!network_cost)
            {
                return std::unexpected(network_cost.error());
            }

            has_network_cost = true;

            continue;
        }
    }

    if (has_related_address != has_related_port)
    {
        return make_error("ice candidate related address and port must be provided together");
    }

    if (transport == ice_candidate_transport::tcp && !has_tcp_type)
    {
        return make_error("tcp ice candidate requires tcptype");
    }

    if (transport == ice_candidate_transport::udp && has_tcp_type)
    {
        return make_error("udp ice candidate must not contain tcptype");
    }

    return {};
}

std::expected<void, std::string> parse_candidate_fields(std::string_view candidate_text, remote_ice_candidate& candidate)
{
    auto tokens = split_candidate_tokens(candidate_text);

    if (!tokens)
    {
        return std::unexpected(tokens.error());
    }

    if (tokens->size() < 8)
    {
        return make_error("ice candidate is missing mandatory fields");
    }

    auto foundation = validate_foundation((*tokens)[0]);

    if (!foundation)
    {
        return std::unexpected(foundation.error());
    }

    auto component = parse_unsigned_integer<uint32_t>((*tokens)[1], k_min_component_id, k_max_component_id, "ice candidate component");

    if (!component)
    {
        return std::unexpected(component.error());
    }

    auto transport = parse_transport((*tokens)[2]);

    if (!transport)
    {
        return std::unexpected(transport.error());
    }

    auto priority = parse_unsigned_integer<uint32_t>((*tokens)[3], 1, std::numeric_limits<uint32_t>::max(), "ice candidate priority");

    if (!priority)
    {
        return std::unexpected(priority.error());
    }

    auto address = parse_candidate_address((*tokens)[4], "ice candidate address");

    if (!address)
    {
        return std::unexpected(address.error());
    }

    auto port = parse_unsigned_integer<uint16_t>((*tokens)[5], 1, std::numeric_limits<uint16_t>::max(), "ice candidate port");

    if (!port)
    {
        return std::unexpected(port.error());
    }

    if (!boost::algorithm::iequals((*tokens)[6], "typ"))
    {
        return make_error("ice candidate typ field is missing");
    }

    auto type = validate_candidate_type((*tokens)[7]);

    if (!type)
    {
        return std::unexpected(type.error());
    }

    candidate.address = std::move(*address);

    candidate.port = *port;

    candidate.address_is_hostname = !is_ip_literal(candidate.address);

    candidate.address_is_mdns_hostname = is_mdns_hostname(candidate.address);

    return parse_candidate_extensions(*tokens, *transport);
}
}    // namespace

remote_ice_candidate_result make_remote_ice_candidate(std::string_view candidate,
                                                      std::string_view sdp_mid,
                                                      int sdp_mline_index)
{
    auto normalized_candidate = normalize_candidate_text(candidate);

    if (!normalized_candidate)
    {
        return std::unexpected(normalized_candidate.error());
    }

    auto normalized_sdp_mid = normalize_sdp_mid(sdp_mid);

    if (!normalized_sdp_mid)
    {
        return std::unexpected(normalized_sdp_mid.error());
    }

    auto mline_index_result = validate_sdp_mline_index(sdp_mline_index);

    if (!mline_index_result)
    {
        return std::unexpected(mline_index_result.error());
    }

    if (normalized_sdp_mid->empty() && sdp_mline_index < 0)
    {
        return make_error("sdpMid or sdpMLineIndex is required");
    }

    remote_ice_candidate value;

    value.candidate = std::move(*normalized_candidate);

    value.sdp_mid = std::move(*normalized_sdp_mid);

    value.sdp_mline_index = sdp_mline_index;

    value.end_of_candidates = value.candidate.empty();

    if (value.end_of_candidates)
    {
        return value;
    }

    auto parse_result = parse_candidate_fields(value.candidate, value);

    if (!parse_result)
    {
        return std::unexpected(parse_result.error());
    }

    return value;
}

}    // namespace webrtc
