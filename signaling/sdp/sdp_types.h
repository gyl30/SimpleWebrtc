#ifndef SIMPLE_WEBRTC_SIGNALING_SDP_TYPES_H
#define SIMPLE_WEBRTC_SIGNALING_SDP_TYPES_H

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace webrtc::sdp
{
struct sdp_attribute
{
    std::string key;
    std::string value;
};

sdp_attribute make_property_attribute(std::string key);
sdp_attribute make_attribute(std::string key, std::string value);

struct media_name_line
{
    std::string media;
    int32_t port = 0;
    std::vector<std::string> formats;
};

struct media_description
{
    media_name_line media_name;
    std::string connection_address;
    std::vector<sdp_attribute> attributes;

    std::optional<std::string> find_attribute_value(std::string_view key) const;
    std::vector<const sdp_attribute*> find_attributes(std::string_view key) const;
};

enum class media_direction
{
    unknown = 0,
    send_recv,
    send_only,
    recv_only,
    inactive,
};

std::string_view to_string(media_direction direction);

enum class dtls_connection_role
{
    unknown = 0,
    active,
    passive,
    actpass,
    holdconn,
};

std::string_view to_string(dtls_connection_role role);
std::optional<dtls_connection_role> parse_dtls_connection_role(std::string_view value);

struct rtp_header_extension
{
    int32_t id = 0;
    media_direction direction = media_direction::unknown;
    std::string uri;
    std::optional<std::string> extension_attributes;

    bool parse_attribute_value(std::string_view value);
};

struct session_description
{
    uint64_t session_id = 0;
    uint64_t session_version = 0;
    std::vector<sdp_attribute> attributes;
    std::vector<media_description> media_descriptions;

    std::optional<std::string> find_attribute_value(std::string_view key) const;
    std::vector<const sdp_attribute*> find_attributes(std::string_view key) const;
};

inline constexpr std::string_view k_attribute_group = "group";
inline constexpr std::string_view k_attribute_ssrc_group = "ssrc-group";
inline constexpr std::string_view k_attribute_setup = "setup";
inline constexpr std::string_view k_attribute_mid = "mid";
inline constexpr std::string_view k_attribute_ice_ufrag = "ice-ufrag";
inline constexpr std::string_view k_attribute_ice_pwd = "ice-pwd";
inline constexpr std::string_view k_attribute_fingerprint = "fingerprint";
inline constexpr std::string_view k_attribute_rtcp_mux = "rtcp-mux";
inline constexpr std::string_view k_attribute_rtcp_rsize = "rtcp-rsize";
inline constexpr std::string_view k_attribute_inactive = "inactive";
inline constexpr std::string_view k_attribute_recv_only = "recvonly";
inline constexpr std::string_view k_attribute_send_only = "sendonly";
inline constexpr std::string_view k_attribute_send_recv = "sendrecv";
inline constexpr std::string_view k_attribute_rtp_map = "rtpmap";
inline constexpr std::string_view k_attribute_fmtp = "fmtp";
inline constexpr std::string_view k_attribute_rtcp_feedback = "rtcp-fb";
inline constexpr std::string_view k_attribute_ext_map = "extmap";
inline constexpr std::string_view k_attribute_ext_map_allow_mixed = "extmap-allow-mixed";

inline constexpr std::string_view k_rtp_header_extension_sdes_rtp_stream_id_uri = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
inline constexpr std::string_view k_rtp_header_extension_sdes_repaired_rtp_stream_id_uri = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";
}    // namespace webrtc::sdp

#endif
