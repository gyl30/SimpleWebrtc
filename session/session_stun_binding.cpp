#include "session/session_stun_binding.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include "ice/ice_username.h"
#include "ice/session_ice_udp_server.h"
#include "ice/stun_message.h"
#include "log/log.h"
#include "net/socket.h"

namespace webrtc
{
namespace
{
bool ice_username_matches_session(const ice_username_parts& username, const session_stun_binding_context& context)
{
    return username.recipient_ufrag == context.local_ice_ufrag && username.sender_ufrag == context.remote_ice_ufrag;
}

std::optional<session_udp_outbound_packet> make_stun_binding_response(const stun_message& request,
                                                                      const boost::asio::ip::udp::endpoint& remote_endpoint,
                                                                      const session_stun_binding_context& context)
{
    const std::string remote_ip = get_endpoint_ip(remote_endpoint);

    if (remote_ip.empty())
    {
        WEBRTC_LOG_WARN("{} stun remote endpoint ip is empty stream={} session={} remote={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        format_udp_endpoint(remote_endpoint));

        return std::nullopt;
    }

    auto response = write_stun_binding_success_response(request, remote_ip, remote_endpoint.port(), context.local_ice_pwd);

    if (!response)
    {
        WEBRTC_LOG_WARN("{} stun binding response build failed stream={} session={} remote={} error={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        format_udp_endpoint(remote_endpoint),
                        response.error());

        return std::nullopt;
    }

    session_udp_outbound_packet packet;

    packet.data = std::move(*response);
    packet.remote_endpoint = remote_endpoint;

    return packet;
}
}    // namespace

session_stun_binding_result handle_session_stun_binding(std::span<const uint8_t> data,
                                                        const boost::asio::ip::udp::endpoint& remote_endpoint,
                                                        const session_stun_binding_context& context)
{
    session_stun_binding_result result;

    if (!is_stun_packet(data))
    {
        return result;
    }

    result.handled = true;

    const std::string remote_address = format_udp_endpoint(remote_endpoint);

    auto message = parse_stun_message(data);

    if (!message)
    {
        WEBRTC_LOG_WARN("{} stun parse failed stream={} session={} remote={} error={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        remote_address,
                        message.error());

        return result;
    }

    if (message->method != stun_method::binding || message->message_class != stun_message_class::request)
    {
        WEBRTC_LOG_DEBUG("{} stun ignored stream={} session={} remote={} method={} class={}",
                         context.log_prefix,
                         context.stream_id,
                         context.session_id,
                         remote_address,
                         stun_method_to_string(message->method),
                         stun_class_to_string(message->message_class));

        return result;
    }

    if (!message->username.has_value())
    {
        WEBRTC_LOG_WARN("{} stun binding request missing username stream={} session={} remote={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        remote_address);

        return result;
    }

    auto connectivity_check = validate_ice_connectivity_check(*message);

    if (!connectivity_check)
    {
        WEBRTC_LOG_WARN("{} stun connectivity check rejected stream={} session={} username={} remote={} error={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        *message->username,
                        remote_address,
                        connectivity_check.error());

        return result;
    }

    auto username = parse_ice_username(*message->username);

    if (!username)
    {
        WEBRTC_LOG_WARN("{} stun username invalid stream={} session={} username={} remote={} error={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        *message->username,
                        remote_address,
                        username.error());

        return result;
    }

    if (!ice_username_matches_session(*username, context))
    {
        WEBRTC_LOG_WARN("{} stun username mismatch stream={} session={} username={} remote={} expected_local={} expected_remote={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        *message->username,
                        remote_address,
                        context.local_ice_ufrag,
                        context.remote_ice_ufrag);

        return result;
    }

    if (context.local_ice_pwd.empty())
    {
        WEBRTC_LOG_WARN("{} stun local ice pwd is empty stream={} session={} username={} remote={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        *message->username,
                        remote_address);

        return result;
    }

    if (!message->has_message_integrity)
    {
        WEBRTC_LOG_WARN("{} stun binding request missing message-integrity stream={} session={} username={} remote={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        *message->username,
                        remote_address);

        return result;
    }

    auto integrity = verify_stun_message_integrity(data, context.local_ice_pwd);

    if (!integrity)
    {
        WEBRTC_LOG_WARN("{} stun message-integrity verify failed stream={} session={} username={} remote={} error={}",
                        context.log_prefix,
                        context.stream_id,
                        context.session_id,
                        *message->username,
                        remote_address,
                        integrity.error());

        return result;
    }
    if (message->has_fingerprint)
    {
        auto fingerprint = verify_stun_fingerprint(data);

        if (!fingerprint)
        {
            WEBRTC_LOG_WARN("{} stun fingerprint verify failed stream={} session={} username={} remote={} error={}",
                            context.log_prefix,
                            context.stream_id,
                            context.session_id,
                            *message->username,
                            remote_address,
                            fingerprint.error());

            return result;
        }
    }

    result.response = make_stun_binding_response(*message, remote_endpoint, context);
    if (result.response.has_value())
    {
        result.nominated = message->has_use_candidate;

        WEBRTC_LOG_DEBUG("{} stun binding accepted stream={} session={} username={} remote={} nominated={}",
                         context.log_prefix,
                         context.stream_id,
                         context.session_id,
                         *message->username,
                         remote_address,
                         result.nominated ? 1 : 0);
    }

    return result;
}
}    // namespace webrtc
