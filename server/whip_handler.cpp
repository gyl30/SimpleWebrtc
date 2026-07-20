#include "server/whip_handler.h"

#include <chrono>
#include <cstddef>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "server/http_error_response.h"
#include "server/trickle_ice_patch_handler.h"
#include "session/whip_session_transport.h"
#include "signaling/sdp/sdp_offer_validator.h"
#include "signaling/sdp/sdp_parser.h"
#include "signaling/sdp/sdp_summary.h"
#include "signaling/webrtc_answer_factory.h"
#include "webrtc_config.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;
constexpr std::string_view k_whip_invalid_sdp_offer_error = "whip_invalid_sdp_offer";
constexpr std::string_view k_whip_invalid_webrtc_offer_error = "whip_invalid_webrtc_offer";
constexpr std::string_view k_whip_invalid_offer_error = "whip_invalid_offer";
constexpr std::string_view k_whip_sdp_answer_failed_error = "whip_sdp_answer_failed";
constexpr std::string_view k_whip_runtime_offer_filter_failed_error = "whip_runtime_offer_filter_failed";
constexpr std::string_view k_whip_precondition_failed_error = "whip_precondition_failed";
constexpr std::string_view k_whip_stream_already_has_publisher_error = "whip_stream_already_has_publisher";
constexpr std::string_view k_whip_create_session_failed_error = "whip_create_session_failed";
constexpr std::string_view k_whip_session_not_found_error = "whip_session_not_found";
constexpr std::string_view k_whip_delete_session_failed_error = "whip_delete_session_failed";
std::string make_prefixed_error(std::string_view prefix, std::string_view error)
{
    std::string message;

    message.reserve(prefix.size() + error.size());

    message.append(prefix);

    message.append(error);

    return message;
}
}    // namespace

whip_handler::whip_handler(std::shared_ptr<stream_registry> registry,
                           std::shared_ptr<webrtc_answer_factory> answer_factory,
                           std::shared_ptr<udp_port_allocator> udp_port_allocator,
                           boost::asio::io_context& io_context,
                           const webrtc_config& config,
                           std::shared_ptr<dtls_context> dtls_context,
                           std::shared_ptr<media_fanout_router> media_fanout_router)
    : registry_(std::move(registry)),
      answer_factory_(std::move(answer_factory)),
      udp_port_allocator_(std::move(udp_port_allocator)),
      media_fanout_router_(std::move(media_fanout_router)),
      io_context_(io_context),
      config_(config),
      dtls_context_(std::move(dtls_context))
{
}

http_response_ptr whip_handler::create_publisher(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);

    if (!description)
    {
        WEBRTC_LOG_WARN("WHIP parse SDP offer failed stream={} error={}", stream_id, description.error());

        return json_error_response(request, 400, k_whip_invalid_sdp_offer_error, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    WEBRTC_LOG_INFO("WHIP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHIP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());

        return json_error_response(
            request, 400, k_whip_invalid_webrtc_offer_error, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whip_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHIP validate offer failed stream={} error={}", stream_id, validation_result.error());

        return json_error_response(request, 400, k_whip_invalid_offer_error, make_prefixed_error("invalid whip offer: ", validation_result.error()));
    }

    auto local_udp_port = reserve_udp_port(udp_port_allocator_);

    if (!local_udp_port)
    {
        WEBRTC_LOG_ERROR("WHIP allocate session udp port failed stream={}", stream_id);

        return json_error_response(request, 503, "whip_udp_port_unavailable", "session udp port unavailable");
    }

    auto transport =
        std::make_shared<whip_session_transport>(io_context_, config_.ice_bind_host, dtls_context_, config_.dtls_ip_mtu, media_fanout_router_);

    auto transport_start = transport->start((*local_udp_port)->port());

    if (!transport_start)
    {
        WEBRTC_LOG_ERROR(
            "WHIP start session transport failed stream={} port={} error={}", stream_id, (*local_udp_port)->port(), transport_start.error());

        return json_error_response(request, 503, "whip_udp_bind_failed", "session udp bind failed");
    }

    auto answer = answer_factory_->build_whip_answer(stream_id, *offer_summary, (*local_udp_port)->port());

    if (!answer)
    {
        WEBRTC_LOG_WARN("WHIP build SDP answer failed stream={} error={}", stream_id, answer.error());

        return json_error_response(request, 400, k_whip_sdp_answer_failed_error, make_prefixed_error("cannot build sdp answer: ", answer.error()));
    }

    auto runtime_offer = sdp::make_offer_summary(*offer_summary, answer->accepted_mline_indexes);

    if (!runtime_offer)
    {
        WEBRTC_LOG_WARN("WHIP runtime publisher offer filter failed stream={} error={}", stream_id, runtime_offer.error());

        return json_error_response(request,
                                   400,
                                   k_whip_runtime_offer_filter_failed_error,
                                   make_prefixed_error("failed to filter runtime publisher offer: ", runtime_offer.error()));
    }

    auto session_result = registry_->create_publisher_session(std::string(stream_id), std::move(*runtime_offer));
    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::stream_already_has_publisher)
        {
            WEBRTC_LOG_WARN("WHIP create publisher failed stream={} already has publisher", stream_id);

            return json_error_response(request, 409, k_whip_stream_already_has_publisher_error, "stream already has publisher");
        }

        WEBRTC_LOG_ERROR("WHIP create publisher failed stream={} error={}", stream_id, stream_registry_error_to_string(error));
        return json_error_response(request, 500, k_whip_create_session_failed_error, "create publisher session failed");
    }

    const auto& session = *session_result;
    const std::string publisher_session_id = session->session_id();
    const std::string publisher_stream_id = session->stream_id();
    const std::weak_ptr<stream_registry> weak_registry = registry_;
    const std::weak_ptr<media_fanout_router> weak_media_fanout_router = media_fanout_router_;

    transport->start_inactivity_monitor(std::chrono::seconds(config_.session_inactivity_timeout_seconds),
                                        [weak_registry, weak_media_fanout_router, publisher_session_id, publisher_stream_id]()
                                        {
                                            const auto registry = weak_registry.lock();
                                            const auto media_fanout_router = weak_media_fanout_router.lock();

                                            if (registry == nullptr || media_fanout_router == nullptr)
                                            {
                                                return;
                                            }

                                            const auto session = registry->find_publisher_by_session_id(publisher_session_id);
                                            auto result = registry->remove_publisher_session(publisher_session_id);

                                            if (session == nullptr || !result)
                                            {
                                                return;
                                            }

                                            session->close("inactivity_timeout");
                                            media_fanout_router->clear_publisher_source(publisher_stream_id, publisher_session_id);
                                        });

    session->complete_initial_setup(
        std::move(answer->local_ice), std::move(answer->accepted_mline_indexes), std::move(*local_udp_port), std::move(transport));

    const uint64_t source_generation =
        media_fanout_router_->set_publisher_source(session->stream_id(),
                                                   session->session_id(),
                                                   session->remote_offer_summary(),
                                                   [weak_session = std::weak_ptr<publisher_session>(session)](uint32_t media_ssrc)
                                                   {
                                                       if (const auto current_session = weak_session.lock())
                                                       {
                                                           current_session->request_keyframe(media_ssrc);
                                                       }
                                                   });
    session->set_publisher_source_generation(source_generation);

    WEBRTC_LOG_INFO("WHIP create publisher stream={} session={} sdp_size={} offer_media_count={} accepted_media_count={} accepted_mline_count={}",
                    session->stream_id(),
                    session->session_id(),
                    offer.size(),
                    offer_summary->media.size(),
                    session->remote_offer_summary().media.size(),
                    session->accepted_remote_media_mline_indexes().size());

    auto response = make_sdp_http_response(request, 201, answer->sdp);

    const std::string session_location_path = "/whip/session/" + session->session_id();

    response->set(http::field::location, session_location_path);

    set_session_resource_headers(response, *session, config_.ice_server_link_header);

    return response;
}

http_response_ptr whip_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    auto session = registry_->find_publisher_by_session_id(session_id);

    return handle_trickle_ice_patch_request(
        request,
        session_id,
        session,
        "WHIP",
        "publisher session not found",
        [this, &request](int status, std::string_view error_code, std::string_view message) -> http_response_ptr
        {
            if (error_code == "trickle_ice_session_not_found")
            {
                return json_error_response(request, status, k_whip_session_not_found_error, message);
            }

            if (error_code == "trickle_ice_precondition_failed")
            {
                return json_error_response(request, status, k_whip_precondition_failed_error, message);
            }

            return json_error_response(request, status, error_code, message);
        },
        [&request](const auto& updated_session) -> http_response_ptr
        {
            (void)updated_session;
            auto response = create_response(request, 204, "");
            add_http_common_headers(response);

            return response;
        });
}

http_response_ptr whip_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHIP delete session={}", session_id);

    auto session = registry_->find_publisher_by_session_id(session_id);

    if (session == nullptr)
    {
        return json_error_response(request, 404, k_whip_session_not_found_error, "publisher session not found");
    }
    const std::string stream_id = session->stream_id();
    const std::string publisher_session_id = session->session_id();

    auto result = registry_->remove_publisher_session(session_id);

    if (!result)
    {
        if (result.error() == stream_registry_error::publisher_session_not_found)
        {
            return json_error_response(request, 404, k_whip_session_not_found_error, "publisher session not found");
        }

        WEBRTC_LOG_ERROR("WHIP delete publisher failed session={} error={}", session_id, stream_registry_error_to_string(result.error()));
        return json_error_response(request, 500, k_whip_delete_session_failed_error, "delete publisher session failed");
    }

    session->close("whip_delete");
    media_fanout_router_->clear_publisher_source(stream_id, publisher_session_id);

    auto response = create_response(request, 204, "");

    add_http_common_headers(response);

    return response;
}

http_response_ptr whip_handler::json_error_response(http_request_t& request, int code, std::string_view message)
{
    return json_error_response(request, code, "whip_error", message);
}

http_response_ptr whip_handler::json_error_response(http_request_t& request, int code, std::string_view error_code, std::string_view message)
{
    return make_json_http_error_response(request, code, error_code, message);
}

}    // namespace webrtc
