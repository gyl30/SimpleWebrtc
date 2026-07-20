#include "server/whep_handler.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "media/whep_rtp_rewriter.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "server/http_error_response.h"
#include "server/trickle_ice_patch_handler.h"
#include "session/whep_session_transport.h"
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
constexpr std::string_view k_whep_invalid_sdp_offer_error = "whep_invalid_sdp_offer";
constexpr std::string_view k_whep_invalid_webrtc_offer_error = "whep_invalid_webrtc_offer";
constexpr std::string_view k_whep_invalid_offer_error = "whep_invalid_offer";
constexpr std::string_view k_whep_publisher_not_found_error = "whep_publisher_not_found";
constexpr std::string_view k_whep_precondition_failed_error = "whep_precondition_failed";
constexpr std::string_view k_whep_sdp_answer_failed_error = "whep_sdp_answer_failed";
constexpr std::string_view k_whep_runtime_offer_filter_failed_error = "whep_runtime_offer_filter_failed";
constexpr std::string_view k_whep_create_session_failed_error = "whep_create_session_failed";
constexpr std::string_view k_whep_session_not_found_error = "whep_session_not_found";
constexpr std::string_view k_whep_delete_session_failed_error = "whep_delete_session_failed";

std::string make_prefixed_error(std::string_view prefix, std::string_view error)
{
    std::string message;

    message.reserve(prefix.size() + error.size());

    message.append(prefix);

    message.append(error);

    return message;
}
uint32_t make_whep_outbound_ssrc(std::unordered_set<uint32_t>& used_ssrcs)
{
    thread_local std::mt19937 generator(std::random_device{}());

    std::uniform_int_distribution<uint32_t> distribution(1U, std::numeric_limits<uint32_t>::max());

    for (uint32_t attempt = 0; attempt < 4096; ++attempt)
    {
        const uint32_t candidate = distribution(generator);

        if (used_ssrcs.insert(candidate).second)
        {
            return candidate;
        }
    }

    for (uint32_t candidate = 1; candidate < std::numeric_limits<uint32_t>::max(); ++candidate)
    {
        if (used_ssrcs.insert(candidate).second)
        {
            return candidate;
        }
    }

    return 1;
}

std::string make_whep_outbound_source_cname()
{
    thread_local std::mt19937 generator(std::random_device{}());

    std::uniform_int_distribution<uint32_t> distribution(0U, 15U);

    std::string cname;

    cname.reserve(19);
    cname.append("sw-");

    for (std::size_t index = 0; index < 16; ++index)
    {
        const uint32_t value = distribution(generator);

        if (value < 10)
        {
            cname.push_back(static_cast<char>('0' + value));
        }
        else
        {
            cname.push_back(static_cast<char>('a' + (value - 10)));
        }
    }

    return cname;
}

std::vector<sdp::sdp_answer_media_source> make_whep_outbound_media_sources(const sdp::webrtc_offer_summary& offer)
{
    std::vector<sdp::sdp_answer_media_source> sources;

    sources.reserve(offer.media.size());

    std::unordered_set<uint32_t> used_ssrcs;
    const std::string cname = make_whep_outbound_source_cname();

    for (const auto& media : offer.media)
    {
        sdp::sdp_answer_media_source source;

        source.mid = media.mid;
        source.kind = media.kind;
        source.ssrc = make_whep_outbound_ssrc(used_ssrcs);

        if (media.kind == "video")
        {
            source.rtx_repair_ssrc = make_whep_outbound_ssrc(used_ssrcs);
        }

        source.cname = cname;
        sources.push_back(std::move(source));
    }

    return sources;
}

std::vector<sdp::sdp_answer_media_source> filter_whep_outbound_media_sources(const std::vector<sdp::sdp_answer_media_source>& sources,
                                                                             std::span<const int> accepted_mline_indexes)
{
    std::vector<sdp::sdp_answer_media_source> filtered_sources;

    filtered_sources.reserve(accepted_mline_indexes.size());

    for (const int mline_index : accepted_mline_indexes)
    {
        filtered_sources.push_back(sources[static_cast<std::size_t>(mline_index)]);
    }

    return filtered_sources;
}

}    // namespace

whep_handler::whep_handler(std::shared_ptr<stream_registry> registry,
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

http_response_ptr whep_handler::create_subscriber(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);

    if (!description)
    {
        WEBRTC_LOG_WARN("WHEP parse SDP offer failed stream={} error={}", stream_id, description.error());
        return json_error_response(request, 400, k_whep_invalid_sdp_offer_error, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    WEBRTC_LOG_INFO("WHEP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHEP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());
        return json_error_response(
            request, 400, k_whep_invalid_webrtc_offer_error, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whep_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHEP validate WebRTC offer failed stream={} error={}", stream_id, validation_result.error());
        return json_error_response(request, 400, k_whep_invalid_offer_error, make_prefixed_error("invalid whep offer: ", validation_result.error()));
    }

    WEBRTC_LOG_INFO("WHEP validated WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

    auto publisher = registry_->find_publisher_by_stream_id(stream_id);

    if (publisher == nullptr)
    {
        WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

        return json_error_response(request, 404, k_whep_publisher_not_found_error, "publisher not found");
    }
    auto outbound_media_sources = make_whep_outbound_media_sources(*offer_summary);

    auto local_udp_port = reserve_udp_port(udp_port_allocator_);

    if (!local_udp_port)
    {
        WEBRTC_LOG_ERROR("WHEP allocate session udp port failed stream={}", stream_id);

        return json_error_response(request, 503, "whep_udp_port_unavailable", "session udp port unavailable");
    }

    auto transport =
        std::make_shared<whep_session_transport>(io_context_, config_.ice_bind_host, dtls_context_, config_.dtls_ip_mtu, media_fanout_router_);

    auto transport_start = transport->start((*local_udp_port)->port());

    if (!transport_start)
    {
        WEBRTC_LOG_ERROR(
            "WHEP start session transport failed stream={} port={} error={}", stream_id, (*local_udp_port)->port(), transport_start.error());

        return json_error_response(request, 503, "whep_udp_bind_failed", "session udp bind failed");
    }

    auto generated_answer = answer_factory_->build_whep_answer(
        stream_id, *offer_summary, publisher->remote_offer_summary(), outbound_media_sources, (*local_udp_port)->port());
    if (!generated_answer)
    {
        WEBRTC_LOG_WARN("WHEP build SDP answer failed stream={} error={}", stream_id, generated_answer.error());
        return json_error_response(
            request, 400, k_whep_sdp_answer_failed_error, make_prefixed_error("failed to build sdp answer: ", generated_answer.error()));
    }

    auto runtime_offer = sdp::make_offer_summary(*offer_summary, generated_answer->accepted_mline_indexes);

    if (!runtime_offer)
    {
        WEBRTC_LOG_WARN("WHEP runtime subscriber offer filter failed stream={} error={}", stream_id, runtime_offer.error());
        return json_error_response(request,
                                   400,
                                   k_whep_runtime_offer_filter_failed_error,
                                   make_prefixed_error("failed to filter runtime subscriber offer: ", runtime_offer.error()));
    }

    auto accepted_outbound_media_sources = filter_whep_outbound_media_sources(outbound_media_sources, generated_answer->accepted_mline_indexes);

    whep_rtp_rewriter_target rewriter_target{
        .subscriber_offer = *offer_summary,
        .accepted_mline_indexes = generated_answer->accepted_mline_indexes,
        .accepted_media_sources = accepted_outbound_media_sources,
    };

    auto rewriter_config = make_whep_rtp_rewriter_config(publisher->session_id(), publisher->remote_offer_summary(), rewriter_target);

    if (!rewriter_config)
    {
        WEBRTC_LOG_WARN("WHEP build RTP rewrite mapping failed stream={} publisher_session={} error={}",
                        stream_id,
                        publisher->session_id(),
                        rewriter_config.error());
        return json_error_response(
            request, 400, k_whep_sdp_answer_failed_error, make_prefixed_error("failed to build rtp rewrite mapping: ", rewriter_config.error()));
    }

    auto session_result = registry_->create_subscriber_session(std::string(stream_id), std::move(*runtime_offer));
    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::publisher_not_found)
        {
            WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

            return json_error_response(request, 404, k_whep_publisher_not_found_error, "publisher not found");
        }
        WEBRTC_LOG_ERROR("WHEP create subscriber failed stream={} error={}", stream_id, stream_registry_error_to_string(error));
        return json_error_response(request, 500, k_whep_create_session_failed_error, "create subscriber session failed");
    }

    const auto& session = *session_result;
    const std::string subscriber_session_id = session->session_id();
    const std::string subscriber_stream_id = session->stream_id();
    const std::weak_ptr<stream_registry> weak_registry = registry_;

    transport->start_inactivity_monitor(std::chrono::seconds(config_.session_inactivity_timeout_seconds),
                                        [weak_registry, subscriber_session_id]()
                                        {
                                            const auto registry = weak_registry.lock();

                                            if (registry == nullptr)
                                            {
                                                return;
                                            }

                                            const auto session = registry->find_subscriber_by_session_id(subscriber_session_id);
                                            auto result = registry->remove_subscriber_session(subscriber_session_id);

                                            if (session == nullptr || !result)
                                            {
                                                return;
                                            }

                                            session->close("inactivity_timeout");
                                        });
    transport->set_publisher_recovery_timeout(std::chrono::seconds(config_.publisher_recovery_timeout_seconds),
                                              [weak_registry, subscriber_stream_id](std::string_view reason)
                                              {
                                                  const auto registry = weak_registry.lock();

                                                  if (registry == nullptr)
                                                  {
                                                      return;
                                                  }

                                                  auto sessions = registry->remove_subscriber_sessions_by_stream_id(subscriber_stream_id);

                                                  for (const auto& current_session : sessions)
                                                  {
                                                      current_session->close(reason);
                                                  }
                                              });

    session->complete_initial_setup(std::move(generated_answer->local_ice),
                                    std::move(generated_answer->accepted_mline_indexes),
                                    std::move(accepted_outbound_media_sources),
                                    std::move(rewriter_target),
                                    std::move(*local_udp_port),
                                    std::move(transport));

    WEBRTC_LOG_INFO(
        "WHEP create subscriber stream={} session={} rtp_session=new sdp_size={} offer_media_count={} accepted_media_count={} "
        "outbound_media_source_count={}",
        session->stream_id(),
        session->session_id(),
        generated_answer->sdp.size(),
        offer_summary->media.size(),
        session->remote_offer_summary().media.size(),
        session->outbound_media_sources().size());

    auto response = make_sdp_http_response(request, 201, generated_answer->sdp);
    const std::string session_location_path = "/whep/session/" + session->session_id();
    response->set(http::field::location, session_location_path);
    set_session_resource_headers(response, *session, config_.ice_server_link_header);
    return response;
}
http_response_ptr whep_handler::patch_session(http_request_t& request, std::string_view session_id)
{
    auto session = registry_->find_subscriber_by_session_id(session_id);

    return handle_trickle_ice_patch_request(
        request,
        session_id,
        session,
        "WHEP",
        "subscriber session not found",
        [this, &request](int status, std::string_view error_code, std::string_view message) -> http_response_ptr
        {
            if (error_code == "trickle_ice_session_not_found")
            {
                return json_error_response(request, status, k_whep_session_not_found_error, message);
            }

            if (error_code == "trickle_ice_precondition_failed")
            {
                return json_error_response(request, status, k_whep_precondition_failed_error, message);
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

http_response_ptr whep_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHEP delete session={}", session_id);

    auto session = registry_->find_subscriber_by_session_id(session_id);

    if (session == nullptr)
    {
        return json_error_response(request, 404, k_whep_session_not_found_error, "subscriber session not found");
    }
    auto result = registry_->remove_subscriber_session(session_id);
    if (!result)
    {
        if (result.error() == stream_registry_error::subscriber_session_not_found)
        {
            return json_error_response(request, 404, k_whep_session_not_found_error, "subscriber session not found");
        }

        WEBRTC_LOG_ERROR("WHEP delete subscriber failed session={} error={}", session_id, stream_registry_error_to_string(result.error()));
        return json_error_response(request, 500, k_whep_delete_session_failed_error, "delete subscriber session failed");
    }

    session->close("whep_delete");
    auto response = create_response(request, 204, "");

    add_http_common_headers(response);

    return response;
}

http_response_ptr whep_handler::json_error_response(http_request_t& request, int code, std::string_view message)
{
    return json_error_response(request, code, "whep_error", message);
}

http_response_ptr whep_handler::json_error_response(http_request_t& request, int code, std::string_view error_code, std::string_view message)
{
    return make_json_http_error_response(request, code, error_code, message);
}

}    // namespace webrtc
