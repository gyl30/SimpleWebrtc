#include "server/whep_handler.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <optional>

#include <boost/beast/http.hpp>

#include "log/log.h"
#include "net/http.h"
#include "server/signaling_json.h"
#include "server/trickle_ice_http.h"
#include "server/trickle_ice_patch_handler.h"
#include "signaling/sdp/sdp_offer_validator.h"
#include "signaling/sdp/sdp_parser.h"
#include "signaling/sdp/sdp_summary.h"
#include "signaling/webrtc_answer_factory.h"

namespace webrtc
{
namespace
{
namespace http = boost::beast::http;

constexpr std::string_view k_cors_private_network_header = "Access-Control-Allow-Private-Network";

std::string make_prefixed_error(std::string_view prefix, std::string_view error)
{
    std::string message;

    message.reserve(prefix.size() + error.size());

    message.append(prefix);

    message.append(error);

    return message;
}
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool contains_mid(const std::vector<std::string>& mids, std::string_view mid)
{
    for (const auto& current : mids)
    {
        if (current == mid)
        {
            return true;
        }
    }

    return false;
}

std::expected<std::vector<std::string>, std::string> collect_accepted_answer_mids(std::string_view answer_sdp)
{
    auto answer_description = sdp::parse_session_description(answer_sdp);

    if (!answer_description)
    {
        std::string message = "accepted media parse answer failed: ";

        message.append(answer_description.error());

        return std::unexpected(std::move(message));
    }

    std::vector<std::string> accepted_mids;

    for (const auto& media : answer_description->media_descriptions)
    {
        if (media.media_name.port.value == 0)
        {
            continue;
        }

        const std::optional<std::string> mid = media.find_attribute_value("mid");

        if (!mid.has_value() || mid->empty())
        {
            return make_error("accepted answer media is missing mid");
        }

        if (contains_mid(accepted_mids, *mid))
        {
            return make_error("accepted answer media mid is duplicated");
        }

        accepted_mids.push_back(*mid);
    }

    if (accepted_mids.empty())
    {
        return make_error("answer has no accepted media");
    }

    return accepted_mids;
}

std::expected<sdp::webrtc_offer_summary, std::string> make_runtime_subscriber_offer_summary(const sdp::webrtc_offer_summary& original_offer,
                                                                                            std::string_view answer_sdp)
{
    auto accepted_mids = collect_accepted_answer_mids(answer_sdp);

    if (!accepted_mids)
    {
        return std::unexpected(accepted_mids.error());
    }

    sdp::webrtc_offer_summary runtime_offer = original_offer;

    runtime_offer.bundle_mids.clear();
    runtime_offer.media.clear();

    for (const auto& mid : *accepted_mids)
    {
        bool media_found = false;

        for (const auto& media : original_offer.media)
        {
            if (media.mid != mid)
            {
                continue;
            }

            runtime_offer.media.push_back(media);

            media_found = true;

            break;
        }

        if (!media_found)
        {
            std::string message = "accepted answer mid not found in subscriber offer mid=";

            message.append(mid);

            return std::unexpected(std::move(message));
        }
    }

    for (const auto& mid : original_offer.bundle_mids)
    {
        if (!contains_mid(*accepted_mids, mid))
        {
            continue;
        }

        runtime_offer.bundle_mids.push_back(mid);
    }

    if (runtime_offer.bundle_mids.empty())
    {
        for (const auto& mid : *accepted_mids)
        {
            runtime_offer.bundle_mids.push_back(mid);
        }
    }

    return runtime_offer;
}
}    // namespace

whep_handler::whep_handler(std::shared_ptr<stream_registry> registry, std::shared_ptr<webrtc_answer_factory> answer_factory)
    : registry_(std::move(registry)), answer_factory_(std::move(answer_factory))
{
}

http_response_ptr whep_handler::create_subscriber(http_request_t& request, std::string_view stream_id)
{
    const std::string& offer = request.req.body();

    auto description = sdp::parse_session_description(offer);

    if (!description)
    {
        WEBRTC_LOG_WARN("WHEP parse SDP offer failed stream={} error={}", stream_id, description.error());

        return json_error_response(request, 400, make_prefixed_error("invalid sdp offer: ", description.error()));
    }

    WEBRTC_LOG_INFO("WHEP parsed SDP offer stream={} media_count={}", stream_id, description->media_descriptions.size());

    auto offer_summary = sdp::extract_webrtc_offer_summary(*description);

    if (!offer_summary)
    {
        WEBRTC_LOG_WARN("WHEP extract WebRTC offer failed stream={} error={}", stream_id, offer_summary.error());

        return json_error_response(request, 400, make_prefixed_error("invalid webrtc offer: ", offer_summary.error()));
    }

    auto validation_result = sdp::validate_whep_offer(*offer_summary);

    if (!validation_result)
    {
        WEBRTC_LOG_WARN("WHEP validate WebRTC offer failed stream={} error={}", stream_id, validation_result.error());

        return json_error_response(request, 400, make_prefixed_error("invalid whep offer: ", validation_result.error()));
    }

    WEBRTC_LOG_INFO("WHEP validated WebRTC offer stream={} bundle_mid_count={} media_count={} ice_ufrag_size={}",
                    stream_id,
                    offer_summary->bundle_mids.size(),
                    offer_summary->media.size(),
                    offer_summary->ice_ufrag.size());

    if (answer_factory_ == nullptr)
    {
        WEBRTC_LOG_ERROR("WHEP answer factory is not configured stream={}", stream_id);

        return json_error_response(request, 500, "answer factory is not configured");
    }

    auto publisher = registry_->find_publisher_by_stream_id(stream_id);

    if (publisher == nullptr)
    {
        WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

        return json_error_response(request, 404, "publisher not found");
    }

    auto generated_answer = answer_factory_->build_whep_answer(stream_id, *offer_summary, publisher->remote_offer_summary());
    if (!generated_answer)
    {
        WEBRTC_LOG_WARN("WHEP build SDP answer failed stream={} error={}", stream_id, generated_answer.error());

        return json_error_response(request, 400, make_prefixed_error("failed to build sdp answer: ", generated_answer.error()));
    }

    auto runtime_offer_summary = make_runtime_subscriber_offer_summary(*offer_summary, generated_answer->sdp);

    if (!runtime_offer_summary)
    {
        WEBRTC_LOG_WARN("WHEP runtime subscriber offer summary failed stream={} error={}", stream_id, runtime_offer_summary.error());

        return json_error_response(
            request, 400, make_prefixed_error("failed to build runtime subscriber offer summary: ", runtime_offer_summary.error()));
    }

    auto session_result = registry_->create_subscriber_session(std::string(stream_id), offer, std::move(*runtime_offer_summary));
    if (!session_result)
    {
        const auto error = session_result.error();

        if (error == stream_registry_error::publisher_not_found)
        {
            WEBRTC_LOG_WARN("WHEP create subscriber failed stream={} publisher not found", stream_id);

            return json_error_response(request, 404, "publisher not found");
        }

        WEBRTC_LOG_ERROR("WHEP create subscriber failed stream={} error={}", stream_id, stream_registry_error_to_string(error));

        return json_error_response(request, 500, "create subscriber session failed");
    }

    const auto& session = *session_result;

    session->set_local_answer(std::move(generated_answer->sdp),
                              std::move(generated_answer->local_ice),
                              std::move(generated_answer->local_fingerprint),
                              generated_answer->sdp_session_id,
                              generated_answer->sdp_session_version);
    WEBRTC_LOG_INFO("WHEP create subscriber stream={} session={} sdp_size={} offer_media_count={} accepted_media_count={}",
                    session->stream_id(),
                    session->session_id(),
                    offer.size(),
                    offer_summary->media.size(),
                    session->remote_offer_summary().media.size());

    auto response = sdp_response(request, 201, session->local_sdp_answer());

    response->set(http::field::location, "/whep/session/" + session->session_id());

    set_session_resource_headers(response, *session);

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
        [this, &request](int status, std::string_view message) -> http_response_ptr { return json_error_response(request, status, message); },
        [this, &request](const auto& updated_session) -> http_response_ptr
        {
            auto response = create_response(request, 204, "");

            add_common_headers(response);

            set_session_resource_headers(response, updated_session);

            return response;
        });
}

http_response_ptr whep_handler::delete_session(http_request_t& request, std::string_view session_id)
{
    WEBRTC_LOG_INFO("WHEP delete session={}", session_id);

    auto session = registry_->find_subscriber_by_session_id(session_id);

    if (session == nullptr)
    {
        return json_error_response(request, 404, "subscriber session not found");
    }

    auto precondition = validate_session_if_match(request, *session);

    if (!precondition)
    {
        WEBRTC_LOG_WARN("WHEP delete session precondition failed session={} error={}", session_id, precondition.error());

        return json_error_response(request, 412, precondition.error());
    }

    auto result = registry_->remove_subscriber_session(session_id);

    if (!result)
    {
        if (result.error() == stream_registry_error::subscriber_session_not_found)
        {
            return json_error_response(request, 404, "subscriber session not found");
        }

        WEBRTC_LOG_ERROR("WHEP delete subscriber failed session={} error={}", session_id, stream_registry_error_to_string(result.error()));

        return json_error_response(request, 500, "delete subscriber session failed");
    }

    auto response = create_response(request, 204, "");

    add_common_headers(response);

    return response;
}

http_response_ptr whep_handler::json_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    content.push_back('\n');

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "application/json; charset=utf-8");

    add_common_headers(response);

    return response;
}

http_response_ptr whep_handler::json_error_response(http_request_t& request, int code, std::string_view message)
{
    return json_response(request, code, make_error_response_body(message));
}

http_response_ptr whep_handler::sdp_response(http_request_t& request, int code, std::string_view body)
{
    std::string content(body);

    auto response = create_response(request, code, content);

    response->set(http::field::content_type, "application/sdp");

    add_common_headers(response);

    return response;
}

void whep_handler::add_common_headers(const http_response_ptr& response)
{
    if (response == nullptr)
    {
        return;
    }

    response->set(http::field::access_control_allow_origin, "*");

    response->set(http::field::access_control_expose_headers, std::string(k_trickle_ice_expose_headers_value));

    response->set(std::string(k_cors_private_network_header), "true");

    response->set(http::field::cache_control, "no-store");

    set_trickle_ice_patch_headers(response);
}

}    // namespace webrtc
