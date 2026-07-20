#ifndef SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_PATCH_HANDLER_H
#define SIMPLE_WEBRTC_SERVER_TRICKLE_ICE_PATCH_HANDLER_H

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include <boost/algorithm/string.hpp>

#include "log/log.h"
#include "net/http.h"
#include "ice/ice_candidate.h"
#include "server/trickle_ice_http.h"
#include "server/trickle_ice_metrics.h"
#include "server/trickle_ice_sdpfrag.h"

namespace webrtc
{
namespace trickle_ice_patch_detail
{
inline constexpr std::string_view k_application_trickle_ice_sdpfrag = "application/trickle-ice-sdpfrag";

inline std::string_view beast_string_view_to_std_string_view(boost::beast::string_view value) { return {value.data(), value.size()}; }

inline std::string_view request_content_type(http_request_t& request)
{
    const auto content_type_field = request.req[boost::beast::http::field::content_type];

    return beast_string_view_to_std_string_view(content_type_field);
}

inline trickle_ice_patch_content_kind content_kind_from_request(http_request_t& request)
{
    std::string_view content_type = boost::algorithm::trim_copy(request_content_type(request));

    const std::size_t semicolon = content_type.find(';');

    if (semicolon != std::string_view::npos)
    {
        content_type = boost::algorithm::trim_copy(content_type.substr(0, semicolon));
    }

    if (boost::algorithm::iequals(content_type, k_application_trickle_ice_sdpfrag))
    {
        return trickle_ice_patch_content_kind::kSdpfrag;
    }

    return trickle_ice_patch_content_kind::kUnsupported;
}

inline std::string describe_content_type(http_request_t& request, trickle_ice_patch_content_kind content_kind)
{
    switch (content_kind)
    {
        case trickle_ice_patch_content_kind::kSdpfrag:
            return std::string(k_application_trickle_ice_sdpfrag);

        case trickle_ice_patch_content_kind::kUnsupported:
            break;
    }

    const std::string_view content_type = request_content_type(request);

    return std::string(content_type.data(), content_type.size());
}

template <typename session_type>
bool remote_ice_candidate_media_is_accepted(const session_type& session, const remote_ice_candidate& candidate)
{
    const bool has_mid = !candidate.sdp_mid.empty();
    const bool has_mline_index = candidate.sdp_mline_index >= 0;

    if (!has_mid && !has_mline_index)
    {
        return false;
    }

    const auto& accepted_mline_indexes = session.accepted_remote_media_mline_indexes();
    const auto& media_values = session.remote_offer_summary().media;

    for (std::size_t index = 0; index < media_values.size(); ++index)
    {
        if (has_mid && media_values[index].mid != candidate.sdp_mid)
        {
            continue;
        }

        if (has_mline_index && accepted_mline_indexes[index] != candidate.sdp_mline_index)
        {
            continue;
        }

        return true;
    }

    return false;
}

inline bool remote_ice_candidate_matches(const remote_ice_candidate& left, const remote_ice_candidate& right)
{
    return left.end_of_candidates == right.end_of_candidates && left.candidate == right.candidate && left.sdp_mid == right.sdp_mid &&
           left.sdp_mline_index == right.sdp_mline_index;
}

template <typename session_type>
bool remote_ice_candidate_already_known(const session_type& session, const remote_ice_candidate& candidate)
{
    if (candidate.end_of_candidates && session.remote_ice_completed())
    {
        return true;
    }

    for (const auto& existing_candidate : session.remote_ice_candidates())
    {
        if (remote_ice_candidate_matches(existing_candidate, candidate))
        {
            return true;
        }
    }

    return false;
}

}    // namespace trickle_ice_patch_detail

template <typename session_ptr_type, typename error_response_callback, typename success_response_callback>
http_response_ptr handle_trickle_ice_patch_request(http_request_t& request,
                                                   std::string_view session_id,
                                                   session_ptr_type session,
                                                   std::string_view protocol_name,
                                                   std::string_view session_not_found_message,
                                                   error_response_callback&& make_error_response,
                                                   success_response_callback&& make_success_response)
{
    const trickle_ice_patch_content_kind content_kind = trickle_ice_patch_detail::content_kind_from_request(request);

    WEBRTC_LOG_INFO("{} patch session={} body_size={} content_type={}",
                    protocol_name,
                    session_id,
                    request.req.body().size(),
                    trickle_ice_patch_detail::describe_content_type(request, content_kind));

    global_trickle_ice_metrics().record_patch_request(content_kind);

    auto fail = [&](int status, std::string_view error_code, std::string_view message) -> http_response_ptr
    {
        global_trickle_ice_metrics().record_patch_failed();

        return make_error_response(status, error_code, message);
    };
    if (content_kind == trickle_ice_patch_content_kind::kUnsupported)
    {
        return fail(415,
                    "trickle_ice_unsupported_media_type",
                    "unsupported media type, expected application/trickle-ice-sdpfrag");
    }

    if (request.req.body().size() > k_trickle_ice_max_patch_body_bytes)
    {
        WEBRTC_LOG_WARN("{} trickle ice patch body too large session={} body_size={} limit={}",
                        protocol_name,
                        session_id,
                        request.req.body().size(),
                        k_trickle_ice_max_patch_body_bytes);

        return fail(413, "trickle_ice_body_too_large", "trickle ice patch body too large");
    }

    if (session == nullptr)
    {
        global_trickle_ice_metrics().record_session_not_found();

        return fail(404, "trickle_ice_session_not_found", session_not_found_message);
    }

    const auto if_match_field = request.req[boost::beast::http::field::if_match];

    if (if_match_field.empty())
    {
        return fail(428, "trickle_ice_precondition_required", "missing if-match header");
    }

    auto precondition = validate_session_if_match(request, *session);

    if (!precondition)
    {
        WEBRTC_LOG_WARN("{} trickle ice patch precondition failed session={} error={}", protocol_name, session_id, precondition.error());

        return fail(412, "trickle_ice_precondition_failed", precondition.error());
    }

    auto patch_body = parse_trickle_ice_sdpfrag(request.req.body());

    if (!patch_body)
    {
        global_trickle_ice_metrics().record_parse_failed();

        WEBRTC_LOG_WARN("{} trickle ice candidates invalid session={} error={}", protocol_name, session_id, patch_body.error());

        std::string message;

        message.reserve(patch_body.error().size() + 32);

        message.append("invalid trickle ice candidates: ");

        message.append(patch_body.error());

        return fail(400, "trickle_ice_invalid_candidates", message);
    }

    if (patch_body->candidates.size() > k_trickle_ice_max_candidates_per_patch)
    {
        WEBRTC_LOG_WARN("{} trickle ice patch too many candidates session={} candidates={} limit={}",
                        protocol_name,
                        session_id,
                        patch_body->candidates.size(),
                        k_trickle_ice_max_candidates_per_patch);

        return fail(413, "trickle_ice_too_many_candidates", "too many trickle ice candidates in one patch");
    }

    const auto& remote_offer = session->remote_offer_summary();
    const bool ice_restart = !patch_body->ice_ufrag.empty() &&
                             (patch_body->ice_ufrag != remote_offer.ice_ufrag || patch_body->ice_pwd != remote_offer.ice_pwd);

    if (ice_restart)
    {
        WEBRTC_LOG_WARN("{} ICE restart is unsupported session={}", protocol_name, session_id);

        return fail(422, "trickle_ice_restart_unsupported", "ICE restart is not supported");
    }

    std::size_t end_of_candidates_received_count = 0;
    std::size_t received_candidate_bytes = 0;

    for (const auto& candidate : patch_body->candidates)
    {
        end_of_candidates_received_count += candidate.end_of_candidates ? 1U : 0U;
        received_candidate_bytes += candidate.candidate.size();
    }

    global_trickle_ice_metrics().record_candidate_batch(
        patch_body->candidates.size(), end_of_candidates_received_count, received_candidate_bytes);

    std::size_t accepted_count = 0;
    std::size_t duplicate_count = 0;
    std::size_t filtered_media_count = 0;
    std::size_t end_of_candidates_count = 0;
    std::size_t accepted_candidate_bytes = 0;

    for (auto& candidate : patch_body->candidates)
    {
        const bool end_of_candidates = candidate.end_of_candidates;

        const std::size_t candidate_size = candidate.candidate.size();

        const std::string sdp_mid = candidate.sdp_mid;

        const int sdp_mline_index = candidate.sdp_mline_index;

        if (!trickle_ice_patch_detail::remote_ice_candidate_media_is_accepted(*session, candidate))
        {
            filtered_media_count += 1;

            WEBRTC_LOG_DEBUG("{} trickle ice candidate filtered by rejected media stream={} session={} mid={} mline={} end={} candidate_size={}",
                             protocol_name,
                             session->stream_id(),
                             session->session_id(),
                             sdp_mid,
                             sdp_mline_index,
                             end_of_candidates ? 1 : 0,
                             candidate_size);

            continue;
        }

        if (trickle_ice_patch_detail::remote_ice_candidate_already_known(*session, candidate))
        {
            duplicate_count += 1;

            WEBRTC_LOG_DEBUG("{} trickle ice duplicate candidate ignored stream={} session={} mid={} mline={} end={} candidate_size={}",
                             protocol_name,
                             session->stream_id(),
                             session->session_id(),
                             sdp_mid,
                             sdp_mline_index,
                             end_of_candidates ? 1 : 0,
                             candidate_size);

            continue;
        }

        auto add_result = session->add_remote_ice_candidate(std::move(candidate));

        if (!add_result)
        {
            global_trickle_ice_metrics().record_candidate_rejected();

            WEBRTC_LOG_WARN("{} trickle ice candidate rejected stream={} session={} mid={} mline={} end={} error={}",
                            protocol_name,
                            session->stream_id(),
                            session->session_id(),
                            sdp_mid,
                            sdp_mline_index,
                            end_of_candidates ? 1 : 0,
                            add_result.error());

            std::string message;

            message.reserve(add_result.error().size() + 32);

            message.append("trickle ice candidate rejected: ");

            message.append(add_result.error());

            return fail(400, "trickle_ice_candidate_rejected", message);
        }

        global_trickle_ice_metrics().record_candidate_accepted(end_of_candidates);

        accepted_count += 1;

        accepted_candidate_bytes += candidate_size;

        if (end_of_candidates)
        {
            end_of_candidates_count += 1;
        }

        WEBRTC_LOG_DEBUG("{} trickle ice candidate accepted stream={} session={} mid={} mline={} end={} candidate_size={}",
                         protocol_name,
                         session->stream_id(),
                         session->session_id(),
                         sdp_mid,
                         sdp_mline_index,
                         end_of_candidates ? 1 : 0,
                         candidate_size);
    }

    global_trickle_ice_metrics().record_patch_success();

    WEBRTC_LOG_INFO(
        "{} trickle ice patch accepted stream={} session={} candidates={} duplicates={} filtered_media={} end_of_candidates={} candidate_bytes={} "
        "total_candidates={} completed={}",
        protocol_name,
        session->stream_id(),
        session->session_id(),
        accepted_count,
        duplicate_count,
        filtered_media_count,
        end_of_candidates_count,
        accepted_candidate_bytes,
        session->remote_ice_candidates().size(),
        session->remote_ice_completed() ? 1 : 0);

    return make_success_response(*session);
}
}    // namespace webrtc

#endif
