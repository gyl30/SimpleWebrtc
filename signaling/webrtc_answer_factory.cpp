#include "signaling/webrtc_answer_factory.h"

#include <chrono>
#include <cctype>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ice/ice_credentials.h"
#include "signaling/sdp/sdp_answer_builder.h"

namespace webrtc
{
namespace
{
bool is_safe_stream_id_char(char ch)
{
    const auto value = static_cast<unsigned char>(ch);

    if (std::isalnum(value) != 0)
    {
        return true;
    }

    return ch == '-' || ch == '_' || ch == '.';
}

std::string make_safe_stream_id(std::string_view stream_id)
{
    if (stream_id.empty())
    {
        return "default";
    }

    std::string result;
    result.reserve(stream_id.size());

    for (const auto ch : stream_id)
    {
        if (is_safe_stream_id_char(ch))
        {
            result.push_back(ch);
        }
        else
        {
            result.push_back('_');
        }
    }

    return result;
}

std::string make_local_stream_id(std::string_view stream_id)
{
    const std::string safe_stream_id = make_safe_stream_id(stream_id);

    std::string value = "webrtc";
    value.reserve(value.size() + safe_stream_id.size() + 1);

    value.push_back('-');
    value.append(safe_stream_id);

    return value;
}

}    // namespace

webrtc_answer_factory::webrtc_answer_factory(sdp::fingerprint_info local_fingerprint,
                                               std::vector<std::string> ice_candidate_addresses)
    : local_fingerprint_(std::move(local_fingerprint)),
      ice_candidate_addresses_(std::move(ice_candidate_addresses)),
      next_session_id_(make_initial_session_id())
{
}
generated_sdp_answer_result webrtc_answer_factory::build_whip_answer(std::string_view stream_id,
                                                                     const sdp::webrtc_offer_summary& offer,
                                                                     uint16_t local_candidate_port)
{
    return build_answer(stream_id, offer, nullptr, {}, local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_whep_answer(std::string_view stream_id,
                                                                     const sdp::webrtc_offer_summary& subscriber_offer,
                                                                     const sdp::webrtc_offer_summary& publisher_offer,
                                                                     std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                     uint16_t local_candidate_port)
{
    return build_answer(stream_id, subscriber_offer, &publisher_offer, std::move(media_sources), local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_whip_restart_answer(std::string_view stream_id,
                                                                             const sdp::webrtc_offer_summary& offer,
                                                                             uint64_t sdp_session_id,
                                                                             uint64_t sdp_session_version,
                                                                             uint16_t local_candidate_port)
{
    return build_answer_with_origin(stream_id, offer, nullptr, sdp_session_id, sdp_session_version, {}, local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_whep_restart_answer(std::string_view stream_id,
                                                                             const sdp::webrtc_offer_summary& subscriber_offer,
                                                                             const sdp::webrtc_offer_summary& publisher_offer,
                                                                             uint64_t sdp_session_id,
                                                                             uint64_t sdp_session_version,
                                                                             std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                             uint16_t local_candidate_port)
{
    return build_answer_with_origin(stream_id,
                                    subscriber_offer,
                                    &publisher_offer,
                                    sdp_session_id,
                                    sdp_session_version,
                                    std::move(media_sources),
                                    local_candidate_port);
}

sdp::sdp_answer_options webrtc_answer_factory::make_answer_options(std::string_view stream_id,
                                                                   const ice_credentials& local_ice,
                                                                   uint64_t session_id,
                                                                   uint64_t session_version,
                                                                   uint16_t local_candidate_port) const
{
    sdp::sdp_answer_options options;

    options.session_id = session_id;
    options.session_version = session_version;

    options.local_ice_ufrag = local_ice.ufrag;
    options.local_ice_pwd = local_ice.pwd;
    options.local_fingerprint = local_fingerprint_;

    options.local_candidate_addresses = ice_candidate_addresses_;
    options.local_candidate_port = local_candidate_port;
    options.local_stream_id = make_local_stream_id(stream_id);

    return options;
}

generated_sdp_answer_result webrtc_answer_factory::build_answer(std::string_view stream_id,
                                                                const sdp::webrtc_offer_summary& offer,
                                                                const sdp::webrtc_offer_summary* whep_publisher_offer,
                                                                std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                uint16_t local_candidate_port)
{
    const uint64_t session_id = next_session_id_.fetch_add(1, std::memory_order_relaxed);

    const uint64_t session_version = 1;

    return build_answer_with_origin(
        stream_id, offer, whep_publisher_offer, session_id, session_version, std::move(media_sources), local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_answer_with_origin(std::string_view stream_id,
                                                                            const sdp::webrtc_offer_summary& offer,
                                                                            const sdp::webrtc_offer_summary* whep_publisher_offer,
                                                                            uint64_t sdp_session_id,
                                                                            uint64_t sdp_session_version,
                                                                            std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                            uint16_t local_candidate_port)
{
    auto local_ice = generate_ice_credentials();

    if (!local_ice)
    {
        return std::unexpected(local_ice.error());
    }

    auto options = make_answer_options(stream_id, *local_ice, sdp_session_id, sdp_session_version, local_candidate_port);

    options.media_sources = std::move(media_sources);

    sdp::sdp_answer_text_result answer_sdp = whep_publisher_offer == nullptr
                                                 ? sdp::build_whip_answer_sdp(offer, options)
                                                 : sdp::build_whep_answer_sdp(offer, *whep_publisher_offer, options);

    if (!answer_sdp)
    {
        return std::unexpected(answer_sdp.error());
    }

    generated_sdp_answer answer;
    answer.sdp = std::move(answer_sdp->sdp);
    answer.local_ice = std::move(*local_ice);
    answer.sdp_session_id = sdp_session_id;
    answer.sdp_session_version = sdp_session_version;
    answer.media_sources = std::move(options.media_sources);
    answer.accepted_mids = std::move(answer_sdp->accepted_mids);
    answer.accepted_mline_indexes = std::move(answer_sdp->accepted_mline_indexes);

    return answer;
}

uint64_t webrtc_answer_factory::make_initial_session_id()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();

    const auto value = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();

    if (value <= 0)
    {
        return 1;
    }

    return static_cast<uint64_t>(value);
}
}    // namespace webrtc
