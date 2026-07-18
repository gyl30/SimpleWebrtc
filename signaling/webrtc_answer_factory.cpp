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
using validation_result = std::expected<void, std::string>;

inline constexpr std::string_view k_local_stream_id_prefix = "webrtc";

std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

bool contains_whitespace(std::string_view value)
{
    for (const auto ch : value)
    {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            return true;
        }
    }

    return false;
}

validation_result validate_token(std::string_view value, std::string_view name)
{
    if (value.empty())
    {
        std::string message(name);
        message.append(" is empty");
        return std::unexpected(std::move(message));
    }

    if (contains_whitespace(value))
    {
        std::string message(name);
        message.append(" contains whitespace");
        return std::unexpected(std::move(message));
    }

    return {};
}

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

    if (result.empty())
    {
        return "default";
    }

    return result;
}

std::string make_local_stream_id(std::string_view prefix, std::string_view stream_id)
{
    const std::string safe_stream_id = make_safe_stream_id(stream_id);

    std::string value;
    value.reserve(prefix.size() + safe_stream_id.size() + 1);

    value.append(prefix);

    if (!safe_stream_id.empty())
    {
        value.push_back('-');
        value.append(safe_stream_id);
    }

    return value;
}

void normalize_answer_media_sources(std::vector<sdp::sdp_answer_media_source>& media_sources, std::string_view local_stream_id)
{
    for (auto& source : media_sources)
    {
        if (source.stream_id.empty())
        {
            source.stream_id = std::string(local_stream_id);
        }

        if (source.track_id.empty())
        {
            source.track_id.reserve(source.kind.size() + source.mid.size() + 1);
            source.track_id.append(source.kind);
            source.track_id.push_back('-');
            source.track_id.append(source.mid);
        }
    }
}

bool answer_sdp_contains_media_source_attributes(std::string_view answer_sdp, const sdp::sdp_answer_media_source& source)
{
    if (source.ssrc == 0)
    {
        return true;
    }

    const std::string ssrc = std::to_string(source.ssrc);

    std::string cname_line;

    cname_line.reserve(ssrc.size() + 16);

    cname_line.append("a=ssrc:");
    cname_line.append(ssrc);
    cname_line.append(" cname:");

    if (answer_sdp.find(cname_line) == std::string_view::npos)
    {
        return false;
    }

    std::string msid_line;

    msid_line.reserve(ssrc.size() + 15);

    msid_line.append("a=ssrc:");
    msid_line.append(ssrc);
    msid_line.append(" msid:");

    if (answer_sdp.find(msid_line) == std::string_view::npos)
    {
        return false;
    }

    return true;
}

bool answer_sdp_contains_all_media_source_attributes(std::string_view answer_sdp, const std::vector<sdp::sdp_answer_media_source>& media_sources)
{
    for (const auto& source : media_sources)
    {
        if (!answer_sdp_contains_media_source_attributes(answer_sdp, source))
        {
            return false;
        }
    }

    return true;
}

std::string make_candidate_field_name(std::string_view prefix, std::string_view field)
{
    std::string value;

    value.reserve(prefix.size() + field.size() + 1);

    value.append(prefix);
    value.push_back(' ');
    value.append(field);

    return value;
}

std::vector<sdp::sdp_ice_candidate_options> make_local_ice_candidates(const webrtc_answer_factory_config& config, uint16_t local_candidate_port)
{
    std::vector<sdp::sdp_ice_candidate_options> candidates = config.ice_candidates;

    if (local_candidate_port == 0)
    {
        return candidates;
    }

    for (auto& candidate : candidates)
    {
        candidate.port = local_candidate_port;
    }

    return candidates;
}

validation_result validate_ice_candidate_config(const sdp::sdp_ice_candidate_options& candidate, std::string_view prefix)
{
    auto address_result = validate_token(candidate.address, make_candidate_field_name(prefix, "address"));

    if (!address_result)
    {
        return std::unexpected(address_result.error());
    }

    if (candidate.port == 0)
    {
        return make_error(make_candidate_field_name(prefix, "port is zero"));
    }

    auto foundation_result = validate_token(candidate.foundation, make_candidate_field_name(prefix, "foundation"));

    if (!foundation_result)
    {
        return std::unexpected(foundation_result.error());
    }

    if (candidate.component == 0)
    {
        return make_error(make_candidate_field_name(prefix, "component is zero"));
    }

    auto transport_result = validate_token(candidate.transport, make_candidate_field_name(prefix, "transport"));

    if (!transport_result)
    {
        return std::unexpected(transport_result.error());
    }

    if (candidate.priority == 0)
    {
        return make_error(make_candidate_field_name(prefix, "priority is zero"));
    }

    auto type_result = validate_token(candidate.type, make_candidate_field_name(prefix, "type"));

    if (!type_result)
    {
        return std::unexpected(type_result.error());
    }

    return {};
}

validation_result validate_ice_candidates_config(const webrtc_answer_factory_config& config)
{
    if (config.ice_candidates.empty())
    {
        return make_error("ice candidate list is empty");
    }

    for (std::size_t index = 0; index < config.ice_candidates.size(); ++index)
    {
        std::string prefix("ice candidate ");

        prefix.append(std::to_string(index));

        auto result = validate_ice_candidate_config(config.ice_candidates[index], prefix);

        if (!result)
        {
            return std::unexpected(result.error());
        }
    }

    return {};
}
}    // namespace

webrtc_answer_factory::webrtc_answer_factory(webrtc_answer_factory_config config)
    : config_(std::move(config)), next_session_id_(make_initial_session_id())
{
}
generated_sdp_answer_result webrtc_answer_factory::build_whip_answer(std::string_view stream_id,
                                                                     const sdp::webrtc_offer_summary& offer,
                                                                     uint16_t local_candidate_port)
{
    return build_answer(true, stream_id, offer, nullptr, {}, local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_whep_answer(std::string_view stream_id,
                                                                     const sdp::webrtc_offer_summary& subscriber_offer,
                                                                     const sdp::webrtc_offer_summary& publisher_offer,
                                                                     std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                     uint16_t local_candidate_port)
{
    return build_answer(false, stream_id, subscriber_offer, &publisher_offer, std::move(media_sources), local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_whip_restart_answer(std::string_view stream_id,
                                                                             const sdp::webrtc_offer_summary& offer,
                                                                             uint64_t sdp_session_id,
                                                                             uint64_t sdp_session_version,
                                                                             uint16_t local_candidate_port)
{
    return build_answer_with_origin(true, stream_id, offer, nullptr, sdp_session_id, sdp_session_version, {}, local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_whep_restart_answer(std::string_view stream_id,
                                                                             const sdp::webrtc_offer_summary& subscriber_offer,
                                                                             const sdp::webrtc_offer_summary& publisher_offer,
                                                                             uint64_t sdp_session_id,
                                                                             uint64_t sdp_session_version,
                                                                             std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                             uint16_t local_candidate_port)
{
    return build_answer_with_origin(false,
                                    stream_id,
                                    subscriber_offer,
                                    &publisher_offer,
                                    sdp_session_id,
                                    sdp_session_version,
                                    std::move(media_sources),
                                    local_candidate_port);
}

validation_result webrtc_answer_factory::validate_config() const
{
    auto fingerprint_algorithm_result = validate_token(config_.local_fingerprint.algorithm, "local fingerprint algorithm");

    if (!fingerprint_algorithm_result)
    {
        return std::unexpected(fingerprint_algorithm_result.error());
    }

    auto fingerprint_value_result = validate_token(config_.local_fingerprint.value, "local fingerprint value");

    if (!fingerprint_value_result)
    {
        return std::unexpected(fingerprint_value_result.error());
    }

    return validate_ice_candidates_config(config_);
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

    options.media_address = config_.ice_candidates.front().address;

    options.local_ice_ufrag = local_ice.ufrag;
    options.local_ice_pwd = local_ice.pwd;
    options.local_fingerprint = config_.local_fingerprint;

    options.local_candidates = make_local_ice_candidates(config_, local_candidate_port);
    options.local_stream_id = make_local_stream_id(k_local_stream_id_prefix, stream_id);

    return options;
}

generated_sdp_answer_result webrtc_answer_factory::build_answer(bool is_whip,
                                                                std::string_view stream_id,
                                                                const sdp::webrtc_offer_summary& offer,
                                                                const sdp::webrtc_offer_summary* whep_publisher_offer,
                                                                std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                uint16_t local_candidate_port)
{
    const uint64_t session_id = next_session_id_.fetch_add(1, std::memory_order_relaxed);

    const uint64_t session_version = 1;

    return build_answer_with_origin(
        is_whip, stream_id, offer, whep_publisher_offer, session_id, session_version, std::move(media_sources), local_candidate_port);
}

generated_sdp_answer_result webrtc_answer_factory::build_answer_with_origin(bool is_whip,
                                                                            std::string_view stream_id,
                                                                            const sdp::webrtc_offer_summary& offer,
                                                                            const sdp::webrtc_offer_summary* whep_publisher_offer,
                                                                            uint64_t sdp_session_id,
                                                                            uint64_t sdp_session_version,
                                                                            std::vector<sdp::sdp_answer_media_source> media_sources,
                                                                            uint16_t local_candidate_port)
{
    if (sdp_session_id == 0)
    {
        return make_error("sdp session id is zero");
    }

    if (sdp_session_version == 0)
    {
        return make_error("sdp session version is zero");
    }

    auto config_result = validate_config();

    if (!config_result)
    {
        return std::unexpected(config_result.error());
    }

    auto local_ice = generate_ice_credentials();

    if (!local_ice)
    {
        return std::unexpected(local_ice.error());
    }

    auto options = make_answer_options(stream_id, *local_ice, sdp_session_id, sdp_session_version, local_candidate_port);

    options.media_sources = std::move(media_sources);

    normalize_answer_media_sources(options.media_sources, options.local_stream_id);

    if (!is_whip && whep_publisher_offer == nullptr)
    {
        return make_error("whep publisher offer is missing");
    }

    sdp::sdp_answer_text_result answer_sdp = is_whip ? sdp::build_whip_answer_sdp(offer, options)
                                                     : sdp::build_whep_answer_sdp(offer, *whep_publisher_offer, options);

    if (!answer_sdp)
    {
        return std::unexpected(answer_sdp.error());
    }

    if (!is_whip && !options.media_sources.empty() && !answer_sdp_contains_all_media_source_attributes(*answer_sdp, options.media_sources))
    {
        return make_error("whep answer media sources were provided but ssrc attributes were not generated");
    }

    generated_sdp_answer answer;
    answer.sdp = std::move(*answer_sdp);
    answer.local_ice = std::move(*local_ice);
    answer.sdp_session_id = sdp_session_id;
    answer.sdp_session_version = sdp_session_version;
    answer.media_sources = std::move(options.media_sources);

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
