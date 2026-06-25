#include "signaling/webrtc_answer_factory.h"

#include <chrono>
#include <cctype>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

#include "ice/ice_credentials.h"
#include "security/certificate_fingerprint.h"
#include "signaling/sdp/sdp_answer_builder.h"

namespace webrtc
{
namespace
{
using validation_result = std::expected<void, std::string>;

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

validation_result validate_dtls_setup_role(sdp::dtls_connection_role setup)
{
    switch (setup)
    {
        case sdp::dtls_connection_role::active:
        case sdp::dtls_connection_role::passive:
            return {};

        case sdp::dtls_connection_role::actpass:
            return make_error("local setup must not be actpass");

        case sdp::dtls_connection_role::holdconn:
            return make_error("local setup must not be holdconn");

        case sdp::dtls_connection_role::unknown:
            return make_error("local setup must not be unknown");
    }

    return make_error("unsupported local setup");
}
}    // namespace

webrtc_answer_factory_config_result make_webrtc_answer_factory_config_from_certificate(std::string_view certificate_file)
{
    auto fingerprint = load_certificate_fingerprint(certificate_file);

    if (!fingerprint)
    {
        return std::unexpected(fingerprint.error());
    }

    webrtc_answer_factory_config config;
    config.local_fingerprint = std::move(*fingerprint);

    return config;
}

webrtc_answer_factory::webrtc_answer_factory(webrtc_answer_factory_config config)
    : config_(std::move(config)), next_session_id_(make_initial_session_id())
{
}

generated_sdp_answer_result webrtc_answer_factory::build_whip_answer(std::string_view stream_id, const sdp::webrtc_offer_summary& offer)
{
    return build_answer(true, stream_id, offer);
}

generated_sdp_answer_result webrtc_answer_factory::build_whep_answer(std::string_view stream_id, const sdp::webrtc_offer_summary& offer)
{
    return build_answer(false, stream_id, offer);
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

    auto origin_username_result = validate_token(config_.origin_username, "origin username");

    if (!origin_username_result)
    {
        return std::unexpected(origin_username_result.error());
    }

    auto network_type_result = validate_token(config_.network_type, "network type");

    if (!network_type_result)
    {
        return std::unexpected(network_type_result.error());
    }

    auto address_type_result = validate_token(config_.address_type, "address type");

    if (!address_type_result)
    {
        return std::unexpected(address_type_result.error());
    }

    auto unicast_address_result = validate_token(config_.unicast_address, "unicast address");

    if (!unicast_address_result)
    {
        return std::unexpected(unicast_address_result.error());
    }

    auto media_address_result = validate_token(config_.media_address, "media address");

    if (!media_address_result)
    {
        return std::unexpected(media_address_result.error());
    }

    auto stream_prefix_result = validate_token(config_.local_stream_id_prefix, "local stream id prefix");

    if (!stream_prefix_result)
    {
        return std::unexpected(stream_prefix_result.error());
    }

    auto setup_result = validate_dtls_setup_role(config_.local_setup);

    if (!setup_result)
    {
        return std::unexpected(setup_result.error());
    }

    if (config_.include_host_candidate)
    {
        auto candidate_address_result = validate_token(config_.ice_candidate_address, "ice candidate address");

        if (!candidate_address_result)
        {
            return std::unexpected(candidate_address_result.error());
        }

        if (config_.ice_candidate_port == 0)
        {
            return make_error("ice candidate port is zero");
        }

        auto foundation_result = validate_token(config_.ice_candidate_foundation, "ice candidate foundation");

        if (!foundation_result)
        {
            return std::unexpected(foundation_result.error());
        }

        if (config_.ice_candidate_component == 0)
        {
            return make_error("ice candidate component is zero");
        }

        auto transport_result = validate_token(config_.ice_candidate_transport, "ice candidate transport");

        if (!transport_result)
        {
            return std::unexpected(transport_result.error());
        }

        if (config_.ice_candidate_priority == 0)
        {
            return make_error("ice candidate priority is zero");
        }

        auto type_result = validate_token(config_.ice_candidate_type, "ice candidate type");

        if (!type_result)
        {
            return std::unexpected(type_result.error());
        }
    }

    return {};
}

sdp::sdp_answer_options webrtc_answer_factory::make_answer_options(std::string_view stream_id,
                                                                   const ice_credentials& local_ice,
                                                                   uint64_t session_id,
                                                                   uint64_t session_version) const
{
    sdp::sdp_answer_options options;

    options.origin_username = config_.origin_username;
    options.session_id = session_id;
    options.session_version = session_version;

    options.network_type = config_.network_type;
    options.address_type = config_.address_type;
    options.unicast_address = config_.unicast_address;
    options.media_address = config_.media_address;

    options.local_ice_ufrag = local_ice.ufrag;
    options.local_ice_pwd = local_ice.pwd;
    options.local_fingerprint = config_.local_fingerprint;

    options.local_setup = config_.local_setup;
    options.ice_lite = config_.ice_lite;
    options.enable_trickle = config_.enable_trickle;

    options.include_host_candidate = config_.include_host_candidate;
    options.local_candidate_foundation = config_.ice_candidate_foundation;
    options.local_candidate_component = config_.ice_candidate_component;
    options.local_candidate_transport = config_.ice_candidate_transport;
    options.local_candidate_priority = config_.ice_candidate_priority;
    options.local_candidate_address = config_.ice_candidate_address;
    options.local_candidate_port = config_.ice_candidate_port;
    options.local_candidate_type = config_.ice_candidate_type;
    options.end_of_candidates = config_.end_of_candidates;

    options.local_stream_id = make_local_stream_id(config_.local_stream_id_prefix, stream_id);

    return options;
}

generated_sdp_answer_result webrtc_answer_factory::build_answer(bool is_whip, std::string_view stream_id, const sdp::webrtc_offer_summary& offer)
{
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

    const uint64_t session_id = next_session_id_.fetch_add(1, std::memory_order_relaxed);

    const uint64_t session_version = 1;

    auto options = make_answer_options(stream_id, *local_ice, session_id, session_version);

    sdp::sdp_answer_text_result answer_sdp = is_whip ? sdp::build_whip_answer_sdp(offer, options) : sdp::build_whep_answer_sdp(offer, options);

    if (!answer_sdp)
    {
        return std::unexpected(answer_sdp.error());
    }

    generated_sdp_answer answer;
    answer.sdp = std::move(*answer_sdp);
    answer.local_ice = std::move(*local_ice);
    answer.local_fingerprint = config_.local_fingerprint;
    answer.sdp_session_id = session_id;
    answer.sdp_session_version = session_version;

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
