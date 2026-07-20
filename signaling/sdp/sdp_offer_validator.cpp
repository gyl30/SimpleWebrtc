#include "signaling/sdp/sdp_offer_validator.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>

namespace webrtc::sdp
{
namespace
{
std::unexpected<std::string> make_error(std::string_view message) { return std::unexpected(std::string(message)); }

std::unexpected<std::string> make_media_error(std::string_view prefix, const media_summary& media, std::string_view suffix)
{
    std::string message;

    message.reserve(prefix.size() + media.mid.size() + suffix.size() + 16);

    message.append(prefix);
    message.append(" media mid ");
    message.append(media.mid);
    message.push_back(' ');
    message.append(suffix);

    return std::unexpected(std::move(message));
}

bool is_hex_digit(char character)
{
    const auto value = static_cast<unsigned char>(character);

    return std::isxdigit(value) != 0;
}

std::expected<std::size_t, std::string> fingerprint_digest_size(std::string_view algorithm)
{
    const std::string normalized_algorithm = boost::algorithm::to_lower_copy(std::string(algorithm));

    if (normalized_algorithm == "sha-256")
    {
        return 32;
    }

    if (normalized_algorithm == "sha-384")
    {
        return 48;
    }

    if (normalized_algorithm == "sha-512")
    {
        return 64;
    }

    std::string message = "offer fingerprint algorithm is unsupported: ";

    message.append(algorithm);

    return std::unexpected(std::move(message));
}

offer_validation_result validate_fingerprint(const fingerprint_info& fingerprint)
{
    if (fingerprint.algorithm.empty())
    {
        return make_error("offer fingerprint algorithm is empty");
    }

    if (fingerprint.value.empty())
    {
        return make_error("offer fingerprint value is empty");
    }

    auto digest_size = fingerprint_digest_size(fingerprint.algorithm);

    if (!digest_size)
    {
        return std::unexpected(digest_size.error());
    }

    const std::size_t expected_value_size = (*digest_size * 3) - 1;

    if (fingerprint.value.size() != expected_value_size)
    {
        std::string message = "offer fingerprint value length does not match algorithm ";

        message.append(fingerprint.algorithm);

        return std::unexpected(std::move(message));
    }

    for (std::size_t byte_index = 0; byte_index < *digest_size; ++byte_index)
    {
        const std::size_t character_index = byte_index * 3;

        if (!is_hex_digit(fingerprint.value[character_index]) || !is_hex_digit(fingerprint.value[character_index + 1]))
        {
            return make_error("offer fingerprint value contains invalid hexadecimal byte");
        }

        if (byte_index + 1 < *digest_size)
        {
            if (fingerprint.value[character_index + 2] != ':')
            {
                return make_error("offer fingerprint value must use colon separators");
            }
        }
    }

    return {};
}

offer_validation_result validate_unique_media_mids(const webrtc_offer_summary& offer)
{
    for (std::size_t first_index = 0; first_index < offer.media.size(); ++first_index)
    {
        const auto& media = offer.media[first_index];

        if (media.mid.empty())
        {
            return make_error("media mid is empty");
        }

        for (std::size_t second_index = first_index + 1; second_index < offer.media.size(); ++second_index)
        {
            if (media.mid == offer.media[second_index].mid)
            {
                std::string message = "duplicate media mid: ";

                message.append(media.mid);

                return std::unexpected(std::move(message));
            }
        }
    }

    return {};
}

offer_validation_result validate_unique_bundle_mids(const webrtc_offer_summary& offer)
{
    for (std::size_t first_index = 0; first_index < offer.bundle_mids.size(); ++first_index)
    {
        const auto& mid = offer.bundle_mids[first_index];

        if (mid.empty())
        {
            return make_error("bundle mid is empty");
        }

        for (std::size_t second_index = first_index + 1; second_index < offer.bundle_mids.size(); ++second_index)
        {
            if (mid == offer.bundle_mids[second_index])
            {
                std::string message = "duplicate bundle mid: ";

                message.append(mid);

                return std::unexpected(std::move(message));
            }
        }
    }

    return {};
}

offer_validation_result validate_media_bundle_membership(const webrtc_offer_summary& offer)
{
    for (const auto& media : offer.media)
    {
        if (std::ranges::find(offer.bundle_mids, media.mid) == offer.bundle_mids.end())
        {
            return make_media_error("offer", media, "is not present in bundle group");
        }
    }

    return {};
}

offer_validation_result validate_common_offer(const webrtc_offer_summary& offer)
{
    if (offer.ice_ufrag.empty())
    {
        return make_error("offer ice-ufrag is empty");
    }

    if (offer.ice_pwd.empty())
    {
        return make_error("offer ice-pwd is empty");
    }

    auto fingerprint_result = validate_fingerprint(offer.fingerprint);

    if (!fingerprint_result)
    {
        return std::unexpected(fingerprint_result.error());
    }

    if (offer.setup != dtls_connection_role::actpass)
    {
        return make_error("offer setup must be actpass");
    }

    if (offer.bundle_mids.empty())
    {
        return make_error("offer bundle group is empty");
    }

    if (offer.media.empty())
    {
        return make_error("offer has no audio or video media");
    }

    auto unique_media_result = validate_unique_media_mids(offer);

    if (!unique_media_result)
    {
        return std::unexpected(unique_media_result.error());
    }

    auto unique_bundle_result = validate_unique_bundle_mids(offer);

    if (!unique_bundle_result)
    {
        return std::unexpected(unique_bundle_result.error());
    }

    auto bundle_membership_result = validate_media_bundle_membership(offer);

    if (!bundle_membership_result)
    {
        return std::unexpected(bundle_membership_result.error());
    }

    for (const auto& media : offer.media)
    {
        if (media.kind != "audio" && media.kind != "video")
        {
            return make_media_error("offer", media, "has unsupported media kind");
        }

        if (media.direction == media_direction::unknown)
        {
            return make_media_error("offer", media, "has unknown direction");
        }

        if (!media.rtcp_mux)
        {
            return make_media_error("offer", media, "does not enable rtcp-mux");
        }

        if (media.payload_types.empty())
        {
            return make_media_error("offer", media, "has no payload types");
        }

        if (media.codecs.empty())
        {
            return make_media_error("offer", media, "has no codecs");
        }
    }

    return {};
}
}    // namespace

offer_validation_result validate_whip_offer(const webrtc_offer_summary& offer)
{
    auto common_result = validate_common_offer(offer);

    if (!common_result)
    {
        return std::unexpected(common_result.error());
    }

    bool has_send_capable_media = false;

    for (const auto& media : offer.media)
    {
        switch (media.direction)
        {
            case media_direction::send_only:
            case media_direction::send_recv:
                has_send_capable_media = true;
                break;

            case media_direction::inactive:
                break;

            case media_direction::recv_only:
                return make_media_error("whip", media, "must not be recvonly");

            case media_direction::unknown:
                return make_media_error("whip", media, "has unknown direction");
        }
    }

    if (!has_send_capable_media)
    {
        return make_error("whip offer has no send-capable media");
    }

    return {};
}

offer_validation_result validate_whep_offer(const webrtc_offer_summary& offer)
{
    auto common_result = validate_common_offer(offer);

    if (!common_result)
    {
        return std::unexpected(common_result.error());
    }

    bool has_receive_capable_media = false;

    for (const auto& media : offer.media)
    {
        switch (media.direction)
        {
            case media_direction::recv_only:
            case media_direction::send_recv:
                has_receive_capable_media = true;
                break;

            case media_direction::inactive:
                break;

            case media_direction::send_only:
                return make_media_error("whep", media, "must not be sendonly");

            case media_direction::unknown:
                return make_media_error("whep", media, "has unknown direction");
        }
    }

    if (!has_receive_capable_media)
    {
        return make_error("whep offer has no receive-capable media");
    }

    return {};
}
}    // namespace webrtc::sdp
