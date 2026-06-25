#include "signaling/sdp/sdp_offer_validator.h"

#include <expected>
#include <string>
#include <string_view>

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
    message.append(" ");
    message.append(suffix);

    return std::unexpected(std::move(message));
}

bool contains_string(const std::vector<std::string>& values, std::string_view value)
{
    for (const auto& current : values)
    {
        if (current == value)
        {
            return true;
        }
    }

    return false;
}

offer_validation_result validate_unique_media_mids(const webrtc_offer_summary& offer)
{
    for (std::size_t i = 0; i < offer.media.size(); ++i)
    {
        const auto& media = offer.media[i];

        if (media.mid.empty())
        {
            return make_error("media mid is empty");
        }

        for (std::size_t j = i + 1; j < offer.media.size(); ++j)
        {
            if (media.mid == offer.media[j].mid)
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
    for (std::size_t i = 0; i < offer.bundle_mids.size(); ++i)
    {
        const auto& mid = offer.bundle_mids[i];

        if (mid.empty())
        {
            return make_error("bundle mid is empty");
        }

        for (std::size_t j = i + 1; j < offer.bundle_mids.size(); ++j)
        {
            if (mid == offer.bundle_mids[j])
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
        if (!contains_string(offer.bundle_mids, media.mid))
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

    if (offer.fingerprint.algorithm.empty())
    {
        return make_error("offer fingerprint algorithm is empty");
    }

    if (offer.fingerprint.value.empty())
    {
        return make_error("offer fingerprint value is empty");
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
