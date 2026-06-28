#include "server/runtime_offer_filter.h"

#include <cstddef>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "signaling/sdp/sdp_parser.h"

namespace webrtc
{
namespace
{
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

std::expected<sdp::webrtc_offer_summary, std::string> make_runtime_offer_summary_from_mids(const sdp::webrtc_offer_summary& original_offer,
                                                                                           const std::vector<std::string>& accepted_mids)
{
    sdp::webrtc_offer_summary runtime_offer = original_offer;

    runtime_offer.bundle_mids.clear();
    runtime_offer.media.clear();

    for (const auto& accepted_mid : accepted_mids)
    {
        bool media_found = false;

        for (const auto& media : original_offer.media)
        {
            if (media.mid != accepted_mid)
            {
                continue;
            }

            runtime_offer.media.push_back(media);

            media_found = true;

            break;
        }

        if (!media_found)
        {
            std::string message = "accepted answer mid not found in offer mid=";

            message.append(accepted_mid);

            return std::unexpected(std::move(message));
        }
    }

    for (const auto& mid : original_offer.bundle_mids)
    {
        if (!contains_mid(accepted_mids, mid))
        {
            continue;
        }

        runtime_offer.bundle_mids.push_back(mid);
    }

    if (runtime_offer.bundle_mids.empty())
    {
        for (const auto& mid : accepted_mids)
        {
            runtime_offer.bundle_mids.push_back(mid);
        }
    }

    return runtime_offer;
}

std::expected<std::vector<int>, std::string> collect_accepted_offer_mline_indexes_from_mids(const sdp::webrtc_offer_summary& original_offer,
                                                                                            const std::vector<std::string>& accepted_mids)
{
    std::vector<int> accepted_mline_indexes;

    accepted_mline_indexes.reserve(accepted_mids.size());

    for (const auto& accepted_mid : accepted_mids)
    {
        bool media_found = false;

        for (std::size_t index = 0; index < original_offer.media.size(); ++index)
        {
            const auto& media = original_offer.media[index];

            if (media.mid != accepted_mid)
            {
                continue;
            }

            if (index > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            {
                return make_error("accepted offer media mline index is too large");
            }

            accepted_mline_indexes.push_back(static_cast<int>(index));

            media_found = true;

            break;
        }

        if (!media_found)
        {
            std::string message = "accepted answer mid not found in offer mid=";

            message.append(accepted_mid);

            return std::unexpected(std::move(message));
        }
    }

    if (accepted_mline_indexes.empty())
    {
        return make_error("answer has no accepted media mline indexes");
    }

    return accepted_mline_indexes;
}
}    // namespace

runtime_offer_filter_result_type make_runtime_offer_filter_result(const sdp::webrtc_offer_summary& original_offer, std::string_view answer_sdp)
{
    auto accepted_mids = collect_accepted_answer_mids(answer_sdp);

    if (!accepted_mids)
    {
        return std::unexpected(accepted_mids.error());
    }

    auto runtime_offer_summary = make_runtime_offer_summary_from_mids(original_offer, *accepted_mids);

    if (!runtime_offer_summary)
    {
        return std::unexpected(runtime_offer_summary.error());
    }

    auto accepted_mline_indexes = collect_accepted_offer_mline_indexes_from_mids(original_offer, *accepted_mids);

    if (!accepted_mline_indexes)
    {
        return std::unexpected(accepted_mline_indexes.error());
    }

    runtime_offer_filter_result result;

    result.offer_summary = std::move(*runtime_offer_summary);

    result.accepted_mids = std::move(*accepted_mids);

    result.accepted_mline_indexes = std::move(*accepted_mline_indexes);

    return result;
}
}    // namespace webrtc
