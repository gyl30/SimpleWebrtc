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
#include "signaling/sdp/sdp_types.h"

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
std::vector<std::string> split_space_separated_tokens(std::string_view value)
{
    std::vector<std::string> tokens;

    std::size_t position = 0;

    while (position < value.size())
    {
        position = value.find_first_not_of(" \t", position);

        if (position == std::string_view::npos)
        {
            break;
        }

        const std::size_t end = value.find_first_of(" \t", position);

        if (end == std::string_view::npos)
        {
            tokens.emplace_back(value.substr(position));

            break;
        }

        tokens.emplace_back(value.substr(position, end - position));

        position = end + 1;
    }

    return tokens;
}

std::expected<std::vector<std::string>, std::string> collect_answer_bundle_mids(const sdp::session_description& answer_description)
{
    const auto group_attributes = answer_description.find_attributes(sdp::k_attribute_group);

    std::optional<std::vector<std::string>> bundle_mids;

    for (const auto* attribute : group_attributes)
    {
        if (attribute == nullptr)
        {
            continue;
        }

        const std::vector<std::string> tokens = split_space_separated_tokens(attribute->value);

        if (tokens.empty())
        {
            return make_error("answer group attribute is empty");
        }

        if (tokens.front() != "BUNDLE")
        {
            continue;
        }

        if (bundle_mids.has_value())
        {
            return make_error("answer has multiple bundle groups");
        }

        if (tokens.size() == 1)
        {
            return make_error("answer bundle group has no mids");
        }

        std::vector<std::string> current_bundle_mids;

        current_bundle_mids.reserve(tokens.size() - 1);

        for (std::size_t index = 1; index < tokens.size(); ++index)
        {
            const std::string& mid = tokens[index];

            if (mid.empty())
            {
                return make_error("answer bundle mid is empty");
            }

            if (contains_mid(current_bundle_mids, mid))
            {
                std::string message = "answer bundle mid duplicated mid=";

                message.append(mid);

                return std::unexpected(std::move(message));
            }

            current_bundle_mids.push_back(mid);
        }

        bundle_mids = std::move(current_bundle_mids);
    }

    if (!bundle_mids.has_value())
    {
        return make_error("answer bundle group is missing");
    }

    return *bundle_mids;
}

std::expected<void, std::string> validate_answer_bundle_mids(const std::vector<std::string>& accepted_mids,
                                                             const std::vector<std::string>& bundle_mids)
{
    if (accepted_mids.empty())
    {
        return make_error("answer accepted mids is empty");
    }

    if (bundle_mids.empty())
    {
        return make_error("answer bundle mids is empty");
    }

    if (accepted_mids.size() != bundle_mids.size())
    {
        return make_error("answer bundle mids and accepted mids size mismatch");
    }

    for (std::size_t index = 0; index < bundle_mids.size(); ++index)
    {
        const std::string& bundle_mid = bundle_mids[index];

        if (!contains_mid(accepted_mids, bundle_mid))
        {
            std::string message = "answer bundle mid is not accepted mid=";

            message.append(bundle_mid);

            return std::unexpected(std::move(message));
        }

        if (accepted_mids[index] != bundle_mid)
        {
            std::string message = "answer bundle mid order mismatch expected=";

            message.append(accepted_mids[index]);

            message.append(" actual=");

            message.append(bundle_mid);

            return std::unexpected(std::move(message));
        }
    }

    return {};
}
std::expected<void, std::string> observe_answer_media_direction(const sdp::media_description& media,
                                                                std::string_view attribute_name,
                                                                sdp::media_direction direction_value,
                                                                std::optional<sdp::media_direction>& direction)
{
    const auto attributes = media.find_attributes(attribute_name);

    if (attributes.empty())
    {
        return {};
    }

    if (attributes.size() > 1)
    {
        std::string message = "answer media has duplicated direction attribute direction=";

        message.append(attribute_name);

        return std::unexpected(std::move(message));
    }

    if (direction.has_value())
    {
        return make_error("answer media has multiple direction attributes");
    }

    direction = direction_value;

    return {};
}

std::expected<std::optional<sdp::media_direction>, std::string> find_answer_media_direction(const sdp::media_description& media)
{
    std::optional<sdp::media_direction> direction;

    auto send_recv_result = observe_answer_media_direction(media, sdp::k_attribute_send_recv, sdp::media_direction::send_recv, direction);

    if (!send_recv_result)
    {
        return std::unexpected(send_recv_result.error());
    }

    auto send_only_result = observe_answer_media_direction(media, sdp::k_attribute_send_only, sdp::media_direction::send_only, direction);

    if (!send_only_result)
    {
        return std::unexpected(send_only_result.error());
    }

    auto recv_only_result = observe_answer_media_direction(media, sdp::k_attribute_recv_only, sdp::media_direction::recv_only, direction);

    if (!recv_only_result)
    {
        return std::unexpected(recv_only_result.error());
    }

    auto inactive_result = observe_answer_media_direction(media, sdp::k_attribute_inactive, sdp::media_direction::inactive, direction);

    if (!inactive_result)
    {
        return std::unexpected(inactive_result.error());
    }

    return direction;
}

std::expected<bool, std::string> answer_media_is_accepted(const sdp::media_description& media)
{
    if (media.media_name.port == 0)
    {
        return false;
    }

    auto direction = find_answer_media_direction(media);

    if (!direction)
    {
        return std::unexpected(direction.error());
    }

    if (!direction->has_value())
    {
        return make_error("accepted answer media is missing direction attribute");
    }

    if (**direction == sdp::media_direction::inactive)
    {
        return false;
    }

    return true;
}

std::expected<std::vector<std::string>, std::string> collect_accepted_answer_mids(const sdp::session_description& answer_description)
{
    std::vector<std::string> accepted_mids;

    for (const auto& media : answer_description.media_descriptions)
    {
        auto accepted_result = answer_media_is_accepted(media);

        if (!accepted_result)
        {
            return std::unexpected(accepted_result.error());
        }

        if (!*accepted_result)
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

struct filtered_runtime_offer
{
    sdp::webrtc_offer_summary offer_summary;
    std::vector<int> accepted_mline_indexes;
};

std::expected<filtered_runtime_offer, std::string> make_filtered_runtime_offer(const sdp::webrtc_offer_summary& original_offer,
                                                                                const std::vector<std::string>& accepted_mids)
{
    filtered_runtime_offer result;

    result.offer_summary = original_offer;
    result.offer_summary.bundle_mids.clear();
    result.offer_summary.media.clear();

    result.offer_summary.media.reserve(accepted_mids.size());
    result.accepted_mline_indexes.reserve(accepted_mids.size());

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

            result.offer_summary.media.push_back(media);
            result.accepted_mline_indexes.push_back(static_cast<int>(index));

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
        if (contains_mid(accepted_mids, mid))
        {
            result.offer_summary.bundle_mids.push_back(mid);
        }
    }

    if (result.offer_summary.bundle_mids.size() != accepted_mids.size())
    {
        return make_error("runtime offer filter bundle mids and accepted mids size mismatch");
    }

    for (std::size_t index = 0; index < accepted_mids.size(); ++index)
    {
        const std::string& bundle_mid = result.offer_summary.bundle_mids[index];

        if (bundle_mid != accepted_mids[index])
        {
            std::string message = "runtime offer filter bundle mid order mismatch expected=";

            message.append(accepted_mids[index]);
            message.append(" actual=");
            message.append(bundle_mid);

            return std::unexpected(std::move(message));
        }
    }

    return result;
}
}    // namespace

runtime_offer_filter_result_type make_runtime_offer_filter_result(const sdp::webrtc_offer_summary& original_offer, std::string_view answer_sdp)
{
    auto answer_description = sdp::parse_session_description(answer_sdp);

    if (!answer_description)
    {
        std::string message = "runtime offer filter parse answer failed: ";

        message.append(answer_description.error());

        return std::unexpected(std::move(message));
    }

    auto accepted_mids = collect_accepted_answer_mids(*answer_description);

    if (!accepted_mids)
    {
        return std::unexpected(accepted_mids.error());
    }

    auto bundle_mids = collect_answer_bundle_mids(*answer_description);

    if (!bundle_mids)
    {
        return std::unexpected(bundle_mids.error());
    }

    auto bundle_validation_result = validate_answer_bundle_mids(*accepted_mids, *bundle_mids);

    if (!bundle_validation_result)
    {
        return std::unexpected(bundle_validation_result.error());
    }
    auto filtered_offer = make_filtered_runtime_offer(original_offer, *accepted_mids);

    if (!filtered_offer)
    {
        return std::unexpected(filtered_offer.error());
    }

    runtime_offer_filter_result result;

    result.offer_summary = std::move(filtered_offer->offer_summary);
    result.accepted_mids = std::move(*accepted_mids);
    result.accepted_mline_indexes = std::move(filtered_offer->accepted_mline_indexes);

    return result;
}
}    // namespace webrtc
