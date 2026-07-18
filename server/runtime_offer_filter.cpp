#include "server/runtime_offer_filter.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

std::expected<void, std::string> populate_filtered_runtime_offer(runtime_offer_filter_result& result,
                                                                 const sdp::webrtc_offer_summary& original_offer)
{
    result.offer_summary = original_offer;
    result.offer_summary.bundle_mids.clear();
    result.offer_summary.media.clear();

    result.offer_summary.media.reserve(result.accepted_mline_indexes.size());

    for (const int mline_index : result.accepted_mline_indexes)
    {
        result.offer_summary.media.push_back(original_offer.media[static_cast<std::size_t>(mline_index)]);
    }

    for (const auto& mid : original_offer.bundle_mids)
    {
        if (contains_mid(result.accepted_mids, mid))
        {
            result.offer_summary.bundle_mids.push_back(mid);
        }
    }

    if (result.offer_summary.bundle_mids.size() != result.accepted_mids.size())
    {
        return make_error("runtime offer filter bundle mids and accepted mids size mismatch");
    }

    for (std::size_t index = 0; index < result.accepted_mids.size(); ++index)
    {
        const std::string& bundle_mid = result.offer_summary.bundle_mids[index];

        if (bundle_mid != result.accepted_mids[index])
        {
            std::string message = "runtime offer filter bundle mid order mismatch expected=";
            message.append(result.accepted_mids[index]);
            message.append(" actual=");
            message.append(bundle_mid);
            return std::unexpected(std::move(message));
        }
    }

    return {};
}
}    // namespace

runtime_offer_filter_result_type make_runtime_offer_filter_result(const sdp::webrtc_offer_summary& original_offer,
                                                                  std::vector<std::string> accepted_mids,
                                                                  std::vector<int> accepted_mline_indexes)
{
    runtime_offer_filter_result result;
    result.accepted_mids = std::move(accepted_mids);
    result.accepted_mline_indexes = std::move(accepted_mline_indexes);

    auto populate_result = populate_filtered_runtime_offer(result, original_offer);
    if (!populate_result)
    {
        return std::unexpected(populate_result.error());
    }

    return result;
}
}    // namespace webrtc
