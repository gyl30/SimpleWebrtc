#include "server/runtime_offer_filter.h"

#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <utility>

namespace webrtc
{
std::expected<sdp::webrtc_offer_summary, std::string> make_runtime_offer_summary(
    const sdp::webrtc_offer_summary& original_offer, std::span<const int> accepted_mline_indexes)
{
    sdp::webrtc_offer_summary result = original_offer;

    result.bundle_mids.clear();
    result.media.clear();
    result.media.reserve(accepted_mline_indexes.size());

    for (const int mline_index : accepted_mline_indexes)
    {
        result.media.push_back(original_offer.media[static_cast<std::size_t>(mline_index)]);
    }

    for (const auto& mid : original_offer.bundle_mids)
    {
        if (std::ranges::find(result.media, mid, &sdp::media_summary::mid) != result.media.end())
        {
            result.bundle_mids.push_back(mid);
        }
    }

    if (result.bundle_mids.size() != result.media.size())
    {
        return std::unexpected(std::string("runtime offer filter bundle mids and accepted mids size mismatch"));
    }

    for (std::size_t index = 0; index < result.media.size(); ++index)
    {
        const std::string& expected_mid = result.media[index].mid;
        const std::string& bundle_mid = result.bundle_mids[index];

        if (bundle_mid != expected_mid)
        {
            std::string message = "runtime offer filter bundle mid order mismatch expected=";
            message.append(expected_mid);
            message.append(" actual=");
            message.append(bundle_mid);
            return std::unexpected(std::move(message));
        }
    }

    return result;
}
}    // namespace webrtc
