#ifndef SIMPLE_WEBRTC_SERVER_RUNTIME_OFFER_FILTER_H
#define SIMPLE_WEBRTC_SERVER_RUNTIME_OFFER_FILTER_H

#include <expected>
#include <string>
#include <vector>

#include "signaling/sdp/sdp_summary.h"

namespace webrtc
{
struct runtime_offer_filter_result
{
    sdp::webrtc_offer_summary offer_summary;

    std::vector<std::string> accepted_mids;
    std::vector<int> accepted_mline_indexes;
};

using runtime_offer_filter_result_type = std::expected<runtime_offer_filter_result, std::string>;

[[nodiscard]]
runtime_offer_filter_result_type make_runtime_offer_filter_result(const sdp::webrtc_offer_summary& original_offer,
                                                                  std::vector<std::string> accepted_mids,
                                                                  std::vector<int> accepted_mline_indexes);
}    // namespace webrtc

#endif
