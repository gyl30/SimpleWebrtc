#ifndef SIMPLE_WEBRTC_MEDIA_MEDIA_ROUTER_STATS_PROMETHEUS_H
#define SIMPLE_WEBRTC_MEDIA_MEDIA_ROUTER_STATS_PROMETHEUS_H

#include <string>

#include "media/media_router.h"

namespace webrtc
{
[[nodiscard]] std::string media_router_stats_snapshot_to_prometheus(const media_router_stats_snapshot& snapshot);
}    // namespace webrtc

#endif
