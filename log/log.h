#ifndef SIMPLE_WEBRTC_LOG_H
#define SIMPLE_WEBRTC_LOG_H

#define SPDLOG_SHORT_LEVEL_NAMES {"TRC", "DBG", "INF", "WRN", "ERR", "CTL", "OFF"}

#include <expected>
#include <string>

#include <spdlog/spdlog.h>

namespace webrtc
{
using log_init_result = std::expected<void, std::string>;

[[nodiscard]] log_init_result init_log(const std::string& filename);

void shutdown_log();
}    // namespace webrtc

#define WEBRTC_LOG_TRACE(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::trace, __VA_ARGS__)
#define WEBRTC_LOG_DEBUG(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::debug, __VA_ARGS__)
#define WEBRTC_LOG_INFO(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::info, __VA_ARGS__)
#define WEBRTC_LOG_WARN(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::warn, __VA_ARGS__)
#define WEBRTC_LOG_ERROR(...) SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::err, __VA_ARGS__)

#endif
