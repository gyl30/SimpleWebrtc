#include "log/log.h"

#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "webrtc_config.h"

namespace webrtc
{
namespace
{
spdlog::level::level_enum to_spdlog_level(webrtc_log_level level)
{
    switch (level)
    {
        case webrtc_log_level::trace:
            return spdlog::level::trace;
        case webrtc_log_level::debug:
            return spdlog::level::debug;
        case webrtc_log_level::info:
            return spdlog::level::info;
        case webrtc_log_level::warn:
            return spdlog::level::warn;
        case webrtc_log_level::error:
            return spdlog::level::err;
        case webrtc_log_level::critical:
            return spdlog::level::critical;
        case webrtc_log_level::off:
            return spdlog::level::off;
    }

    return spdlog::level::info;
}

std::string_view log_level_to_string(webrtc_log_level level)
{
    switch (level)
    {
        case webrtc_log_level::trace:
            return "trace";

        case webrtc_log_level::debug:
            return "debug";

        case webrtc_log_level::info:
            return "info";

        case webrtc_log_level::warn:
            return "warn";

        case webrtc_log_level::error:
            return "error";

        case webrtc_log_level::critical:
            return "critical";

        case webrtc_log_level::off:
            return "off";
    }

    return "unknown";
}

void initialize_default_logger(const std::string& filename, spdlog::level::level_enum level, std::size_t file_size_bytes, std::size_t file_count)
{
    std::vector<spdlog::sink_ptr> sinks;

    sinks.reserve(2);

    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());

    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, file_size_bytes, file_count));

    auto logger = std::make_shared<spdlog::logger>("", sinks.begin(), sinks.end());

    auto net_logger = std::make_shared<spdlog::logger>("net", sinks.begin(), sinks.end());

    spdlog::set_default_logger(std::move(logger));

    spdlog::register_logger(std::move(net_logger));

    spdlog::flush_every(std::chrono::seconds(3));

    spdlog::set_pattern("%Y%m%d %T.%f %t %L %v %s:%#");

    spdlog::set_level(level);
}
}    // namespace

log_init_result init_log(const std::string& filename, const webrtc_log_config& config)
{
    const spdlog::level::level_enum level = to_spdlog_level(config.level);

    try
    {
        initialize_default_logger(filename, level, config.file_size_bytes, config.file_count);
    }
    catch (const spdlog::spdlog_ex& error)
    {
        spdlog::shutdown();

        std::string message = "initialize logger failed: ";

        message.append(error.what());

        return std::unexpected(std::move(message));
    }

    WEBRTC_LOG_INFO("log configuration level={} file={} file_size_bytes={} file_count={}",
                    log_level_to_string(config.level),
                    filename,
                    config.file_size_bytes,
                    config.file_count);

    return {};
}

void shutdown_log()
{
    const auto logger = spdlog::default_logger();

    if (logger != nullptr)
    {
        logger->flush();
    }

    spdlog::shutdown();
}
}    // namespace webrtc
