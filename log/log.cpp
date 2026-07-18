#include "log/log.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "util/number_parse.h"

namespace webrtc
{
namespace
{
inline constexpr char k_log_level_environment[] = "WEBRTC_LOG_LEVEL";
inline constexpr char k_log_file_size_environment[] = "WEBRTC_LOG_FILE_SIZE_BYTES";
inline constexpr char k_log_file_count_environment[] = "WEBRTC_LOG_FILE_COUNT";

inline constexpr uint64_t k_default_log_file_size_bytes = 50ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t k_minimum_log_file_size_bytes = 1ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t k_maximum_log_file_size_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;

inline constexpr uint32_t k_default_log_file_count = 5U;
inline constexpr uint32_t k_minimum_log_file_count = 1U;
inline constexpr uint32_t k_maximum_log_file_count = 100U;

struct log_config
{
    spdlog::level::level_enum level = spdlog::level::info;

    std::size_t file_size_bytes = static_cast<std::size_t>(k_default_log_file_size_bytes);

    std::size_t file_count = static_cast<std::size_t>(k_default_log_file_count);
};

std::expected<spdlog::level::level_enum, std::string> parse_log_level(std::string_view value)
{
    if (value == "trace")
    {
        return spdlog::level::trace;
    }

    if (value == "debug")
    {
        return spdlog::level::debug;
    }

    if (value == "info")
    {
        return spdlog::level::info;
    }

    if (value == "warn" || value == "warning")
    {
        return spdlog::level::warn;
    }

    if (value == "error" || value == "err")
    {
        return spdlog::level::err;
    }

    if (value == "critical")
    {
        return spdlog::level::critical;
    }

    if (value == "off")
    {
        return spdlog::level::off;
    }

    std::string error = k_log_level_environment;

    error.append(": unsupported log level: ");
    error.append(value);
    error.append("; expected trace, debug, info, warn, error, critical, or off");

    return std::unexpected(std::move(error));
}

std::string_view log_level_to_string(spdlog::level::level_enum level)
{
    switch (level)
    {
        case spdlog::level::trace:
            return "trace";

        case spdlog::level::debug:
            return "debug";

        case spdlog::level::info:
            return "info";

        case spdlog::level::warn:
            return "warn";

        case spdlog::level::err:
            return "error";

        case spdlog::level::critical:
            return "critical";

        case spdlog::level::off:
            return "off";

        case spdlog::level::n_levels:
            return "unknown";
    }

    return "unknown";
}

template <std::integral Integer>
std::expected<Integer, std::string> load_integer_environment(const char* environment_name, Integer default_value, Integer minimum, Integer maximum)
{
    const char* environment_value = std::getenv(environment_name);

    if (environment_value == nullptr)
    {
        return default_value;
    }

    return parse_integer<Integer>(environment_value, minimum, maximum, environment_name);
}

std::expected<log_config, std::string> load_log_config()
{
    log_config config;

    const char* level_value = std::getenv(k_log_level_environment);

    if (level_value != nullptr)
    {
        auto level = parse_log_level(level_value);

        if (!level)
        {
            return std::unexpected(level.error());
        }

        config.level = *level;
    }

    auto file_size = load_integer_environment<uint64_t>(
        k_log_file_size_environment, k_default_log_file_size_bytes, k_minimum_log_file_size_bytes, k_maximum_log_file_size_bytes);

    if (!file_size)
    {
        return std::unexpected(file_size.error());
    }

    if (*file_size > static_cast<uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        return std::unexpected(std::string(k_log_file_size_environment) + ": value cannot be represented by std::size_t");
    }

    auto file_count = load_integer_environment<uint32_t>(
        k_log_file_count_environment, k_default_log_file_count, k_minimum_log_file_count, k_maximum_log_file_count);

    if (!file_count)
    {
        return std::unexpected(file_count.error());
    }

    config.file_size_bytes = static_cast<std::size_t>(*file_size);
    config.file_count = static_cast<std::size_t>(*file_count);

    return config;
}

void initialize_default_logger(const std::string& filename, const log_config& config)
{
    std::vector<spdlog::sink_ptr> sinks;

    sinks.reserve(2);

    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());

    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, config.file_size_bytes, config.file_count));

    auto logger = std::make_shared<spdlog::logger>("", sinks.begin(), sinks.end());

    auto net_logger = std::make_shared<spdlog::logger>("net", sinks.begin(), sinks.end());

    spdlog::set_default_logger(std::move(logger));

    spdlog::register_logger(std::move(net_logger));

    spdlog::flush_every(std::chrono::seconds(3));

    spdlog::set_pattern("%Y%m%d %T.%f %t %L %v %s:%#");

    spdlog::set_level(config.level);
}
}    // namespace

log_init_result init_log(const std::string& filename)
{
    auto config = load_log_config();

    if (!config)
    {
        return std::unexpected(config.error());
    }

    try
    {
        initialize_default_logger(filename, *config);
    }
    catch (const spdlog::spdlog_ex& error)
    {
        spdlog::shutdown();

        std::string message = "initialize logger failed: ";

        message.append(error.what());

        return std::unexpected(std::move(message));
    }

    WEBRTC_LOG_INFO("log configuration level={} file={} file_size_bytes={} file_count={}",
                    log_level_to_string(config->level),
                    filename,
                    config->file_size_bytes,
                    config->file_count);

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
