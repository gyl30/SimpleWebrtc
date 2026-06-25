#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include "log/log.h"
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

static void init_default_log(const std::string& filename);
static void set_log_level();
static uint32_t get_log_file_size();
static uint32_t get_log_file_count();
namespace webrtc
{

void init_log(const std::string& filename)
{
    init_default_log(filename);

    set_log_level();
}
void set_level(const std::string& level)
{
    if (level == "info")
    {
        spdlog::default_logger_raw()->set_level(spdlog::level::info);
    }
    else if (level == "debug")
    {
        spdlog::default_logger_raw()->set_level(spdlog::level::debug);
    }
    else if (level == "warn" || level == "warning")
    {
        spdlog::default_logger_raw()->set_level(spdlog::level::warn);
    }
    else if (level == "err" || level == "error")
    {
        spdlog::default_logger_raw()->set_level(spdlog::level::err);
    }
    else if (level == "trace")
    {
        spdlog::default_logger_raw()->set_level(spdlog::level::trace);
    }
    else
    {
        spdlog::default_logger_raw()->set_level(spdlog::level::info);
    }
}
void shutdown_log()
{
    spdlog::default_logger()->flush();
    spdlog::shutdown();
}
}    // namespace webrtc

static void init_default_log(const std::string& filename)
{
    uint32_t file_size = get_log_file_size();
    uint32_t file_count = get_log_file_count();
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, file_size, file_count));
    auto logger = std::make_shared<spdlog::logger>("", begin(sinks), end(sinks));
    auto net_logger = std::make_shared<spdlog::logger>("net", begin(sinks), end(sinks));
    spdlog::set_default_logger(logger);
    spdlog::register_logger(net_logger);
    spdlog::flush_every(std::chrono::seconds(3));
    spdlog::set_level(spdlog::level::info);
    // spdlog::set_pattern("%v");
    spdlog::set_pattern("%Y%m%d %T.%f %t %L %v %s:%#");
}

static void set_log_level()
{
    // 默认 info 级别日志
    // 如果环境变量中有 DEBUG 和 TRACE 就使用环境变量中的日志级别
    // 优先使用 TRACE 其次 DEBUG
    spdlog::set_level(spdlog::level::info);
    if (getenv("TRACE") != nullptr)
    {
        spdlog::set_level(spdlog::level::trace);
    }
    else if (getenv("DEBUG") != nullptr)
    {
        spdlog::set_level(spdlog::level::debug);
    }
}
static uint32_t get_log_file_size()
{
    // 环境变量中如果存在日志文件大小，就使用环境变量中的设置，否则使用默认值
    constexpr auto kFileSize = 50 * 1024 * 1024;
    char* file_size = getenv("LOG_FILE_SIZE");
    if (file_size != nullptr)
    {
        return atoi(file_size);
    }
    return kFileSize;
}
static uint32_t get_log_file_count()
{
    // 环境变量中如果存在保留的日志文件数量，就使用环境变量中的设置，否则使用默认值
    constexpr auto kFileCount = 5;
    char* file_count = getenv("LOG_FILE_COUNT");
    if (file_count != nullptr)
    {
        return atoi(file_count);
    }
    return kFileCount;
}
