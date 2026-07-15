#ifndef SIMPLE_WEBRTC_UTIL_FILE_H
#define SIMPLE_WEBRTC_UTIL_FILE_H

#include <expected>
#include <string>
#include <string_view>

namespace webrtc
{

using file_path_result = std::expected<std::string, std::string>;

[[nodiscard]] file_path_result file_abs_path(std::string_view file);

std::string file_name(const std::string& file_full_abs_path);
std::string file_dir(const std::string& file_full_abs_path);
}    // namespace webrtc

#endif
