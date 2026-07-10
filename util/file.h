#ifndef SIMPLE_WEBRTC_UTIL_FILE_H
#define SIMPLE_WEBRTC_UTIL_FILE_H

#include <expected>
#include <string>
#include <string_view>

namespace webrtc
{

/**
 * @brief 从文件中读取指定字节内容
 *
 * @param filename 文件名称
 * @param read_size 读取字节数
 *
 * @return 读取的内容
 */
std::string read_file_to_string(const char* filename, std::size_t read_size);

/**
 * @brief 将内容写入文件
 *
 * @param filename 文件名称
 * @param content  写入的内容
 *
 * @return 写入是否成功 0 成功 非 0 失败
 */
int write_string_to_file(const char* filename, const std::string& content);

/**
 * @brief 删除文件
 *
 * @param filename 文件名称
 *
 * @return 删除是否成功 0 成功 非 0 失败
 */
int remove_file(const char* filename);

using file_path_result = std::expected<std::string, std::string>;

[[nodiscard]] file_path_result file_abs_path(std::string_view file);

std::string file_name(const std::string& file_full_abs_path);
std::string file_dir(const std::string& file_full_abs_path);
std::string file_ext(const std::string& file_full_abs_path);
}    // namespace webrtc

#endif
