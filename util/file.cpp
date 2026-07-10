#include "util/file.h"

#include <cstdio>
#include <string>
#include <string_view>
#include <utility>

#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>

namespace webrtc
{

namespace
{
std::unexpected<std::string> make_file_path_error(std::string_view file, std::string_view error)
{
    std::string message;

    message.reserve(file.size() + error.size() + 48);

    message.append("resolve absolute file path failed path=");

    if (file.empty())
    {
        message.append("<empty>");
    }
    else
    {
        message.append(file);
    }

    if (!error.empty())
    {
        message.append(" error=");
        message.append(error);
    }

    return std::unexpected(std::move(message));
}
}    // namespace
int remove_file(const char* filename) { return ::remove(filename); }

int write_string_to_file(const char* filename, const std::string& content)
{
    FILE* fp = ::fopen(filename, "wb");
    if (fp == nullptr)
    {
        return -1;
    }

    auto size = fwrite(content.c_str(), 1, content.size(), fp);
    ::fclose(fp);

    return size == content.size() ? 0 : -1;
}

std::string read_file_to_string(const char* filename, std::size_t read_size)
{
    std::string content;
    FILE* fp = ::fopen(filename, "rb");
    if (fp == nullptr)
    {
        return content;
    }

    char buf[8192];
    while (content.size() < read_size)
    {
        auto read_bytes = ::fread(buf, 1, sizeof buf, fp);
        if (read_bytes == 0)
        {
            if (ferror(fp))
            {
                content.clear();
            }
            break;
        }

        content.append(buf, read_bytes);
    }
    ::fclose(fp);
    return content;
}

std::string file_name(const std::string& file_full_abs_path)
{
    boost::filesystem::path p(file_full_abs_path);
    return p.filename().string();
}

std::string file_dir(const std::string& file_full_abs_path)
{
    boost::filesystem::path p(file_full_abs_path);
    return p.parent_path().string();
}
file_path_result file_abs_path(std::string_view file)
{
    if (file.empty())
    {
        return make_file_path_error(file, "path is empty");
    }

    const boost::filesystem::path input_path{std::string(file)};

    boost::system::error_code error;

    const boost::filesystem::path canonical_path = boost::filesystem::canonical(input_path, error);

    if (error)
    {
        return make_file_path_error(file, error.message());
    }

    if (canonical_path.empty())
    {
        return make_file_path_error(file, "canonical path is empty");
    }

    return canonical_path.string();
}
std::string file_ext(const std::string& file_full_abs_path)
{
    boost::filesystem::path p(file_full_abs_path);
    return p.extension().string();
}
}    // namespace webrtc
