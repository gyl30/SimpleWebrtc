#include <string>
#include <cstdio>
#include <boost/filesystem.hpp>

#include "util/file.h"

namespace webrtc
{

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
std::string file_abs_path(const std::string& file)
{
    boost::filesystem::path p(file);
    return boost::filesystem::canonical(p).string();
}
std::string file_ext(const std::string& file_full_abs_path)
{
    boost::filesystem::path p(file_full_abs_path);
    return p.extension().string();
}
}    // namespace webrtc
