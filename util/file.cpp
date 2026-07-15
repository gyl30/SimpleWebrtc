#include "util/file.h"

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
}    // namespace webrtc
