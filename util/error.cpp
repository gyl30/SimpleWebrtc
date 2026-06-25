#include "util/error.h"
#include <boost/system.hpp>

namespace webrtc
{
std::string errno_to_str()
{
    const int saved_errno = errno;
    return boost::system::error_code(saved_errno, boost::system::generic_category()).message();
}
}    // namespace webrtc
