#include <iostream>
#include <spdlog/spdlog.h>
#include <spdlog/version.h>
#include <boost/version.hpp>
#include <openssl/opensslv.h>
#include <rapidjson/document.h>

int main()
{
    std::cout << "OpenSSL: " << OPENSSL_VERSION_STR << '\n';

    std::cout << "Boost: " << BOOST_VERSION / 100000 << '.' << BOOST_VERSION / 100 % 1000 << '.' << BOOST_VERSION % 100 << '\n';

    std::cout << "spdlog: " << SPDLOG_VER_MAJOR << '.' << SPDLOG_VER_MINOR << '.' << SPDLOG_VER_PATCH << '\n';

    rapidjson::Document doc;
    doc.Parse(R"({"name": "SimpleWebrtc", "version": "0.1"})");
    if (doc.HasParseError())
    {
        std::cerr << "rapidjson parse error\n";
        return 1;
    }
    std::cout << doc["name"].GetString() << ": " << doc["version"].GetString() << '\n';

    return 0;
}
