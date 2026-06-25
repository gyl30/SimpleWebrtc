cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

project(
  SimpleWebrtc
  VERSION 0.0.1
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE
      Debug
      CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
                                               "RelWithDebInfo" "MinSizeRel")
endif()

include(CheckCXXCompilerFlag)

add_compile_options(
  -Wall
  -Wextra
  -Wformat
  -Wformat=2
  -Wconversion
  -Wimplicit-fallthrough
  -Werror=format-security
  -fno-strict-aliasing)

option(ENABLE_STRICT_WARNINGS "Enable stricter C++ warning set" OFF)
if(ENABLE_STRICT_WARNINGS)
  add_compile_options(
    "$<$<COMPILE_LANGUAGE:CXX>:-Wshadow>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wpedantic>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wcast-qual>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wsign-conversion>")
endif()

add_compile_options(-D_GLIBCXX_ASSERTIONS -fstack-protector-strong
                    -fno-delete-null-pointer-checks -fno-strict-overflow)

check_cxx_compiler_flag("-fstrict-flex-arrays=3" HAS_STRICT_FLEX_ARRAYS)
if(HAS_STRICT_FLEX_ARRAYS)
  add_compile_options(-fstrict-flex-arrays=3)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  check_cxx_compiler_flag("-fstack-clash-protection" HAS_STACK_CLASH_PROTECTION)
  if(HAS_STACK_CLASH_PROTECTION)
    add_compile_options(-fstack-clash-protection)
  endif()
endif()

check_cxx_compiler_flag("-fcf-protection=full" HAS_CF_PROTECTION)
if(HAS_CF_PROTECTION)
  add_compile_options(-fcf-protection=full)
endif()

check_cxx_compiler_flag("-mbranch-protection=standard" HAS_BRANCH_PROTECTION)
if(HAS_BRANCH_PROTECTION)
  add_compile_options(-mbranch-protection=standard)
endif()

option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_LSAN "Enable LeakSanitizer" OFF)
option(ENABLE_FUZZ "Enable libFuzzer targets" OFF)
option(ENABLE_STATIC_LINK
       "Link executable and third-party dependencies statically" OFF)

if(ENABLE_STATIC_LINK)
  set(BUILD_SHARED_LIBS OFF)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  add_link_options(-static)
endif()

add_compile_options(-fno-omit-frame-pointer)

if(ENABLE_LSAN)
  set(ENABLE_ASAN OFF)
endif()

if(ENABLE_TSAN AND ENABLE_LSAN)
  message(FATAL_ERROR "ENABLE_TSAN cannot be combined with ENABLE_LSAN.")
endif()

if(ENABLE_TSAN)
  if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                                   "AppleClang"))
    message(FATAL_ERROR "ENABLE_TSAN requires Clang toolchain.")
  endif()
  add_compile_options(-fsanitize=thread)
  add_link_options(-fsanitize=thread)
elseif(ENABLE_ASAN)
  if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                                   "AppleClang"))
    message(FATAL_ERROR "ENABLE_ASAN requires Clang toolchain.")
  endif()
  add_compile_options(-fsanitize=address,undefined)
  add_link_options(-fsanitize=address,undefined)
elseif(ENABLE_LSAN)
  if(NOT (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES
                                                   "AppleClang"))
    message(FATAL_ERROR "ENABLE_LSAN requires Clang toolchain.")
  endif()
  add_compile_options(-fsanitize=leak)
  add_link_options(-fsanitize=leak)
else()
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>")
  add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
endif()

if(NOT ENABLE_TSAN
   AND NOT ENABLE_ASAN
   AND NOT ENABLE_LSAN)
  check_cxx_compiler_flag("-ftrivial-auto-var-init=zero"
                          HAS_TRIVIAL_AUTO_VAR_INIT_ZERO)
  if(HAS_TRIVIAL_AUTO_VAR_INIT_ZERO)
    add_compile_options(-ftrivial-auto-var-init=zero)
  endif()
endif()

if(NOT DEFINED OPENSSL_ROOT_DIR
   AND DEFINED ENV{OPENSSL_ROOT_DIR}
   AND NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
  set(OPENSSL_ROOT_DIR
      "$ENV{OPENSSL_ROOT_DIR}"
      CACHE PATH "Custom OpenSSL root directory")
endif()

if(DEFINED OPENSSL_ROOT_DIR AND NOT "${OPENSSL_ROOT_DIR}" STREQUAL "")
  list(PREPEND CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib64/cmake/OpenSSL")
    set(OpenSSL_DIR
        "${OPENSSL_ROOT_DIR}/lib64/cmake/OpenSSL"
        CACHE PATH "Custom OpenSSL config directory" FORCE)
  endif()
endif()

if(NOT DEFINED BROTLI_ROOT_DIR
   AND DEFINED ENV{BROTLI_ROOT_DIR}
   AND NOT "$ENV{BROTLI_ROOT_DIR}" STREQUAL "")
  set(BROTLI_ROOT_DIR
      "$ENV{BROTLI_ROOT_DIR}"
      CACHE PATH "Custom Brotli root directory")
endif()

set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost 1.83.0 REQUIRED COMPONENTS filesystem)

set(WEBRTC_SOURCES
    log/log.cpp
    net/http.cpp
    net/socket.cpp
    util/file.cpp
    util/random.cpp
    util/error.cpp
    util/timestamp.cpp
    server/router.cpp
    server/whip_handler.cpp
    server/whep_handler.cpp
    session/publisher_session.cpp
    session/subscriber_session.cpp
    session/stream_registry.cpp
    signaling/sdp/sdp_types.cpp
    signaling/sdp/sdp_lexer.cpp
    signaling/sdp/sdp_parser.cpp
    signaling/sdp/sdp_summary.cpp
    signaling/sdp/sdp_offer_validator.cpp
    signaling/sdp/sdp_formatter.cpp
    signaling/sdp/sdp_answer_builder.cpp
    signaling/sdp/sdp_codec_negotiator.cpp
    security/certificate_fingerprint.cpp
    ice/ice_credentials.cpp
    signaling/webrtc_answer_factory.cpp)

add_executable(SimpleWebrtc ${WEBRTC_SOURCES} main.cpp)

target_include_directories(
  SimpleWebrtc
  PRIVATE ${CMAKE_SOURCE_DIR} ${Boost_INCLUDE_DIRS}
          ${CMAKE_SOURCE_DIR}/third/spdlog/include
          ${CMAKE_SOURCE_DIR}/third/rapidjson/include)

if(UNIX
   AND NOT APPLE
   AND NOT ENABLE_STATIC_LINK)
  target_link_options(SimpleWebrtc PRIVATE "-Wl,--no-as-needed"
                      "${BROTLICOMMON_LIBRARY}" "-Wl,--as-needed")
endif()

target_link_libraries(SimpleWebrtc PRIVATE OpenSSL::SSL OpenSSL::Crypto
                                           Threads::Threads ${Boost_LIBRARIES})
