cmake_minimum_required(VERSION 3.15)
project(SENTINNELLE VERSION 1.0.0 LANGUAGES CXX)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Security and warning flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -pie")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security")

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(pybind11 REQUIRED)

# Policy settings
cmake_policy(SET CMP0135 NEW)  # Use extraction timestamp for FetchContent

# nlohmann/json (header-only) - use version compatible with CMake 3.15
include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.10.5/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

# Core library
add_library(sentinelle_core STATIC
    core/crypto.cpp
    core/validation.cpp
)

target_include_directories(sentinelle_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(sentinelle_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Ingest library
add_library(sentinelle_ingest STATIC
    ingest/http_client.cpp
    ingest/parsers.cpp
)

target_include_directories(sentinelle_ingest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CURL_INCLUDE_DIRS}
    ${LIBXML2_INCLUDE_DIR}
)

target_link_libraries(sentinelle_ingest PUBLIC
    sentinelle_core
    ${CURL_LIBRARIES}
    ${LIBXML2_LIBRARIES}
    nlohmann_json::nlohmann_json
)

# Python bindings
pybind11_add_module(sentinelle_core_module
    bindings/python_bindings.cpp
)

target_link_libraries(sentinelle_core_module PRIVATE
    sentinelle_core
    sentinelle_ingest
)

# Set output name to sentinelle_core (without _module suffix)
set_target_properties(sentinelle_core_module PROPERTIES OUTPUT_NAME sentinelle_core)

# Testing
option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    
    # Google Test
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/release-1.12.1.tar.gz
    )
    FetchContent_MakeAvailable(googletest)
    
    # C++ tests
    add_executable(test_crypto tests/cpp/test_crypto.cpp)
    target_link_libraries(test_crypto sentinelle_core gtest_main)
    add_test(NAME test_crypto COMMAND test_crypto)
    
    add_executable(test_validation tests/cpp/test_validation.cpp)
    target_link_libraries(test_validation sentinelle_core gtest_main)
    add_test(NAME test_validation COMMAND test_validation)
    
    add_executable(test_http_client tests/cpp/test_http_client.cpp)
    target_link_libraries(test_http_client sentinelle_ingest gtest_main)
    add_test(NAME test_http_client COMMAND test_http_client)
    
    add_executable(test_parsers tests/cpp/test_parsers.cpp)
    target_link_libraries(test_parsers sentinelle_ingest gtest_main)
    add_test(NAME test_parsers COMMAND test_parsers)
endif()

# Fuzzing (optional, requires Clang)
option(BUILD_FUZZ "Build fuzzing targets" OFF)

if(BUILD_FUZZ)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_executable(fuzz_parsers tests/fuzz/fuzz_parsers.cpp)
        target_link_libraries(fuzz_parsers sentinelle_ingest)
        target_compile_options(fuzz_parsers PRIVATE -fsanitize=fuzzer,address)
        target_link_options(fuzz_parsers PRIVATE -fsanitize=fuzzer,address)
    else()
        message(WARNING "Fuzzing requires Clang compiler")
    endif()
endif()

# Installation
install(TARGETS sentinelle_core_module
    LIBRARY DESTINATION ${Python_SITEARCH}
)
