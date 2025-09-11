cmake_minimum_required(VERSION 3.20)
project(AveroxCryptoCPP VERSION 2.0.0)

# Government-level security compilation flags
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Security hardening flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -Wformat -Wformat-security")

# Find packages with specific versions
find_package(OpenSSL 3.1.0 REQUIRED)
find_package(cryptopp 8.7.0 REQUIRED)

# FIPS compliance check
if(ENABLE_FIPS)
    if(NOT OPENSSL_FIPS_CAPABLE)
        message(FATAL_ERROR "FIPS mode requested but OpenSSL is not FIPS capable")
    endif()
endif()

# Add main library
add_library(averox_crypto_cpp STATIC src/averox_crypto.cpp)
target_link_libraries(averox_crypto_cpp OpenSSL::SSL OpenSSL::Crypto cryptopp::cryptopp)

# Security properties
set_target_properties(averox_crypto_cpp PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Testing
if(BUILD_TESTING)
    find_package(GTest 1.14.0 REQUIRED)
    add_executable(crypto_tests tests/test_crypto.cpp)
    target_link_libraries(crypto_tests averox_crypto_cpp GTest::gtest_main)
endif()
