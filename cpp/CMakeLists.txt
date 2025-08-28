cmake_minimum_required(VERSION 3.15)
project(salman_40_crypto_sdk VERSION 2.0.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

# Find GoogleTest for testing
find_package(GTest)

# Include directories
include_directories(include)

# Main library
add_library(${PROJECT_NAME} SHARED
    src/averox_crypto.cpp
)

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    OpenSSL::SSL 
    OpenSSL::Crypto
    pthread
)

# Set library properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER include/averox_crypto.h
)

# Installation
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# Benchmark executable
add_executable(benchmark
    benchmarks/benchmark.cpp
)

target_link_libraries(benchmark ${PROJECT_NAME})

# Tests
if(GTest_FOUND)
    enable_testing()
    
    add_executable(crypto_tests
        tests/test_crypto.cpp
    )
    
    target_link_libraries(crypto_tests
        ${PROJECT_NAME}
        GTest::gtest_main
    )
    
    add_test(NAME CryptoTests COMMAND crypto_tests)
endif()

# Security tests
add_executable(security_tests
    tests/security_tests.cpp
)

target_link_libraries(security_tests ${PROJECT_NAME})

# Packaging
set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "Enterprise cryptographic SDK for salman 40")
set(CPACK_GENERATOR "DEB;RPM;TGZ")

include(CPack)

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif()