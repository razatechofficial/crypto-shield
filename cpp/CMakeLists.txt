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

# Install targets for production packaging
include(GNUInstallDirs)

# Install the library
install(TARGETS averox_crypto_cpp
    EXPORT AveroxCryptoCPPTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install headers
install(FILES include/averox_crypto.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install export targets
install(EXPORT AveroxCryptoCPPTargets
    FILE AveroxCryptoCPPTargets.cmake
    NAMESPACE AveroxCrypto::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AveroxCryptoCPP
)

# Generate and install pkg-config descriptor
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/averox-crypto.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/averox-crypto.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/averox-crypto.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Generate and install sdkcrypto pkg-config descriptor for external audit compliance
include(GNUInstallDirs)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sdkcrypto.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/sdkcrypto.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sdkcrypto.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Install CMake config files
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoCPPConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/AveroxCryptoCPPConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoCPPConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AveroxCryptoCPP
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoCPPConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoCPPConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AveroxCryptoCPP
)
