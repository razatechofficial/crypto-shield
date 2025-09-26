cmake_minimum_required(VERSION 3.10)
project(testnativesdk_crypto VERSION 2.0.0)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Create the library
add_library(testnativesdk_crypto SHARED
    src/averox_crypto.c
)

# Set properties
set_target_properties(testnativesdk_crypto PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/averox_crypto.h"
)

# Link libraries
target_link_libraries(testnativesdk_crypto PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Include directories
target_include_directories(testnativesdk_crypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Install the library
install(TARGETS testnativesdk_crypto
    EXPORT testnativesdk_cryptoTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# Generate and install pkg-config file
configure_file(sdkcrypto.pc.in sdkcrypto.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/sdkcrypto.pc
    DESTINATION lib/pkgconfig
)

# Install CMake config files
install(EXPORT testnativesdk_cryptoTargets
    FILE testnativesdk_cryptoTargets.cmake
    NAMESPACE TestNativeSDK::
    DESTINATION lib/cmake/testnativesdk_crypto
)

# Add tests
enable_testing()
add_executable(test_crypto test/test_crypto.c)
target_link_libraries(test_crypto testnativesdk_crypto)
add_test(NAME crypto_test COMMAND test_crypto)

# Post-install CI assertion (for automated testing)
add_custom_target(verify_install
    COMMAND ${CMAKE_COMMAND} --install . --prefix /tmp/verify_pfx
    COMMAND test -f /tmp/verify_pfx/lib/pkgconfig/sdkcrypto.pc
    COMMAND PKG_CONFIG_PATH=/tmp/verify_pfx/lib/pkgconfig pkg-config --exists sdkcrypto
    COMMENT "Verifying pkg-config installation"
    VERBATIM
)
