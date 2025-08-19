# Averox Cryptographic SDK - C/C++ Implementation
# Production-grade encryption with enterprise security features

cmake_minimum_required(VERSION 3.16)
project(averox_crypto_sdk VERSION 2.0.0 LANGUAGES C CXX)

# Compiler requirements
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security compilation flags
if(NOT WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
    
    # Position independent code
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    
    # Address sanitizer for debug builds
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
    endif()
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

# Source files
set(SOURCES
    src/averox_crypto.c
    src/averox_envelope.c
    src/averox_hkdf.c
    src/averox_telemetry.c
    src/averox_secure_memory.c
    src/averox_nist_vectors.c
)

set(HEADERS
    include/averox/crypto.h
    include/averox/envelope.h
    include/averox/hkdf.h
    include/averox/telemetry.h
    include/averox/secure_memory.h
    include/averox/nist_vectors.h
    include/averox/common.h
)

# Create shared library
add_library(averox_crypto SHARED ${SOURCES})
target_link_libraries(averox_crypto ${LIBSODIUM_LIBRARIES} OpenSSL::Crypto)
target_compile_options(averox_crypto PRIVATE ${LIBSODIUM_CFLAGS_OTHER})

# Create static library
add_library(averox_crypto_static STATIC ${SOURCES})
target_link_libraries(averox_crypto_static ${LIBSODIUM_LIBRARIES} OpenSSL::Crypto)
target_compile_options(averox_crypto_static PRIVATE ${LIBSODIUM_CFLAGS_OTHER})
set_target_properties(averox_crypto_static PROPERTIES OUTPUT_NAME averox_crypto)

# Version information
set_target_properties(averox_crypto PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 2
    PUBLIC_HEADER "${HEADERS}"
)

# Example executable
add_executable(averox_example examples/example.c)
target_link_libraries(averox_example averox_crypto)

# Test executable with NIST vectors
add_executable(averox_test_nist tests/test_nist_vectors.c)
target_link_libraries(averox_test_nist averox_crypto)

# Fuzzing target (if libFuzzer available)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(averox_fuzz tests/fuzz_target.c)
    target_compile_options(averox_fuzz PRIVATE -fsanitize=fuzzer,address)
    target_link_options(averox_fuzz PRIVATE -fsanitize=fuzzer,address)
    target_link_libraries(averox_fuzz averox_crypto)
endif()

# Install targets
include(GNUInstallDirs)

install(TARGETS averox_crypto averox_crypto_static
    EXPORT AveroxCryptoTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/averox
)

install(FILES averox-crypto.pc.in
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    RENAME averox-crypto.pc
)

# Export configuration
install(EXPORT AveroxCryptoTargets
    FILE AveroxCryptoTargets.cmake
    NAMESPACE Averox::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AveroxCrypto
)

# Config file for find_package
include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/AveroxCryptoConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AveroxCrypto
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/AveroxCryptoConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AveroxCrypto
)

# Enable testing
enable_testing()
add_test(NAME nist_vectors COMMAND averox_test_nist)
add_test(NAME example_basic COMMAND averox_example)

# CPack configuration for distribution
set(CPACK_PACKAGE_NAME "averox-crypto-sdk")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Production-grade cryptographic SDK")
set(CPACK_PACKAGE_VENDOR "Averox Security Platform")
set(CPACK_PACKAGE_CONTACT "security@averox.com")

include(CPack)

# Security policy
message(STATUS "Averox Crypto SDK v${PROJECT_VERSION}")
message(STATUS "Security features: HKDF, Memory zeroization, Timing-safe comparisons")
message(STATUS "Compliance: NIST test vectors, FIPS-ready")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")