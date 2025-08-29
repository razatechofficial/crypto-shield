cmake_minimum_required(VERSION 3.16)
project(averox-crypto-sdk VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Security flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security -Wall -Wextra")

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)

# Source files
set(SOURCES
    src/averox_crypto.c
    src/aes_gcm.c  
    src/hkdf.c
    src/envelope.c
    src/telemetry.c
)

set(HEADERS
    include/averox_crypto.h
    include/averox_types.h
    include/averox_errors.h
)

# Create library
add_library(averox-crypto-sdk SHARED ${SOURCES})
target_include_directories(averox-crypto-sdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(averox-crypto-sdk ${OPENSSL_LIBRARIES})
target_compile_options(averox-crypto-sdk PRIVATE ${OPENSSL_CFLAGS_OTHER})
target_include_directories(averox-crypto-sdk PRIVATE ${OPENSSL_INCLUDE_DIRS})

# Install targets
install(TARGETS averox-crypto-sdk 
    EXPORT averox-crypto-sdk-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS} DESTINATION include)

# pkg-config support
configure_file(averox-crypto-sdk.pc.in averox-crypto-sdk.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/averox-crypto-sdk.pc DESTINATION lib/pkgconfig)

# CMake config
install(EXPORT averox-crypto-sdk-targets
    FILE averox-crypto-sdk-targets.cmake
    DESTINATION lib/cmake/averox-crypto-sdk
)