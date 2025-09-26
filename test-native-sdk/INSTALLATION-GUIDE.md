# TestNativeSDK SDK - C/C++ Installation Guide

## System Requirements
- **CMake**: 3.10+
- **Compiler**: GCC 7+, Clang 10+, MSVC 2019+
- **OpenSSL**: 1.1.0+
- **pkg-config**: For integration
- **Operating System**: Windows 10+, macOS 10.15+, Linux

## Installation

### From Source (Recommended)
```bash
# Download and extract SDK
git clone https://github.com/averox/testnativesdk-c-sdk.git
cd testnativesdk-c-sdk

# Build and install
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

### Using Package Manager

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install libaverox-crypto-dev
```

#### CentOS/RHEL
```bash
sudo yum install averox-crypto-devel
```

#### macOS (Homebrew)
```bash
brew install averox/testnativesdk-crypto
```

## Quick Start

### Basic Usage
```c
#include <averox_crypto.h>
#include <stdio.h>
#include <string.h>

int main() {
    // Generate master key
    uint8_t master_key[AVEROX_KEY_SIZE];
    averox_generate_key(master_key);
    
    // Setup encryption
    const char* plaintext = "Sensitive data";
    const char* aad = "context-info";
    
    averox_envelope_t envelope;
    averox_envelope_init(&envelope);
    
    // Encrypt (AAD required)
    averox_error_t result = averox_encrypt(
        master_key,
        (uint8_t*)plaintext, strlen(plaintext),
        (uint8_t*)aad, strlen(aad),
        &envelope
    );
    
    if (result != AVEROX_SUCCESS) {
        printf("Encryption failed: %d\n", result);
        return 1;
    }
    
    printf("✅ Encryption successful\n");
    
    // Decrypt
    uint8_t decrypted[256];
    size_t decrypted_len;
    
    result = averox_decrypt(
        master_key,
        &envelope,
        (uint8_t*)aad, strlen(aad),
        decrypted, &decrypted_len
    );
    
    if (result == AVEROX_SUCCESS) {
        printf("Decrypted: %.*s\n", (int)decrypted_len, decrypted);
    }
    
    // Cleanup
    averox_envelope_free(&envelope);
    averox_secure_zero(master_key, AVEROX_KEY_SIZE);
    
    return 0;
}
```

### CMake Integration
```cmake
cmake_minimum_required(VERSION 3.10)
project(MyApp)

find_package(PkgConfig REQUIRED)
pkg_check_modules(AVEROX REQUIRED sdkcrypto)

add_executable(myapp main.c)
target_link_libraries(myapp ${AVEROX_LIBRARIES})
target_include_directories(myapp PRIVATE ${AVEROX_INCLUDE_DIRS})
target_compile_options(myapp PRIVATE ${AVEROX_CFLAGS_OTHER})
```

### Makefile Integration
```makefile
CFLAGS += $(shell pkg-config --cflags sdkcrypto)
LDFLAGS += $(shell pkg-config --libs sdkcrypto)

myapp: main.c
        gcc $(CFLAGS) main.c $(LDFLAGS) -o myapp
```

## Configuration

### Build Options
```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build
cmake -DCMAKE_BUILD_TYPE=Release ..

# With AddressSanitizer
cmake -DCMAKE_C_FLAGS="-fsanitize=address" ..
```

### Environment Variables
```bash
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

## Uninstallation

### From Source
```bash
cd build
sudo make uninstall

# Manual cleanup if needed
sudo rm -f /usr/local/include/averox_crypto.h
sudo rm -f /usr/local/lib/lib*averox*
sudo rm -f /usr/local/lib/pkgconfig/sdkcrypto.pc
```

### Package Manager
```bash
# Ubuntu/Debian
sudo apt remove libaverox-crypto-dev

# CentOS/RHEL  
sudo yum remove averox-crypto-devel

# macOS
brew uninstall averox/testnativesdk-crypto
```

## Troubleshooting

### Build Errors
```bash
# Missing OpenSSL
sudo apt install libssl-dev  # Ubuntu
brew install openssl         # macOS

# Missing CMake
sudo apt install cmake       # Ubuntu
brew install cmake          # macOS

# Missing pkg-config
sudo apt install pkg-config  # Ubuntu
brew install pkgconfig      # macOS
```

### Runtime Errors
```bash
# Library not found
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Check installation
pkg-config --exists sdkcrypto && echo "✅ SDK found" || echo "❌ SDK not found"
```

### Memory Issues
```bash
# Run with AddressSanitizer
gcc -fsanitize=address -g main.c $(pkg-config --cflags --libs sdkcrypto) -o myapp
./myapp

# Run with Valgrind
valgrind --tool=memcheck --leak-check=full ./myapp
```
