# TestNativeSDK Cryptographic SDK - C/C++

Enterprise-grade encryption library with ENFORCED security policies.

## Features

✅ **ENFORCED AAD Policy** - All operations require Additional Authenticated Data
✅ **AES-256-GCM** - Industry standard authenticated encryption
✅ **12-byte IV Policy** - Cryptographically secure initialization vectors
✅ **Memory Zeroization** - Secure cleanup of sensitive data
✅ **OpenSSL Backend** - Production-tested cryptographic primitives

## Building

### Prerequisites
- CMake 3.10+
- OpenSSL 1.1.0+
- C compiler (GCC, Clang, MSVC)
- pkg-config (for integration)

### Standard Build
```bash
mkdir build && cd build
cmake ..
make
make install
```

### Using pkg-config
After installation, you can use pkg-config to get build flags:

```bash
# Get compiler and linker flags
pkg-config --cflags --libs sdkcrypto

# Example compilation
gcc myapp.c $(pkg-config --cflags --libs sdkcrypto) -o myapp
```

### CMake Integration
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDKCRYPTO REQUIRED sdkcrypto)

target_link_libraries(myapp ${SDKCRYPTO_LIBRARIES})
target_include_directories(myapp PRIVATE ${SDKCRYPTO_INCLUDE_DIRS})
```

## Usage

### Basic Encryption/Decryption
```c
#include <averox_crypto.h>

int main() {
    // Generate a key
    uint8_t key[AVEROX_KEY_SIZE];
    averox_generate_key(key);
    
    // Prepare data
    const char *message = "Secret message";
    const char *metadata = "important-context";  // AAD is REQUIRED
    
    // Encrypt
    averox_envelope_t envelope;
    averox_envelope_init(&envelope);
    
    averox_error_t result = averox_encrypt(
        key,
        (uint8_t*)message, strlen(message),
        (uint8_t*)metadata, strlen(metadata),  // AAD cannot be NULL
        &envelope
    );
    
    if (result != AVEROX_SUCCESS) {
        printf("Encryption failed: %d\n", result);
        return 1;
    }
    
    // Decrypt
    uint8_t plaintext[1024];
    size_t plaintext_len;
    
    result = averox_decrypt(
        key, &envelope,
        (uint8_t*)metadata, strlen(metadata),  // Must match encryption AAD
        plaintext, &plaintext_len
    );
    
    if (result == AVEROX_SUCCESS) {
        printf("Decrypted: %.*s\n", (int)plaintext_len, plaintext);
    }
    
    // Cleanup
    averox_envelope_free(&envelope);
    averox_secure_zero(key, sizeof(key));
    
    return 0;
}
```

## Testing

### Run Tests
```bash
make test
```

### Verify Installation
```bash
# This runs post-install verification
make verify_install
```

The verification process:
1. Installs to a temporary prefix
2. Verifies pkg-config file exists: `/tmp/pfx/lib/pkgconfig/sdkcrypto.pc`
3. Tests pkg-config functionality: `pkg-config --exists sdkcrypto`

## Integration with pkg-config

After installation, you can use pkg-config to compile applications:

```bash
# Check if the library is available
pkg-config --exists sdkcrypto

# Get compiler flags
pkg-config --cflags sdkcrypto

# Get linker flags  
pkg-config --libs sdkcrypto

# Compile your application
gcc myapp.c $(pkg-config --cflags --libs sdkcrypto) -o myapp
```

### Example Application
```c
#include <averox_crypto.h>
#include <stdio.h>

int main() {
    uint8_t key[AVEROX_KEY_SIZE];
    averox_generate_key(key);
    printf("Generated 256-bit encryption key\n");
    return 0;
}
```

Compile with:
```bash
gcc example.c $(pkg-config --cflags --libs sdkcrypto) -o example
```

## Error Handling

All functions return `averox_error_t`:

- `AVEROX_SUCCESS` (0) - Operation successful
- `AVEROX_ERROR_AAD_REQUIRED` (-5) - **AAD is mandatory for all operations**
- `AVEROX_ERROR_AUTHENTICATION_FAILED` (-3) - Invalid tag or tampered data
- `AVEROX_ERROR_INVALID_PARAMETER` (-1) - Invalid input parameters

## Security Notes

🔒 **AAD ENFORCEMENT**: This library REQUIRES Additional Authenticated Data for all encrypt/decrypt operations. This prevents certain classes of attacks and ensures data integrity.

🔒 **IV Policy**: 12-byte IVs are automatically generated and cannot be overridden.

🔒 **Memory Security**: Use `averox_secure_zero()` to clear sensitive data.

## License

MIT License - see LICENSE file for details.
