#ifndef AVEROX_CRYPTO_H
#define AVEROX_CRYPTO_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// AES-256-GCM Constants
#define AVEROX_KEY_SIZE 32
#define AVEROX_IV_SIZE 12
#define AVEROX_TAG_SIZE 16
#define AVEROX_MAX_AAD_SIZE 65536
#define AVEROX_MAX_PLAINTEXT_SIZE 1048576

// Error codes
typedef enum {
    AVEROX_SUCCESS = 0,
    AVEROX_ERROR_INVALID_PARAMETER = -1,
    AVEROX_ERROR_BUFFER_TOO_SMALL = -2,
    AVEROX_ERROR_AUTHENTICATION_FAILED = -3,
    AVEROX_ERROR_MEMORY_ALLOCATION = -4,
    AVEROX_ERROR_AAD_REQUIRED = -5
} averox_error_t;

// Envelope structure
typedef struct {
    char version[8];
    char algorithm[16];
    uint8_t iv[AVEROX_IV_SIZE];
    uint8_t tag[AVEROX_TAG_SIZE];
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t *aad;
    size_t aad_len;
} averox_envelope_t;

// Core functions with ENFORCED AAD policy
averox_error_t averox_encrypt(
    const uint8_t *key,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,        // REQUIRED - cannot be NULL
    size_t aad_len,            // REQUIRED - must be > 0
    averox_envelope_t *envelope
);

averox_error_t averox_decrypt(
    const uint8_t *key,
    const averox_envelope_t *envelope,
    const uint8_t *aad,        // REQUIRED - cannot be NULL
    size_t aad_len,            // REQUIRED - must match encryption AAD
    uint8_t *plaintext,
    size_t *plaintext_len
);

// Memory management
averox_error_t averox_envelope_init(averox_envelope_t *envelope);
void averox_envelope_free(averox_envelope_t *envelope);
void averox_secure_zero(void *ptr, size_t len);

// Key generation
averox_error_t averox_generate_key(uint8_t *key);

#ifdef __cplusplus
}
#endif

#endif // AVEROX_CRYPTO_H
