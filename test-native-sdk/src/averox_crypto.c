#include "averox_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>

// ENFORCED AAD validation - all operations REQUIRE AAD
#define VALIDATE_AAD(aad, aad_len) \
    do { \
        if (!aad || aad_len == 0) { \
            return AVEROX_ERROR_AAD_REQUIRED; \
        } \
    } while(0)

averox_error_t averox_encrypt(
    const uint8_t *key,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    averox_envelope_t *envelope
) {
    if (!key || !plaintext || !envelope) {
        return AVEROX_ERROR_INVALID_PARAMETER;
    }
    
    // ENFORCED: AAD is required for all encryption operations
    VALIDATE_AAD(aad, aad_len);
    
    if (plaintext_len > AVEROX_MAX_PLAINTEXT_SIZE) {
        return AVEROX_ERROR_INVALID_PARAMETER;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return AVEROX_ERROR_MEMORY_ALLOCATION;
    
    // Initialize envelope
    strcpy(envelope->version, "2.0");
    strcpy(envelope->algorithm, "AES-256-GCM");
    
    // ENFORCED 12-byte IV generation (cannot be overridden)
    if (RAND_bytes(envelope->iv, AVEROX_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AVEROX_IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, envelope->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Set AAD
    int len;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Allocate ciphertext buffer
    envelope->ciphertext = malloc(plaintext_len);
    if (!envelope->ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Encrypt
    if (EVP_EncryptUpdate(ctx, envelope->ciphertext, &len, plaintext, plaintext_len) != 1) {
        free(envelope->ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    envelope->ciphertext_len = len;
    
    // Finalize
    if (EVP_EncryptFinal_ex(ctx, envelope->ciphertext + len, &len) != 1) {
        free(envelope->ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    envelope->ciphertext_len += len;
    
    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AVEROX_TAG_SIZE, envelope->tag) != 1) {
        free(envelope->ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Store AAD copy
    envelope->aad = malloc(aad_len);
    if (!envelope->aad) {
        free(envelope->ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    memcpy(envelope->aad, aad, aad_len);
    envelope->aad_len = aad_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return AVEROX_SUCCESS;
}

averox_error_t averox_decrypt(
    const uint8_t *key,
    const averox_envelope_t *envelope,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *plaintext,
    size_t *plaintext_len
) {
    if (!key || !envelope || !plaintext || !plaintext_len) {
        return AVEROX_ERROR_INVALID_PARAMETER;
    }
    
    // ENFORCED: AAD is required for all decryption operations
    VALIDATE_AAD(aad, aad_len);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return AVEROX_ERROR_MEMORY_ALLOCATION;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AVEROX_IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, envelope->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Set AAD
    int len;
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Decrypt
    if (EVP_DecryptUpdate(ctx, plaintext, &len, envelope->ciphertext, envelope->ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    *plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AVEROX_TAG_SIZE, (void*)envelope->tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_MEMORY_ALLOCATION;
    }
    
    // Verify authentication tag
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return AVEROX_ERROR_AUTHENTICATION_FAILED;
    }
    *plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return AVEROX_SUCCESS;
}

void averox_secure_zero(void *ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

averox_error_t averox_generate_key(uint8_t *key) {
    if (!key) return AVEROX_ERROR_INVALID_PARAMETER;
    return (RAND_bytes(key, AVEROX_KEY_SIZE) == 1) ? AVEROX_SUCCESS : AVEROX_ERROR_MEMORY_ALLOCATION;
}

averox_error_t averox_envelope_init(averox_envelope_t *envelope) {
    if (!envelope) return AVEROX_ERROR_INVALID_PARAMETER;
    memset(envelope, 0, sizeof(averox_envelope_t));
    return AVEROX_SUCCESS;
}

void averox_envelope_free(averox_envelope_t *envelope) {
    if (envelope) {
        if (envelope->ciphertext) {
            averox_secure_zero(envelope->ciphertext, envelope->ciphertext_len);
            free(envelope->ciphertext);
        }
        if (envelope->aad) {
            averox_secure_zero(envelope->aad, envelope->aad_len);
            free(envelope->aad);
        }
        memset(envelope, 0, sizeof(averox_envelope_t));
    }
}
