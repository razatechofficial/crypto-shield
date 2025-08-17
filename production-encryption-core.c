/**
 * Production-Ready AES-GCM Encryption Core (C Implementation)
 * Compliant with NIST SP 800-38D standards
 * Features: Standardized 12-byte IV, AAD support, EVP_CTRL_GCM_SET_IVLEN implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Standard sizes for AES-GCM
#define AES_GCM_IV_SIZE 12      // Standardized 12-byte IV
#define AES_GCM_TAG_SIZE 16     // 128-bit authentication tag
#define AES_256_KEY_SIZE 32     // 256-bit key
#define AES_192_KEY_SIZE 24     // 192-bit key
#define AES_128_KEY_SIZE 16     // 128-bit key

// Error codes
typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INVALID_PARAM = -1,
    CRYPTO_ERROR_MEMORY = -2,
    CRYPTO_ERROR_ENCRYPTION = -3,
    CRYPTO_ERROR_DECRYPTION = -4,
    CRYPTO_ERROR_TAG_VERIFICATION = -5,
    CRYPTO_ERROR_IV_LENGTH = -6,
    CRYPTO_ERROR_KEY_LENGTH = -7
} crypto_result_t;

// Envelope structure for cross-platform compatibility
typedef struct {
    char version[8];
    char algorithm[32];
    unsigned char iv[AES_GCM_IV_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *aad;
    size_t aad_len;
    long timestamp;
    int key_size;
} crypto_envelope_t;

/**
 * Secure memory clearing function
 */
void secure_memzero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * Generate cryptographically secure random bytes
 */
crypto_result_t generate_random_bytes(unsigned char *buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (RAND_bytes(buffer, size) != 1) {
        return CRYPTO_ERROR_ENCRYPTION;
    }
    
    return CRYPTO_SUCCESS;
}

/**
 * Generate AES key
 */
crypto_result_t generate_key(unsigned char *key, int key_size) {
    if (key == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (key_size != AES_128_KEY_SIZE && 
        key_size != AES_192_KEY_SIZE && 
        key_size != AES_256_KEY_SIZE) {
        return CRYPTO_ERROR_KEY_LENGTH;
    }
    
    return generate_random_bytes(key, key_size);
}

/**
 * Generate IV (always 12 bytes for optimal GCM performance)
 */
crypto_result_t generate_iv(unsigned char *iv) {
    if (iv == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    return generate_random_bytes(iv, AES_GCM_IV_SIZE);
}

/**
 * Validate key size
 */
crypto_result_t validate_key_size(int key_size) {
    if (key_size != AES_128_KEY_SIZE && 
        key_size != AES_192_KEY_SIZE && 
        key_size != AES_256_KEY_SIZE) {
        return CRYPTO_ERROR_KEY_LENGTH;
    }
    return CRYPTO_SUCCESS;
}

/**
 * Get EVP cipher based on key size
 */
const EVP_CIPHER* get_evp_cipher(int key_size) {
    switch (key_size) {
        case AES_128_KEY_SIZE:
            return EVP_aes_128_gcm();
        case AES_192_KEY_SIZE:
            return EVP_aes_192_gcm();
        case AES_256_KEY_SIZE:
            return EVP_aes_256_gcm();
        default:
            return NULL;
    }
}

/**
 * AES-GCM Encryption with proper EVP_CTRL_GCM_SET_IVLEN implementation
 */
crypto_result_t aes_gcm_encrypt(
    const unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *key, int key_size,
    const unsigned char *iv,
    const unsigned char *aad, size_t aad_len,
    unsigned char *ciphertext, size_t *ciphertext_len,
    unsigned char *tag
) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    crypto_result_t result = CRYPTO_ERROR_ENCRYPTION;
    
    // Validate inputs
    if (plaintext == NULL || key == NULL || iv == NULL || 
        ciphertext == NULL || ciphertext_len == NULL || tag == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (validate_key_size(key_size) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR_KEY_LENGTH;
    }
    
    // Create and initialize context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, get_evp_cipher(key_size), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }
    
    // CRITICAL: Set IV length to 12 bytes for interoperability
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL) != 1) {
        goto cleanup;
    }
    
    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto cleanup;
    }
    
    // Provide AAD if present
    if (aad != NULL && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            goto cleanup;
        }
    }
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        goto cleanup;
    }
    *ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        goto cleanup;
    }
    *ciphertext_len += len;
    
    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        goto cleanup;
    }
    
    result = CRYPTO_SUCCESS;
    
cleanup:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    
    // Clear sensitive data on error
    if (result != CRYPTO_SUCCESS) {
        secure_memzero(ciphertext, *ciphertext_len);
        secure_memzero(tag, AES_GCM_TAG_SIZE);
    }
    
    return result;
}

/**
 * AES-GCM Decryption with proper EVP_CTRL_GCM_SET_IVLEN implementation
 */
crypto_result_t aes_gcm_decrypt(
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *key, int key_size,
    const unsigned char *iv,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *tag,
    unsigned char *plaintext, size_t *plaintext_len
) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    crypto_result_t result = CRYPTO_ERROR_DECRYPTION;
    
    // Validate inputs
    if (ciphertext == NULL || key == NULL || iv == NULL || 
        tag == NULL || plaintext == NULL || plaintext_len == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (validate_key_size(key_size) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR_KEY_LENGTH;
    }
    
    // Create and initialize context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, get_evp_cipher(key_size), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }
    
    // CRITICAL: Set IV length to 12 bytes for interoperability
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL) != 1) {
        goto cleanup;
    }
    
    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto cleanup;
    }
    
    // Provide AAD if present
    if (aad != NULL && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            goto cleanup;
        }
    }
    
    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        goto cleanup;
    }
    *plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void*)tag) != 1) {
        goto cleanup;
    }
    
    // Finalize decryption and verify tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret <= 0) {
        result = CRYPTO_ERROR_TAG_VERIFICATION;
        goto cleanup;
    }
    *plaintext_len += len;
    
    result = CRYPTO_SUCCESS;
    
cleanup:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    
    // Clear sensitive data on error
    if (result != CRYPTO_SUCCESS) {
        secure_memzero(plaintext, *plaintext_len);
    }
    
    return result;
}

/**
 * High-level encrypt function with envelope
 */
crypto_result_t encrypt_with_envelope(
    const unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *key, int key_size,
    const unsigned char *aad, size_t aad_len,
    crypto_envelope_t *envelope
) {
    crypto_result_t result;
    
    if (plaintext == NULL || key == NULL || envelope == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // Initialize envelope
    strcpy(envelope->version, "1.0");
    snprintf(envelope->algorithm, sizeof(envelope->algorithm), "aes-%d-gcm", key_size * 8);
    envelope->key_size = key_size;
    envelope->timestamp = time(NULL);
    
    // Generate IV
    result = generate_iv(envelope->iv);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    // Allocate ciphertext buffer
    envelope->ciphertext = malloc(plaintext_len);
    if (envelope->ciphertext == NULL) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    // Copy AAD if provided
    if (aad != NULL && aad_len > 0) {
        envelope->aad = malloc(aad_len);
        if (envelope->aad == NULL) {
            free(envelope->ciphertext);
            return CRYPTO_ERROR_MEMORY;
        }
        memcpy(envelope->aad, aad, aad_len);
        envelope->aad_len = aad_len;
    } else {
        envelope->aad = NULL;
        envelope->aad_len = 0;
    }
    
    // Perform encryption
    result = aes_gcm_encrypt(
        plaintext, plaintext_len,
        key, key_size,
        envelope->iv,
        envelope->aad, envelope->aad_len,
        envelope->ciphertext, &envelope->ciphertext_len,
        envelope->tag
    );
    
    if (result != CRYPTO_SUCCESS) {
        free(envelope->ciphertext);
        if (envelope->aad) free(envelope->aad);
        return result;
    }
    
    return CRYPTO_SUCCESS;
}

/**
 * High-level decrypt function with envelope
 */
crypto_result_t decrypt_with_envelope(
    const crypto_envelope_t *envelope,
    const unsigned char *key,
    unsigned char *plaintext, size_t *plaintext_len
) {
    if (envelope == NULL || key == NULL || plaintext == NULL || plaintext_len == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // Validate envelope
    if (strcmp(envelope->version, "1.0") != 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    return aes_gcm_decrypt(
        envelope->ciphertext, envelope->ciphertext_len,
        key, envelope->key_size,
        envelope->iv,
        envelope->aad, envelope->aad_len,
        envelope->tag,
        plaintext, plaintext_len
    );
}

/**
 * Free envelope memory
 */
void free_envelope(crypto_envelope_t *envelope) {
    if (envelope == NULL) return;
    
    if (envelope->ciphertext) {
        secure_memzero(envelope->ciphertext, envelope->ciphertext_len);
        free(envelope->ciphertext);
        envelope->ciphertext = NULL;
    }
    
    if (envelope->aad) {
        secure_memzero(envelope->aad, envelope->aad_len);
        free(envelope->aad);
        envelope->aad = NULL;
    }
}

/**
 * NIST SP 800-38D Test Vector Validation
 */
crypto_result_t run_nist_validation() {
    printf("Running NIST SP 800-38D validation tests...\n");
    
    // Test Case 15 - Empty plaintext and AAD
    unsigned char key_15[AES_128_KEY_SIZE] = {0}; // All zeros
    unsigned char iv_15[AES_GCM_IV_SIZE] = {0};   // All zeros
    unsigned char expected_tag_15[] = {
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
    };
    
    unsigned char ciphertext[1]; // Empty
    size_t ciphertext_len = 0;
    unsigned char tag[AES_GCM_TAG_SIZE];
    
    crypto_result_t result = aes_gcm_encrypt(
        NULL, 0,           // Empty plaintext
        key_15, AES_128_KEY_SIZE,
        iv_15,
        NULL, 0,           // Empty AAD
        ciphertext, &ciphertext_len,
        tag
    );
    
    if (result != CRYPTO_SUCCESS) {
        printf("❌ Test Case 15 encryption failed\n");
        return result;
    }
    
    if (memcmp(tag, expected_tag_15, AES_GCM_TAG_SIZE) != 0) {
        printf("❌ Test Case 15 tag mismatch\n");
        return CRYPTO_ERROR_TAG_VERIFICATION;
    }
    
    printf("✅ NIST Test Case 15 passed\n");
    
    // Test Case 16 - 16-byte plaintext, empty AAD
    unsigned char plaintext_16[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char expected_ciphertext_16[] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };
    unsigned char expected_tag_16[] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };
    
    unsigned char ciphertext_16[16];
    size_t ciphertext_16_len;
    unsigned char tag_16[AES_GCM_TAG_SIZE];
    
    result = aes_gcm_encrypt(
        plaintext_16, 16,
        key_15, AES_128_KEY_SIZE,
        iv_15,
        NULL, 0,           // Empty AAD
        ciphertext_16, &ciphertext_16_len,
        tag_16
    );
    
    if (result != CRYPTO_SUCCESS) {
        printf("❌ Test Case 16 encryption failed\n");
        return result;
    }
    
    if (memcmp(ciphertext_16, expected_ciphertext_16, 16) != 0) {
        printf("❌ Test Case 16 ciphertext mismatch\n");
        return CRYPTO_ERROR_ENCRYPTION;
    }
    
    if (memcmp(tag_16, expected_tag_16, AES_GCM_TAG_SIZE) != 0) {
        printf("❌ Test Case 16 tag mismatch\n");
        return CRYPTO_ERROR_TAG_VERIFICATION;
    }
    
    printf("✅ NIST Test Case 16 passed\n");
    printf("✅ All NIST test vectors passed\n");
    
    return CRYPTO_SUCCESS;
}

/**
 * Print error message
 */
void print_crypto_error(crypto_result_t error) {
    switch (error) {
        case CRYPTO_SUCCESS:
            printf("Success\n");
            break;
        case CRYPTO_ERROR_INVALID_PARAM:
            printf("Error: Invalid parameter\n");
            break;
        case CRYPTO_ERROR_MEMORY:
            printf("Error: Memory allocation failed\n");
            break;
        case CRYPTO_ERROR_ENCRYPTION:
            printf("Error: Encryption failed\n");
            break;
        case CRYPTO_ERROR_DECRYPTION:
            printf("Error: Decryption failed\n");
            break;
        case CRYPTO_ERROR_TAG_VERIFICATION:
            printf("Error: Tag verification failed\n");
            break;
        case CRYPTO_ERROR_IV_LENGTH:
            printf("Error: Invalid IV length\n");
            break;
        case CRYPTO_ERROR_KEY_LENGTH:
            printf("Error: Invalid key length\n");
            break;
        default:
            printf("Error: Unknown error\n");
            break;
    }
}