#include "averox_crypto.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int test_aad_enforcement() {
    printf("Testing AAD enforcement...\n");
    
    uint8_t key[AVEROX_KEY_SIZE];
    averox_generate_key(key);
    
    const char *plaintext = "Hello, World!";
    averox_envelope_t envelope;
    averox_envelope_init(&envelope);
    
    // Test 1: Encryption without AAD should fail
    averox_error_t result = averox_encrypt(key, (uint8_t*)plaintext, strlen(plaintext), 
                                          NULL, 0, &envelope);
    assert(result == AVEROX_ERROR_AAD_REQUIRED);
    printf("  ✅ Correctly rejected encryption without AAD\n");
    
    // Test 2: Encryption with AAD should succeed
    const char *aad = "metadata";
    result = averox_encrypt(key, (uint8_t*)plaintext, strlen(plaintext), 
                           (uint8_t*)aad, strlen(aad), &envelope);
    assert(result == AVEROX_SUCCESS);
    printf("  ✅ Successfully encrypted with AAD\n");
    
    // Test 3: Decryption without AAD should fail
    uint8_t decrypted[256];
    size_t decrypted_len;
    result = averox_decrypt(key, &envelope, NULL, 0, decrypted, &decrypted_len);
    assert(result == AVEROX_ERROR_AAD_REQUIRED);
    printf("  ✅ Correctly rejected decryption without AAD\n");
    
    // Test 4: Decryption with correct AAD should succeed
    result = averox_decrypt(key, &envelope, (uint8_t*)aad, strlen(aad), decrypted, &decrypted_len);
    assert(result == AVEROX_SUCCESS);
    assert(decrypted_len == strlen(plaintext));
    assert(memcmp(decrypted, plaintext, decrypted_len) == 0);
    printf("  ✅ Successfully decrypted with correct AAD\n");
    
    averox_envelope_free(&envelope);
    return 1;
}

int main() {
    printf("🔐 Averox Crypto C SDK Test Suite\n");
    printf("==================================\n");
    
    if (!test_aad_enforcement()) {
        printf("❌ AAD enforcement tests failed\n");
        return 1;
    }
    
    printf("\n🎉 All tests passed!\n");
    return 0;
}
