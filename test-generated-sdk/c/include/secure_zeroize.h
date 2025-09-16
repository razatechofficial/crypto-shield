#ifndef SECURE_ZEROIZE_H
#define SECURE_ZEROIZE_H

void averox_secure_memzero(void* ptr, size_t len);
void secure_clear_openssl_pattern(void* ptr, size_t len);
void secure_clear_explicit_bzero_pattern(void* ptr, size_t len);
void secure_clear_sodium_pattern(void* ptr, size_t len);

#endif