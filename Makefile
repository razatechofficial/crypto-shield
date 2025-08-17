# Production-Ready AES-GCM SDK Makefile
# Builds C library with proper pkg-config and install targets

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -fPIC -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS = -shared -lssl -lcrypto
INCLUDES = -I/usr/include/openssl

# Library details
LIBNAME = libproductioncrypto
VERSION = 1.0.0
SONAME = $(LIBNAME).so.1

# Source files
SOURCES = production-encryption-core.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = production-encryption-core.h

# Build targets
TARGET = $(LIBNAME).so.$(VERSION)
STATIC_TARGET = $(LIBNAME).a

# Installation directories
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include
PKGCONFIGDIR = $(LIBDIR)/pkgconfig

.PHONY: all clean install uninstall test

all: $(TARGET) $(STATIC_TARGET) pkg-config

# Shared library
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -Wl,-soname,$(SONAME) -o $@ $^
	ln -sf $@ $(SONAME)
	ln -sf $@ $(LIBNAME).so

# Static library
$(STATIC_TARGET): $(OBJECTS)
	ar rcs $@ $^

# Object files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Create header file
production-encryption-core.h:
	@echo "/* Production-Ready AES-GCM Encryption Core Header */" > $@
	@echo "#ifndef PRODUCTION_ENCRYPTION_CORE_H" >> $@
	@echo "#define PRODUCTION_ENCRYPTION_CORE_H" >> $@
	@echo "" >> $@
	@echo "#include <stddef.h>" >> $@
	@echo "" >> $@
	@echo "/* Error codes */" >> $@
	@echo "typedef enum {" >> $@
	@echo "    CRYPTO_SUCCESS = 0," >> $@
	@echo "    CRYPTO_ERROR_INVALID_PARAM = -1," >> $@
	@echo "    CRYPTO_ERROR_MEMORY = -2," >> $@
	@echo "    CRYPTO_ERROR_ENCRYPTION = -3," >> $@
	@echo "    CRYPTO_ERROR_DECRYPTION = -4," >> $@
	@echo "    CRYPTO_ERROR_TAG_VERIFICATION = -5," >> $@
	@echo "    CRYPTO_ERROR_IV_LENGTH = -6," >> $@
	@echo "    CRYPTO_ERROR_KEY_LENGTH = -7" >> $@
	@echo "} crypto_result_t;" >> $@
	@echo "" >> $@
	@echo "/* Standard sizes */" >> $@
	@echo "#define AES_GCM_IV_SIZE 12" >> $@
	@echo "#define AES_GCM_TAG_SIZE 16" >> $@
	@echo "#define AES_256_KEY_SIZE 32" >> $@
	@echo "#define AES_192_KEY_SIZE 24" >> $@
	@echo "#define AES_128_KEY_SIZE 16" >> $@
	@echo "" >> $@
	@echo "/* Envelope structure */" >> $@
	@echo "typedef struct {" >> $@
	@echo "    char version[8];" >> $@
	@echo "    char algorithm[32];" >> $@
	@echo "    unsigned char iv[AES_GCM_IV_SIZE];" >> $@
	@echo "    unsigned char tag[AES_GCM_TAG_SIZE];" >> $@
	@echo "    unsigned char *ciphertext;" >> $@
	@echo "    size_t ciphertext_len;" >> $@
	@echo "    unsigned char *aad;" >> $@
	@echo "    size_t aad_len;" >> $@
	@echo "    long timestamp;" >> $@
	@echo "    int key_size;" >> $@
	@echo "} crypto_envelope_t;" >> $@
	@echo "" >> $@
	@echo "/* Function declarations */" >> $@
	@echo "crypto_result_t generate_random_bytes(unsigned char *buffer, size_t size);" >> $@
	@echo "crypto_result_t generate_key(unsigned char *key, int key_size);" >> $@
	@echo "crypto_result_t generate_iv(unsigned char *iv);" >> $@
	@echo "crypto_result_t aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len," >> $@
	@echo "                               const unsigned char *key, int key_size," >> $@
	@echo "                               const unsigned char *iv," >> $@
	@echo "                               const unsigned char *aad, size_t aad_len," >> $@
	@echo "                               unsigned char *ciphertext, size_t *ciphertext_len," >> $@
	@echo "                               unsigned char *tag);" >> $@
	@echo "crypto_result_t aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len," >> $@
	@echo "                               const unsigned char *key, int key_size," >> $@
	@echo "                               const unsigned char *iv," >> $@
	@echo "                               const unsigned char *aad, size_t aad_len," >> $@
	@echo "                               const unsigned char *tag," >> $@
	@echo "                               unsigned char *plaintext, size_t *plaintext_len);" >> $@
	@echo "crypto_result_t encrypt_with_envelope(const unsigned char *plaintext, size_t plaintext_len," >> $@
	@echo "                                     const unsigned char *key, int key_size," >> $@
	@echo "                                     const unsigned char *aad, size_t aad_len," >> $@
	@echo "                                     crypto_envelope_t *envelope);" >> $@
	@echo "crypto_result_t decrypt_with_envelope(const crypto_envelope_t *envelope," >> $@
	@echo "                                     const unsigned char *key," >> $@
	@echo "                                     unsigned char *plaintext, size_t *plaintext_len);" >> $@
	@echo "void free_envelope(crypto_envelope_t *envelope);" >> $@
	@echo "crypto_result_t run_nist_validation(void);" >> $@
	@echo "void print_crypto_error(crypto_result_t error);" >> $@
	@echo "" >> $@
	@echo "#endif /* PRODUCTION_ENCRYPTION_CORE_H */" >> $@

# Create pkg-config file
pkg-config: production-crypto.pc

production-crypto.pc:
	@echo "prefix=$(PREFIX)" > $@
	@echo "exec_prefix=\$${prefix}" >> $@
	@echo "libdir=\$${exec_prefix}/lib" >> $@
	@echo "includedir=\$${prefix}/include" >> $@
	@echo "" >> $@
	@echo "Name: Production Crypto" >> $@
	@echo "Description: Production-ready AES-GCM encryption library" >> $@
	@echo "Version: $(VERSION)" >> $@
	@echo "Libs: -L\$${libdir} -lproductioncrypto -lssl -lcrypto" >> $@
	@echo "Cflags: -I\$${includedir}" >> $@

# Test the library
test: $(TARGET) test-production-crypto

test-production-crypto: test-production-crypto.c $(TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -L. -lproductioncrypto -lssl -lcrypto
	LD_LIBRARY_PATH=. ./$@

test-production-crypto.c:
	@echo "/* Test program for production crypto library */" > $@
	@echo "#include \"production-encryption-core.h\"" >> $@
	@echo "#include <stdio.h>" >> $@
	@echo "#include <string.h>" >> $@
	@echo "" >> $@
	@echo "int main() {" >> $@
	@echo "    printf(\"Testing production crypto library...\\n\");" >> $@
	@echo "    " >> $@
	@echo "    // Run NIST validation" >> $@
	@echo "    crypto_result_t result = run_nist_validation();" >> $@
	@echo "    if (result != CRYPTO_SUCCESS) {" >> $@
	@echo "        printf(\"NIST validation failed\\n\");" >> $@
	@echo "        return 1;" >> $@
	@echo "    }" >> $@
	@echo "    " >> $@
	@echo "    // Test basic encryption/decryption" >> $@
	@echo "    unsigned char key[AES_256_KEY_SIZE];" >> $@
	@echo "    unsigned char iv[AES_GCM_IV_SIZE];" >> $@
	@echo "    " >> $@
	@echo "    generate_key(key, AES_256_KEY_SIZE);" >> $@
	@echo "    generate_iv(iv);" >> $@
	@echo "    " >> $@
	@echo "    const char *message = \"Hello, Production Crypto!\";" >> $@
	@echo "    crypto_envelope_t envelope;" >> $@
	@echo "    " >> $@
	@echo "    result = encrypt_with_envelope(" >> $@
	@echo "        (unsigned char*)message, strlen(message)," >> $@
	@echo "        key, AES_256_KEY_SIZE," >> $@
	@echo "        NULL, 0," >> $@
	@echo "        &envelope" >> $@
	@echo "    );" >> $@
	@echo "    " >> $@
	@echo "    if (result != CRYPTO_SUCCESS) {" >> $@
	@echo "        printf(\"Encryption failed\\n\");" >> $@
	@echo "        return 1;" >> $@
	@echo "    }" >> $@
	@echo "    " >> $@
	@echo "    unsigned char decrypted[256];" >> $@
	@echo "    size_t decrypted_len;" >> $@
	@echo "    " >> $@
	@echo "    result = decrypt_with_envelope(&envelope, key, decrypted, &decrypted_len);" >> $@
	@echo "    " >> $@
	@echo "    if (result != CRYPTO_SUCCESS) {" >> $@
	@echo "        printf(\"Decryption failed\\n\");" >> $@
	@echo "        free_envelope(&envelope);" >> $@
	@echo "        return 1;" >> $@
	@echo "    }" >> $@
	@echo "    " >> $@
	@echo "    if (memcmp(message, decrypted, strlen(message)) != 0) {" >> $@
	@echo "        printf(\"Decrypted message doesn't match original\\n\");" >> $@
	@echo "        free_envelope(&envelope);" >> $@
	@echo "        return 1;" >> $@
	@echo "    }" >> $@
	@echo "    " >> $@
	@echo "    printf(\"All tests passed! Library is working correctly.\\n\");" >> $@
	@echo "    free_envelope(&envelope);" >> $@
	@echo "    return 0;" >> $@
	@echo "}" >> $@

# Install library
install: $(TARGET) $(STATIC_TARGET) $(HEADERS) production-crypto.pc
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -d $(DESTDIR)$(PKGCONFIGDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(LIBDIR)/
	install -m 644 $(STATIC_TARGET) $(DESTDIR)$(LIBDIR)/
	install -m 644 $(HEADERS) $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 production-crypto.pc $(DESTDIR)$(PKGCONFIGDIR)/
	ln -sf $(TARGET) $(DESTDIR)$(LIBDIR)/$(SONAME)
	ln -sf $(TARGET) $(DESTDIR)$(LIBDIR)/$(LIBNAME).so
	ldconfig

# Uninstall library
uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(TARGET)
	rm -f $(DESTDIR)$(LIBDIR)/$(STATIC_TARGET)
	rm -f $(DESTDIR)$(LIBDIR)/$(SONAME)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIBNAME).so
	rm -f $(DESTDIR)$(INCLUDEDIR)/$(HEADERS)
	rm -f $(DESTDIR)$(PKGCONFIGDIR)/production-crypto.pc
	ldconfig

# Clean build files
clean:
	rm -f $(OBJECTS) $(TARGET) $(STATIC_TARGET) $(SONAME) $(LIBNAME).so
	rm -f $(HEADERS) production-crypto.pc
	rm -f test-production-crypto test-production-crypto.c

# Help
help:
	@echo "Available targets:"
	@echo "  all       - Build shared and static libraries"
	@echo "  test      - Build and run tests"
	@echo "  install   - Install library system-wide"
	@echo "  uninstall - Remove installed library"
	@echo "  clean     - Remove build files"
	@echo "  help      - Show this help"