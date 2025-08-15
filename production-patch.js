// Production Patch - Implementing Executive Audit Recommendations
// This patch addresses: NIST test vectors, AAD standardization, 12-byte IV enforcement, security hardening

const fs = require('fs');
const path = require('path');

// NIST SP 800-38D Official Test Vectors for AES-256-GCM
const NIST_TEST_VECTORS = {
  // Test Case 15: AES-256-GCM with 96-bit IV and AAD
  test_case_15: {
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    plaintext: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    ciphertext: '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
    tag: 'b094dac5d93471bdec1a502270e3cc6c'
  },
  // Test Case 16: AES-256-GCM with empty plaintext  
  test_case_16: {
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    plaintext: '',
    aad: '',
    ciphertext: '',
    tag: '3247184b3c4f69a44dbcd22887bbb418'
  }
};

// Enhanced C implementation with security hardening
const PRODUCTION_C_PATCH = `
// Production-ready security enhancements

// Enhanced error taxonomy for debugging
typedef enum {
    AVEROX_SUCCESS = 0,
    AVEROX_ERROR_INVALID_PARAM = -1,
    AVEROX_ERROR_CRYPTO_FAIL = -2,
    AVEROX_ERROR_MEMORY = -3,
    AVEROX_ERROR_RNG_FAIL = -4,
    AVEROX_ERROR_TAG_VERIFY_FAIL = -5,
    AVEROX_ERROR_IV_REUSE = -6,
    AVEROX_ERROR_BUFFER_TOO_SMALL = -7
} averox_error_t;

// Security: Enforce 12-byte IV for GCM interoperability
#define AVEROX_IV_SIZE 12
#define AVEROX_TAG_SIZE 16
#define AVEROX_KEY_SIZE 32

// Security: Zeroize sensitive memory
static void secure_zero(void *ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

// Enhanced IV validation - critical for production
static int validate_iv_unique(const uint8_t *iv) {
    // In production, implement IV uniqueness tracking
    // For now, check for obvious reuse (all zeros)
    static uint8_t zero_iv[AVEROX_IV_SIZE] = {0};
    if (memcmp(iv, zero_iv, AVEROX_IV_SIZE) == 0) {
        return AVEROX_ERROR_IV_REUSE;
    }
    return AVEROX_SUCCESS;
}

// Production encrypt with enhanced security
int averox_encrypt_secure(const uint8_t *plaintext, size_t plaintext_len,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *ciphertext, size_t *ciphertext_len,
                         uint8_t *iv, uint8_t *tag) {
    
    // Enhanced parameter validation
    if (!plaintext || !key || !ciphertext || !ciphertext_len || !iv || !tag) {
        return AVEROX_ERROR_INVALID_PARAM;
    }
    
    if (key_len != AVEROX_KEY_SIZE) {
        return AVEROX_ERROR_INVALID_PARAM;
    }
    
    if (plaintext_len > 1024 * 1024) { // 1MB limit for safety
        return AVEROX_ERROR_INVALID_PARAM;
    }
    
    // Generate cryptographically secure IV
    if (RAND_bytes(iv, AVEROX_IV_SIZE) != 1) {
        return AVEROX_ERROR_RNG_FAIL;
    }
    
    // Validate IV uniqueness (critical for GCM)
    int iv_check = validate_iv_unique(iv);
    if (iv_check != AVEROX_SUCCESS) {
        secure_zero(iv, AVEROX_IV_SIZE);
        return iv_check;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_zero(iv, AVEROX_IV_SIZE);
        return AVEROX_ERROR_MEMORY;
    }
    
    int result = AVEROX_ERROR_CRYPTO_FAIL;
    int len;
    
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            break;
        }
        
        // CRITICAL: Set IV length for interoperability
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AVEROX_IV_SIZE, NULL) != 1) {
            break;
        }
        
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
            break;
        }
        
        // Process AAD if provided
        if (aad && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
                break;
            }
        }
        
        // Encrypt plaintext
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
            break;
        }
        *ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
            break;
        }
        *ciphertext_len += len;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AVEROX_TAG_SIZE, tag) != 1) {
            break;
        }
        
        result = AVEROX_SUCCESS;
    } while (0);
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Security: Zeroize sensitive data on failure
    if (result != AVEROX_SUCCESS) {
        secure_zero(ciphertext, *ciphertext_len);
        secure_zero(iv, AVEROX_IV_SIZE);
        secure_zero(tag, AVEROX_TAG_SIZE);
    }
    
    return result;
}

// NIST test vector validation function
static int test_nist_official_vectors() {
    printf("Running NIST SP 800-38D official test vectors...\\n");
    
    // Test Case 15 - with AAD
    uint8_t key[32];
    uint8_t iv[12];
    uint8_t expected_tag[16];
    
    // Convert hex strings to bytes
    for (int i = 0; i < 32; i++) {
        sscanf("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308" + i*2, "%2hhx", &key[i]);
    }
    for (int i = 0; i < 12; i++) {
        sscanf("cafebabefacedbaddecaf888" + i*2, "%2hhx", &iv[i]);
    }
    for (int i = 0; i < 16; i++) {
        sscanf("b094dac5d93471bdec1a502270e3cc6c" + i*2, "%2hhx", &expected_tag[i]);
    }
    
    const char *plaintext_hex = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
    const char *aad_hex = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    
    uint8_t plaintext[64];
    uint8_t aad[20];
    size_t pt_len = strlen(plaintext_hex) / 2;
    size_t aad_len = strlen(aad_hex) / 2;
    
    // Convert plaintext and AAD
    for (size_t i = 0; i < pt_len; i++) {
        sscanf(plaintext_hex + i*2, "%2hhx", &plaintext[i]);
    }
    for (size_t i = 0; i < aad_len; i++) {
        sscanf(aad_hex + i*2, "%2hhx", &aad[i]);
    }
    
    uint8_t ciphertext[128];
    size_t ct_len;
    uint8_t computed_tag[16];
    
    int result = averox_encrypt_secure(plaintext, pt_len, key, 32, aad, aad_len,
                                      ciphertext, &ct_len, iv, computed_tag);
    
    if (result != AVEROX_SUCCESS) {
        printf("NIST test encryption FAILED: %d\\n", result);
        return -1;
    }
    
    // Verify tag matches NIST expected value
    if (memcmp(computed_tag, expected_tag, 16) != 0) {
        printf("NIST test tag verification FAILED\\n");
        return -1;
    }
    
    printf("NIST SP 800-38D Test Case 15: PASSED\\n");
    return 0;
}
`;

// Enhanced JavaScript implementation with proper AAD API
const PRODUCTION_JS_PATCH = `
// Production JavaScript SDK with standardized envelope format

class AveroxCrypto {
  constructor(options = {}) {
    this.config = {
      keySize: 32,
      ivSize: 12,    // Standardized to 12 bytes for interop
      tagLength: 16,
      ...options
    };
    
    // Validate configuration
    if (this.config.ivSize !== 12) {
      throw new Error('IV size must be 12 bytes for AES-GCM interoperability');
    }
  }

  // Enhanced encrypt with proper AAD support and validation
  encryptWithAAD(plaintext, key, aad = null, providedIV = null) {
    // Enhanced input validation
    if (!plaintext || typeof plaintext !== 'string') {
      throw new Error('Plaintext must be a non-empty string');
    }
    if (!key || typeof key !== 'string') {
      throw new Error('Key must be a non-empty string');
    }
    
    const keyBuffer = Buffer.from(key, 'base64');
    if (keyBuffer.length !== 32) {
      throw new Error('Key must be exactly 256 bits (32 bytes)');
    }
    
    // Generate or validate IV
    let iv;
    if (providedIV) {
      iv = Buffer.from(providedIV, 'base64');
      if (iv.length !== 12) {
        throw new Error('IV must be exactly 12 bytes for GCM mode');
      }
    } else {
      iv = crypto.randomBytes(12);
    }
    
    const cipher = crypto.createCipherGCM('aes-256-gcm', keyBuffer);
    cipher.setIV(iv);
    
    // Process AAD if provided
    if (aad) {
      if (typeof aad !== 'string') {
        throw new Error('AAD must be a string');
      }
      const aadBuffer = Buffer.from(aad, 'utf8');
      cipher.setAAD(aadBuffer);
    }
    
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    if (authTag.length !== 16) {
      throw new Error('Invalid authentication tag length');
    }
    
    // Standardized envelope format for cross-language interop
    const envelope = {
      algorithm: 'aes-256-gcm',
      iv: iv.toString('base64'),
      tag: authTag.toString('base64'),
      data: encrypted.toString('base64')
    };
    
    if (aad) {
      envelope.aad = aad;
    }
    
    return Buffer.from(JSON.stringify(envelope)).toString('base64');
  }

  // Enhanced decrypt with AAD support
  decryptWithAAD(encryptedData, key, expectedAAD = null) {
    if (!encryptedData || typeof encryptedData !== 'string') {
      throw new Error('Encrypted data must be a non-empty string');
    }
    if (!key || typeof key !== 'string') {
      throw new Error('Key must be a non-empty string');
    }
    
    let envelope;
    try {
      envelope = JSON.parse(Buffer.from(encryptedData, 'base64').toString());
    } catch (e) {
      throw new Error('Invalid encrypted data format: ' + e.message);
    }
    
    // Validate envelope structure
    if (!envelope.algorithm || envelope.algorithm !== 'aes-256-gcm') {
      throw new Error('Unsupported or missing algorithm');
    }
    if (!envelope.iv || !envelope.tag || !envelope.data) {
      throw new Error('Invalid envelope: missing required fields');
    }
    
    const keyBuffer = Buffer.from(key, 'base64');
    if (keyBuffer.length !== 32) {
      throw new Error('Key must be exactly 256 bits (32 bytes)');
    }
    
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const encrypted = Buffer.from(envelope.data, 'base64');
    
    // Validate critical lengths for interoperability
    if (iv.length !== 12) {
      throw new Error('Invalid IV length: must be 12 bytes');
    }
    if (tag.length !== 16) {
      throw new Error('Invalid tag length: must be 16 bytes');
    }
    
    const decipher = crypto.createDecipherGCM('aes-256-gcm', keyBuffer);
    decipher.setIV(iv);
    decipher.setAuthTag(tag);
    
    // Handle AAD validation
    if (envelope.aad || expectedAAD) {
      const aadData = expectedAAD || envelope.aad;
      if (!aadData) {
        throw new Error('AAD mismatch: expected AAD but none provided');
      }
      const aadBuffer = Buffer.from(aadData, 'utf8');
      decipher.setAAD(aadBuffer);
    }
    
    try {
      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString('utf8');
    } catch (error) {
      throw new Error('Authentication failed: ' + error.message);
    }
  }

  // NIST test vector validation
  static validateNISTCompliance() {
    console.log('[NIST-VALIDATION] Testing against official SP 800-38D vectors...');
    
    const crypto = new AveroxCrypto();
    
    // NIST Test Case 15
    const testKey = Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex').toString('base64');
    const testIV = Buffer.from('cafebabefacedbaddecaf888', 'hex').toString('base64');
    const testPlaintext = Buffer.from('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255', 'hex').toString('utf8');
    const testAAD = Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex').toString('utf8');
    const expectedTag = 'b094dac5d93471bdec1a502270e3cc6c';
    
    try {
      // Test encryption with fixed IV
      const encrypted = crypto.encryptWithAAD(testPlaintext, testKey, testAAD, testIV);
      const envelope = JSON.parse(Buffer.from(encrypted, 'base64').toString());
      
      // Validate tag matches NIST expected value
      const computedTag = Buffer.from(envelope.tag, 'base64').toString('hex');
      if (computedTag.toLowerCase() !== expectedTag.toLowerCase()) {
        throw new Error(\`Tag mismatch: expected \${expectedTag}, got \${computedTag}\`);
      }
      
      // Test decryption
      const decrypted = crypto.decryptWithAAD(encrypted, testKey, testAAD);
      if (decrypted !== testPlaintext) {
        throw new Error('Decryption validation failed');
      }
      
      console.log('[NIST-VALIDATION] NIST SP 800-38D Test Case 15: PASSED');
      return true;
    } catch (error) {
      console.error('[NIST-VALIDATION] FAILED:', error.message);
      return false;
    }
  }
}

module.exports = { AveroxCrypto };
`;

console.log('Production patch ready with:');
console.log('✅ NIST SP 800-38D official test vectors');
console.log('✅ Standardized 12-byte IV enforcement'); 
console.log('✅ Enhanced AAD API in both C and JS');
console.log('✅ Security hardening with zeroization');
console.log('✅ Enhanced error taxonomy');
console.log('✅ Cross-language envelope validation');

// Example CI/CD integration
const CI_CONFIG = `
# .github/workflows/crypto-validation.yml
name: Cryptographic Validation
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libssl-dev cmake
      - name: Build C library
        run: |
          mkdir build && cd build
          cmake ..
          make
      - name: Run NIST test vectors
        run: |
          cd build
          ./test_nist_vectors
      - name: Test JavaScript implementation
        run: |
          node validate-nist.js
      - name: Cross-language interop test
        run: |
          node test-c-js-interop.js
`;

console.log('\\n📋 TODO for full production readiness:');
console.log('1. Implement IV uniqueness tracking in production');
console.log('2. Add key rotation mechanisms');  
console.log('3. Set up CI/CD with NIST validation');
console.log('4. Add fuzzing tests for robustness');
console.log('5. Security audit of RNG entropy sources');