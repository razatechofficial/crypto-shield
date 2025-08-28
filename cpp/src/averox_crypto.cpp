/**
 * salman 40 - Enterprise C++ Implementation
 * Generated: 2025-08-28T10:26:18.964Z
 */

#include "averox_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <stdexcept>
#include <memory>
#include <chrono>
#include <iostream>
#include <fstream>

namespace AveroxCrypto {

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& message) : std::runtime_error(message) {}
};

AveroxCrypto::AveroxCrypto(const std::vector<uint8_t>& masterKey, const Config& config) 
    : masterKey_(masterKey), config_(config) {
    
    if (masterKey.size() < 32) {
        throw CryptoError("Master key must be at least 32 bytes");
    }
    
    // Initialize OpenSSL
    if (!isOpenSSLInitialized_) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        isOpenSSLInitialized_ = true;
    }
    
    // Initialize performance tracking
    if (config_.enableMetrics) {
        startTime_ = std::chrono::high_resolution_clock::now();
    }
}

AveroxCrypto::~AveroxCrypto() {
    // Secure cleanup
    if (!masterKey_.empty()) {
        OPENSSL_cleanse(masterKey_.data(), masterKey_.size());
        masterKey_.clear();
    }
}

EncryptionResult AveroxCrypto::encrypt(const std::string& plaintext, 
                                     const std::string& aad,
                                     const std::string& algorithm) {
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    try {
        EncryptionResult result;
        
        if (algorithm == "aes-256-gcm") {
            result = encryptAESGCM(plaintext, aad);
        } else if (algorithm == "chacha20-poly1305") {
            result = encryptChaCha20(plaintext, aad);
        } else {
            throw CryptoError("Unsupported algorithm: " + algorithm);
        }
        
        if (config_.enableAudit) {
            logOperation("encrypt", algorithm, plaintext.length());
        }
        
        if (config_.enableMetrics) {
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
            std::cout << "Encryption took: " << duration.count() << " microseconds" << std::endl;
        }
        
        return result;
        
    } catch (const std::exception& e) {
        if (config_.enableAudit) {
            logOperation("encrypt_error", algorithm, 0);
        }
        throw;
    }
}

std::string AveroxCrypto::decrypt(const EncryptionResult& encrypted, const std::string& aad) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    try {
        std::string result;
        
        if (encrypted.algorithm == "aes-256-gcm") {
            result = decryptAESGCM(encrypted, aad);
        } else if (encrypted.algorithm == "chacha20-poly1305") {
            result = decryptChaCha20(encrypted, aad);
        } else {
            throw CryptoError("Unsupported algorithm: " + encrypted.algorithm);
        }
        
        if (config_.enableAudit) {
            logOperation("decrypt", encrypted.algorithm, result.length());
        }
        
        if (config_.enableMetrics) {
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
            std::cout << "Decryption took: " << duration.count() << " microseconds" << std::endl;
        }
        
        return result;
        
    } catch (const std::exception& e) {
        if (config_.enableAudit) {
            logOperation("decrypt_error", encrypted.algorithm, 0);
        }
        throw;
    }
}

EncryptionResult AveroxCrypto::encryptAESGCM(const std::string& plaintext, const std::string& aad) {
    EncryptionResult result;
    result.algorithm = "aes-256-gcm";
    
    // Derive key
    auto key = deriveKey();
    
    // Generate random IV (12 bytes for GCM)
    std::vector<uint8_t> iv(12);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw CryptoError("Failed to generate random IV");
    }
    
    // Create cipher context
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    
    if (!ctx) {
        throw CryptoError("Failed to create cipher context");
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw CryptoError("Failed to initialize AES-GCM encryption");
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        throw CryptoError("Failed to set IV length");
    }
    
    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoError("Failed to set key and IV");
    }
    
    // Set AAD if provided
    int len;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, 
                             reinterpret_cast<const uint8_t*>(aad.data()), aad.length()) != 1) {
            throw CryptoError("Failed to set AAD");
        }
    }
    
    // Encrypt plaintext
    std::vector<uint8_t> ciphertext(plaintext.length() + 16); // Extra space for potential padding
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                         reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.length()) != 1) {
        throw CryptoError("Failed to encrypt data");
    }
    int ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        throw CryptoError("Failed to finalize encryption");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    // Get authentication tag
    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1) {
        throw CryptoError("Failed to get authentication tag");
    }
    
    // Secure cleanup
    OPENSSL_cleanse(key.data(), key.size());
    
    // Encode results
    result.iv = base64Encode(iv);
    result.ciphertext = base64Encode(ciphertext);
    result.tag = base64Encode(tag);
    
    return result;
}

std::string AveroxCrypto::decryptAESGCM(const EncryptionResult& encrypted, const std::string& aad) {
    auto key = deriveKey();
    auto iv = base64Decode(encrypted.iv);
    auto ciphertext = base64Decode(encrypted.ciphertext);
    auto tag = base64Decode(encrypted.tag);
    
    // Create cipher context
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    
    if (!ctx) {
        throw CryptoError("Failed to create cipher context");
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw CryptoError("Failed to initialize AES-GCM decryption");
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        throw CryptoError("Failed to set IV length");
    }
    
    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoError("Failed to set key and IV");
    }
    
    // Set AAD if provided
    int len;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len,
                             reinterpret_cast<const uint8_t*>(aad.data()), aad.length()) != 1) {
            throw CryptoError("Failed to set AAD");
        }
    }
    
    // Decrypt ciphertext
    std::vector<uint8_t> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        throw CryptoError("Failed to decrypt data");
    }
    int plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), 
                           const_cast<uint8_t*>(tag.data())) != 1) {
        throw CryptoError("Failed to set authentication tag");
    }
    
    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) <= 0) {
        throw CryptoError("Authentication verification failed");
    }
    plaintext_len += len;
    
    // Secure cleanup
    OPENSSL_cleanse(key.data(), key.size());
    
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

std::vector<uint8_t> AveroxCrypto::deriveKey(size_t keyLength) {
    std::vector<uint8_t> derivedKey(keyLength);
    
    if (config_.keyDerivation == "hkdf") {
        return deriveKeyHKDF(keyLength);
    } else {
        return deriveKeyPBKDF2(keyLength);
    }
}

std::vector<uint8_t> AveroxCrypto::deriveKeyPBKDF2(size_t keyLength) {
    std::vector<uint8_t> derivedKey(keyLength);
    const std::string salt = "averox-salt";
    
    if (PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(masterKey_.data()), masterKey_.size(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.length(),
        config_.iterations,
        EVP_sha256(),
        keyLength,
        derivedKey.data()) != 1) {
        throw CryptoError("Key derivation failed");
    }
    
    return derivedKey;
}

std::vector<uint8_t> AveroxCrypto::deriveKeyHKDF(size_t keyLength) {
    std::vector<uint8_t> derivedKey(keyLength);
    const std::string salt = "averox-salt";
    const std::string info = "encryption";
    
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    
    if (!pctx) {
        throw CryptoError("Failed to create HKDF context");
    }
    
    if (EVP_PKEY_derive_init(pctx.get()) <= 0) {
        throw CryptoError("Failed to initialize HKDF");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0) {
        throw CryptoError("Failed to set HKDF hash function");
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(), salt.length()) <= 0) {
        throw CryptoError("Failed to set HKDF salt");
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), masterKey_.data(), masterKey_.size()) <= 0) {
        throw CryptoError("Failed to set HKDF key");
    }
    
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info.data(), info.length()) <= 0) {
        throw CryptoError("Failed to set HKDF info");
    }
    
    size_t outlen = keyLength;
    if (EVP_PKEY_derive(pctx.get(), derivedKey.data(), &outlen) <= 0) {
        throw CryptoError("HKDF derivation failed");
    }
    
    return derivedKey;
}

void AveroxCrypto::rotateKey(const std::vector<uint8_t>& newMasterKey) {
    if (newMasterKey.size() < 32) {
        throw CryptoError("New master key must be at least 32 bytes");
    }
    
    // Secure cleanup of old key
    OPENSSL_cleanse(masterKey_.data(), masterKey_.size());
    
    masterKey_ = newMasterKey;
    
    if (config_.enableAudit) {
        logOperation("key_rotation", "master_key", newMasterKey.size());
    }
}

std::vector<uint8_t> AveroxCrypto::generateSecureRandom(size_t bytes) {
    std::vector<uint8_t> randomData(bytes);
    
    if (RAND_bytes(randomData.data(), bytes) != 1) {
        throw CryptoError("Failed to generate secure random data");
    }
    
    return randomData;
}

std::vector<uint8_t> AveroxCrypto::hashData(const std::vector<uint8_t>& data, const std::string& algorithm) {
    const EVP_MD* md;
    
    if (algorithm == "sha256") {
        md = EVP_sha256();
    } else if (algorithm == "sha512") {
        md = EVP_sha512();
    } else {
        throw CryptoError("Unsupported hash algorithm: " + algorithm);
    }
    
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    
    if (!ctx) {
        throw CryptoError("Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        throw CryptoError("Failed to initialize hash");
    }
    
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
        throw CryptoError("Failed to update hash");
    }
    
    std::vector<uint8_t> hash(EVP_MD_size(md));
    unsigned int hashLen;
    
    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hashLen) != 1) {
        throw CryptoError("Failed to finalize hash");
    }
    
    hash.resize(hashLen);
    return hash;
}

bool AveroxCrypto::timingSafeEquals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

void AveroxCrypto::logOperation(const std::string& operation, const std::string& algorithm, size_t dataSize) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::cout << "AUDIT: " << std::ctime(&time_t) 
              << " Operation: " << operation 
              << " Algorithm: " << algorithm 
              << " DataSize: " << dataSize << std::endl;
}

std::string AveroxCrypto::base64Encode(const std::vector<uint8_t>& data) {
    // Simple base64 encoding implementation
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    
    return result;
}

std::vector<uint8_t> AveroxCrypto::base64Decode(const std::string& encoded) {
    // Simple base64 decoding implementation
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    
    int val = 0, valb = -8;
    for (char c : encoded) {
        if (c == '=') break;
        auto pos = chars.find(c);
        if (pos == std::string::npos) continue;
        
        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    return result;
}

bool AveroxCrypto::isOpenSSLInitialized_ = false;

} // namespace AveroxCrypto