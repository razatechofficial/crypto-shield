/**
 * salman 40 - Enterprise Cryptographic SDK
 * Generated: 2025-08-28T10:28:26.240Z
 */

#ifndef AVEROX_CRYPTO_H
#define AVEROX_CRYPTO_H

#include <string>
#include <vector>

class AveroxCrypto {
public:
    AveroxCrypto(const std::vector<uint8_t>& masterKey);
    
    std::string encrypt(const std::string& plaintext, const std::string& aad = "");
    std::string decrypt(const std::string& encrypted, const std::string& aad = "");

private:
    std::vector<uint8_t> masterKey;
    std::vector<uint8_t> deriveKey();
};

#endif // AVEROX_CRYPTO_H