/**
 * salman 40 - Enterprise Cryptographic SDK for iOS/macOS
 * Generated: 2025-08-28T10:28:26.241Z
 */

import Foundation
import CryptoKit

@available(iOS 13.0, macOS 10.15, *)
public class AveroxCrypto {
    private let masterKey: Data
    
    public init(masterKey: Data) throws {
        guard masterKey.count >= 32 else {
            throw CryptoError.invalidKeySize
        }
        self.masterKey = masterKey
    }
    
    public func encrypt(_ plaintext: String, aad: Data? = nil) throws -> EncryptedData {
        let key = try deriveKey()
        let symmetricKey = SymmetricKey(data: key)
        let data = Data(plaintext.utf8)
        
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey, authenticating: aad)
        
        return EncryptedData(
            iv: sealedBox.nonce.withUnsafeBytes { Data($0) }.base64EncodedString(),
            ciphertext: sealedBox.ciphertext.base64EncodedString(),
            tag: sealedBox.tag.base64EncodedString()
        )
    }
    
    private func deriveKey() throws -> Data {
        let salt = "averox-salt".data(using: .utf8)!
        return try HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: masterKey),
            salt: salt,
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
    }
}

public struct EncryptedData {
    public let iv: String
    public let ciphertext: String
    public let tag: String
}

public enum CryptoError: Error {
    case invalidKeySize
}