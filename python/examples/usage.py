"""
salman 40 - Python Usage Examples
Generated: 2025-08-28T10:26:18.966Z
"""

from averox_crypto import AveroxCrypto, CryptoUtils
import json

def main():
    # Example 1: Basic Encryption
    print("=== Basic Encryption Example ===")
    master_key = CryptoUtils.generate_master_key()
    crypto = AveroxCrypto(master_key, {'enable_audit': True, 'enable_metrics': True})
    
    plaintext = "This is sensitive data that needs encryption"
    encrypted = crypto.encrypt(plaintext)
    print(f"Encrypted: {json.dumps(encrypted, indent=2)}")
    
    decrypted = crypto.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Example 2: Encryption with AAD
    print("\n=== AAD Example ===")
    confidential_data = "TOP SECRET: Nuclear launch codes are 12345"
    metadata = b"classified-document-id-789"
    
    encrypted_with_aad = crypto.encrypt(confidential_data, metadata)
    decrypted_with_aad = crypto.decrypt(encrypted_with_aad, metadata)
    print("AAD Encrypted/Decrypted successfully")
    
    # Example 3: ChaCha20-Poly1305
    print("\n=== ChaCha20-Poly1305 Example ===")
    chacha_encrypted = crypto.encrypt(plaintext, algorithm='chacha20-poly1305')
    chacha_decrypted = crypto.decrypt(chacha_encrypted)
    print(f"ChaCha20 Algorithm: {chacha_encrypted['algorithm']}")
    
    # Example 4: Key Rotation
    print("\n=== Key Rotation Example ===")
    new_master_key = CryptoUtils.generate_master_key()
    crypto.rotate_key(new_master_key)
    after_rotation = crypto.encrypt("Data after key rotation")
    print("Key rotation successful")
    
    # Example 5: Utility Functions
    print("\n=== Utility Functions Example ===")
    random_bytes = crypto.generate_secure_random(16)
    print(f"Random bytes: {random_bytes.hex()}")
    
    hash_result = crypto.hash_data(b"Data to hash")
    print(f"SHA-256 hash: {hash_result.hex()}")
    
    # Example 6: Key Pair Generation
    print("\n=== Key Pair Example ===")
    key_pair = CryptoUtils.generate_key_pair()
    print(f"RSA Public Key (first 100 chars): {key_pair['public_key'][:100]}")
    
    # Example 7: Error Handling
    print("\n=== Error Handling Example ===")
    try:
        invalid_crypto = AveroxCrypto(b'too_short')
    except Exception as e:
        print(f"Caught expected error: {e}")
    
    # Example 8: Performance Monitoring
    print("\n=== Performance Monitoring Example ===")
    perf_crypto = AveroxCrypto(master_key, {'enable_metrics': True})
    large_data = 'x' * 10000
    perf_result = perf_crypto.encrypt(large_data)
    print("Performance monitoring enabled - check console for timing")
    
    # Cleanup
    crypto.destroy()
    perf_crypto.destroy()
    
    print("\n=== All Examples Completed Successfully ===")

if __name__ == "__main__":
    main()