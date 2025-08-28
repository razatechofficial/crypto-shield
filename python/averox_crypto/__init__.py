"""
salman 40 - Enterprise Cryptographic SDK
Generated: 2025-08-28T10:28:26.243Z
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AveroxCrypto:
    def __init__(self, master_key: bytes):
        if not master_key or len(master_key) < 32:
            raise ValueError("Master key must be at least 32 bytes")
        self.master_key = master_key

    def encrypt(self, plaintext: str, aad: bytes = None) -> dict:
        key = self._derive_key()
        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        
        ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), aad)
        
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt(self, encrypted: dict, aad: bytes = None) -> str:
        key = self._derive_key()
        iv = base64.b64decode(encrypted['iv'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, aad)
        
        return plaintext.decode('utf-8')

    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'averox-salt',
            iterations=100000,
        )
        return kdf.derive(self.master_key)