<?php
/**
 * salman 40 - Enterprise Cryptographic SDK for PHP
 * Generated: 2025-08-28T10:28:26.243Z
 */

class AveroxCrypto {
    private $masterKey;
    
    public function __construct($masterKey) {
        if (strlen($masterKey) < 32) {
            throw new InvalidArgumentException('Master key must be at least 32 bytes');
        }
        $this->masterKey = $masterKey;
    }
    
    public function encrypt($plaintext, $aad = null) {
        $key = $this->deriveKey();
        $iv = random_bytes(12);
        
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );
        
        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed');
        }
        
        return [
            'iv' => base64_encode($iv),
            'ciphertext' => base64_encode($ciphertext),
            'tag' => base64_encode($tag)
        ];
    }
    
    public function decrypt($encrypted, $aad = null) {
        $key = $this->deriveKey();
        $iv = base64_decode($encrypted['iv']);
        $ciphertext = base64_decode($encrypted['ciphertext']);
        $tag = base64_decode($encrypted['tag']);
        
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );
        
        if ($plaintext === false) {
            throw new RuntimeException('Decryption failed');
        }
        
        return $plaintext;
    }
    
    private function deriveKey() {
        return hash_pbkdf2('sha256', $this->masterKey, 'averox-salt', 100000, 32, true);
    }
}