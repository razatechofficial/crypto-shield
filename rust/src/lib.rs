/**
 * salman 40 - Enterprise Cryptographic SDK for Rust
 * Generated: 2025-08-28T10:26:18.964Z
 */

use aes_gcm::{Aes256Gcm, Key, Nonce, AeadCore, AeadInPlace, KeyInit};
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose};

pub struct AveroxCrypto {
    master_key: Vec<u8>,
}

impl AveroxCrypto {
    pub fn new(master_key: Vec<u8>) -> Result<Self, &'static str> {
        if master_key.len() < 32 {
            return Err("Master key must be at least 32 bytes");
        }
        Ok(AveroxCrypto { master_key })
    }
    
    pub fn encrypt(&self, plaintext: &str, aad: Option<&[u8]>) -> Result<EncryptedData, Box<dyn std::error::Error>> {
        let key = self.derive_key()?;
        let cipher = Aes256Gcm::new(&key);
        
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = plaintext.as_bytes().to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, aad.unwrap_or(&[]), &mut buffer)?;
        
        Ok(EncryptedData {
            iv: general_purpose::STANDARD.encode(&nonce_bytes),
            ciphertext: general_purpose::STANDARD.encode(&buffer),
            tag: general_purpose::STANDARD.encode(&tag),
        })
    }
    
    fn derive_key(&self) -> Result<Key<Aes256Gcm>, &'static str> {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(&self.master_key, b"averox-salt", 100_000, &mut key);
        Ok(*Key::<Aes256Gcm>::from_slice(&key))
    }
}

pub struct EncryptedData {
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}