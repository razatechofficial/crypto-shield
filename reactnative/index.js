/**
 * salman 40 - Enterprise Cryptographic SDK for React Native
 * Generated: 2025-08-28T10:26:18.964Z
 */

import { NativeModules, Platform } from 'react-native';
import CryptoJS from 'crypto-js';

class AveroxCrypto {
  constructor(masterKey) {
    if (!masterKey || masterKey.length < 32) {
      throw new Error('Master key must be at least 32 bytes');
    }
    this.masterKey = masterKey;
  }
  
  async encrypt(plaintext, aad = null) {
    const key = this.deriveKey();
    const iv = CryptoJS.lib.WordArray.random(96/8);
    
    const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
      iv: iv,
      mode: CryptoJS.mode.GCM,
      padding: CryptoJS.pad.NoPadding
    });
    
    return {
      iv: iv.toString(CryptoJS.enc.Base64),
      ciphertext: encrypted.ciphertext.toString(CryptoJS.enc.Base64),
      tag: encrypted.tag ? encrypted.tag.toString(CryptoJS.enc.Base64) : ''
    };
  }
  
  deriveKey() {
    return CryptoJS.PBKDF2(this.masterKey, 'averox-salt', {
      keySize: 256/32,
      iterations: 100000,
      hasher: CryptoJS.algo.SHA256
    });
  }
}

export default AveroxCrypto;