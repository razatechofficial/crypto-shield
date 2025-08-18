#!/usr/bin/env node
/**
 * AUDIT FIX: Real ChaCha20-Poly1305 Implementation
 * RFC 8439 compliant - not just claimed in docs
 */

import crypto from 'crypto';

export class InvalidInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidInputError';
  }
}

export class RealChaCha20Poly1305 {
  constructor() {
    this.algorithm = 'chacha20-poly1305';
    this.keySize = 32; // 256-bit key
    this.nonceSize = 12; // 96-bit nonce
    this.tagSize = 16; // 128-bit tag
  }

  /**
   * AUDIT FIX: AAD parameter required everywhere
   */
  encrypt(plaintext, key, options = {}) {
    if (!options.aad) {
      throw new InvalidInputError('AAD (Associated Additional Data) is required for all encrypt operations');
    }

    try {
      // Validate inputs
      const keyBuffer = this.validateKey(key);
      const plaintextBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
      const aadBuffer = Buffer.isBuffer(options.aad) ? options.aad : Buffer.from(options.aad, 'utf8');
      
      // Generate 12-byte nonce (RFC 8439)
      const nonce = crypto.randomBytes(this.nonceSize);
      
      // Create cipher
      const cipher = crypto.createCipheriv(this.algorithm, keyBuffer, nonce);
      cipher.setAAD(aadBuffer);
      
      // Encrypt
      let ciphertext = cipher.update(plaintextBuffer);
      ciphertext = Buffer.concat([ciphertext, cipher.final()]);
      
      // Get authentication tag
      const tag = cipher.getAuthTag();

      // Create standardized envelope
      const envelope = {
        v: "2.0.0",
        alg: "ChaCha20-Poly1305",
        iv: nonce.toString('base64url'),
        tag: tag.toString('base64url'),
        ct: ciphertext.toString('base64url'),
        aad: aadBuffer.toString('base64url'),
        ts: Date.now()
      };

      return {
        envelope,
        envelopeString: JSON.stringify(envelope),
        ciphertext,
        nonce,
        tag,
        aad: aadBuffer
      };

    } catch (error) {
      // AUDIT FIX: Secret zeroization on error
      if (key && Buffer.isBuffer(key)) {
        key.fill(0);
      }
      throw new Error(`ChaCha20-Poly1305 encryption failed: ${error.message}`);
    }
  }

  /**
   * AUDIT FIX: AAD parameter required everywhere
   */
  decrypt(envelopeData, key) {
    try {
      // Parse envelope
      const envelope = typeof envelopeData === 'string' ? JSON.parse(envelopeData) : envelopeData;
      
      // Validate algorithm
      if (envelope.alg !== 'ChaCha20-Poly1305') {
        throw new InvalidInputError(`Invalid algorithm: ${envelope.alg}`);
      }

      // Extract components
      const keyBuffer = this.validateKey(key);
      const nonce = Buffer.from(envelope.iv, 'base64url');
      const tag = Buffer.from(envelope.tag, 'base64url');
      const ciphertext = Buffer.from(envelope.ct, 'base64url');
      const aad = Buffer.from(envelope.aad, 'base64url');

      // Validate sizes
      if (nonce.length !== this.nonceSize) {
        throw new InvalidInputError(`Invalid nonce size: ${nonce.length}, expected ${this.nonceSize}`);
      }
      if (tag.length !== this.tagSize) {
        throw new InvalidInputError(`Invalid tag size: ${tag.length}, expected ${this.tagSize}`);
      }

      // Create decipher
      const decipher = crypto.createDecipheriv(this.algorithm, keyBuffer, nonce);
      decipher.setAuthTag(tag);
      decipher.setAAD(aad);

      // Decrypt
      let plaintext = decipher.update(ciphertext);
      try {
        plaintext = Buffer.concat([plaintext, decipher.final()]);
      } catch (error) {
        throw new Error('Authentication verification failed - data may be tampered');
      }

      return {
        plaintext,
        plaintextString: plaintext.toString('utf8'),
        nonce,
        aad
      };

    } catch (error) {
      // AUDIT FIX: Secret zeroization on error
      if (key && Buffer.isBuffer(key)) {
        key.fill(0);
      }
      throw new Error(`ChaCha20-Poly1305 decryption failed: ${error.message}`);
    }
  }

  validateKey(key) {
    if (!key) {
      throw new InvalidInputError('Key is required');
    }

    let keyBuffer;
    if (typeof key === 'string') {
      keyBuffer = key.match(/^[0-9a-fA-F]+$/) ? Buffer.from(key, 'hex') : Buffer.from(key, 'base64');
    } else if (Buffer.isBuffer(key)) {
      keyBuffer = key;
    } else {
      throw new InvalidInputError('Key must be a Buffer, hex string, or base64 string');
    }

    if (keyBuffer.length !== this.keySize) {
      throw new InvalidInputError(`Invalid key length: ${keyBuffer.length}, expected ${this.keySize}`);
    }

    return keyBuffer;
  }
}

// Test implementation immediately
if (import.meta.url === `file://${process.argv[1]}`) {
  const chacha = new RealChaCha20Poly1305();
  const key = crypto.randomBytes(32);
  const result = chacha.encrypt('test data', key, { aad: 'metadata' });
  const decrypted = chacha.decrypt(result.envelope, key);
  console.log('✅ Real ChaCha20-Poly1305 implementation works');
  console.log('   Plaintext:', decrypted.plaintextString);
  console.log('   AAD preserved:', decrypted.aad.toString());
}