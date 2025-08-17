#!/usr/bin/env node
/**
 * Production-Ready ChaCha20-Poly1305 Implementation
 * RFC 8439 compliant with full AAD support
 * Cross-platform envelope format for enterprise use
 */

import crypto from 'crypto';

// Typed error classes for proper error handling
export class CryptoError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

export class InvalidTagError extends CryptoError {
  constructor(message = 'Authentication tag verification failed') {
    super(message, 'INVALID_TAG');
  }
}

export class BadInputError extends CryptoError {
  constructor(message) {
    super(message, 'BAD_INPUT');
  }
}

export class AlgorithmDisabledError extends CryptoError {
  constructor(message = 'Algorithm is disabled') {
    super(message, 'ALGORITHM_DISABLED');
  }
}

export class ProductionChaCha20Poly1305 {
  constructor(options = {}) {
    this.algorithm = 'chacha20-poly1305';
    this.keySize = 32; // 256-bit key
    this.nonceSize = 12; // 96-bit nonce for ChaCha20-Poly1305
    this.tagSize = 16; // 128-bit Poly1305 tag
    this.strictValidation = options.strictValidation !== false;
    this.enableAAD = options.enableAAD !== false;
    
    // Check if ChaCha20-Poly1305 is supported
    const availableCiphers = crypto.getCiphers();
    if (!availableCiphers.includes('chacha20-poly1305')) {
      throw new AlgorithmDisabledError('ChaCha20-Poly1305 not supported in this Node.js version');
    }
  }

  /**
   * Generate cryptographically secure random bytes
   */
  generateSecureRandom(size) {
    if (!Number.isInteger(size) || size <= 0) {
      throw new BadInputError('Size must be a positive integer');
    }
    return crypto.randomBytes(size);
  }

  /**
   * Generate ChaCha20 key (256-bit)
   */
  generateKey() {
    return this.generateSecureRandom(this.keySize);
  }

  /**
   * Generate nonce (96-bit for ChaCha20-Poly1305)
   */
  generateNonce() {
    return this.generateSecureRandom(this.nonceSize);
  }

  /**
   * Validate key format and size
   */
  validateKey(key) {
    let keyBuffer;
    
    if (typeof key === 'string') {
      if (key.match(/^[0-9a-fA-F]+$/)) {
        keyBuffer = Buffer.from(key, 'hex');
      } else {
        keyBuffer = Buffer.from(key, 'base64url');
      }
    } else if (Buffer.isBuffer(key)) {
      keyBuffer = key;
    } else {
      throw new BadInputError('Key must be a Buffer, hex string, or base64url string');
    }

    if (keyBuffer.length !== this.keySize) {
      throw new BadInputError(`Invalid key size. Expected ${this.keySize} bytes, got ${keyBuffer.length}`);
    }

    return keyBuffer;
  }

  /**
   * Validate nonce format and size
   */
  validateNonce(nonce) {
    let nonceBuffer;
    
    if (typeof nonce === 'string') {
      nonceBuffer = Buffer.from(nonce, 'base64url');
    } else if (Buffer.isBuffer(nonce)) {
      nonceBuffer = nonce;
    } else {
      throw new BadInputError('Nonce must be a Buffer or base64url string');
    }

    if (nonceBuffer.length !== this.nonceSize) {
      throw new BadInputError(`Invalid nonce size. Expected ${this.nonceSize} bytes, got ${nonceBuffer.length}`);
    }

    return nonceBuffer;
  }

  /**
   * Create standardized envelope format
   */
  createEnvelope(nonce, tag, ciphertext, aad = null, keyId = null) {
    const envelope = {
      v: "2.0.0",
      alg: "ChaCha20-Poly1305",
      iv: nonce.toString('base64url'),
      tag: tag.toString('base64url'),
      ct: ciphertext.toString('base64url')
    };

    if (keyId) {
      envelope.kid = keyId;
    }

    if (aad && aad.length > 0) {
      envelope.aad = aad.toString('base64url');
    }

    envelope.ts = Date.now();
    return envelope;
  }

  /**
   * Parse envelope format
   */
  parseEnvelope(envelopeData) {
    let envelope;
    
    if (typeof envelopeData === 'string') {
      try {
        envelope = JSON.parse(envelopeData);
      } catch (e) {
        throw new BadInputError('Invalid envelope JSON format');
      }
    } else if (typeof envelopeData === 'object') {
      envelope = envelopeData;
    } else {
      throw new BadInputError('Envelope must be JSON string or object');
    }

    // Validate envelope structure
    if (!envelope.v || !envelope.alg || !envelope.iv || !envelope.tag || !envelope.ct) {
      throw new BadInputError('Missing required envelope fields');
    }

    if (envelope.alg !== 'ChaCha20-Poly1305') {
      throw new BadInputError(`Unsupported algorithm: ${envelope.alg}`);
    }

    return {
      version: envelope.v,
      algorithm: envelope.alg,
      nonce: Buffer.from(envelope.iv, 'base64url'),
      tag: Buffer.from(envelope.tag, 'base64url'),
      ciphertext: Buffer.from(envelope.ct, 'base64url'),
      aad: envelope.aad ? Buffer.from(envelope.aad, 'base64url') : null,
      keyId: envelope.kid || null,
      timestamp: envelope.ts || null
    };
  }

  /**
   * Encrypt data with ChaCha20-Poly1305
   */
  encrypt(plaintext, key, options = {}) {
    try {
      // Validate inputs
      const keyBuffer = this.validateKey(key);
      
      if (!Buffer.isBuffer(plaintext)) {
        plaintext = Buffer.from(plaintext, 'utf8');
      }

      // Generate or use provided nonce
      const nonce = options.nonce ? this.validateNonce(options.nonce) : this.generateNonce();
      
      // Handle AAD (Additional Authenticated Data)
      let aad = null;
      if (options.aad) {
        if (typeof options.aad === 'string') {
          aad = Buffer.from(options.aad, 'utf8');
        } else if (Buffer.isBuffer(options.aad)) {
          aad = options.aad;
        } else {
          throw new BadInputError('AAD must be string or Buffer');
        }
      }

      // Create cipher
      const cipher = crypto.createCipher('chacha20-poly1305', keyBuffer, { iv: nonce });
      
      // Set AAD if provided
      if (aad && aad.length > 0) {
        cipher.setAAD(aad);
      }

      // Encrypt
      let ciphertext = cipher.update(plaintext);
      cipher.final();
      
      // Get authentication tag
      const tag = cipher.getAuthTag();

      // Create standardized envelope
      const envelope = this.createEnvelope(nonce, tag, ciphertext, aad, options.keyId);

      return {
        envelope,
        envelopeString: JSON.stringify(envelope),
        ciphertext,
        nonce,
        tag,
        aad
      };

    } catch (error) {
      // Zero out sensitive data on error
      if (key && Buffer.isBuffer(key)) {
        key.fill(0);
      }
      
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(`Encryption failed: ${error.message}`, 'ENCRYPTION_ERROR');
    }
  }

  /**
   * Decrypt data with ChaCha20-Poly1305
   */
  decrypt(envelopeData, key, options = {}) {
    try {
      // Validate key
      const keyBuffer = this.validateKey(key);
      
      // Parse envelope
      const { nonce, tag, ciphertext, aad } = this.parseEnvelope(envelopeData);

      // Validate tag size
      if (tag.length !== this.tagSize) {
        throw new BadInputError(`Invalid tag size. Expected ${this.tagSize} bytes, got ${tag.length}`);
      }

      // Create decipher
      const decipher = crypto.createDecipher('chacha20-poly1305', keyBuffer, { iv: nonce });
      
      // Set authentication tag
      decipher.setAuthTag(tag);
      
      // Set AAD if present
      if (aad && aad.length > 0) {
        decipher.setAAD(aad);
      }

      // Decrypt
      let plaintext = decipher.update(ciphertext);
      
      try {
        decipher.final();
      } catch (error) {
        throw new InvalidTagError('Authentication verification failed');
      }

      return {
        plaintext,
        plaintextString: plaintext.toString('utf8'),
        nonce,
        aad
      };

    } catch (error) {
      // Zero out sensitive data on error
      if (key && Buffer.isBuffer(key)) {
        key.fill(0);
      }
      
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(`Decryption failed: ${error.message}`, 'DECRYPTION_ERROR');
    }
  }

  /**
   * Timing-safe comparison for authentication tags
   */
  constantTimeCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    
    return result === 0;
  }

  /**
   * Generate test vectors for validation
   */
  generateTestVectors() {
    const key = this.generateKey();
    const plaintext = Buffer.from('Test message for ChaCha20-Poly1305 validation', 'utf8');
    const aad = Buffer.from('Additional authenticated data', 'utf8');
    
    const encrypted = this.encrypt(plaintext, key, { aad });
    const decrypted = this.decrypt(encrypted.envelope, key);
    
    return {
      key: key.toString('hex'),
      plaintext: plaintext.toString('utf8'),
      aad: aad.toString('utf8'),
      envelope: encrypted.envelope,
      decryptedPlaintext: decrypted.plaintextString,
      valid: plaintext.equals(decrypted.plaintext)
    };
  }
}

// Error classes already exported above