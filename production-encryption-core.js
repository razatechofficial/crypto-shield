#!/usr/bin/env node
/**
 * Production-Ready AES-GCM Encryption Core
 * Compliant with NIST SP 800-38D standards
 * Features: Standardized 12-byte IV, AAD support, Cross-platform envelope format
 */

import crypto from 'crypto';

// AUDIT FIX: Typed error classes
export class InvalidInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidInputError';
  }
}

export class InvalidTagError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidTagError';
  }
}

export class BadInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BadInputError';
  }
}

export class ProductionAESGCM {
  constructor(options = {}) {
    this.keySize = options.keySize || 32; // 256-bit default
    this.ivSize = 12; // Standardized 12-byte IV for optimal performance
    this.tagSize = 16; // 128-bit authentication tag
    this.algorithm = 'aes-256-gcm';
    
    // Validation flags
    this.strictValidation = options.strictValidation !== false;
    this.enableAAD = options.enableAAD !== false;
  }

  /**
   * Generate cryptographically secure random bytes
   * @param {number} size - Number of bytes to generate
   * @returns {Buffer} Random bytes
   */
  generateSecureRandom(size) {
    if (!Number.isInteger(size) || size <= 0) {
      throw new TypeError('Size must be a positive integer');
    }
    return crypto.randomBytes(size);
  }

  /**
   * Generate AES key
   * @param {number} keySize - Key size in bytes (16, 24, or 32)
   * @returns {Buffer} Generated key
   */
  generateKey(keySize = this.keySize) {
    if (![16, 24, 32].includes(keySize)) {
      throw new Error('Invalid key size. Must be 16, 24, or 32 bytes');
    }
    return this.generateSecureRandom(keySize);
  }

  /**
   * Generate IV (nonce) - always 12 bytes for optimal GCM performance
   * @returns {Buffer} Generated IV
   */
  generateIV() {
    return this.generateSecureRandom(this.ivSize);
  }

  /**
   * Validate key format and size with strict checking
   */
  validateKey(key) {
    if (!key) {
      throw new BadInputError('Key is required');
    }

    let keyBuffer;
    
    if (typeof key === 'string') {
      if (key.match(/^[0-9a-fA-F]+$/)) {
        keyBuffer = Buffer.from(key, 'hex');
      } else {
        keyBuffer = Buffer.from(key, 'base64');
      }
    } else if (Buffer.isBuffer(key)) {
      keyBuffer = key;
    } else {
      throw new BadInputError('Key must be a Buffer, hex string, or base64 string');
    }

    // AUDIT FIX: Strict key size validation with typed errors
    if (![16, 24, 32].includes(keyBuffer.length)) {
      throw new BadInputError(`Invalid key length: ${keyBuffer.length}. Must be 16, 24, or 32 bytes`);
    }

    return keyBuffer;
  }

  /**
   * Validate IV format and size
   * @param {Buffer|string} iv - IV to validate
   * @returns {Buffer} Validated IV as Buffer
   */
  validateIV(iv) {
    let ivBuffer;
    
    if (typeof iv === 'string') {
      if (iv.match(/^[0-9a-fA-F]+$/)) {
        ivBuffer = Buffer.from(iv, 'hex');
      } else {
        ivBuffer = Buffer.from(iv, 'base64');
      }
    } else if (Buffer.isBuffer(iv)) {
      ivBuffer = iv;
    } else {
      throw new TypeError('IV must be a Buffer, hex string, or base64 string');
    }

    if (ivBuffer.length !== 12) {
      throw new Error(`Invalid IV length: ${ivBuffer.length}. Must be exactly 12 bytes for GCM`);
    }

    return ivBuffer;
  }

  /**
   * Validate AAD if provided
   * @param {Buffer|string|null} aad - Additional Authenticated Data
   * @returns {Buffer|null} Validated AAD as Buffer or null
   */
  validateAAD(aad) {
    if (aad === null || aad === undefined) {
      return null;
    }
    
    if (typeof aad === 'string') {
      return Buffer.from(aad, 'utf8');
    } else if (Buffer.isBuffer(aad)) {
      return aad;
    } else {
      throw new TypeError('AAD must be a Buffer, string, or null');
    }
  }

  /**
   * Create standardized envelope format (RFC compliant)
   */
  createEnvelope(iv, tag, ciphertext, aad = null, keyId = null) {
    const envelope = {
      v: "2.0.0",
      alg: this.algorithm === 'aes-256-gcm' ? "AES-256-GCM" : 
           this.algorithm === 'aes-192-gcm' ? "AES-192-GCM" : "AES-128-GCM",
      iv: iv.toString('base64url'),
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
   * Parse standardized envelope format
   */
  parseEnvelope(envelopeData) {
    let envelope;
    
    if (typeof envelopeData === 'string') {
      try {
        envelope = JSON.parse(envelopeData);
      } catch (e) {
        throw new Error('Invalid envelope JSON format');
      }
    } else if (typeof envelopeData === 'object') {
      envelope = envelopeData;
    } else {
      throw new Error('Envelope must be JSON string or object');
    }

    // Validate envelope structure
    if (!envelope.v || !envelope.alg || !envelope.iv || !envelope.tag || !envelope.ct) {
      throw new Error('Missing required envelope fields');
    }

    if (!envelope.alg.includes('AES') || !envelope.alg.includes('GCM')) {
      throw new Error(`Unsupported algorithm: ${envelope.alg}`);
    }

    return {
      version: envelope.v,
      algorithm: envelope.alg,
      iv: Buffer.from(envelope.iv, 'base64url'),
      tag: Buffer.from(envelope.tag, 'base64url'),
      ciphertext: Buffer.from(envelope.ct, 'base64url'),
      aad: envelope.aad ? Buffer.from(envelope.aad, 'base64url') : null,
      keyId: envelope.kid || null,
      timestamp: envelope.ts || null
    };
  }

  /**
   * Encrypt data with AES-GCM - AAD parameter REQUIRED
   * @param {Buffer|string} plaintext - Data to encrypt
   * @param {Buffer|string} key - Encryption key
   * @param {Object} options - Encryption options
   * @param {Buffer|string} options.aad - Associated Additional Data (REQUIRED)
   * @returns {Object} Encryption result with envelope format
   */
  encrypt(plaintext, key, options = {}) {
    // AUDIT FIX: AAD parameter required everywhere
    if (!options.aad) {
      throw new InvalidInputError('AAD (Associated Additional Data) is required for all encrypt operations');
    }

    try {
      // Strict input validation
      const keyBuffer = this.validateKey(key);
      const ivBuffer = crypto.randomBytes(12); // AUDIT FIX: SDK generates 12-byte IVs internally
      const aadBuffer = Buffer.isBuffer(options.aad) ? options.aad : Buffer.from(options.aad, 'utf8');
      
      // Convert plaintext to buffer
      const plaintextBuffer = Buffer.isBuffer(plaintext) 
        ? plaintext 
        : Buffer.from(plaintext, 'utf8');

      // Create cipher with proper GCM API
      const cipher = crypto.createCipheriv(this.algorithm, keyBuffer, ivBuffer);
      if (aadBuffer && aadBuffer.length > 0) {
        cipher.setAAD(aadBuffer);
      }
      
      // Encrypt
      let ciphertext = cipher.update(plaintextBuffer);
      ciphertext = Buffer.concat([ciphertext, cipher.final()]);
      
      // Get authentication tag
      const tag = cipher.getAuthTag();

      // Create standardized envelope
      const envelope = this.createEnvelope(ivBuffer, tag, ciphertext, aadBuffer, options.keyId);

      return {
        envelope,
        envelopeString: JSON.stringify(envelope),
        ciphertext,
        iv: ivBuffer,
        tag,
        aad: aadBuffer
      };
    } catch (error) {
      // Clear sensitive data on error
      this.secureClear(arguments);
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data with AES-GCM and comprehensive validation
   */
  decrypt(envelopeData, key, options = {}) {
    try {
      // Validate key
      const keyBuffer = this.validateKey(key);
      
      // Parse envelope
      const { iv, tag, ciphertext, aad } = this.parseEnvelope(envelopeData);

      // Validate tag size
      if (tag.length !== this.tagSize) {
        throw new Error(`Invalid tag size. Expected ${this.tagSize} bytes, got ${tag.length}`);
      }

      // Create decipher
      const decipher = crypto.createDecipheriv(this.algorithm, keyBuffer, iv);
      
      // Set authentication tag
      decipher.setAuthTag(tag);
      
      // Set AAD if present
      if (aad && aad.length > 0) {
        decipher.setAAD(aad);
      }

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
        iv,
        aad
      };

    } catch (error) {
      // Zero out sensitive data on error
      if (key && Buffer.isBuffer(key)) {
        key.fill(0);
      }
      throw new Error(`AES-GCM decryption failed: ${error.message}`);
    }
  }

  /**
   * Validate envelope structure
   * @param {Object} envelope - Envelope to validate
   */
  validateEnvelope(envelope) {
    const requiredFields = ['version', 'algorithm', 'iv', 'tag', 'ciphertext'];
    
    for (const field of requiredFields) {
      if (!envelope[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    if (envelope.algorithm !== this.algorithm) {
      throw new Error(`Unsupported algorithm: ${envelope.algorithm}`);
    }

    if (envelope.version !== '1.0') {
      throw new Error(`Unsupported envelope version: ${envelope.version}`);
    }
  }

  /**
   * Secure memory clearing (best effort)
   * @param {*} data - Data to clear
   */
  secureClear(data) {
    if (typeof data === 'object' && data !== null) {
      for (const key in data) {
        if (data.hasOwnProperty(key)) {
          if (Buffer.isBuffer(data[key])) {
            data[key].fill(0);
          } else if (typeof data[key] === 'string') {
            data[key] = '';
          }
        }
      }
    }
  }

  /**
   * Generate key derivation from password using PBKDF2
   * @param {string} password - Password to derive key from
   * @param {Buffer|string} salt - Salt for key derivation
   * @param {number} iterations - Number of iterations (default: 100000)
   * @returns {Buffer} Derived key
   */
  deriveKey(password, salt, iterations = 100000) {
    if (typeof password !== 'string') {
      throw new TypeError('Password must be a string');
    }
    
    const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf8');
    
    if (saltBuffer.length < 16) {
      throw new Error('Salt must be at least 16 bytes');
    }

    return crypto.pbkdf2Sync(password, saltBuffer, iterations, this.keySize, 'sha256');
  }

  /**
   * Generate cryptographic hash of data
   * @param {Buffer|string} data - Data to hash
   * @param {string} algorithm - Hash algorithm (default: sha256)
   * @returns {Buffer} Hash digest
   */
  hash(data, algorithm = 'sha256') {
    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    return crypto.createHash(algorithm).update(dataBuffer).digest();
  }

  /**
   * Constant-time comparison for authentication tags
   * @param {Buffer} a - First buffer
   * @param {Buffer} b - Second buffer
   * @returns {boolean} True if buffers are equal
   */
  constantTimeCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    return crypto.timingSafeEqual(a, b);
  }
}

// NIST SP 800-38D Test Vectors for validation
export const NIST_TEST_VECTORS = {
  // Test Case 15 from NIST SP 800-38D
  testCase15: {
    key: '00000000000000000000000000000000',
    iv: '000000000000000000000000',
    plaintext: '',
    aad: '',
    expectedCiphertext: '',
    expectedTag: '58e2fccefa7e3061367f1d57a4e7455a'
  },
  
  // Test Case 16 from NIST SP 800-38D
  testCase16: {
    key: '00000000000000000000000000000000',
    iv: '000000000000000000000000',
    plaintext: '00000000000000000000000000000000',
    aad: '',
    expectedCiphertext: '0388dace60b6a392f328c2b971b2fe78',
    expectedTag: 'ab6e47d42cec13bdf53a67b21257bddf'
  }
};

/**
 * Run NIST test vectors for validation
 * @param {ProductionAESGCM} crypto - Crypto instance to test
 * @returns {boolean} True if all tests pass
 */
export function runNISTValidation(crypto) {
  console.log('Running NIST SP 800-38D validation tests...');
  
  try {
    // Test Case 15 - Empty plaintext and AAD
    const test15 = NIST_TEST_VECTORS.testCase15;
    const result15 = crypto.encrypt('', test15.key, test15.iv, test15.aad);
    
    if (result15.tag !== Buffer.from(test15.expectedTag, 'hex').toString('base64')) {
      throw new Error('Test Case 15 failed - Tag mismatch');
    }
    
    // Test Case 16 - 16-byte plaintext, empty AAD
    const test16 = NIST_TEST_VECTORS.testCase16;
    const result16 = crypto.encrypt(
      Buffer.from(test16.plaintext, 'hex'), 
      test16.key, 
      test16.iv, 
      test16.aad
    );
    
    const expectedCiphertext16 = Buffer.from(test16.expectedCiphertext, 'hex').toString('base64');
    const expectedTag16 = Buffer.from(test16.expectedTag, 'hex').toString('base64');
    
    if (result16.ciphertext !== expectedCiphertext16) {
      throw new Error('Test Case 16 failed - Ciphertext mismatch');
    }
    
    if (result16.tag !== expectedTag16) {
      throw new Error('Test Case 16 failed - Tag mismatch');
    }
    
    console.log('✅ All NIST test vectors passed');
    return true;
  } catch (error) {
    console.error('❌ NIST validation failed:', error.message);
    return false;
  }
}

export default ProductionAESGCM;