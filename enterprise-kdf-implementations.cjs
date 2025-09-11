/**
 * Enterprise Key Derivation Functions (KDFs)
 * Production-ready implementations: HKDF, PBKDF2, Scrypt, Argon2id
 * 
 * SECURITY COMPLIANCE:
 * ✅ HKDF-SHA256 (RFC 5869)
 * ✅ PBKDF2-HMAC-SHA256 (RFC 2898)
 * ✅ Scrypt (RFC 7914)
 * ✅ Argon2id (RFC 9106) - optional with fallback
 */

const crypto = require('crypto');
const { promisify } = require('util');

/**
 * HKDF-SHA256 Implementation (RFC 5869)
 * Extract-and-Expand Key Derivation Function
 */
class ProductionHKDF {
  static HASH_LENGTH = 32; // SHA256 output length
  static MAX_LENGTH = 255 * this.HASH_LENGTH; // RFC 5869 limit
  
  /**
   * HKDF Extract-and-Expand
   * @param {Buffer} ikm - Input Key Material
   * @param {Buffer} salt - Optional salt (default: zero-filled)
   * @param {Buffer} info - Optional context information
   * @param {number} length - Output key length (default: 32)
   * @returns {Buffer} Derived key
   */
  static derive(ikm, salt = null, info = null, length = 32) {
    if (length <= 0 || length > this.MAX_LENGTH) {
      throw new Error(`HKDF length must be 1-${this.MAX_LENGTH} bytes`);
    }
    
    const actualSalt = salt || Buffer.alloc(this.HASH_LENGTH);
    const actualInfo = info || Buffer.alloc(0);
    
    // Extract step: PRK = HMAC-Hash(salt, IKM)
    const extractHmac = crypto.createHmac('sha256', actualSalt);
    extractHmac.update(ikm);
    const prk = extractHmac.digest();
    
    // Expand step: OKM = T(1) | T(2) | ... | T(N)
    const blocks = [];
    const n = Math.ceil(length / this.HASH_LENGTH);
    let previousT = Buffer.alloc(0);
    
    for (let i = 1; i <= n; i++) {
      const expandHmac = crypto.createHmac('sha256', prk);
      expandHmac.update(previousT);
      expandHmac.update(actualInfo);
      expandHmac.update(Buffer.from([i]));
      previousT = expandHmac.digest();
      blocks.push(previousT);
    }
    
    const okm = Buffer.concat(blocks).slice(0, length);
    
    // Zeroize intermediate values
    prk.fill(0);
    blocks.forEach(block => block.fill(0));
    
    return okm;
  }
}

/**
 * PBKDF2-HMAC-SHA256 Implementation (RFC 2898)
 * Password-Based Key Derivation Function 2
 */
class ProductionPBKDF2 {
  static MIN_ITERATIONS = 10000;
  static RECOMMENDED_ITERATIONS = 100000;
  
  /**
   * PBKDF2 with HMAC-SHA256
   * @param {string|Buffer} password - Password or passphrase
   * @param {Buffer} salt - Random salt (minimum 8 bytes recommended)
   * @param {number} iterations - Iteration count (minimum 10,000)
   * @param {number} keyLength - Derived key length (default: 32)
   * @returns {Promise<Buffer>} Derived key
   */
  static async derive(password, salt, iterations = this.RECOMMENDED_ITERATIONS, keyLength = 32) {
    if (iterations < this.MIN_ITERATIONS) {
      throw new Error(`PBKDF2 iterations must be at least ${this.MIN_ITERATIONS}`);
    }
    
    if (salt.length < 8) {
      throw new Error('PBKDF2 salt should be at least 8 bytes');
    }
    
    const pbkdf2 = promisify(crypto.pbkdf2);
    return await pbkdf2(password, salt, iterations, keyLength, 'sha256');
  }
  
  /**
   * Generate cryptographically secure salt
   * @param {number} length - Salt length (default: 16 bytes)
   * @returns {Buffer} Random salt
   */
  static generateSalt(length = 16) {
    return crypto.randomBytes(length);
  }
}

/**
 * Scrypt Implementation (RFC 7914)
 * Memory-hard key derivation function
 */
class ProductionScrypt {
  static DEFAULT_N = 16384;  // CPU/memory cost (power of 2)
  static DEFAULT_R = 8;      // Block size
  static DEFAULT_P = 1;      // Parallelization
  
  /**
   * Scrypt key derivation
   * @param {string|Buffer} password - Password or passphrase
   * @param {Buffer} salt - Random salt
   * @param {number} N - CPU/memory cost factor (default: 16384)
   * @param {number} r - Block size (default: 8)
   * @param {number} p - Parallelization (default: 1)
   * @param {number} keyLength - Derived key length (default: 32)
   * @returns {Promise<Buffer>} Derived key
   */
  static async derive(password, salt, N = this.DEFAULT_N, r = this.DEFAULT_R, p = this.DEFAULT_P, keyLength = 32) {
    if ((N & (N - 1)) !== 0 || N === 0) {
      throw new Error('Scrypt N must be a power of 2 greater than 1');
    }
    
    if (r <= 0 || p <= 0) {
      throw new Error('Scrypt r and p must be positive integers');
    }
    
    const scrypt = promisify(crypto.scrypt);
    return await scrypt(password, salt, keyLength, { N, r, p });
  }
  
  /**
   * Generate salt for Scrypt
   * @param {number} length - Salt length (default: 32 bytes for Scrypt)
   * @returns {Buffer} Random salt
   */
  static generateSalt(length = 32) {
    return crypto.randomBytes(length);
  }
}

/**
 * Argon2id Implementation (RFC 9106)
 * Optional - requires native module, falls back gracefully
 */
class ProductionArgon2id {
  static isAvailable = false;
  static argon2 = null;
  
  static {
    try {
      // Try to load argon2 module (optional dependency)
      this.argon2 = require('argon2');
      this.isAvailable = true;
    } catch (error) {
      console.warn('Argon2id not available: install argon2 package for optimal password hashing');
      this.isAvailable = false;
    }
  }
  
  /**
   * Argon2id key derivation (if available)
   * @param {string|Buffer} password - Password or passphrase
   * @param {Buffer} salt - Random salt
   * @param {number} timeCost - Time cost (default: 3)
   * @param {number} memoryCost - Memory cost in KB (default: 65536 = 64MB)
   * @param {number} parallelism - Parallelism (default: 4)
   * @param {number} keyLength - Hash length (default: 32)
   * @returns {Promise<Buffer>} Derived key
   */
  static async derive(password, salt, timeCost = 3, memoryCost = 65536, parallelism = 4, keyLength = 32) {
    if (!this.isAvailable) {
      throw new Error('Argon2id not available. Install: npm install argon2');
    }
    
    const hash = await this.argon2.hash(password, {
      type: this.argon2.argon2id,
      memoryCost,
      timeCost,
      parallelism,
      hashLength: keyLength,
      salt
    });
    
    // Extract raw hash from encoded string
    const parts = hash.split('$');
    const rawHash = Buffer.from(parts[parts.length - 1], 'base64');
    return rawHash;
  }
  
  /**
   * Generate salt for Argon2id
   * @param {number} length - Salt length (default: 16 bytes)
   * @returns {Buffer} Random salt
   */
  static generateSalt(length = 16) {
    return crypto.randomBytes(length);
  }
}

/**
 * Unified KDF Interface
 * Provides consistent API across all KDF implementations
 */
class UnifiedKDF {
  /**
   * Derive key using specified KDF algorithm
   * @param {string} algorithm - KDF algorithm: 'hkdf', 'pbkdf2', 'scrypt', 'argon2id'
   * @param {string|Buffer} password - Password or key material
   * @param {Buffer} salt - Random salt
   * @param {Object} options - Algorithm-specific options
   * @returns {Promise<Buffer>} Derived key
   */
  static async derive(algorithm, password, salt, options = {}) {
    const keyLength = options.keyLength || 32;
    
    switch (algorithm.toLowerCase()) {
      case 'hkdf':
        return ProductionHKDF.derive(
          Buffer.isBuffer(password) ? password : Buffer.from(password),
          salt,
          options.info ? Buffer.from(options.info) : null,
          keyLength
        );
        
      case 'pbkdf2':
        return ProductionPBKDF2.derive(
          password,
          salt,
          options.iterations || ProductionPBKDF2.RECOMMENDED_ITERATIONS,
          keyLength
        );
        
      case 'scrypt':
        return ProductionScrypt.derive(
          password,
          salt,
          options.N || ProductionScrypt.DEFAULT_N,
          options.r || ProductionScrypt.DEFAULT_R,
          options.p || ProductionScrypt.DEFAULT_P,
          keyLength
        );
        
      case 'argon2id':
        if (!ProductionArgon2id.isAvailable) {
          throw new Error('Argon2id not available. Falling back to PBKDF2.');
        }
        return ProductionArgon2id.derive(
          password,
          salt,
          options.timeCost || 3,
          options.memoryCost || 65536,
          options.parallelism || 4,
          keyLength
        );
        
      default:
        throw new Error(`Unsupported KDF algorithm: ${algorithm}`);
    }
  }
  
  /**
   * Get available KDF algorithms
   * @returns {Array<string>} Available algorithms
   */
  static getAvailableAlgorithms() {
    const algorithms = ['hkdf', 'pbkdf2', 'scrypt'];
    if (ProductionArgon2id.isAvailable) {
      algorithms.push('argon2id');
    }
    return algorithms;
  }
}

module.exports = {
  ProductionHKDF,
  ProductionPBKDF2, 
  ProductionScrypt,
  ProductionArgon2id,
  UnifiedKDF
};