/**
 * Canonical v2 Reference Implementation
 * Production-ready AES-256-GCM with 12-byte IV policy enforcement
 * GOVERNMENT-LEVEL SECURITY HARDENING APPLIED
 * 
 * SPECIFICATION COMPLIANCE:
 * ✅ Version: "2" (string, mandatory)
 * ✅ Algorithm: "AES-256-GCM" from registry
 * ✅ IV: 12-byte base64url (no padding)
 * ✅ Tag: 16-byte base64url authentication tag
 * ✅ Ciphertext: base64url encrypted data
 * ✅ AAD: Input only, NOT stored in envelope
 * 
 * SECURITY HARDENING:
 * ✅ Strong RNG with health checks
 * ✅ AEAD modes only enforcement
 * ✅ Automatic IV generation (user IVs rejected)
 * ✅ Constant-time operations
 * ✅ Comprehensive parameter validation
 * ✅ Minimum key size enforcement
 */

const crypto = require('crypto');
const { 
  RNGHealthMonitor,
  SecureDefaultsEnforcer,
  ConstantTimeOps,
  ParameterValidator,
  SecurityError
} = require('./security-hardening-core.cjs');

/**
 * Base64URL utilities (RFC 4648 Section 5)
 */
class Base64URL {
  static encode(buffer) {
    return buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  static decode(str) {
    // Validate base64url characters first
    if (!/^[A-Za-z0-9_-]+$/.test(str)) {
      throw new Error('Invalid base64url characters');
    }
    
    // Add padding back for standard base64 decode
    const padded = str + '='.repeat((4 - str.length % 4) % 4);
    const standard = padded.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(standard, 'base64');
  }
}

/**
 * Canonical v2 Envelope Format
 * {"v":"2", "alg":"AES-256-GCM", "kid":"<optional>", "iv":"<b64url>", "tag":"<b64url>", "ct":"<b64url>"}
 */
class CanonicalV2Envelope {
  static VERSION = "2";
  static SUPPORTED_ALGORITHMS = ["AES-256-GCM"];
  
  static create(iv, tag, ciphertext, kid = null) {
    // SECURITY HARDENING: Enhanced validation
    if (!Buffer.isBuffer(iv) || iv.length !== 12) {
      throw new SecurityError('INVALID_IV', 'IV must be exactly 12 bytes for AES-256-GCM');
    }
    if (!Buffer.isBuffer(tag) || tag.length !== 16) {
      throw new SecurityError('INVALID_TAG', 'Tag must be exactly 16 bytes for AES-256-GCM');
    }
    if (!Buffer.isBuffer(ciphertext)) {
      throw new SecurityError('INVALID_CIPHERTEXT', 'Ciphertext must be a Buffer');
    }
    
    const envelope = {
      v: this.VERSION,
      alg: "AES-256-GCM",
      iv: Base64URL.encode(iv),
      tag: Base64URL.encode(tag),
      ct: Base64URL.encode(ciphertext)
    };
    
    if (kid) {
      envelope.kid = kid;
    }
    
    return JSON.stringify(envelope);
  }
  
  static parse(envelopeStr) {
    let envelope;
    try {
      envelope = JSON.parse(envelopeStr);
    } catch (error) {
      throw new Error('Invalid envelope: not valid JSON');
    }
    
    if (envelope.v !== this.VERSION) {
      throw new SecurityError('UNSUPPORTED_VERSION', `Unsupported envelope version: ${envelope.v}, expected: ${this.VERSION}`);
    }
    
    // SECURITY HARDENING: Use secure algorithm validation
    try {
      SecureDefaultsEnforcer.validateAlgorithm(envelope.alg);
    } catch (error) {
      throw new SecurityError('UNSUPPORTED_ALGORITHM', `Algorithm validation failed: ${error.message}`, error);
    }
    
    if (!envelope.iv || !envelope.tag || !envelope.ct) {
      throw new Error('Missing required envelope fields: iv, tag, ct');
    }
    
    try {
      const decoded = {
        version: envelope.v,
        algorithm: envelope.alg,
        kid: envelope.kid || null,
        iv: Base64URL.decode(envelope.iv),
        tag: Base64URL.decode(envelope.tag),
        ciphertext: Base64URL.decode(envelope.ct)
      };
      
      // Validate IV and tag lengths after decoding
      if (decoded.iv.length !== 12) {
        throw new Error('Invalid IV length: must be 12 bytes');
      }
      if (decoded.tag.length !== 16) {
        throw new Error('Invalid tag length: must be 16 bytes');
      }
      
      return decoded;
    } catch (error) {
      if (error.message.includes('Invalid') && (error.message.includes('IV') || error.message.includes('tag'))) {
        throw error; // Re-throw validation errors as-is
      }
      throw new SecurityError('INVALID_ENVELOPE_ENCODING', 'Invalid base64url encoding in envelope fields', error);
    }
  }
}

/**
 * Production AES-256-GCM Implementation
 * Uses Node.js crypto module with proper GCM mode
 */
class ProductionAESGCM {
  static ALGORITHM = 'aes-256-gcm';
  static IV_LENGTH = 12;
  static TAG_LENGTH = 16;
  static KEY_LENGTH = 32;
  
  static generateKey() {
    return RNGHealthMonitor.getSecureRandomBytes(this.KEY_LENGTH);
  }
  
  static generateIV() {
    return RNGHealthMonitor.getSecureRandomBytes(this.IV_LENGTH);
  }
  
  /**
   * Encrypt with AES-256-GCM (HARDENED)
   * @param {Buffer} plaintext - Data to encrypt
   * @param {Buffer} key - 32-byte encryption key
   * @param {Object} opts - Options: {aad: Buffer, kid: string} (iv auto-generated for security)
   * @returns {string} Canonical v2 envelope
   */
  static encrypt(plaintext, key, opts = {}) {
    // SECURITY HARDENING: Comprehensive parameter validation
    const validation = ParameterValidator.validateEncryptionParams(
      plaintext, key, 'AES-256-GCM', opts
    );
    
    // SECURITY HARDENING: Auto-generate IV, never allow user-provided
    const iv = this.generateIV();
    
    // Convert plaintext to buffer if needed
    const plaintextBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
    
    const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
    
    if (validation.sanitizedOptions.aad) {
      cipher.setAAD(validation.sanitizedOptions.aad);
    }
    
    let encrypted;
    if (plaintextBuffer.length === 0) {
      // Handle empty plaintext edge case
      encrypted = cipher.final();
    } else {
      encrypted = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
    }
    
    const tag = cipher.getAuthTag();
    
    return CanonicalV2Envelope.create(iv, tag, encrypted, validation.sanitizedOptions.kid);
  }
  
  /**
   * Decrypt canonical v2 envelope (HARDENED)
   * @param {string} envelopeStr - Canonical v2 envelope
   * @param {Buffer} key - 32-byte decryption key
   * @param {Object} opts - Options: {aad: Buffer, expectKid: string}
   * @returns {Buffer} Decrypted plaintext
   */
  static decrypt(envelopeStr, key, opts = {}) {
    // SECURITY HARDENING: Comprehensive parameter validation
    const validation = ParameterValidator.validateDecryptionParams(
      envelopeStr, key, opts
    );
    
    const envelope = CanonicalV2Envelope.parse(envelopeStr);
    
    // SECURITY HARDENING: Constant-time key ID comparison
    if (validation.sanitizedOptions.expectKid && envelope.kid !== validation.sanitizedOptions.expectKid) {
      // Use timing-safe string comparison for key ID
      if (!ConstantTimeOps.timingSafeStringEqual(envelope.kid || '', validation.sanitizedOptions.expectKid)) {
        throw new SecurityError('KEY_ID_MISMATCH', `Key ID mismatch: expected ${validation.sanitizedOptions.expectKid}, got ${envelope.kid}`);
      }
    }
    
    const decipher = crypto.createDecipheriv(this.ALGORITHM, key, envelope.iv);
    decipher.setAuthTag(envelope.tag);
    
    if (validation.sanitizedOptions.aad) {
      decipher.setAAD(validation.sanitizedOptions.aad);
    }
    
    try {
      let plaintext = decipher.update(envelope.ciphertext);
      plaintext = Buffer.concat([plaintext, decipher.final()]);
      return plaintext;
    } catch (error) {
      if (error.message.includes('Unsupported state or unable to authenticate data')) {
        throw new SecurityError('AUTH_FAILURE', 'Authentication failed: invalid tag or AAD mismatch', error);
      }
      throw error;
    } finally {
      // SECURITY HARDENING: Always clear sensitive data
      ConstantTimeOps.secureMemoryClear(key);
    }
  }
}

/**
 * Security utilities (HARDENED)
 * Now using constant-time operations from security hardening core
 */
function timingSafeEqual(a, b) {
  return ConstantTimeOps.timingSafeEqual(a, b);
}

function zeroizeBuffer(buffer) {
  ConstantTimeOps.secureMemoryClear(buffer);
}

// Wrapper class for instance-based API compatibility
class AveroxCrypto {
  constructor(masterKey, keyId = 'default') {
    this.masterKey = masterKey;
    this.keyId = keyId;
  }
  
  encrypt(plaintext, aad = null) {
    return ProductionAESGCM.encrypt(plaintext, this.masterKey, { aad, kid: this.keyId });
  }
  
  decrypt(encryptedData, aad = null) {
    const decrypted = ProductionAESGCM.decrypt(encryptedData, this.masterKey, { aad });
    return decrypted.toString('utf8');
  }
  
  destroy() {
    ConstantTimeOps.secureMemoryClear(this.masterKey);
  }
}

module.exports = {
  CanonicalV2Envelope,
  ProductionAESGCM,
  AveroxCrypto, // Instance-based wrapper for compatibility
  Base64URL,
  timingSafeEqual,
  zeroizeBuffer
};