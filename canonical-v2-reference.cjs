/**
 * Canonical v2 Reference Implementation
 * Production-ready AES-256-GCM with 12-byte IV policy enforcement
 * 
 * SPECIFICATION COMPLIANCE:
 * ✅ Version: "2" (string, mandatory)
 * ✅ Algorithm: "AES-256-GCM" from registry
 * ✅ IV: 12-byte base64url (no padding)
 * ✅ Tag: 16-byte base64url authentication tag
 * ✅ Ciphertext: base64url encrypted data
 * ✅ AAD: Input only, NOT stored in envelope
 */

const crypto = require('crypto');

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
    if (iv.length !== 12) {
      throw new Error('IV must be exactly 12 bytes for AES-256-GCM');
    }
    if (tag.length !== 16) {
      throw new Error('Tag must be exactly 16 bytes for AES-256-GCM');
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
      throw new Error(`Unsupported envelope version: ${envelope.v}, expected: ${this.VERSION}`);
    }
    
    if (!this.SUPPORTED_ALGORITHMS.includes(envelope.alg)) {
      throw new Error(`Unsupported algorithm: ${envelope.alg}`);
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
      throw new Error('Invalid base64url encoding in envelope fields');
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
    return crypto.randomBytes(this.KEY_LENGTH);
  }
  
  static generateIV() {
    return crypto.randomBytes(this.IV_LENGTH);
  }
  
  /**
   * Encrypt with AES-256-GCM
   * @param {Buffer} plaintext - Data to encrypt
   * @param {Buffer} key - 32-byte encryption key
   * @param {Object} opts - Options: {aad: Buffer, kid: string, iv: Buffer}
   * @returns {string} Canonical v2 envelope
   */
  static encrypt(plaintext, key, opts = {}) {
    if (key.length !== this.KEY_LENGTH) {
      throw new Error(`Key must be exactly ${this.KEY_LENGTH} bytes`);
    }
    
    const iv = opts.iv || this.generateIV(); // Allow fixed IV for test vectors
    if (iv.length !== this.IV_LENGTH) {
      throw new Error(`IV must be exactly ${this.IV_LENGTH} bytes`);
    }
    
    const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
    
    if (opts.aad) {
      cipher.setAAD(opts.aad);
    }
    
    let encrypted;
    if (plaintext.length === 0) {
      // Handle empty plaintext edge case
      encrypted = cipher.final();
    } else {
      encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    }
    
    const tag = cipher.getAuthTag();
    
    return CanonicalV2Envelope.create(iv, tag, encrypted, opts.kid);
  }
  
  /**
   * Decrypt canonical v2 envelope
   * @param {string} envelopeStr - Canonical v2 envelope
   * @param {Buffer} key - 32-byte decryption key
   * @param {Object} opts - Options: {aad: Buffer, expectKid: string}
   * @returns {Buffer} Decrypted plaintext
   */
  static decrypt(envelopeStr, key, opts = {}) {
    if (key.length !== this.KEY_LENGTH) {
      throw new Error(`Key must be exactly ${this.KEY_LENGTH} bytes`);
    }
    
    const envelope = CanonicalV2Envelope.parse(envelopeStr);
    
    if (opts.expectKid && envelope.kid !== opts.expectKid) {
      throw new Error(`Key ID mismatch: expected ${opts.expectKid}, got ${envelope.kid}`);
    }
    
    const decipher = crypto.createDecipheriv(this.ALGORITHM, key, envelope.iv);
    decipher.setAuthTag(envelope.tag);
    
    if (opts.aad) {
      decipher.setAAD(opts.aad);
    }
    
    try {
      let plaintext = decipher.update(envelope.ciphertext);
      plaintext = Buffer.concat([plaintext, decipher.final()]);
      return plaintext;
    } catch (error) {
      if (error.message.includes('Unsupported state or unable to authenticate data')) {
        throw new Error('Authentication failed: invalid tag or AAD mismatch');
      }
      throw error;
    }
  }
}

/**
 * Security utilities
 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

function zeroizeBuffer(buffer) {
  if (Buffer.isBuffer(buffer)) {
    buffer.fill(0);
  } else if (buffer instanceof Uint8Array) {
    buffer.fill(0);
  }
}

module.exports = {
  CanonicalV2Envelope,
  ProductionAESGCM,
  Base64URL,
  timingSafeEqual,
  zeroizeBuffer
};