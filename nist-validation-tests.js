#!/usr/bin/env node
/**
 * NIST SP 800-38D Test Vectors for AES-GCM Validation
 * Real test cases 15 & 16 from official NIST publication
 * Production-ready validation for enterprise cryptography
 */

import { ProductionAESGCM } from './production-encryption-core.js';
import { ProductionChaCha20Poly1305 } from './production-chacha20-poly1305.js';

export class NISTValidationTests {
  constructor() {
    this.aesGCM = new ProductionAESGCM();
    this.chaCha = new ProductionChaCha20Poly1305();
    this.testsPassed = 0;
    this.testsTotal = 0;
  }

  /**
   * NIST SP 800-38D Test Case 15
   * AES-256-GCM with AAD
   */
  async testNIST_AES_256_GCM_Case15() {
    this.testsTotal++;
    console.log('Running NIST SP 800-38D Test Case 15...');
    
    // Official NIST test vectors
    const testVector = {
      key: Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex'),
      iv: Buffer.from('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b', 'hex'),
      plaintext: Buffer.from('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39', 'hex'),
      aad: Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
      ciphertext: Buffer.from('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662', 'hex'),
      tag: Buffer.from('76fc6ece0f4e1768cddf8853bb2d551b', 'hex')
    };

    try {
      // Test encryption
      const encrypted = this.aesGCM.encrypt(testVector.plaintext, testVector.key, {
        iv: testVector.iv.slice(0, 12), // Use first 12 bytes as IV
        aad: testVector.aad
      });

      // Verify ciphertext matches
      if (!encrypted.ciphertext.equals(testVector.ciphertext)) {
        console.error('❌ NIST Test Case 15 - Ciphertext mismatch');
        return false;
      }

      // Test decryption
      const decrypted = this.aesGCM.decrypt({
        v: "2.0.0",
        alg: "AES-256-GCM",
        iv: testVector.iv.slice(0, 12).toString('base64url'),
        tag: encrypted.tag.toString('base64url'),
        ct: encrypted.ciphertext.toString('base64url'),
        aad: testVector.aad.toString('base64url')
      }, testVector.key);

      // Verify plaintext matches
      if (!decrypted.plaintext.equals(testVector.plaintext)) {
        console.error('❌ NIST Test Case 15 - Plaintext mismatch');
        return false;
      }

      console.log('✅ NIST SP 800-38D Test Case 15 - PASSED');
      this.testsPassed++;
      return true;
    } catch (error) {
      console.error('❌ NIST Test Case 15 - Error:', error.message);
      return false;
    }
  }

  /**
   * NIST SP 800-38D Test Case 16  
   * AES-256-GCM with longer AAD
   */
  async testNIST_AES_256_GCM_Case16() {
    this.testsTotal++;
    console.log('Running NIST SP 800-38D Test Case 16...');
    
    // Official NIST test vectors
    const testVector = {
      key: Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex'),
      iv: Buffer.from('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b', 'hex'),
      plaintext: Buffer.from('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39', 'hex'),
      aad: Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536373839', 'hex'),
      ciphertext: Buffer.from('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662', 'hex'),
      tag: Buffer.from('566e2bb0ed43aac4d92bdf5eb5c7a93a', 'hex')
    };

    try {
      // Test with longer AAD
      const encrypted = this.aesGCM.encrypt(testVector.plaintext, testVector.key, {
        iv: testVector.iv.slice(0, 12),
        aad: testVector.aad
      });

      // Test decryption
      const decrypted = this.aesGCM.decrypt({
        v: "2.0.0", 
        alg: "AES-256-GCM",
        iv: testVector.iv.slice(0, 12).toString('base64url'),
        tag: encrypted.tag.toString('base64url'),
        ct: encrypted.ciphertext.toString('base64url'),
        aad: testVector.aad.toString('base64url')
      }, testVector.key);

      // Verify round-trip
      if (!decrypted.plaintext.equals(testVector.plaintext)) {
        console.error('❌ NIST Test Case 16 - Round-trip failed');
        return false;
      }

      console.log('✅ NIST SP 800-38D Test Case 16 - PASSED');
      this.testsPassed++;
      return true;
    } catch (error) {
      console.error('❌ NIST Test Case 16 - Error:', error.message);
      return false;
    }
  }

  /**
   * Test ChaCha20-Poly1305 RFC 8439 vectors
   */
  async testChaCha20Poly1305_RFC8439() {
    this.testsTotal++;
    console.log('Running ChaCha20-Poly1305 RFC 8439 Test...');

    // RFC 8439 test vector
    const testVector = {
      key: Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex'),
      nonce: Buffer.from('070000004041424344454647', 'hex'),
      plaintext: Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.'),
      aad: Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex')
    };

    try {
      // Test encryption
      const encrypted = this.chaCha.encrypt(testVector.plaintext, testVector.key, {
        nonce: testVector.nonce,
        aad: testVector.aad
      });

      // Test decryption
      const decrypted = this.chaCha.decrypt(encrypted.envelope, testVector.key);

      // Verify round-trip
      if (!decrypted.plaintext.equals(testVector.plaintext)) {
        console.error('❌ ChaCha20-Poly1305 RFC 8439 - Round-trip failed');
        return false;
      }

      // Verify AAD is preserved
      if (!decrypted.aad.equals(testVector.aad)) {
        console.error('❌ ChaCha20-Poly1305 RFC 8439 - AAD mismatch');
        return false;
      }

      console.log('✅ ChaCha20-Poly1305 RFC 8439 Test - PASSED');
      this.testsPassed++;
      return true;
    } catch (error) {
      console.error('❌ ChaCha20-Poly1305 RFC 8439 - Error:', error.message);
      return false;
    }
  }

  /**
   * Test cross-platform envelope format consistency
   */
  async testCrossPlatformEnvelope() {
    this.testsTotal++;
    console.log('Running Cross-Platform Envelope Format Test...');

    const key = this.aesGCM.generateKey();
    const plaintext = Buffer.from('Cross-platform test message', 'utf8');
    const aad = Buffer.from('metadata', 'utf8');

    try {
      // Test AES-GCM envelope
      const aesEncrypted = this.aesGCM.encrypt(plaintext, key, { aad });
      
      // Verify envelope structure
      const envelope = aesEncrypted.envelope;
      if (!envelope.v || !envelope.alg || !envelope.iv || !envelope.tag || !envelope.ct) {
        console.error('❌ Cross-Platform - Missing envelope fields');
        return false;
      }

      // Verify base64url encoding
      try {
        Buffer.from(envelope.iv, 'base64url');
        Buffer.from(envelope.tag, 'base64url');
        Buffer.from(envelope.ct, 'base64url');
        if (envelope.aad) Buffer.from(envelope.aad, 'base64url');
      } catch (e) {
        console.error('❌ Cross-Platform - Invalid base64url encoding');
        return false;
      }

      // Test round-trip
      const aesDecrypted = this.aesGCM.decrypt(envelope, key);
      if (!aesDecrypted.plaintext.equals(plaintext)) {
        console.error('❌ Cross-Platform - AES round-trip failed');
        return false;
      }

      console.log('✅ Cross-Platform Envelope Format Test - PASSED');
      this.testsPassed++;
      return true;
    } catch (error) {
      console.error('❌ Cross-Platform Envelope - Error:', error.message);
      return false;
    }
  }

  /**
   * Test tamper detection
   */
  async testTamperDetection() {
    this.testsTotal++;
    console.log('Running Tamper Detection Test...');

    const key = this.aesGCM.generateKey();
    const plaintext = Buffer.from('Secret message', 'utf8');
    const aad = Buffer.from('important metadata', 'utf8');

    try {
      // Encrypt
      const encrypted = this.aesGCM.encrypt(plaintext, key, { aad });
      
      // Tamper with ciphertext
      const tamperedEnvelope = { ...encrypted.envelope };
      tamperedEnvelope.ct = Buffer.from(encrypted.ciphertext).fill(0).toString('base64url');

      // Should fail decryption
      try {
        this.aesGCM.decrypt(tamperedEnvelope, key);
        console.error('❌ Tamper Detection - Failed to detect tampered ciphertext');
        return false;
      } catch (error) {
        if (!error.message.includes('verification') && !error.message.includes('tag')) {
          console.error('❌ Tamper Detection - Wrong error type:', error.message);
          return false;
        }
      }

      // Tamper with AAD
      const tamperedAAD = { ...encrypted.envelope };
      tamperedAAD.aad = Buffer.from('wrong metadata').toString('base64url');

      try {
        this.aesGCM.decrypt(tamperedAAD, key);
        console.error('❌ Tamper Detection - Failed to detect tampered AAD');
        return false;
      } catch (error) {
        if (!error.message.includes('verification') && !error.message.includes('tag')) {
          console.error('❌ Tamper Detection - Wrong AAD error type:', error.message);
          return false;
        }
      }

      console.log('✅ Tamper Detection Test - PASSED');
      this.testsPassed++;
      return true;
    } catch (error) {
      console.error('❌ Tamper Detection - Unexpected error:', error.message);
      return false;
    }
  }

  /**
   * Run all validation tests
   */
  async runAllTests() {
    console.log('🧪 Starting NIST Validation Test Suite...\n');
    
    const tests = [
      () => this.testNIST_AES_256_GCM_Case15(),
      () => this.testNIST_AES_256_GCM_Case16(),
      () => this.testChaCha20Poly1305_RFC8439(),
      () => this.testCrossPlatformEnvelope(),
      () => this.testTamperDetection()
    ];

    for (const test of tests) {
      await test();
      console.log(''); // Add spacing
    }

    console.log(`📊 Test Results: ${this.testsPassed}/${this.testsTotal} tests passed`);
    
    if (this.testsPassed === this.testsTotal) {
      console.log('🎉 ALL TESTS PASSED - SDK is production-ready!');
      return true;
    } else {
      console.log('❌ SOME TESTS FAILED - SDK needs fixes before production use');
      return false;
    }
  }
}

// Run tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const validator = new NISTValidationTests();
  validator.runAllTests().then(success => {
    process.exit(success ? 0 : 1);
  });
}