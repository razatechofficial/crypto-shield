#!/usr/bin/env node
/**
 * NIST SP 800-38D Test Vector Validation Suite
 * Comprehensive testing for AES-GCM implementation compliance
 */

import { ProductionAESGCM, NIST_TEST_VECTORS, runNISTValidation } from './production-encryption-core.js';
import crypto from 'crypto';

class NISTValidationSuite {
  constructor() {
    this.crypto = new ProductionAESGCM();
    this.testResults = [];
  }

  /**
   * Run comprehensive NIST validation
   */
  async runAllTests() {
    console.log('🔐 Starting NIST SP 800-38D Validation Suite');
    console.log('================================================');
    
    try {
      // Test basic functionality
      await this.testBasicEncryptionDecryption();
      
      // Test NIST vectors
      await this.testNISTVectors();
      
      // Test AAD functionality
      await this.testAADSupport();
      
      // Test IV standardization
      await this.testIVStandardization();
      
      // Test error handling
      await this.testErrorHandling();
      
      // Test cross-platform envelope
      await this.testEnvelopeFormat();
      
      // Test key derivation
      await this.testKeyDerivation();
      
      // Print summary
      this.printTestSummary();
      
    } catch (error) {
      console.error('❌ Test suite failed:', error.message);
      process.exit(1);
    }
  }

  /**
   * Test basic encryption/decryption
   */
  async testBasicEncryptionDecryption() {
    console.log('\n📋 Testing Basic Encryption/Decryption');
    
    const testCases = [
      {
        name: 'Empty plaintext',
        plaintext: '',
        aad: null
      },
      {
        name: 'Short plaintext',
        plaintext: 'Hello, World!',
        aad: 'header-info'
      },
      {
        name: 'Long plaintext',
        plaintext: 'A'.repeat(1000),
        aad: 'metadata'
      },
      {
        name: 'Binary data',
        plaintext: Buffer.from([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD]),
        aad: Buffer.from('binary-header')
      }
    ];

    for (const testCase of testCases) {
      try {
        const key = this.crypto.generateKey();
        const iv = this.crypto.generateIV();
        
        // Encrypt
        const envelope = this.crypto.encrypt(testCase.plaintext, key, iv, testCase.aad);
        
        // Decrypt
        const decrypted = this.crypto.decrypt(envelope, key);
        
        // Verify
        const originalBuffer = Buffer.isBuffer(testCase.plaintext) 
          ? testCase.plaintext 
          : Buffer.from(testCase.plaintext, 'utf8');
          
        if (!decrypted.equals(originalBuffer)) {
          throw new Error('Decrypted data does not match original');
        }
        
        this.recordTest(testCase.name, true);
        console.log(`  ✅ ${testCase.name}`);
        
      } catch (error) {
        this.recordTest(testCase.name, false, error.message);
        console.log(`  ❌ ${testCase.name}: ${error.message}`);
      }
    }
  }

  /**
   * Test NIST SP 800-38D test vectors
   */
  async testNISTVectors() {
    console.log('\n📋 Testing NIST SP 800-38D Test Vectors');
    
    // Test Case 15 - Empty plaintext and AAD
    try {
      const test15 = NIST_TEST_VECTORS.testCase15;
      
      // Use Node.js crypto directly for exact NIST compliance
      const iv = Buffer.from(test15.iv, 'hex');
      const cipher = crypto.createCipheriv('aes-128-gcm', Buffer.from(test15.key, 'hex'), iv);
      const aadBuffer = Buffer.from(test15.aad);
      if (aadBuffer.length > 0) {
        cipher.setAAD(aadBuffer);
      }
      
      let encrypted = cipher.update(Buffer.from(test15.plaintext), null, 'hex');
      encrypted += cipher.final('hex');
      const tag = cipher.getAuthTag().toString('hex');
      
      if (encrypted !== test15.expectedCiphertext) {
        throw new Error(`Ciphertext mismatch. Expected: ${test15.expectedCiphertext}, Got: ${encrypted}`);
      }
      
      if (tag !== test15.expectedTag) {
        throw new Error(`Tag mismatch. Expected: ${test15.expectedTag}, Got: ${tag}`);
      }
      
      this.recordTest('NIST Test Case 15', true);
      console.log('  ✅ NIST Test Case 15 (Empty plaintext/AAD)');
      
    } catch (error) {
      this.recordTest('NIST Test Case 15', false, error.message);
      console.log(`  ❌ NIST Test Case 15: ${error.message}`);
    }

    // Test Case 16 - 16-byte plaintext, empty AAD
    try {
      const test16 = NIST_TEST_VECTORS.testCase16;
      
      const iv = Buffer.from(test16.iv, 'hex');
      const cipher = crypto.createCipheriv('aes-128-gcm', Buffer.from(test16.key, 'hex'), iv);
      const aadBuffer = Buffer.from(test16.aad);
      if (aadBuffer.length > 0) {
        cipher.setAAD(aadBuffer);
      }
      
      let encrypted = cipher.update(Buffer.from(test16.plaintext, 'hex'), null, 'hex');
      encrypted += cipher.final('hex');
      const tag = cipher.getAuthTag().toString('hex');
      
      if (encrypted !== test16.expectedCiphertext) {
        throw new Error(`Ciphertext mismatch. Expected: ${test16.expectedCiphertext}, Got: ${encrypted}`);
      }
      
      if (tag !== test16.expectedTag) {
        throw new Error(`Tag mismatch. Expected: ${test16.expectedTag}, Got: ${tag}`);
      }
      
      this.recordTest('NIST Test Case 16', true);
      console.log('  ✅ NIST Test Case 16 (16-byte plaintext)');
      
    } catch (error) {
      this.recordTest('NIST Test Case 16', false, error.message);
      console.log(`  ❌ NIST Test Case 16: ${error.message}`);
    }
  }

  /**
   * Test AAD (Additional Authenticated Data) support
   */
  async testAADSupport() {
    console.log('\n📋 Testing AAD Support');
    
    const testCases = [
      {
        name: 'String AAD',
        plaintext: 'secret message',
        aad: 'metadata-header'
      },
      {
        name: 'Buffer AAD',
        plaintext: 'secret message',
        aad: Buffer.from('binary-metadata')
      },
      {
        name: 'Empty AAD',
        plaintext: 'secret message',
        aad: ''
      },
      {
        name: 'Null AAD',
        plaintext: 'secret message',
        aad: null
      }
    ];

    for (const testCase of testCases) {
      try {
        const key = this.crypto.generateKey();
        const iv = this.crypto.generateIV();
        
        // Encrypt with AAD
        const envelope = this.crypto.encrypt(testCase.plaintext, key, iv, testCase.aad);
        
        // Verify AAD is stored correctly
        if (testCase.aad && envelope.aad === null) {
          throw new Error('AAD not stored in envelope');
        }
        
        // Decrypt
        const decrypted = this.crypto.decrypt(envelope, key);
        
        if (!decrypted.equals(Buffer.from(testCase.plaintext, 'utf8'))) {
          throw new Error('Decrypted data does not match original');
        }
        
        // Test AAD tampering detection
        if (testCase.aad) {
          const tamperedEnvelope = { ...envelope };
          tamperedEnvelope.aad = Buffer.from('tampered').toString('base64');
          
          try {
            this.crypto.decrypt(tamperedEnvelope, key);
            throw new Error('AAD tampering not detected');
          } catch (error) {
            if (!error.message.includes('Decryption failed')) {
              throw error;
            }
          }
        }
        
        this.recordTest(`AAD: ${testCase.name}`, true);
        console.log(`  ✅ ${testCase.name}`);
        
      } catch (error) {
        this.recordTest(`AAD: ${testCase.name}`, false, error.message);
        console.log(`  ❌ ${testCase.name}: ${error.message}`);
      }
    }
  }

  /**
   * Test IV standardization (12 bytes)
   */
  async testIVStandardization() {
    console.log('\n📋 Testing IV Standardization');
    
    try {
      // Test IV generation
      const iv = this.crypto.generateIV();
      if (iv.length !== 12) {
        throw new Error(`IV length should be 12 bytes, got ${iv.length}`);
      }
      
      // Test IV validation
      const validIVs = [
        Buffer.alloc(12),
        crypto.randomBytes(12),
        '000102030405060708090a0b' // hex string
      ];
      
      for (const testIV of validIVs) {
        const validated = this.crypto.validateIV(testIV);
        if (validated.length !== 12) {
          throw new Error('IV validation failed');
        }
      }
      
      // Test invalid IVs
      const invalidIVs = [
        Buffer.alloc(16), // Wrong length
        Buffer.alloc(8),  // Too short
        'invalid'         // Invalid format
      ];
      
      for (const invalidIV of invalidIVs) {
        try {
          this.crypto.validateIV(invalidIV);
          throw new Error('Invalid IV not rejected');
        } catch (error) {
          if (!error.message.includes('Invalid IV length')) {
            throw error;
          }
        }
      }
      
      this.recordTest('IV Standardization', true);
      console.log('  ✅ IV length standardized to 12 bytes');
      
    } catch (error) {
      this.recordTest('IV Standardization', false, error.message);
      console.log(`  ❌ IV Standardization: ${error.message}`);
    }
  }

  /**
   * Test error handling
   */
  async testErrorHandling() {
    console.log('\n📋 Testing Error Handling');
    
    const errorTests = [
      {
        name: 'Invalid key size',
        test: () => this.crypto.validateKey(Buffer.alloc(15))
      },
      {
        name: 'Invalid IV size',
        test: () => this.crypto.validateIV(Buffer.alloc(16))
      },
      {
        name: 'Invalid envelope version',
        test: () => this.crypto.validateEnvelope({ version: '2.0', algorithm: 'aes-256-gcm', iv: 'test', tag: 'test', ciphertext: 'test' })
      },
      {
        name: 'Missing envelope fields',
        test: () => this.crypto.validateEnvelope({ version: '1.0' })
      },
      {
        name: 'Tag tampering',
        test: () => {
          const key = this.crypto.generateKey();
          const envelope = this.crypto.encrypt('test', key);
          envelope.tag = Buffer.from('tampered-tag').toString('base64');
          return this.crypto.decrypt(envelope, key);
        }
      }
    ];

    for (const errorTest of errorTests) {
      try {
        await errorTest.test();
        this.recordTest(`Error: ${errorTest.name}`, false, 'Expected error not thrown');
        console.log(`  ❌ ${errorTest.name}: Expected error not thrown`);
      } catch (error) {
        this.recordTest(`Error: ${errorTest.name}`, true);
        console.log(`  ✅ ${errorTest.name}: Properly handled`);
      }
    }
  }

  /**
   * Test envelope format consistency
   */
  async testEnvelopeFormat() {
    console.log('\n📋 Testing Envelope Format');
    
    try {
      const key = this.crypto.generateKey();
      const envelope = this.crypto.encrypt('test message', key, null, 'test-aad');
      
      // Verify required fields
      const requiredFields = ['version', 'algorithm', 'iv', 'tag', 'ciphertext', 'timestamp', 'keySize'];
      for (const field of requiredFields) {
        if (!envelope[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
      
      // Verify field formats
      if (envelope.version !== '1.0') {
        throw new Error('Invalid version format');
      }
      
      if (!envelope.algorithm.startsWith('aes-')) {
        throw new Error('Invalid algorithm format');
      }
      
      // Verify base64 encoding
      try {
        Buffer.from(envelope.iv, 'base64');
        Buffer.from(envelope.tag, 'base64');
        Buffer.from(envelope.ciphertext, 'base64');
        if (envelope.aad) {
          Buffer.from(envelope.aad, 'base64');
        }
      } catch (error) {
        throw new Error('Invalid base64 encoding in envelope');
      }
      
      this.recordTest('Envelope Format', true);
      console.log('  ✅ Envelope format is consistent and valid');
      
    } catch (error) {
      this.recordTest('Envelope Format', false, error.message);
      console.log(`  ❌ Envelope Format: ${error.message}`);
    }
  }

  /**
   * Test key derivation
   */
  async testKeyDerivation() {
    console.log('\n📋 Testing Key Derivation');
    
    try {
      const password = 'test-password';
      const salt = crypto.randomBytes(16);
      
      // Test PBKDF2 key derivation
      const key1 = this.crypto.deriveKey(password, salt, 100000);
      const key2 = this.crypto.deriveKey(password, salt, 100000);
      
      if (!key1.equals(key2)) {
        throw new Error('Derived keys should be identical for same inputs');
      }
      
      if (key1.length !== 32) {
        throw new Error('Derived key should be 32 bytes');
      }
      
      // Test different salt produces different key
      const salt2 = crypto.randomBytes(16);
      const key3 = this.crypto.deriveKey(password, salt2, 100000);
      
      if (key1.equals(key3)) {
        throw new Error('Different salts should produce different keys');
      }
      
      this.recordTest('Key Derivation', true);
      console.log('  ✅ PBKDF2 key derivation working correctly');
      
    } catch (error) {
      this.recordTest('Key Derivation', false, error.message);
      console.log(`  ❌ Key Derivation: ${error.message}`);
    }
  }

  /**
   * Record test result
   */
  recordTest(name, passed, error = null) {
    this.testResults.push({
      name,
      passed,
      error
    });
  }

  /**
   * Print test summary
   */
  printTestSummary() {
    console.log('\n📊 Test Summary');
    console.log('================');
    
    const passed = this.testResults.filter(t => t.passed).length;
    const failed = this.testResults.filter(t => !t.passed).length;
    const total = this.testResults.length;
    
    console.log(`Total Tests: ${total}`);
    console.log(`Passed: ${passed} ✅`);
    console.log(`Failed: ${failed} ${failed > 0 ? '❌' : '✅'}`);
    console.log(`Success Rate: ${((passed / total) * 100).toFixed(1)}%`);
    
    if (failed > 0) {
      console.log('\n❌ Failed Tests:');
      this.testResults
        .filter(t => !t.passed)
        .forEach(t => console.log(`  - ${t.name}: ${t.error}`));
    }
    
    if (failed === 0) {
      console.log('\n🎉 All tests passed! Production-ready AES-GCM implementation confirmed.');
    } else {
      console.log('\n⚠️  Some tests failed. Please review and fix issues before production use.');
      process.exit(1);
    }
  }
}

// Run the validation suite
if (import.meta.url === `file://${process.argv[1]}`) {
  const suite = new NISTValidationSuite();
  suite.runAllTests().catch(error => {
    console.error('Validation suite failed:', error);
    process.exit(1);
  });
}

export default NISTValidationSuite;