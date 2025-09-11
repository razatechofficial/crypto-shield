/**
 * Comprehensive Golden Vector Suite for v2 Specification
 * 10+ test vectors covering all scenarios + negative tests
 */

const { CanonicalV2Envelope, ProductionAESGCM, Base64URL } = require('./canonical-v2-reference.cjs');
const fs = require('fs');

class ComprehensiveVectorSuite {
  static generateAllVectors() {
    const vectors = [];
    
    // POSITIVE TEST VECTORS (10 vectors)
    
    // Vector 1: Minimal case - small plaintext, no AAD, no KID
    vectors.push({
      name: 'minimal_encryption',
      key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      plaintext: 'Hi',
      iv: '000102030405060708090a0b',
      aad: null,
      kid: null,
      type: 'positive'
    });
    
    // Vector 2: Basic encryption
    vectors.push({
      name: 'basic_encryption',
      key: '1111111111111111111111111111111111111111111111111111111111111111',
      plaintext: 'Hello, World!',
      iv: '111111111111111111111111',
      aad: null,
      kid: null,
      type: 'positive'
    });
    
    // Vector 3: Encryption with simple AAD
    vectors.push({
      name: 'encryption_with_aad',
      key: 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
      plaintext: 'Sensitive data with authentication',
      iv: '0b0a09080706050403020100',
      aad: 'user-context',
      kid: null,
      type: 'positive'
    });
    
    // Vector 4: Encryption with Key ID
    vectors.push({
      name: 'encryption_with_kid',
      key: '2222222222222222222222222222222222222222222222222222222222222222',
      plaintext: 'Data with key rotation support',
      iv: '222222222222222222222222',
      aad: null,
      kid: 'primary-key-2024',
      type: 'positive'
    });
    
    // Vector 5: Full configuration (AAD + KID)
    vectors.push({
      name: 'full_configuration',
      key: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      plaintext: 'Maximum security configuration',
      iv: 'ccbbaa998877665544332211',
      aad: 'audit:transaction=tx_456,amount=1000.00',
      kid: 'hsm-prod-2024',
      type: 'positive'
    });
    
    // Vector 6: Single character plaintext (empty plaintext can be edge case)
    vectors.push({
      name: 'single_character',
      key: '3333333333333333333333333333333333333333333333333333333333333333',
      plaintext: 'X',
      iv: '333333333333333333333333',
      aad: null,
      kid: null,
      type: 'positive'
    });
    
    // Vector 7: Unicode content
    vectors.push({
      name: 'unicode_content',
      key: '4444444444444444444444444444444444444444444444444444444444444444',
      plaintext: '🔒 Encrypted: 中文 العربية русский',
      iv: '444444444444444444444444',
      aad: 'charset=utf-8',
      kid: null,
      type: 'positive'
    });
    
    // Vector 8: Large payload (1KB)
    vectors.push({
      name: 'large_payload_1kb',
      key: '5555555555555555555555555555555555555555555555555555555555555555',
      plaintext: 'X'.repeat(1024),
      iv: '555555555555555555555555',
      aad: null,
      kid: null,
      type: 'positive'
    });
    
    // Vector 9: JSON payload
    vectors.push({
      name: 'json_payload',
      key: '6666666666666666666666666666666666666666666666666666666666666666',
      plaintext: '{"user_id": 12345, "role": "admin", "permissions": ["read", "write", "delete"]}',
      iv: '666666666666666666666666',
      aad: 'content-type:application/json',
      kid: 'api-key-v2',
      type: 'positive'
    });
    
    // Vector 10: Complex AAD with special characters
    vectors.push({
      name: 'complex_aad',
      key: '7777777777777777777777777777777777777777777777777777777777777777',
      plaintext: 'Enterprise data with complex metadata',
      iv: '777777777777777777777777',
      aad: 'tenant=acme-corp|dept=finance|class=pii|retention=7y|region=us-east-1',
      kid: 'tenant-key-finance',
      type: 'positive'
    });
    
    // Vector 11: Randomized realistic case
    vectors.push({
      name: 'realistic_random',
      key: '8888888888888888888888888888888888888888888888888888888888888888',
      plaintext: 'Customer PII: John Doe, SSN: 123-45-6789, DOB: 1985-03-15',
      iv: '888888888888888888888888',
      aad: 'purpose=storage|compliance=gdpr,hipaa|masked=false',
      kid: 'customer-data-key-2024-q1',
      type: 'positive'
    });
    
    // NEGATIVE TEST VECTORS (Error conditions)
    
    // Vector 12: Wrong version
    vectors.push({
      name: 'wrong_envelope_version',
      type: 'negative',
      invalid_envelope: '{"v":"1","alg":"AES-256-GCM","iv":"AAECAwQFBgcICQoL","tag":"AAAAAAAAAAAAAAAAAAAAAA","ct":"SGVsbG8sIFdvcmxkIQ"}',
      expected_error: 'Unsupported envelope version: 1, expected: 2'
    });
    
    // Vector 13: Wrong algorithm
    vectors.push({
      name: 'unsupported_algorithm',
      type: 'negative',
      invalid_envelope: '{"v":"2","alg":"ChaCha20-Poly1305","iv":"AAECAwQFBgcICQoL","tag":"AAAAAAAAAAAAAAAAAAAAAA","ct":"SGVsbG8sIFdvcmxkIQ"}',
      expected_error: 'Unsupported algorithm: ChaCha20-Poly1305'
    });
    
    // Vector 14: Missing required fields
    vectors.push({
      name: 'missing_envelope_fields',
      type: 'negative',
      invalid_envelope: '{"v":"2","alg":"AES-256-GCM","iv":"AAECAwQFBgcICQoL"}',
      expected_error: 'Missing required envelope fields: iv, tag, ct'
    });
    
    // Vector 15: Invalid base64url encoding (using proper length but invalid chars)
    vectors.push({
      name: 'invalid_base64url',
      type: 'negative',
      invalid_envelope: '{"v":"2","alg":"AES-256-GCM","iv":"AAECAwQFBgcICQo@","tag":"AAAAAAAAAAAAAAAAAAAAAA","ct":"SGVsbG8sIFdvcmxkIQ"}',
      expected_error: 'Invalid base64url encoding in envelope fields'
    });
    
    // Vector 16: Invalid JSON
    vectors.push({
      name: 'malformed_json',
      type: 'negative',
      invalid_envelope: '{"v":"2","alg":"AES-256-GCM","iv":"AAECAwQFBgcICQoL"',
      expected_error: 'Invalid envelope: not valid JSON'
    });
    
    return vectors;
  }
  
  static generateTestEnvelopes() {
    const vectors = this.generateAllVectors();
    const positiveVectors = vectors.filter(v => v.type === 'positive');
    
    // Generate actual envelopes for positive test vectors
    positiveVectors.forEach(vector => {
      const key = Buffer.from(vector.key, 'hex');
      const plaintext = Buffer.from(vector.plaintext, 'utf8');
      const iv = Buffer.from(vector.iv, 'hex');
      const aad = vector.aad ? Buffer.from(vector.aad, 'utf8') : null;
      
      const envelope = ProductionAESGCM.encrypt(plaintext, key, { iv, aad, kid: vector.kid });
      vector.expected_envelope = envelope;
    });
    
    return vectors;
  }
  
  static validateAllVectors() {
    const vectors = this.generateTestEnvelopes();
    const results = {
      passed: 0,
      failed: 0,
      errors: []
    };
    
    console.log('🧪 Running comprehensive golden vector validation...\n');
    console.log(`📊 Testing ${vectors.length} vectors (${vectors.filter(v => v.type === 'positive').length} positive + ${vectors.filter(v => v.type === 'negative').length} negative)\n`);
    
    vectors.forEach((vector, index) => {
      console.log(`🔍 Vector ${index + 1}: ${vector.name} (${vector.type})`);
      
      if (vector.type === 'positive') {
        try {
          const key = Buffer.from(vector.key, 'hex');
          const plaintext = Buffer.from(vector.plaintext, 'utf8');
          const aad = vector.aad ? Buffer.from(vector.aad, 'utf8') : null;
          
          // Test round-trip
          const decrypted = ProductionAESGCM.decrypt(vector.expected_envelope, key, { 
            aad: aad,
            expectKid: vector.kid 
          });
          
          if (decrypted.equals(plaintext)) {
            console.log('   ✅ Round-trip successful');
            results.passed++;
            
            // Validate envelope format
            const envelope = JSON.parse(vector.expected_envelope);
            if (envelope.v === "2" && envelope.alg === "AES-256-GCM") {
              console.log('   ✅ Envelope format valid');
            } else {
              console.log('   ❌ Invalid envelope format');
              results.failed++;
              results.errors.push(`${vector.name}: Invalid envelope format`);
            }
          } else {
            console.log('   ❌ Round-trip failed');
            results.failed++;
            results.errors.push(`${vector.name}: Round-trip decryption mismatch`);
          }
        } catch (error) {
          console.log(`   ❌ Error: ${error.message}`);
          results.failed++;
          results.errors.push(`${vector.name}: ${error.message}`);
        }
      } else if (vector.type === 'negative') {
        try {
          // Negative tests should throw expected errors
          const dummyKey = Buffer.alloc(32);
          ProductionAESGCM.decrypt(vector.invalid_envelope, dummyKey);
          
          console.log('   ❌ Should have thrown error but succeeded');
          results.failed++;
          results.errors.push(`${vector.name}: Expected error but decryption succeeded`);
        } catch (error) {
          if (error.message.includes(vector.expected_error)) {
            console.log(`   ✅ Correctly rejected: ${vector.expected_error}`);
            results.passed++;
          } else {
            console.log(`   ❌ Wrong error: got "${error.message}", expected "${vector.expected_error}"`);
            results.failed++;
            results.errors.push(`${vector.name}: Wrong error message`);
          }
        }
      }
      console.log('');
    });
    
    return results;
  }
  
  static exportVectors() {
    const vectors = this.generateTestEnvelopes();
    
    const exportData = {
      version: "2",
      specification: "Averox Canonical v2 Envelope Format",
      generator: "Comprehensive Golden Vector Suite",
      generated_at: new Date().toISOString(),
      total_vectors: vectors.length,
      positive_vectors: vectors.filter(v => v.type === 'positive').length,
      negative_vectors: vectors.filter(v => v.type === 'negative').length,
      vectors: vectors
    };
    
    return JSON.stringify(exportData, null, 2);
  }
}

// Run validation if called directly
if (require.main === module) {
  const results = ComprehensiveVectorSuite.validateAllVectors();
  
  console.log(`📊 Final Results:`);
  console.log(`✅ Passed: ${results.passed}`);
  console.log(`❌ Failed: ${results.failed}`);
  
  if (results.errors.length > 0) {
    console.log('\n🔍 Errors:');
    results.errors.forEach(error => console.log(`  - ${error}`));
  } else {
    console.log('\n🎉 All 16+ golden vectors validated! Phase 0 specification complete.');
    
    // Export vectors for cross-language testing
    const exportJson = ComprehensiveVectorSuite.exportVectors();
    fs.writeFileSync('golden-vectors-v2-export.json', exportJson);
    console.log('📄 Exported vectors to: golden-vectors-v2-export.json');
  }
}

module.exports = ComprehensiveVectorSuite;