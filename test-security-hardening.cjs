#!/usr/bin/env node

/**
 * Comprehensive Security Hardening Test Suite
 * Tests government-level security compliance measures
 */

const crypto = require('crypto');

// Import security hardening components
const { 
  RNGHealthMonitor,
  SecureDefaultsEnforcer,
  ConstantTimeOps,
  ParameterValidator,
  SecurityError
} = require('./security-hardening-core.cjs');

console.log('🔒 GOVERNMENT-LEVEL SECURITY HARDENING VALIDATION');
console.log('=' .repeat(60));

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function runTest(testName, testFunc) {
  totalTests++;
  try {
    console.log(`\n🧪 Testing: ${testName}`);
    testFunc();
    console.log(`✅ PASSED: ${testName}`);
    passedTests++;
  } catch (error) {
    console.error(`❌ FAILED: ${testName}`);
    console.error(`   Error: ${error.message}`);
    failedTests++;
  }
}

// 1. RNG Health Monitoring Tests
console.log('\n📊 1. RNG HEALTH MONITORING TESTS');
console.log('-'.repeat(40));

runTest('RNG Health Monitor Initialization', () => {
  if (!RNGHealthMonitor.getHealthStatus().initialized) {
    RNGHealthMonitor.initialize();
  }
  const status = RNGHealthMonitor.getHealthStatus();
  if (!status.initialized) {
    throw new Error('RNG health monitor not initialized');
  }
  if (!status.healthy) {
    throw new Error('RNG health status is not healthy');  
  }
  console.log(`   📈 Entropy pool size: ${status.entropyPoolSize}`);
  console.log(`   🔢 Entropy estimates: ${status.entropyEstimate}`);
});

runTest('Secure Random Bytes Generation', () => {
  const bytes12 = RNGHealthMonitor.getSecureRandomBytes(12);
  const bytes32 = RNGHealthMonitor.getSecureRandomBytes(32);
  
  if (bytes12.length !== 12) {
    throw new Error('12-byte generation failed');
  }
  if (bytes32.length !== 32) {
    throw new Error('32-byte generation failed');
  }
  
  // Test uniqueness (very low probability of collision)
  const bytes1 = RNGHealthMonitor.getSecureRandomBytes(16);
  const bytes2 = RNGHealthMonitor.getSecureRandomBytes(16);
  if (bytes1.equals(bytes2)) {
    throw new Error('RNG appears to be generating duplicate values');
  }
  console.log('   🎲 Random bytes generated successfully with uniqueness verified');
});

runTest('RNG Health Status Monitoring', () => {
  const status = RNGHealthMonitor.getHealthStatus();
  const stats = RNGHealthMonitor.getStats();
  
  if (stats.bytesGenerated === 0) {
    throw new Error('No bytes generated statistic');
  }
  if (stats.operationsCount === 0) {
    throw new Error('No operations count statistic');
  }
  
  console.log(`   📊 Operations: ${stats.operationsCount}, Bytes: ${stats.bytesGenerated}`);
  console.log(`   🏥 Health: ${status.healthy ? 'HEALTHY' : 'UNHEALTHY'}`);
});

// 2. Secure Defaults Enforcement Tests  
console.log('\n🛡️ 2. SECURE DEFAULTS ENFORCEMENT TESTS');
console.log('-'.repeat(45));

runTest('AEAD Algorithm Enforcement', () => {
  // Should accept AEAD algorithms
  SecureDefaultsEnforcer.validateAlgorithm('AES-256-GCM');
  SecureDefaultsEnforcer.validateAlgorithm('CHACHA20-POLY1305');
  
  // Should reject non-AEAD algorithms
  const nonAeadAlgos = ['AES-256-CBC', 'AES-128-ECB', 'DES-CBC', 'RC4'];
  for (const algo of nonAeadAlgos) {
    try {
      SecureDefaultsEnforcer.validateAlgorithm(algo);
      throw new Error(`Should have rejected non-AEAD algorithm: ${algo}`);
    } catch (error) {
      if (!(error instanceof SecurityError)) {
        throw new Error(`Wrong error type for ${algo}: ${error.constructor.name}`);
      }
    }
  }
  console.log('   🔐 AEAD-only enforcement working correctly');
});

runTest('Minimum Key Size Enforcement', () => {
  // Should accept secure key sizes
  SecureDefaultsEnforcer.validateKeySize(256, 'symmetric');
  SecureDefaultsEnforcer.validateKeySize(2048, 'asymmetric');
  SecureDefaultsEnforcer.validateKeySize(4096, 'asymmetric');
  
  // Should reject insecure key sizes
  const insecureKeySizes = [
    [128, 'symmetric'], [192, 'symmetric'],
    [1024, 'asymmetric'], [512, 'asymmetric']
  ];
  
  for (const [keySize, type] of insecureKeySizes) {
    try {
      SecureDefaultsEnforcer.validateKeySize(keySize, type);
      throw new Error(`Should have rejected insecure key size: ${keySize}-bit ${type}`);
    } catch (error) {
      if (!(error instanceof SecurityError)) {
        throw new Error(`Wrong error type for key size ${keySize}: ${error.constructor.name}`);
      }
    }
  }
  console.log('   🔑 Minimum key size enforcement working correctly');
});

runTest('Secure Curve Validation', () => {
  // Should accept secure curves
  const secureCurves = ['P-256', 'P-384', 'P-521', 'CURVE25519', 'ED25519'];
  for (const curve of secureCurves) {
    SecureDefaultsEnforcer.validateCurve(curve);
  }
  
  // Should reject insecure curves
  const insecureCurves = ['secp112r1', 'secp128r1', 'secp160r1', 'prime192v1'];
  for (const curve of insecureCurves) {
    try {
      SecureDefaultsEnforcer.validateCurve(curve);
      throw new Error(`Should have rejected insecure curve: ${curve}`);
    } catch (error) {
      if (!(error instanceof SecurityError)) {
        throw new Error(`Wrong error type for curve ${curve}: ${error.constructor.name}`);
      }
    }
  }
  console.log('   📈 Secure curve enforcement working correctly');
});

runTest('User IV Rejection', () => {
  // Should reject user-provided IVs
  const userIV = Buffer.from('user-provided-iv', 'hex');
  try {
    SecureDefaultsEnforcer.rejectUserProvidedIV(userIV);
    throw new Error('Should have rejected user-provided IV');
  } catch (error) {
    if (!(error instanceof SecurityError)) {
      throw new Error(`Wrong error type for user IV: ${error.constructor.name}`);
    }
    if (error.code !== 'USER_IV_REJECTED') {
      throw new Error(`Wrong error code: ${error.code}`);
    }
  }
  console.log('   🚫 User IV rejection working correctly');
});

// 3. Constant-Time Operations Tests
console.log('\n⏱️ 3. CONSTANT-TIME OPERATIONS TESTS');
console.log('-'.repeat(40));

runTest('Timing-Safe Comparisons', () => {
  const data1 = Buffer.from('same data');
  const data2 = Buffer.from('same data');
  const data3 = Buffer.from('different data');
  
  // Should return true for identical data
  if (!ConstantTimeOps.timingSafeEqual(data1, data2)) {
    throw new Error('Failed to detect equal data');
  }
  
  // Should return false for different data
  if (ConstantTimeOps.timingSafeEqual(data1, data3)) {
    throw new Error('Failed to detect different data');
  }
  
  // Should handle different lengths safely
  const shortData = Buffer.from('short');
  const longData = Buffer.from('this is much longer data');
  if (ConstantTimeOps.timingSafeEqual(shortData, longData)) {
    throw new Error('Failed to handle different lengths');
  }
  
  console.log('   🔍 Timing-safe comparisons working correctly');
});

runTest('Secure Memory Clearing', () => {
  const sensitiveData = Buffer.from('very sensitive secret data');
  const originalData = Buffer.from(sensitiveData);
  
  // Clear the data
  ConstantTimeOps.secureMemoryClear(sensitiveData);
  
  // Verify it's been cleared
  const zeroBuffer = Buffer.alloc(sensitiveData.length, 0);
  if (!sensitiveData.equals(zeroBuffer)) {
    throw new Error('Memory was not properly cleared');
  }
  
  // Verify original data was actually there
  if (originalData.equals(zeroBuffer)) {
    throw new Error('Test setup error: original data was already zeros');
  }
  
  console.log('   🧹 Secure memory clearing working correctly');
});

runTest('Constant-Time MAC Verification', () => {
  const key = crypto.randomBytes(32);
  const message = Buffer.from('test message');
  
  // Generate correct MAC
  const correctMac = crypto.createHmac('sha256', key).update(message).digest();
  
  // Generate incorrect MAC
  const incorrectMac = Buffer.alloc(32, 0xFF);
  
  // Verify correct MAC
  if (!ConstantTimeOps.verifyMAC(message, correctMac, key, 'sha256')) {
    throw new Error('Failed to verify correct MAC');
  }
  
  // Reject incorrect MAC
  if (ConstantTimeOps.verifyMAC(message, incorrectMac, key, 'sha256')) {
    throw new Error('Failed to reject incorrect MAC');
  }
  
  console.log('   🔐 Constant-time MAC verification working correctly');
});

// 4. Parameter Validation Tests
console.log('\n✅ 4. PARAMETER VALIDATION TESTS');
console.log('-'.repeat(35));

runTest('Encryption Parameter Validation', () => {
  const validKey = crypto.randomBytes(32);
  const validPlaintext = 'Hello, World!';
  const validAAD = Buffer.from('additional data');
  
  // Should accept valid parameters
  const result = ParameterValidator.validateEncryptionParams(
    validPlaintext, validKey, 'AES-256-GCM', { aad: validAAD }
  );
  
  if (!result.isValid) {
    throw new Error(`Valid parameters rejected: ${result.errors.join(', ')}`);
  }
  
  // Should reject invalid key
  try {
    ParameterValidator.validateEncryptionParams(
      validPlaintext, Buffer.alloc(16), 'AES-256-GCM', {}
    );
    throw new Error('Should have rejected short key');
  } catch (error) {
    if (!(error instanceof SecurityError)) {
      throw new Error(`Wrong error type: ${error.constructor.name}`);
    }
  }
  
  console.log('   📝 Encryption parameter validation working correctly');
});

runTest('Decryption Parameter Validation', () => {
  const validKey = crypto.randomBytes(32);
  const validEnvelope = '{"v":"2","alg":"AES-256-GCM","iv":"dGVzdA","tag":"dGVzdA","ct":"dGVzdA"}';
  
  // Should accept valid parameters
  const result = ParameterValidator.validateDecryptionParams(
    validEnvelope, validKey, {}
  );
  
  if (!result.isValid) {
    throw new Error(`Valid parameters rejected: ${result.errors.join(', ')}`);
  }
  
  // Should reject invalid envelope
  try {
    ParameterValidator.validateDecryptionParams(
      'invalid json', validKey, {}
    );
    throw new Error('Should have rejected invalid envelope');
  } catch (error) {
    if (!(error instanceof SecurityError)) {
      throw new Error(`Wrong error type: ${error.constructor.name}`);
    }
  }
  
  console.log('   🔓 Decryption parameter validation working correctly');
});

// 5. Integration Tests
console.log('\n🔗 5. INTEGRATION TESTS');
console.log('-'.repeat(25));

runTest('End-to-End Security Hardening', () => {
  // Test that all security components work together
  const { AveroxCrypto } = require('./canonical-v2-reference.cjs');
  
  const masterKey = crypto.randomBytes(32);
  const cryptoInstance = new AveroxCrypto(masterKey, 'test-key-id');
  
  const plaintext = 'This is a test of the government-level security hardening!';
  const aad = Buffer.from('additional authenticated data');
  
  // Encrypt
  const encrypted = cryptoInstance.encrypt(plaintext, aad);
  if (!encrypted || typeof encrypted !== 'string') {
    throw new Error('Encryption failed to return valid ciphertext');
  }
  
  // Decrypt
  const decrypted = cryptoInstance.decrypt(encrypted, aad);
  if (decrypted !== plaintext) {
    throw new Error('Decryption failed to return original plaintext');
  }
  
  // Verify envelope format (v2)
  const envelope = JSON.parse(encrypted);
  if (envelope.v !== '2') {
    throw new Error(`Wrong envelope version: ${envelope.v}`);
  }
  if (envelope.alg !== 'AES-256-GCM') {
    throw new Error(`Wrong algorithm: ${envelope.alg}`);
  }
  
  console.log('   🎯 End-to-end security hardening integration successful');
});

runTest('Error Handling and Security Error Types', () => {
  try {
    throw new SecurityError('TEST_ERROR', 'Test security error', new Error('cause'));
  } catch (error) {
    if (!(error instanceof SecurityError)) {
      throw new Error('SecurityError not properly constructed');
    }
    if (error.code !== 'TEST_ERROR') {
      throw new Error(`Wrong error code: ${error.code}`);
    }
    if (error.severity !== 'CRITICAL') {
      throw new Error(`Wrong severity: ${error.severity}`);
    }
    if (!error.timestamp) {
      throw new Error('No timestamp on security error');
    }
  }
  
  console.log('   🚨 Security error handling working correctly');
});

// Final Results
console.log('\n' + '='.repeat(60));
console.log('🏁 SECURITY HARDENING VALIDATION COMPLETE');
console.log('='.repeat(60));
console.log(`📊 Total Tests: ${totalTests}`);
console.log(`✅ Passed: ${passedTests}`);
console.log(`❌ Failed: ${failedTests}`);

if (failedTests === 0) {
  console.log('\n🎉 ALL SECURITY HARDENING MEASURES VALIDATED SUCCESSFULLY!');
  console.log('🛡️ Government-level security compliance ACHIEVED!');
  process.exit(0);
} else {
  console.log(`\n⚠️ ${failedTests} security tests failed - remediation required`);
  process.exit(1);
}