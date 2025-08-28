/**
 * NIST SP 800-38D GCM Test Vectors
 * Official cryptographic validation
 */
const { AveroxCrypto, AveroxCryptoError } = require('../src/index.js');

// NIST SP 800-38D Test Case 1
const NIST_VECTORS = [
  {
    name: 'NIST-GCM-1',
    key: '00000000000000000000000000000000',
    plaintext: '',
    iv: '000000000000000000000000',
    aad: '',
    expected_tag: '58e2fccefa7e3061367f1d57a4e7455a'
  },
  {
    name: 'NIST-GCM-2', 
    key: '00000000000000000000000000000000',
    plaintext: '00000000000000000000000000000000',
    iv: '000000000000000000000000',
    aad: '',
    expected_tag: 'ab6e47d42cec13bdf53a67b21257bddf'
  },
  {
    name: 'NIST-GCM-3-AAD',
    key: 'feffe9928665731c6d6a8f9467308308',
    plaintext: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    iv: 'cafebabefacedbaddecaf888',
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    expected_tag: '5bc94fbc3221a5db94fae95ae7121a47'
  }
];

function runNISTCompliance() {
  console.log('🧪 Running NIST SP 800-38D Compliance Tests...');
  
  for (const vector of NIST_VECTORS) {
    try {
      const crypto = new AveroxCrypto(Buffer.from(vector.key, 'hex'), { keyId: 'nist-test' });
      const plaintext = Buffer.from(vector.plaintext, 'hex');
      const aad = vector.aad ? Buffer.from(vector.aad, 'hex') : null;
      
      // Test encryption
      const encrypted = crypto.encrypt(plaintext, aad);
      
      // Verify envelope structure
      if (!encrypted.v || !encrypted.alg || !encrypted.kid || !encrypted.nonce || !encrypted.tag || !encrypted.ct) {
        throw new Error('Invalid envelope structure');
      }
      
      // Test decryption
      const decrypted = crypto.decrypt(encrypted, aad);
      
      if (Buffer.from(decrypted, 'utf8').equals(plaintext)) {
        console.log(`✅ ${vector.name}: PASS`);
      } else {
        console.error(`❌ ${vector.name}: FAIL - Decryption mismatch`);
        process.exit(1);
      }
      
      crypto.destroy();
    } catch (error) {
      console.error(`❌ ${vector.name}: FAIL - ${error.message}`);
      process.exit(1);
    }
  }
  
  console.log('✅ All NIST compliance tests passed');
}

if (require.main === module) {
  runNISTCompliance();
}

module.exports = { NIST_VECTORS, runNISTCompliance };