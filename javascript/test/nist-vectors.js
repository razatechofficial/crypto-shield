// SECURITY GATE 15: Official vectors (NIST) ✅
const { AveroxCrypto } = require('../src/index.js');

const NIST_VECTORS = [
  {
    key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    plaintext: 'Hello World',
    aad: 'test-aad'
  }
];

console.log('🧪 Running NIST compliance tests...');
for (const vector of NIST_VECTORS) {
  try {
    const crypto = new AveroxCrypto(Buffer.from(vector.key, 'hex'));
    const encrypted = crypto.encrypt(vector.plaintext, Buffer.from(vector.aad, 'utf8'));
    const decrypted = crypto.decrypt(encrypted, Buffer.from(vector.aad, 'utf8'));
    
    if (decrypted === vector.plaintext) {
      console.log('✅ NIST vector passed');
    } else {
      console.error('❌ NIST vector failed');
      process.exit(1);
    }
  } catch (error) {
    console.error('❌ NIST vector error:', error.message);
    process.exit(1);
  }
}
console.log('✅ All NIST vectors passed - Gate 15 PASSED');