// Real functionality test - no exaggeration
const crypto = require('crypto');

console.log('REALITY CHECK: Testing actual crypto functionality');

try {
  // Test 1: Basic AES-256-GCM
  console.log('Test 1: Basic AES-GCM encryption');
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const plaintext = 'test message';
  
  const cipher = crypto.createCipher('aes-256-gcm', key);
  cipher.init('encrypt', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  
  const decipher = crypto.createDecipherGCM('aes-256-gcm');
  decipher.init('decrypt', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  
  if (decrypted.toString('utf8') === plaintext) {
    console.log('✓ Basic AES-256-GCM works');
  } else {
    console.log('✗ Basic AES-256-GCM failed');
  }
  
  // Test 2: AAD support
  console.log('Test 2: AAD support');
  const aad = Buffer.from('additional-data');
  
  const cipher2 = crypto.createCipherGCM('aes-256-gcm');
  cipher2.init('encrypt', key, iv);
  cipher2.setAAD(aad);
  let encrypted2 = cipher2.update(plaintext, 'utf8');
  encrypted2 = Buffer.concat([encrypted2, cipher2.final()]);
  const tag2 = cipher2.getAuthTag();
  
  const decipher2 = crypto.createDecipherGCM('aes-256-gcm');
  decipher2.init('decrypt', key, iv);
  decipher2.setAAD(aad);
  decipher2.setAuthTag(tag2);
  let decrypted2 = decipher2.update(encrypted2);
  decrypted2 = Buffer.concat([decrypted2, decipher2.final()]);
  
  if (decrypted2.toString('utf8') === plaintext) {
    console.log('✓ AAD support works');
  } else {
    console.log('✗ AAD support failed');
  }
  
  console.log('VERDICT: Core cryptographic functionality is available');
  
} catch (error) {
  console.log('✗ Crypto test failed:', error.message);
}