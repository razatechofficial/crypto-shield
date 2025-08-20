// Test correct Node.js crypto API for AES-256-GCM
const crypto = require('crypto');

console.log('Testing correct AES-256-GCM implementation...');

try {
  const algorithm = 'aes-256-gcm';
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const plaintext = 'Hello World';
  const aad = Buffer.from('additional-data');
  
  // Encryption
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  cipher.setAAD(aad);
  
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  console.log('✓ Encryption successful');
  
  // Decryption
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAuthTag(authTag);
  decipher.setAAD(aad);
  
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  
  const result = decrypted.toString('utf8');
  console.log('✓ Decryption successful:', result === plaintext);
  console.log('✓ AES-256-GCM with AAD works correctly');
  
} catch (error) {
  console.log('✗ Crypto test failed:', error.message);
}