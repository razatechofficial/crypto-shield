import fs from 'fs';

// Check if the ZIP file exists and get its size
try {
  const stats = fs.statSync('test-sdk.zip');
  console.log(`ZIP file size: ${stats.size} bytes`);
  
  // Read the first 100 bytes to check ZIP signature
  const buffer = fs.readFileSync('test-sdk.zip');
  console.log(`First 4 bytes (ZIP signature): ${buffer.slice(0, 4).toString('hex')}`);
  
  // ZIP files start with 'PK' (0x504B)
  if (buffer[0] === 0x50 && buffer[1] === 0x4B) {
    console.log('✓ Valid ZIP file detected');
  } else {
    console.log('✗ Invalid ZIP file signature');
  }
} catch (error) {
  console.error('Error checking ZIP file:', error.message);
}