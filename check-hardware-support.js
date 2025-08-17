#!/usr/bin/env node
/**
 * Hardware Support Detection for Confidential Computing
 */

import { execSync } from 'child_process';
import os from 'os';

function checkHardwareSupport() {
  console.log('🔍 CONFIDENTIAL COMPUTING HARDWARE SUPPORT CHECK');
  console.log('===============================================\n');

  const results = {
    sgx: false,
    virtualization: false,
    ram: 0,
    cpu: '',
    platform: os.platform(),
    arch: os.arch()
  };

  // Check CPU info
  results.cpu = os.cpus()[0].model;
  results.ram = Math.round(os.totalmem() / (1024 * 1024 * 1024));

  console.log(`Platform: ${results.platform} (${results.arch})`);
  console.log(`CPU: ${results.cpu}`);
  console.log(`RAM: ${results.ram}GB\n`);

  // Check Intel SGX support
  console.log('INTEL SGX SUPPORT:');
  console.log('------------------');
  
  try {
    if (results.platform === 'linux') {
      // Check /proc/cpuinfo for SGX flags
      const cpuinfo = execSync('cat /proc/cpuinfo 2>/dev/null || echo "unavailable"', { encoding: 'utf8' });
      
      if (cpuinfo.includes('sgx')) {
        results.sgx = true;
        console.log('✅ Intel SGX hardware support detected');
        
        // Check if SGX is enabled
        try {
          const sgxDevice = execSync('ls /dev/sgx* 2>/dev/null || echo "none"', { encoding: 'utf8' });
          if (sgxDevice.includes('/dev/sgx')) {
            console.log('✅ SGX device found at /dev/sgx*');
          } else {
            console.log('⚠️  SGX hardware present but device not found (may need to enable in BIOS)');
          }
        } catch (e) {
          console.log('⚠️  Unable to check SGX device status');
        }
      } else {
        console.log('❌ Intel SGX hardware support not detected');
        console.log('💡 You can still use software simulation mode for development');
      }
    } else {
      console.log('ℹ️  SGX detection only available on Linux');
      console.log('💡 Check your CPU specifications for SGX support');
    }
  } catch (error) {
    console.log('⚠️  Unable to check SGX support:', error.message);
  }

  // Check virtualization support
  console.log('\nVIRTUALIZATION SUPPORT:');
  console.log('-----------------------');
  
  try {
    if (results.platform === 'linux') {
      const vmx = execSync('grep -o "vmx\\|svm" /proc/cpuinfo 2>/dev/null || echo "none"', { encoding: 'utf8' });
      if (vmx.includes('vmx') || vmx.includes('svm')) {
        results.virtualization = true;
        console.log('✅ Hardware virtualization support detected');
        console.log('💡 Compatible with cloud TEE services (Azure, AWS)');
      } else {
        console.log('❌ Hardware virtualization not detected');
      }
    } else {
      console.log('ℹ️  Virtualization check only available on Linux');
    }
  } catch (error) {
    console.log('⚠️  Unable to check virtualization support');
  }

  // Recommendations
  console.log('\nRECOMMENDATIONS:');
  console.log('----------------');

  if (results.sgx) {
    console.log('🎯 RECOMMENDED: Full hardware TEE mode');
    console.log('   • Use Intel SGX for maximum security');
    console.log('   • Hardware attestation available');
    console.log('   • Best performance for confidential computing');
  } else if (results.virtualization) {
    console.log('🎯 RECOMMENDED: Cloud TEE services');
    console.log('   • Azure Confidential Computing VMs');
    console.log('   • AWS Nitro Enclaves');
    console.log('   • Google Cloud Confidential Computing');
  } else {
    console.log('🎯 RECOMMENDED: Software-only mode');
    console.log('   • TEE simulation for development');
    console.log('   • Full homomorphic encryption support');
    console.log('   • MPC protocols work on any hardware');
  }

  if (results.ram < 8) {
    console.log('\n⚠️  WARNING: Low RAM detected');
    console.log('   • Recommend 8GB+ for homomorphic encryption');
    console.log('   • Large computations may be slower');
  }

  // SDK Configuration Recommendations
  console.log('\nSDK CONFIGURATION:');
  console.log('------------------');
  
  console.log('```javascript');
  console.log('const sdk = new ConfidentialCrypto({');
  
  if (results.sgx) {
    console.log('  teeEnabled: true,           // Hardware TEE available');
    console.log('  teeMode: "hardware",        // Use real Intel SGX');
  } else {
    console.log('  teeEnabled: true,           // Software simulation');
    console.log('  teeMode: "simulation",      // For development');
  }
  
  console.log('  homomorphicEnabled: true,   // Works on any hardware');
  console.log('  mpcEnabled: true,           // Network-based protocol');
  
  if (results.ram >= 16) {
    console.log('  heOptimization: "high",     // Large RAM available');
  } else if (results.ram >= 8) {
    console.log('  heOptimization: "medium",   // Standard RAM');
  } else {
    console.log('  heOptimization: "low",      // Limited RAM');
  }
  
  console.log('});');
  console.log('```');

  console.log('\n✅ Hardware check complete!');
  
  return results;
}

// Export for use in other modules
export { checkHardwareSupport };

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  checkHardwareSupport();
}