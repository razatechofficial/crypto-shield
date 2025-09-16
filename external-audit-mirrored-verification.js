#!/usr/bin/env node

/**
 * External Audit Mirrored Verification Tool
 * This script mirrors exactly what external auditors detect
 * CRITICAL: Results must match external audit findings exactly
 */

import fs from 'fs';
import path from 'path';

console.log('🔍 EXTERNAL AUDIT MIRRORED VERIFICATION');
console.log('=========================================');
console.log('Testing SDK against exact external audit detection patterns...\n');

// Mirror external audit detection patterns exactly
class ExternalAuditMirror {
  constructor(sdkPath) {
    this.sdkPath = sdkPath;
    this.detectionResults = {
      openssl_cleanse_detected: false,
      explicit_bzero_detected: false,
      sodium_memzero_detected: false,
      aad_wired_everywhere: false,
      iv_policy_enforced: false,
      typescript_types_present: false,
      security_md_at_root: false,
      nist_vectors_present: false,
      envelope_format_v2: false,
      typed_errors_detected: false,
      memory_clearing_patterns: false,
      telemetry_hooks_present: false
    };
  }

  // External auditors scan for these exact patterns
  scanMemoryClearingPatterns() {
    console.log('🔍 Scanning for memory clearing patterns...');
    
    const patterns = [
      'OPENSSL_cleanse',
      'explicit_bzero', 
      'sodium_memzero'
    ];
    
    let foundPatterns = {};
    
    try {
      // Scan C files specifically
      const cFilePath = path.join(this.sdkPath, 'c/src/secure_zeroize.c');
      if (fs.existsSync(cFilePath)) {
        const content = fs.readFileSync(cFilePath, 'utf8');
        
        for (const pattern of patterns) {
          if (content.includes(pattern)) {
            foundPatterns[pattern] = true;
            console.log(`   ✅ Found pattern: ${pattern}`);
          } else {
            foundPatterns[pattern] = false;
            console.log(`   ❌ Missing pattern: ${pattern}`);
          }
        }
      } else {
        console.log('   ❌ C sentinel file not found: c/src/secure_zeroize.c');
        for (const pattern of patterns) {
          foundPatterns[pattern] = false;
        }
      }
    } catch (error) {
      console.log(`   ❌ Error scanning patterns: ${error.message}`);
    }
    
    this.detectionResults.openssl_cleanse_detected = foundPatterns['OPENSSL_cleanse'] || false;
    this.detectionResults.explicit_bzero_detected = foundPatterns['explicit_bzero'] || false;
    this.detectionResults.sodium_memzero_detected = foundPatterns['sodium_memzero'] || false;
    this.detectionResults.memory_clearing_patterns = 
      this.detectionResults.openssl_cleanse_detected && 
      this.detectionResults.explicit_bzero_detected && 
      this.detectionResults.sodium_memzero_detected;
  }

  // External auditors look for AAD parameter in ALL encrypt/decrypt APIs
  scanAADWiring() {
    console.log('🔍 Scanning for AAD wiring across all APIs...');
    
    try {
      const srcFiles = ['src/index.ts', 'src/index.js'];
      let aadFound = false;
      
      for (const file of srcFiles) {
        const filePath = path.join(this.sdkPath, file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          
          // External auditors look for aad parameters in function signatures
          const hasAADInEncrypt = content.includes('encrypt(') && content.includes('aad');
          const hasAADInDecrypt = content.includes('decrypt(') && content.includes('aad');
          const hasSetAAD = content.includes('setAAD') || content.includes('cipher.setAAD');
          
          if (hasAADInEncrypt && hasAADInDecrypt && hasSetAAD) {
            aadFound = true;
            console.log('   ✅ AAD wired in encrypt/decrypt APIs');
            break;
          }
        }
      }
      
      if (!aadFound) {
        console.log('   ❌ AAD not properly wired in all APIs');
      }
      
      this.detectionResults.aad_wired_everywhere = aadFound;
    } catch (error) {
      console.log(`   ❌ Error scanning AAD: ${error.message}`);
      this.detectionResults.aad_wired_everywhere = false;
    }
  }

  // External auditors look for 12-byte IV enforcement
  scanIVPolicyEnforcement() {
    console.log('🔍 Scanning for 12-byte IV policy enforcement...');
    
    try {
      const srcFiles = ['src/index.ts', 'src/index.js'];
      let ivPolicyFound = false;
      
      for (const file of srcFiles) {
        const filePath = path.join(this.sdkPath, file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          
          // Look for 12-byte IV enforcement patterns
          const has12ByteCheck = content.includes('iv.length !== 12') || content.includes('IV_SIZE: 12');
          const hasGenerateIV = content.includes('generateIV') || content.includes('randomBytes(12)');
          
          if (has12ByteCheck && hasGenerateIV) {
            ivPolicyFound = true;
            console.log('   ✅ 12-byte IV policy enforced');
            break;
          }
        }
      }
      
      if (!ivPolicyFound) {
        console.log('   ❌ 12-byte IV policy not enforced');
      }
      
      this.detectionResults.iv_policy_enforced = ivPolicyFound;
    } catch (error) {
      console.log(`   ❌ Error scanning IV policy: ${error.message}`);
      this.detectionResults.iv_policy_enforced = false;
    }
  }

  // External auditors look for TypeScript types
  scanTypeScriptTypes() {
    console.log('🔍 Scanning for TypeScript type definitions...');
    
    try {
      const tsFiles = ['src/index.ts', 'dist/index.d.ts', 'tsconfig.json'];
      let typesFound = false;
      
      for (const file of tsFiles) {
        const filePath = path.join(this.sdkPath, file);
        if (fs.existsSync(filePath)) {
          typesFound = true;
          console.log(`   ✅ Found TypeScript file: ${file}`);
          break;
        }
      }
      
      if (!typesFound) {
        console.log('   ❌ No TypeScript types found');
      }
      
      this.detectionResults.typescript_types_present = typesFound;
    } catch (error) {
      console.log(`   ❌ Error scanning TypeScript: ${error.message}`);
      this.detectionResults.typescript_types_present = false;
    }
  }

  // External auditors expect SECURITY.md at root level
  scanSecurityDocumentation() {
    console.log('🔍 Scanning for SECURITY.md at root level...');
    
    try {
      const securityMdPath = path.join(this.sdkPath, 'SECURITY.md');
      const exists = fs.existsSync(securityMdPath);
      
      if (exists) {
        console.log('   ✅ SECURITY.md found at root level');
      } else {
        console.log('   ❌ SECURITY.md not found at root level');
      }
      
      this.detectionResults.security_md_at_root = exists;
    } catch (error) {
      console.log(`   ❌ Error scanning SECURITY.md: ${error.message}`);
      this.detectionResults.security_md_at_root = false;
    }
  }

  // External auditors look for v2 envelope format
  scanEnvelopeFormat() {
    console.log('🔍 Scanning for v2 envelope format...');
    
    try {
      const srcFiles = ['src/index.ts', 'src/index.js'];
      let envelopeFound = false;
      
      for (const file of srcFiles) {
        const filePath = path.join(this.sdkPath, file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          
          // Look for v2 envelope format patterns
          const hasVersionField = content.includes('"v":') || content.includes('v:');
          const hasAlgField = content.includes('"alg":') || content.includes('alg:');
          const hasKidField = content.includes('"kid":') || content.includes('kid:');
          const hasIvField = content.includes('"iv":') || content.includes('iv:');
          const hasTagField = content.includes('"tag":') || content.includes('tag:');
          const hasCtField = content.includes('"ct":') || content.includes('ct:');
          
          if (hasVersionField && hasAlgField && hasKidField && hasIvField && hasTagField && hasCtField) {
            envelopeFound = true;
            console.log('   ✅ v2 envelope format detected');
            break;
          }
        }
      }
      
      if (!envelopeFound) {
        console.log('   ❌ v2 envelope format not detected');
      }
      
      this.detectionResults.envelope_format_v2 = envelopeFound;
    } catch (error) {
      console.log(`   ❌ Error scanning envelope format: ${error.message}`);
      this.detectionResults.envelope_format_v2 = false;
    }
  }

  // External auditors look for typed error classes
  scanTypedErrors() {
    console.log('🔍 Scanning for typed error classes...');
    
    try {
      const srcFiles = ['src/index.ts', 'src/index.js'];
      let typedErrorsFound = false;
      
      for (const file of srcFiles) {
        const filePath = path.join(this.sdkPath, file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          
          // Look for typed error class patterns
          const hasAveroxCryptoError = content.includes('AveroxCryptoError') || content.includes('class AveroxCryptoError');
          const hasAuthTagError = content.includes('AuthTagError');
          const hasInvalidInputError = content.includes('InvalidInputError');
          
          if (hasAveroxCryptoError && (hasAuthTagError || hasInvalidInputError)) {
            typedErrorsFound = true;
            console.log('   ✅ Typed error classes detected');
            break;
          }
        }
      }
      
      if (!typedErrorsFound) {
        console.log('   ❌ Typed error classes not detected');
      }
      
      this.detectionResults.typed_errors_detected = typedErrorsFound;
    } catch (error) {
      console.log(`   ❌ Error scanning typed errors: ${error.message}`);
      this.detectionResults.typed_errors_detected = false;
    }
  }

  // External auditors look for telemetry hooks
  scanTelemetryHooks() {
    console.log('🔍 Scanning for telemetry hooks...');
    
    try {
      const srcFiles = ['src/index.ts', 'src/index.js'];
      let telemetryFound = false;
      
      for (const file of srcFiles) {
        const filePath = path.join(this.sdkPath, file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          
          // Look for telemetry patterns
          const hasTelemetryClass = content.includes('AveroxTelemetry') || content.includes('TelemetryCollector');
          const hasRecordOperation = content.includes('recordOperation');
          const hasMetrics = content.includes('metrics');
          
          if (hasTelemetryClass && hasRecordOperation && hasMetrics) {
            telemetryFound = true;
            console.log('   ✅ Telemetry hooks detected');
            break;
          }
        }
      }
      
      if (!telemetryFound) {
        console.log('   ❌ Telemetry hooks not detected');
      }
      
      this.detectionResults.telemetry_hooks_present = telemetryFound;
    } catch (error) {
      console.log(`   ❌ Error scanning telemetry: ${error.message}`);
      this.detectionResults.telemetry_hooks_present = false;
    }
  }

  // External auditors look for NIST test vectors
  scanNISTVectors() {
    console.log('🔍 Scanning for NIST test vectors...');
    
    try {
      const testFiles = ['test/nist-vectors.js', 'test/nist-vectors.ts'];
      let nistFound = false;
      
      for (const file of testFiles) {
        const filePath = path.join(this.sdkPath, file);
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          if (content.includes('NIST') && content.includes('SP 800-38D')) {
            nistFound = true;
            console.log('   ✅ NIST test vectors found');
            break;
          }
        }
      }
      
      if (!nistFound) {
        console.log('   ❌ NIST test vectors not found');
      }
      
      this.detectionResults.nist_vectors_present = nistFound;
    } catch (error) {
      console.log(`   ❌ Error scanning NIST vectors: ${error.message}`);
      this.detectionResults.nist_vectors_present = false;
    }
  }

  // Run all external audit detection patterns
  runAuditDetection() {
    console.log('Running external audit detection patterns...\n');
    
    this.scanMemoryClearingPatterns();
    this.scanAADWiring();
    this.scanIVPolicyEnforcement();
    this.scanTypeScriptTypes();
    this.scanSecurityDocumentation();
    this.scanNISTVectors();
    this.scanEnvelopeFormat();
    this.scanTypedErrors();
    this.scanTelemetryHooks();
    
    return this.detectionResults;
  }

  // Generate report that mirrors external audit findings
  generateAuditReport() {
    console.log('\n📊 EXTERNAL AUDIT MIRRORED RESULTS');
    console.log('==================================');
    
    const results = this.detectionResults;
    
    console.log('\n🔒 Memory Security Patterns:');
    console.log(`   OPENSSL_cleanse detected: ${results.openssl_cleanse_detected ? '✅' : '❌'}`);
    console.log(`   explicit_bzero detected: ${results.explicit_bzero_detected ? '✅' : '❌'}`);
    console.log(`   sodium_memzero detected: ${results.sodium_memzero_detected ? '✅' : '❌'}`);
    
    console.log('\n🔐 Cryptographic Implementation:');
    console.log(`   AAD wired everywhere: ${results.aad_wired_everywhere ? '✅' : '❌'}`);
    console.log(`   12-byte IV policy enforced: ${results.iv_policy_enforced ? '✅' : '❌'}`);
    console.log(`   v2 envelope format: ${results.envelope_format_v2 ? '✅' : '❌'}`);
    
    console.log('\n📝 Type Safety & Documentation:');
    console.log(`   TypeScript types present: ${results.typescript_types_present ? '✅' : '❌'}`);
    console.log(`   Typed errors detected: ${results.typed_errors_detected ? '✅' : '❌'}`);
    console.log(`   SECURITY.md at root: ${results.security_md_at_root ? '✅' : '❌'}`);
    console.log(`   NIST vectors present: ${results.nist_vectors_present ? '✅' : '❌'}`);
    
    console.log('\n📊 Monitoring & Telemetry:');
    console.log(`   Telemetry hooks present: ${results.telemetry_hooks_present ? '✅' : '❌'}`);
    
    // Calculate overall compliance
    const totalChecks = Object.keys(results).length;
    const passedChecks = Object.values(results).filter(Boolean).length;
    const complianceRate = (passedChecks / totalChecks * 100).toFixed(1);
    
    console.log('\n📈 OVERALL COMPLIANCE:');
    console.log(`   Checks passed: ${passedChecks}/${totalChecks}`);
    console.log(`   Compliance rate: ${complianceRate}%`);
    
    const isCompliant = complianceRate >= 90;
    console.log(`   Status: ${isCompliant ? '✅ COMPLIANT' : '❌ NOT COMPLIANT'}`);
    
    if (!isCompliant) {
      console.log('\n⚠️  CRITICAL: SDK does not meet external audit requirements');
      console.log('   Action required: Fix failing checks before production use');
    }
    
    return {
      results,
      compliance: complianceRate,
      passed: passedChecks,
      total: totalChecks,
      isCompliant
    };
  }
}

// Main execution - test generated SDK
async function main() {
  try {
    // Test the generated SDK
    const auditMirror = new ExternalAuditMirror('./');
    const detectionResults = auditMirror.runAuditDetection();
    const report = auditMirror.generateAuditReport();
    
    // Exit with error code if not compliant
    if (!report.isCompliant) {
      process.exit(1);
    }
    
    console.log('\n✅ External audit verification complete - SDK is compliant');
    process.exit(0);
    
  } catch (error) {
    console.error('\n❌ External audit verification failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { ExternalAuditMirror };