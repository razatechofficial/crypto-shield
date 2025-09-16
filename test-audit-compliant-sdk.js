#!/usr/bin/env node

/**
 * Test the updated enterprise SDK generator for external audit compliance
 */

import fs from 'fs';
import path from 'path';
import enterpriseSDKPkg from './enterprise-sdk-generator.cjs';
import { ExternalAuditMirror } from './external-audit-mirrored-verification.js';

const { EnterpriseSDKGenerator } = enterpriseSDKPkg;

console.log('🧪 TESTING AUDIT-COMPLIANT SDK GENERATION');
console.log('=========================================');
console.log('');

async function testSDKGeneration() {
  try {
    console.log('📦 Generating TypeScript-only SDK for external audit...');
    
    // Test SDK configuration
    const testSDK = { 
      name: 'AuditCompliantSDK', 
      version: '2.0.0' 
    };
    const testAlgorithms = [
      { name: 'AES-256-GCM', displayName: 'AES-256-GCM', type: 'symmetric' }
    ];
    
    // Generate SDK using new TypeScript-only generator
    const sdkFiles = EnterpriseSDKGenerator.generateTypeScriptOnlySDK(testSDK, testAlgorithms);
    
    console.log('✅ SDK generation successful');
    console.log(`📁 Generated ${Object.keys(sdkFiles).length} files:`);
    
    // Write files to test directory
    const testDir = './test-generated-sdk';
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true });
    }
    fs.mkdirSync(testDir, { recursive: true });
    
    for (const [filePath, content] of Object.entries(sdkFiles)) {
      const fullPath = path.join(testDir, filePath);
      const dirName = path.dirname(fullPath);
      
      // Create subdirectories as needed
      fs.mkdirSync(dirName, { recursive: true });
      
      // Write file
      fs.writeFileSync(fullPath, content);
      console.log(`   ✅ ${filePath}`);
    }
    
    console.log('');
    console.log('🔍 Running external audit mirrored verification...');
    
    // Run the mirrored external audit
    const auditMirror = new ExternalAuditMirror(testDir);
    const detectionResults = auditMirror.runAuditDetection();
    const auditReport = auditMirror.generateAuditReport();
    
    console.log('');
    console.log('📊 FINAL TEST RESULTS');
    console.log('====================');
    
    if (auditReport.isCompliant) {
      console.log('✅ SUCCESS: SDK passes external audit verification!');
      console.log(`   Compliance rate: ${auditReport.compliance}%`);
      console.log(`   Passed checks: ${auditReport.passed}/${auditReport.total}`);
    } else {
      console.log('❌ FAILURE: SDK does not meet external audit requirements');
      console.log(`   Compliance rate: ${auditReport.compliance}%`);
      console.log(`   Passed checks: ${auditReport.passed}/${auditReport.total}`);
      
      console.log('');
      console.log('🔧 REQUIRED FIXES:');
      for (const [check, result] of Object.entries(detectionResults)) {
        if (!result) {
          console.log(`   ❌ ${check}`);
        }
      }
    }
    
    return auditReport.isCompliant;
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack:', error.stack);
    return false;
  }
}

// Run test
testSDKGeneration().then(success => {
  process.exit(success ? 0 : 1);
});