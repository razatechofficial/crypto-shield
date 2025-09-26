#!/usr/bin/env node

/**
 * Native Installation Verification Script
 * Verifies CMake installation and pkg-config functionality for C/C++ consumers
 * 
 * REQUIREMENTS: Implements exact verification requested by user:
 * - cmake --install build --prefix /tmp/pfx
 * - test -f /tmp/pfx/lib/pkgconfig/sdkcrypto.pc
 * - pkg-config --exists sdkcrypto
 */

import fs from 'fs';
import { execSync } from 'child_process';
import path from 'path';

class NativeInstallVerifier {
  constructor() {
    this.testPrefix = '/tmp/pfx';
    this.sdkName = 'sdkcrypto';
    this.buildDir = 'build';
    this.verified = [];
    this.failed = [];
  }

  /**
   * Complete native installation verification
   */
  async verifyInstallation() {
    console.log('🔧 Native Installation Verification');
    console.log('===================================\n');

    try {
      // Step 1: Generate C/C++ SDK for testing
      await this.generateTestSDK();
      
      // Step 2: Build with CMake
      await this.buildWithCMake();
      
      // Step 3: Install to test prefix (user's exact requirement)
      await this.installToPrefix();
      
      // Step 4: Verify pkg-config file exists (user's exact requirement)
      await this.verifyPkgConfigFile();
      
      // Step 5: Test pkg-config functionality (user's exact requirement)
      await this.testPkgConfigExists();
      
      // Step 6: Additional verification tests
      await this.verifyHeaders();
      await this.verifyLibraries();
      await this.testCompilation();
      
      // Report results
      this.reportResults();
      
    } catch (error) {
      console.error('❌ Native verification failed:', error.message);
      throw error;
    }
  }

  async generateTestSDK() {
    console.log('📦 Generating C/C++ SDK for testing...');
    
    // Clean previous test
    if (fs.existsSync('test-native-sdk')) {
      fs.rmSync('test-native-sdk', { recursive: true, force: true });
    }
    
    // Generate SDK using our enterprise generator
    const generateScript = `
    const { FixedEnterpriseSDKGenerator } = require('./enterprise-sdk-generator-fixed.cjs');
    const sdk = { 
      name: 'TestNativeSDK', 
      version: '2.0.0',
      keyId: 'test-key-native' 
    };
    const result = FixedEnterpriseSDKGenerator.generateCSDK(sdk, ['AES-256-GCM']);
    const fs = require('fs');
    Object.entries(result).forEach(([file, content]) => {
      const dir = require('path').dirname('test-native-sdk/' + file);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync('test-native-sdk/' + file, content);
    });
    `;
    
    execSync(`node -e "${generateScript}"`);
    
    this.verified.push('C/C++ SDK generated successfully');
    console.log('✅ C/C++ SDK generated successfully');
  }

  async buildWithCMake() {
    console.log('🔨 Building with CMake...');
    
    process.chdir('test-native-sdk');
    
    try {
      // Create build directory
      if (fs.existsSync(this.buildDir)) {
        fs.rmSync(this.buildDir, { recursive: true, force: true });
      }
      fs.mkdirSync(this.buildDir);
      
      // Configure with CMake
      execSync(`cmake -B ${this.buildDir} -S . -DCMAKE_BUILD_TYPE=Release`, {
        stdio: 'inherit'
      });
      
      // Build
      execSync(`cmake --build ${this.buildDir} -j$(nproc 2>/dev/null || echo 4)`, {
        stdio: 'inherit'
      });
      
      this.verified.push('CMake build completed successfully');
      console.log('✅ CMake build completed successfully');
      
    } catch (error) {
      this.failed.push(`CMake build failed: ${error.message}`);
      throw new Error(`CMake build failed: ${error.message}`);
    }
  }

  async installToPrefix() {
    console.log('📥 Installing to test prefix...');
    
    try {
      // Clean previous installation
      if (fs.existsSync(this.testPrefix)) {
        fs.rmSync(this.testPrefix, { recursive: true, force: true });
      }
      
      // USER'S EXACT REQUIREMENT: cmake --install build --prefix /tmp/pfx
      execSync(`cmake --install ${this.buildDir} --prefix ${this.testPrefix}`, {
        stdio: 'inherit'
      });
      
      this.verified.push(`Installation to ${this.testPrefix} completed`);
      console.log(`✅ Installation to ${this.testPrefix} completed`);
      
    } catch (error) {
      this.failed.push(`Installation failed: ${error.message}`);
      throw new Error(`Installation failed: ${error.message}`);
    }
  }

  async verifyPkgConfigFile() {
    console.log('📋 Verifying pkg-config file...');
    
    const pkgConfigPath = `${this.testPrefix}/lib/pkgconfig/${this.sdkName}.pc`;
    
    try {
      // USER'S EXACT REQUIREMENT: test -f /tmp/pfx/lib/pkgconfig/sdkcrypto.pc
      execSync(`test -f ${pkgConfigPath}`, { stdio: 'inherit' });
      
      // Verify file contents
      const content = fs.readFileSync(pkgConfigPath, 'utf8');
      if (!content.includes('Name:') || !content.includes('Description:')) {
        throw new Error('pkg-config file has invalid format');
      }
      
      this.verified.push(`pkg-config file exists at ${pkgConfigPath}`);
      console.log(`✅ pkg-config file exists at ${pkgConfigPath}`);
      
    } catch (error) {
      this.failed.push(`pkg-config file verification failed: ${error.message}`);
      throw new Error(`pkg-config file not found at ${pkgConfigPath}`);
    }
  }

  async testPkgConfigExists() {
    console.log('🔍 Testing pkg-config functionality...');
    
    try {
      // Set PKG_CONFIG_PATH to include our installation
      const pkgConfigPath = `${this.testPrefix}/lib/pkgconfig`;
      const env = {
        ...process.env,
        PKG_CONFIG_PATH: `${pkgConfigPath}:${process.env.PKG_CONFIG_PATH || ''}`
      };
      
      // USER'S EXACT REQUIREMENT: pkg-config --exists sdkcrypto
      execSync(`pkg-config --exists ${this.sdkName}`, { 
        env,
        stdio: 'inherit' 
      });
      
      // Test additional pkg-config functionality
      const cflags = execSync(`pkg-config --cflags ${this.sdkName}`, { 
        env,
        encoding: 'utf8' 
      }).trim();
      
      const libs = execSync(`pkg-config --libs ${this.sdkName}`, { 
        env,
        encoding: 'utf8' 
      }).trim();
      
      this.verified.push(`pkg-config --exists ${this.sdkName} passed`);
      this.verified.push(`pkg-config --cflags: ${cflags}`);
      this.verified.push(`pkg-config --libs: ${libs}`);
      
      console.log(`✅ pkg-config --exists ${this.sdkName} passed`);
      console.log(`✅ pkg-config --cflags: ${cflags}`);
      console.log(`✅ pkg-config --libs: ${libs}`);
      
    } catch (error) {
      this.failed.push(`pkg-config functionality failed: ${error.message}`);
      throw new Error(`pkg-config --exists ${this.sdkName} failed: ${error.message}`);
    }
  }

  async verifyHeaders() {
    console.log('📁 Verifying header files...');
    
    const headerPath = `${this.testPrefix}/include/averox_crypto.h`;
    
    try {
      if (!fs.existsSync(headerPath)) {
        throw new Error(`Header file not found: ${headerPath}`);
      }
      
      const content = fs.readFileSync(headerPath, 'utf8');
      if (!content.includes('#ifndef AVEROX_CRYPTO_H')) {
        throw new Error('Header file has invalid format');
      }
      
      this.verified.push(`Header file installed: ${headerPath}`);
      console.log(`✅ Header file installed: ${headerPath}`);
      
    } catch (error) {
      this.failed.push(`Header verification failed: ${error.message}`);
      throw error;
    }
  }

  async verifyLibraries() {
    console.log('📚 Verifying library files...');
    
    const libDir = `${this.testPrefix}/lib`;
    
    try {
      const files = fs.readdirSync(libDir);
      const libFiles = files.filter(f => 
        f.includes('testnativesdk') && (f.endsWith('.so') || f.endsWith('.a') || f.endsWith('.dylib'))
      );
      
      if (libFiles.length === 0) {
        throw new Error('No library files found');
      }
      
      this.verified.push(`Library files installed: ${libFiles.join(', ')}`);
      console.log(`✅ Library files installed: ${libFiles.join(', ')}`);
      
    } catch (error) {
      this.failed.push(`Library verification failed: ${error.message}`);
      throw error;
    }
  }

  async testCompilation() {
    console.log('🛠️ Testing compilation with pkg-config...');
    
    try {
      const testProgram = `#include <stdio.h>
#include <averox_crypto.h>

int main() {
    printf("Averox Crypto SDK test compilation successful!\\n");
    return 0;
}`;
      
      fs.writeFileSync('/tmp/test_averox.c', testProgram);
      
      const env = {
        ...process.env,
        PKG_CONFIG_PATH: `${this.testPrefix}/lib/pkgconfig:${process.env.PKG_CONFIG_PATH || ''}`
      };
      
      // Compile using pkg-config
      execSync(`gcc /tmp/test_averox.c $(pkg-config --cflags --libs ${this.sdkName}) -o /tmp/test_averox`, {
        env,
        stdio: 'inherit'
      });
      
      // Run the test program
      const output = execSync('/tmp/test_averox', { encoding: 'utf8' });
      
      this.verified.push('Test compilation and execution successful');
      console.log('✅ Test compilation and execution successful');
      console.log(`   Output: ${output.trim()}`);
      
    } catch (error) {
      this.failed.push(`Test compilation failed: ${error.message}`);
      // Don't throw here - compilation test is nice-to-have
      console.log(`⚠️ Test compilation failed (non-critical): ${error.message}`);
    }
  }

  reportResults() {
    console.log('\n🎯 NATIVE INSTALLATION VERIFICATION RESULTS');
    console.log('============================================\n');
    
    console.log('✅ PASSED REQUIREMENTS:');
    this.verified.forEach(item => console.log(`   ✓ ${item}`));
    
    if (this.failed.length > 0) {
      console.log('\n❌ FAILED REQUIREMENTS:');
      this.failed.forEach(item => console.log(`   ✗ ${item}`));
    }
    
    console.log(`\n📊 SUMMARY: ${this.verified.length} passed, ${this.failed.length} failed`);
    
    // Verify the three exact requirements from user
    const criticalRequirements = [
      'Installation to /tmp/pfx completed',
      'pkg-config file exists at /tmp/pfx/lib/pkgconfig/sdkcrypto.pc',
      'pkg-config --exists sdkcrypto passed'
    ];
    
    const criticalPassed = criticalRequirements.filter(req => 
      this.verified.some(v => v.includes(req))
    ).length;
    
    console.log(`\n🎯 USER REQUIREMENTS: ${criticalPassed}/3 critical requirements met`);
    
    if (criticalPassed === 3) {
      console.log('\n🎉 ALL USER REQUIREMENTS SATISFIED!');
      console.log('   ✅ cmake --install build --prefix /tmp/pfx');
      console.log('   ✅ test -f /tmp/pfx/lib/pkgconfig/sdkcrypto.pc');
      console.log('   ✅ pkg-config --exists sdkcrypto');
    } else {
      throw new Error(`Only ${criticalPassed}/3 critical requirements met`);
    }
  }
}

// Command line interface
async function main() {
  const verifier = new NativeInstallVerifier();
  
  try {
    await verifier.verifyInstallation();
    console.log('\n🏆 Native installation verification PASSED');
    process.exit(0);
  } catch (error) {
    console.error('\n💥 Native installation verification FAILED');
    console.error('Error:', error.message);
    process.exit(1);
  } finally {
    // Cleanup
    process.chdir('..');
    if (fs.existsSync('test-native-sdk')) {
      fs.rmSync('test-native-sdk', { recursive: true, force: true });
    }
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { NativeInstallVerifier };