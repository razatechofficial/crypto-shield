#!/usr/bin/env node

/**
 * Release Artifact Checksum Generator
 * Generates SHA256 and SHA512 checksums for all release artifacts
 * 
 * COMPLIANCE: NIST SP 800-107, FIPS 180-4
 * OUTPUT: Standard checksum files for verification
 */

import fs from 'fs';
import crypto from 'crypto';
import path from 'path';
import { globSync } from 'glob';

class ChecksumGenerator {
  constructor() {
    this.checksums = {
      sha256: new Map(),
      sha512: new Map()
    };
    
    this.outputDir = 'release-artifacts/checksums';
  }

  /**
   * Generate checksums for all release artifacts
   */
  async generateAllChecksums() {
    console.log('🔒 Generating release artifact checksums...');
    
    // Ensure output directory exists
    fs.mkdirSync(this.outputDir, { recursive: true });
    
    // Find all artifacts to checksum
    const artifacts = this.findReleaseArtifacts();
    
    if (artifacts.length === 0) {
      console.log('⚠️ No artifacts found to checksum');
      return;
    }
    
    console.log(`📦 Found ${artifacts.length} artifacts to checksum:`);
    artifacts.forEach(file => console.log(`   📄 ${file}`));
    
    // Calculate checksums
    for (const file of artifacts) {
      await this.calculateFileChecksums(file);
    }
    
    // Write checksum files
    await this.writeChecksumFiles();
    
    console.log('✅ Checksums generated successfully');
  }

  findReleaseArtifacts() {
    const artifacts = [];
    
    // Patterns for release artifacts
    const patterns = [
      'dist/**/*',
      'build/**/*',
      '*.tgz',
      '*.tar.gz',
      '*.zip',
      'package.json',
      'enterprise-sdk-generator-fixed.cjs',
      'release-artifacts/sboms/*'
    ];
    
    for (const pattern of patterns) {
      try {
        const matches = globSync(pattern, { 
          ignore: ['node_modules/**', 'release-artifacts/checksums/**'],
          nodir: true // Only files, not directories
        });
        artifacts.push(...matches);
      } catch (error) {
        // Pattern not found, continue
      }
    }
    
    // Remove duplicates and sort
    return [...new Set(artifacts)].sort();
  }

  async calculateFileChecksums(filePath) {
    try {
      const content = fs.readFileSync(filePath);
      
      // Calculate SHA256
      const sha256Hash = crypto.createHash('sha256').update(content).digest('hex');
      this.checksums.sha256.set(filePath, sha256Hash);
      
      // Calculate SHA512
      const sha512Hash = crypto.createHash('sha512').update(content).digest('hex');
      this.checksums.sha512.set(filePath, sha512Hash);
      
      console.log(`   ✓ ${filePath}`);
    } catch (error) {
      console.error(`   ❌ Failed to checksum ${filePath}: ${error.message}`);
    }
  }

  async writeChecksumFiles() {
    // Write SHA256SUMS file
    const sha256Content = Array.from(this.checksums.sha256.entries())
      .map(([file, hash]) => `${hash}  ${file}`)
      .join('\n');
    
    fs.writeFileSync(path.join(this.outputDir, 'SHA256SUMS'), sha256Content + '\n');
    
    // Write SHA512SUMS file
    const sha512Content = Array.from(this.checksums.sha512.entries())
      .map(([file, hash]) => `${hash}  ${file}`)
      .join('\n');
    
    fs.writeFileSync(path.join(this.outputDir, 'SHA512SUMS'), sha512Content + '\n');
    
    // Write detailed JSON manifest
    const manifest = {
      generated: new Date().toISOString(),
      generator: "Averox Checksum Generator v2.0.0",
      algorithm_compliance: {
        sha256: "FIPS 180-4, NIST SP 800-107",
        sha512: "FIPS 180-4, NIST SP 800-107"
      },
      files: Array.from(this.checksums.sha256.keys()).map(file => ({
        path: file,
        size: fs.statSync(file).size,
        sha256: this.checksums.sha256.get(file),
        sha512: this.checksums.sha512.get(file),
        modified: fs.statSync(file).mtime.toISOString()
      }))
    };
    
    fs.writeFileSync(
      path.join(this.outputDir, 'checksums-manifest.json'), 
      JSON.stringify(manifest, null, 2)
    );
    
    console.log(`📋 Generated checksum files:`);
    console.log(`   📄 ${this.outputDir}/SHA256SUMS`);
    console.log(`   📄 ${this.outputDir}/SHA512SUMS`);
    console.log(`   📄 ${this.outputDir}/checksums-manifest.json`);
  }

  /**
   * Verify checksums against existing checksum files
   */
  async verifyChecksums(checksumFile) {
    console.log(`🔍 Verifying checksums from ${checksumFile}...`);
    
    if (!fs.existsSync(checksumFile)) {
      throw new Error(`Checksum file not found: ${checksumFile}`);
    }
    
    const content = fs.readFileSync(checksumFile, 'utf8');
    const lines = content.trim().split('\n');
    
    let verified = 0;
    let failed = 0;
    
    for (const line of lines) {
      if (!line.trim()) continue;
      
      const [expectedHash, filePath] = line.split(/\s+/, 2);
      
      if (!fs.existsSync(filePath)) {
        console.log(`   ❌ Missing file: ${filePath}`);
        failed++;
        continue;
      }
      
      const content = fs.readFileSync(filePath);
      const actualHash = crypto.createHash('sha256').update(content).digest('hex');
      
      if (actualHash === expectedHash) {
        console.log(`   ✓ ${filePath}`);
        verified++;
      } else {
        console.log(`   ❌ MISMATCH: ${filePath}`);
        console.log(`      Expected: ${expectedHash}`);
        console.log(`      Actual:   ${actualHash}`);
        failed++;
      }
    }
    
    console.log(`\n📊 Verification results: ${verified} verified, ${failed} failed`);
    
    if (failed > 0) {
      throw new Error(`Checksum verification failed: ${failed} files had mismatched checksums`);
    }
    
    return { verified, failed };
  }
}

// Command line interface
async function main() {
  const generator = new ChecksumGenerator();
  
  const command = process.argv[2];
  
  try {
    switch (command) {
      case 'generate':
        await generator.generateAllChecksums();
        break;
        
      case 'verify':
        const checksumFile = process.argv[3] || 'release-artifacts/checksums/SHA256SUMS';
        await generator.verifyChecksums(checksumFile);
        break;
        
      default:
        await generator.generateAllChecksums();
        break;
    }
  } catch (error) {
    console.error('❌ Checksum operation failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { ChecksumGenerator };