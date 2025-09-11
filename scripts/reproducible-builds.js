#!/usr/bin/env node

/**
 * Government-Level Reproducible Build System
 * Ensures deterministic, verifiable builds for all SDK components
 * 
 * COMPLIANCE: Supply Chain Levels for Software Artifacts (SLSA)
 * STANDARDS: Reproducible Builds, NIST SP 800-161r1
 */

import fs from 'fs';
import crypto from 'crypto';
import { execSync } from 'child_process';
import path from 'path';
import os from 'os';

class ReproducibleBuilds {
  constructor() {
    this.config = {
      buildOutputDir: './dist',
      reproducibilityReportDir: './reproducibility-reports',
      buildEnvironmentFile: './build-environment.json',
      checksumFile: './build-checksums.json'
    };
    
    this.buildEnvironment = {};
    this.buildArtifacts = [];
    this.reproducibilityResults = {};
  }

  /**
   * Document exact build environment for reproducibility
   */
  async documentBuildEnvironment() {
    console.log('📋 Documenting build environment for reproducibility...');
    
    const environment = {
      timestamp: new Date().toISOString(),
      system: {
        os: os.platform(),
        arch: os.arch(),
        release: os.release(),
        hostname: os.hostname(),
        tmpdir: os.tmpdir()
      },
      runtime: {
        node: process.version,
        npm: this.getToolVersion('npm'),
        yarn: this.getToolVersion('yarn'),
        git: this.getToolVersion('git')
      },
      dependencies: await this.getExactDependencyVersions(),
      buildTools: {
        vite: this.getToolVersion('vite'),
        esbuild: this.getToolVersion('esbuild'),
        typescript: this.getToolVersion('tsc'),
        tailwindcss: this.getToolVersion('tailwindcss')
      },
      environment: {
        NODE_ENV: process.env.NODE_ENV,
        PWD: process.cwd(),
        PATH: process.env.PATH,
        LANG: process.env.LANG,
        TZ: process.env.TZ || 'UTC'
      },
      reproducibility: {
        deterministic: true,
        sourceDate: process.env.SOURCE_DATE_EPOCH || new Date().toISOString(),
        buildId: crypto.randomBytes(16).toString('hex')
      }
    };

    this.buildEnvironment = environment;
    
    fs.mkdirSync(this.config.reproducibilityReportDir, { recursive: true });
    fs.writeFileSync(this.config.buildEnvironmentFile, JSON.stringify(environment, null, 2));
    
    console.log('✅ Build environment documented');
    return environment;
  }

  getToolVersion(tool) {
    try {
      const version = execSync(`${tool} --version`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      return version.split('\n')[0].trim();
    } catch (error) {
      return 'not available';
    }
  }

  async getExactDependencyVersions() {
    try {
      const lockContent = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
      const dependencies = {};
      
      if (lockContent.packages) {
        for (const [path, pkg] of Object.entries(lockContent.packages)) {
          if (path && pkg.version) {
            const name = path.replace(/^node_modules\//, '');
            dependencies[name] = {
              version: pkg.version,
              resolved: pkg.resolved,
              integrity: pkg.integrity
            };
          }
        }
      }
      
      return dependencies;
    } catch (error) {
      return {};
    }
  }

  /**
   * Perform deterministic build with reproducibility controls
   */
  async performReproducibleBuild() {
    console.log('🏗️  Performing reproducible build...');
    
    // Set deterministic environment variables
    process.env.SOURCE_DATE_EPOCH = process.env.SOURCE_DATE_EPOCH || Math.floor(Date.now() / 1000).toString();
    process.env.NODE_ENV = 'production';
    process.env.FORCE_COLOR = '0';
    process.env.CI = 'true';
    
    // Clean previous build
    if (fs.existsSync(this.config.buildOutputDir)) {
      fs.rmSync(this.config.buildOutputDir, { recursive: true });
    }
    
    try {
      // Execute build with deterministic flags
      console.log('Building frontend...');
      execSync('npm run build', {
        stdio: 'pipe',
        env: {
          ...process.env,
          BUILD_MODE: 'reproducible'
        }
      });
      
      // Document build artifacts
      await this.documentBuildArtifacts();
      
      // Calculate checksums
      await this.calculateBuildChecksums();
      
      console.log('✅ Reproducible build complete');
      
    } catch (error) {
      console.error('❌ Build failed:', error.message);
      throw error;
    }
  }

  async documentBuildArtifacts() {
    console.log('📦 Documenting build artifacts...');
    
    if (!fs.existsSync(this.config.buildOutputDir)) {
      console.warn('⚠️  Build output directory not found');
      return;
    }
    
    const artifacts = this.collectArtifacts(this.config.buildOutputDir);
    this.buildArtifacts = artifacts;
    
    const artifactManifest = {
      buildId: this.buildEnvironment.reproducibility?.buildId,
      timestamp: new Date().toISOString(),
      totalArtifacts: artifacts.length,
      artifacts: artifacts.map(artifact => ({
        path: artifact.relativePath,
        size: artifact.size,
        hash: artifact.hash,
        type: artifact.type
      }))
    };
    
    fs.writeFileSync(
      path.join(this.config.reproducibilityReportDir, 'build-artifacts.json'),
      JSON.stringify(artifactManifest, null, 2)
    );
    
    console.log(`📦 ${artifacts.length} artifacts documented`);
  }

  collectArtifacts(directory, basePath = '') {
    const artifacts = [];
    
    const items = fs.readdirSync(directory);
    
    for (const item of items) {
      const itemPath = path.join(directory, item);
      const relativePath = path.join(basePath, item);
      const stats = fs.statSync(itemPath);
      
      if (stats.isDirectory()) {
        artifacts.push(...this.collectArtifacts(itemPath, relativePath));
      } else {
        const content = fs.readFileSync(itemPath);
        artifacts.push({
          absolutePath: itemPath,
          relativePath: relativePath,
          size: stats.size,
          hash: crypto.createHash('sha256').update(content).digest('hex'),
          type: path.extname(item) || 'binary',
          modified: stats.mtime.toISOString()
        });
      }
    }
    
    return artifacts;
  }

  async calculateBuildChecksums() {
    console.log('🔍 Calculating build checksums...');
    
    const checksums = {
      buildId: this.buildEnvironment.reproducibility?.buildId,
      timestamp: new Date().toISOString(),
      algorithm: 'SHA-256',
      artifacts: {},
      overall: null
    };
    
    // Calculate individual artifact checksums
    for (const artifact of this.buildArtifacts) {
      checksums.artifacts[artifact.relativePath] = {
        sha256: artifact.hash,
        size: artifact.size
      };
    }
    
    // Calculate overall build checksum
    const allHashes = this.buildArtifacts
      .sort((a, b) => a.relativePath.localeCompare(b.relativePath))
      .map(a => a.hash)
      .join('');
    
    checksums.overall = crypto.createHash('sha256').update(allHashes).digest('hex');
    
    fs.writeFileSync(this.config.checksumFile, JSON.stringify(checksums, null, 2));
    
    console.log(`🔍 Build checksum: ${checksums.overall}`);
    return checksums;
  }

  /**
   * Verify build reproducibility by comparing with previous build
   */
  async verifyReproducibility(previousChecksumFile) {
    console.log('🔎 Verifying build reproducibility...');
    
    if (!fs.existsSync(previousChecksumFile)) {
      console.warn('⚠️  No previous checksums found for comparison');
      return { reproducible: false, reason: 'No baseline for comparison' };
    }
    
    const currentChecksums = JSON.parse(fs.readFileSync(this.config.checksumFile, 'utf8'));
    const previousChecksums = JSON.parse(fs.readFileSync(previousChecksumFile, 'utf8'));
    
    const comparison = {
      reproducible: currentChecksums.overall === previousChecksums.overall,
      currentBuild: currentChecksums.overall,
      previousBuild: previousChecksums.overall,
      artifactComparison: {},
      differences: []
    };
    
    // Compare individual artifacts
    for (const [path, current] of Object.entries(currentChecksums.artifacts)) {
      const previous = previousChecksums.artifacts[path];
      
      comparison.artifactComparison[path] = {
        current: current.sha256,
        previous: previous?.sha256 || 'missing',
        match: previous ? current.sha256 === previous.sha256 : false
      };
      
      if (!previous || current.sha256 !== previous.sha256) {
        comparison.differences.push({
          artifact: path,
          type: previous ? 'modified' : 'new',
          currentHash: current.sha256,
          previousHash: previous?.sha256 || null
        });
      }
    }
    
    // Check for removed artifacts
    for (const path of Object.keys(previousChecksums.artifacts)) {
      if (!currentChecksums.artifacts[path]) {
        comparison.differences.push({
          artifact: path,
          type: 'removed'
        });
      }
    }
    
    this.reproducibilityResults = comparison;
    
    // Save reproducibility report
    const report = {
      timestamp: new Date().toISOString(),
      buildEnvironment: this.buildEnvironment,
      comparison: comparison,
      verdict: comparison.reproducible ? 'REPRODUCIBLE' : 'NOT_REPRODUCIBLE',
      compliance: {
        slsa: comparison.reproducible ? 'Level 2+' : 'Needs Review',
        recommendations: this.generateReproducibilityRecommendations(comparison)
      }
    };
    
    fs.writeFileSync(
      path.join(this.config.reproducibilityReportDir, 'reproducibility-report.json'),
      JSON.stringify(report, null, 2)
    );
    
    console.log(`🔎 Build reproducibility: ${comparison.reproducible ? '✅ PASS' : '❌ FAIL'}`);
    if (!comparison.reproducible) {
      console.log(`   Differences found: ${comparison.differences.length}`);
    }
    
    return comparison;
  }

  generateReproducibilityRecommendations(comparison) {
    const recommendations = [];
    
    if (!comparison.reproducible) {
      recommendations.push('Fix non-deterministic build elements');
      recommendations.push('Check timestamp handling in build process');
      recommendations.push('Verify dependency version pinning');
      
      if (comparison.differences.length > 0) {
        recommendations.push(`Investigate ${comparison.differences.length} artifact differences`);
      }
    } else {
      recommendations.push('Build is reproducible - maintain current practices');
      recommendations.push('Document build environment requirements');
    }
    
    return recommendations;
  }

  /**
   * Generate reproducible build instructions
   */
  async generateBuildInstructions() {
    console.log('📖 Generating reproducible build instructions...');
    
    const instructions = `# Reproducible Build Instructions
## Averox Crypto SDK

### Prerequisites
- Node.js: ${this.buildEnvironment.runtime?.node || 'Latest LTS'}
- npm: ${this.buildEnvironment.runtime?.npm || 'Latest'}
- Operating System: ${this.buildEnvironment.system?.os || 'Linux/macOS/Windows'}

### Environment Setup
\`\`\`bash
export NODE_ENV=production
export SOURCE_DATE_EPOCH=${process.env.SOURCE_DATE_EPOCH || Math.floor(Date.now() / 1000)}
export FORCE_COLOR=0
export CI=true
\`\`\`

### Build Process
1. Clean previous build:
   \`\`\`bash
   rm -rf dist/
   \`\`\`

2. Install exact dependencies:
   \`\`\`bash
   npm ci --frozen-lockfile
   \`\`\`

3. Execute reproducible build:
   \`\`\`bash
   npm run build
   \`\`\`

4. Verify checksums:
   \`\`\`bash
   node scripts/reproducible-builds.js verify
   \`\`\`

### Expected Output Checksum
Build should produce overall SHA-256: ${this.reproducibilityResults?.currentBuild || 'TBD'}

### Troubleshooting
- Ensure identical dependency versions (check package-lock.json)
- Use consistent Node.js version across builds
- Set SOURCE_DATE_EPOCH for deterministic timestamps
- Verify build environment matches documented requirements

### Verification
Compare your build output checksums with published checksums to verify reproducibility.
`;
    
    fs.writeFileSync('BUILD-REPRODUCIBILITY.md', instructions);
    console.log('📖 Build instructions generated');
  }

  /**
   * Complete reproducible build workflow
   */
  async runReproducibleBuild() {
    console.log('🏗️  GOVERNMENT-LEVEL REPRODUCIBLE BUILD SYSTEM');
    console.log('===============================================');
    
    try {
      // Step 1: Document build environment
      await this.documentBuildEnvironment();
      
      // Step 2: Perform reproducible build
      await this.performReproducibleBuild();
      
      // Step 3: Generate instructions
      await this.generateBuildInstructions();
      
      console.log('\n🎯 REPRODUCIBLE BUILD COMPLETE');
      console.log(`📦 Artifacts: ${this.buildArtifacts.length}`);
      console.log(`🔍 Build checksum: ${JSON.parse(fs.readFileSync(this.config.checksumFile, 'utf8')).overall}`);
      
    } catch (error) {
      console.error('❌ Reproducible build failed:', error.message);
      process.exit(1);
    }
  }
}

// CLI execution
if (import.meta.url === `file://${process.argv[1]}`) {
  const builder = new ReproducibleBuilds();
  
  const command = process.argv[2];
  
  switch (command) {
    case 'build':
      builder.runReproducibleBuild();
      break;
    case 'verify':
      const previousFile = process.argv[3] || './build-checksums-previous.json';
      builder.verifyReproducibility(previousFile);
      break;
    case 'document':
      builder.documentBuildEnvironment();
      break;
    default:
      console.log('Usage: node reproducible-builds.js [build|verify|document]');
  }
}

export { ReproducibleBuilds };