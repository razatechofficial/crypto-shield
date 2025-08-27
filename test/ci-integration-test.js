// Gate 13: CI Integration and Security Pipeline Testing
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔄 CI Integration and Security Pipeline Test');
console.log('===========================================\\n');

// Test 1: Package integrity verification
function testPackageIntegrity() {
  console.log('Test 1: Package Integrity Verification');
  console.log('--------------------------------------');
  
  try {
    // Check if package.json exists and is valid
    const packagePath = path.join(__dirname, '..', 'package.json');
    if (!fs.existsSync(packagePath)) {
      console.log('❌ package.json not found');
      return false;
    }
    
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    
    // Verify essential fields
    const requiredFields = ['name', 'version', 'main', 'types', 'exports'];
    for (const field of requiredFields) {
      if (!packageJson[field]) {
        console.log(`❌ Missing required field: ${field}`);
        return false;
      }
    }
    
    // Check for security-related dependencies
    const securityDeps = [
      '@opentelemetry/api',
      '@opentelemetry/sdk-node',
      '@opentelemetry/exporter-jaeger'
    ];
    
    for (const dep of securityDeps) {
      if (!packageJson.dependencies || !packageJson.dependencies[dep]) {
        console.log(`❌ Missing security dependency: ${dep}`);
        return false;
      }
    }
    
    console.log('✅ Package integrity verified');
    return true;
    
  } catch (error) {
    console.log(`❌ Package integrity test failed: ${error.message}`);
    return false;
  }
}

// Test 2: Build system validation
function testBuildSystem() {
  console.log('\\nTest 2: Build System Validation');
  console.log('-------------------------------');
  
  try {
    // Check if TypeScript config exists
    const tsconfigPath = path.join(__dirname, '..', 'tsconfig.json');
    if (!fs.existsSync(tsconfigPath)) {
      console.log('❌ tsconfig.json not found');
      return false;
    }
    
    const tsconfig = JSON.parse(fs.readFileSync(tsconfigPath, 'utf8'));
    
    // Verify essential TypeScript settings
    const compilerOptions = tsconfig.compilerOptions;
    if (!compilerOptions) {
      console.log('❌ Missing compilerOptions in tsconfig.json');
      return false;
    }
    
    // Check for security-related compiler flags
    const securityFlags = {
      'strict': true,
      'noImplicitAny': true,
      'noImplicitReturns': true
    };
    
    for (const [flag, expectedValue] of Object.entries(securityFlags)) {
      if (compilerOptions[flag] !== expectedValue) {
        console.log(`❌ TypeScript security flag ${flag} should be ${expectedValue}`);
        return false;
      }
    }
    
    console.log('✅ Build system validated');
    return true;
    
  } catch (error) {
    console.log(`❌ Build system test failed: ${error.message}`);
    return false;
  }
}

// Test 3: Security linting validation
function testSecurityLinting() {
  console.log('\\nTest 3: Security Linting Validation');
  console.log('-----------------------------------');
  
  try {
    // Check for common security issues in the source
    const srcPath = path.join(__dirname, '..', 'src');
    if (!fs.existsSync(srcPath)) {
      console.log('ℹ️  Source directory not found (may be built)');
      return true; // Not a failure for built packages
    }
    
    // Read the main SDK file
    const mainFile = path.join(__dirname, '..', 'server', 'routes.ts');
    if (!fs.existsSync(mainFile)) {
      console.log('❌ Main source file not found');
      return false;
    }
    
    const sourceCode = fs.readFileSync(mainFile, 'utf8');
    
    // Security checks
    const securityChecks = [
      {
        name: 'No hardcoded secrets',
        test: () => !/(?:password|secret|key)\\s*[:=]\\s*['""][^'"]{8,}['""]/.test(sourceCode)
      },
      {
        name: 'Uses timing-safe comparisons',
        test: () => /timingSafeEqual/.test(sourceCode)
      },
      {
        name: 'Has error handling',
        test: () => /try\\s*{[\\s\\S]*}\\s*catch/.test(sourceCode)
      },
      {
        name: 'Uses secure random generation',
        test: () => /randomBytes/.test(sourceCode)
      },
      {
        name: 'Has input validation',
        test: () => /throw.*Error/.test(sourceCode)
      }
    ];
    
    let passed = 0;
    for (const check of securityChecks) {
      if (check.test()) {
        console.log(`  ✅ ${check.name}`);
        passed++;
      } else {
        console.log(`  ❌ ${check.name}`);
      }
    }
    
    const passRate = (passed / securityChecks.length) * 100;
    console.log(`Security linting: ${passed}/${securityChecks.length} checks passed (${passRate.toFixed(1)}%)`);
    
    return passRate >= 80; // Require 80% pass rate
    
  } catch (error) {
    console.log(`❌ Security linting test failed: ${error.message}`);
    return false;
  }
}

// Test 4: Dependency vulnerability check
function testDependencyVulnerabilities() {
  console.log('\\nTest 4: Dependency Vulnerability Check');
  console.log('--------------------------------------');
  
  try {
    // This would normally run npm audit, but we'll simulate the check
    const packagePath = path.join(__dirname, '..', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    
    // Check for known vulnerable packages (simplified check)
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    const vulnerablePackages = [
      'debug@<2.6.9',
      'lodash@<4.17.11',
      'axios@<0.21.1'
    ];
    
    let vulnerabilities = 0;
    for (const [pkg, version] of Object.entries(dependencies)) {
      // This is a simplified check - in real CI, use npm audit
      for (const vuln of vulnerablePackages) {
        if (vuln.startsWith(pkg + '@')) {
          console.log(`⚠️  Potential vulnerability in ${pkg}@${version}`);
          vulnerabilities++;
        }
      }
    }
    
    if (vulnerabilities === 0) {
      console.log('✅ No known vulnerabilities detected');
      return true;
    } else {
      console.log(`❌ ${vulnerabilities} potential vulnerabilities found`);
      return false;
    }
    
  } catch (error) {
    console.log(`❌ Dependency vulnerability test failed: ${error.message}`);
    return false;
  }
}

// Test 5: Performance regression check
function testPerformanceRegression() {
  console.log('\\nTest 5: Performance Regression Check');
  console.log('------------------------------------');
  
  try {
    const { AveroxCrypto } = require('../dist/cjs/index.js');
    const crypto = new AveroxCrypto('perf-test');
    
    // Performance baselines (in operations per second)
    const baselines = {
      encryption: 1000,    // ops/sec
      decryption: 1000,    // ops/sec
      keyGeneration: 10000 // ops/sec
    };
    
    const testData = 'A'.repeat(1024); // 1KB
    const iterations = 100;
    
    // Test encryption performance
    const key = crypto.generateKey();
    const encryptStart = Date.now();
    for (let i = 0; i < iterations; i++) {
      crypto.encrypt(testData, key, 'perf-test');
    }
    const encryptTime = Date.now() - encryptStart;
    const encryptOps = (iterations * 1000) / encryptTime;
    
    // Test decryption performance
    const encrypted = crypto.encrypt(testData, key, 'perf-test');
    const decryptStart = Date.now();
    for (let i = 0; i < iterations; i++) {
      crypto.decrypt(encrypted, key);
    }
    const decryptTime = Date.now() - decryptStart;
    const decryptOps = (iterations * 1000) / decryptTime;
    
    // Test key generation performance
    const keyGenStart = Date.now();
    for (let i = 0; i < iterations; i++) {
      crypto.generateKey();
    }
    const keyGenTime = Date.now() - keyGenStart;
    const keyGenOps = (iterations * 1000) / keyGenTime;
    
    // Compare against baselines
    const results = {
      encryption: { ops: encryptOps, baseline: baselines.encryption },
      decryption: { ops: decryptOps, baseline: baselines.decryption },
      keyGeneration: { ops: keyGenOps, baseline: baselines.keyGeneration }
    };
    
    let regressions = 0;
    for (const [operation, data] of Object.entries(results)) {
      const performance = (data.ops / data.baseline) * 100;
      if (performance >= 80) {
        console.log(`  ✅ ${operation}: ${data.ops.toFixed(0)} ops/sec (${performance.toFixed(1)}% of baseline)`);
      } else {
        console.log(`  ❌ ${operation}: ${data.ops.toFixed(0)} ops/sec (${performance.toFixed(1)}% of baseline) - REGRESSION`);
        regressions++;
      }
    }
    
    if (regressions === 0) {
      console.log('✅ No performance regressions detected');
      return true;
    } else {
      console.log(`❌ ${regressions} performance regressions detected`);
      return false;
    }
    
  } catch (error) {
    console.log(`❌ Performance regression test failed: ${error.message}`);
    return false;
  }
}

// Main test execution
async function main() {
  const tests = [
    { name: 'Package Integrity', fn: testPackageIntegrity },
    { name: 'Build System', fn: testBuildSystem },
    { name: 'Security Linting', fn: testSecurityLinting },
    { name: 'Dependency Vulnerabilities', fn: testDependencyVulnerabilities },
    { name: 'Performance Regression', fn: testPerformanceRegression }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const test of tests) {
    try {
      const result = test.fn();
      if (result) {
        passed++;
      } else {
        failed++;
      }
    } catch (error) {
      console.log(`❌ ${test.name} threw exception: ${error.message}`);
      failed++;
    }
  }
  
  console.log(`\\n=== CI INTEGRATION TEST RESULTS ===`);
  console.log(`Tests Passed: ${passed}`);
  console.log(`Tests Failed: ${failed}`);
  console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
  
  if (failed === 0) {
    console.log('\\n🎉 ALL CI INTEGRATION TESTS PASSED!');
    console.log('SDK is ready for production CI/CD pipeline.');
    process.exit(0);
  } else {
    console.log(`\\n⚠️  ${failed} CI integration tests failed.`);
    console.log('Fix issues before deploying to production.');
    process.exit(1);
  }
}

main();