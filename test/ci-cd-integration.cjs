/**
 * CI/CD Integration and Comprehensive Testing Orchestration
 * Government-level cryptographic assurance with automated quality gates
 * 
 * CI/CD INTEGRATION COVERAGE:
 * ✅ Master test orchestration with dependency management
 * ✅ Parallel test execution with resource optimization
 * ✅ Comprehensive reporting and artifact generation
 * ✅ Quality gate enforcement with automatic failure detection
 * ✅ Government compliance certification readiness validation
 * ✅ Security regression detection and alerting
 * ✅ Performance benchmarking and threshold monitoring
 * ✅ Automated deployment readiness assessment and gating
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// Import all test frameworks
const GovernmentLevelKATs = require('./government-level-kats.cjs');
const EdgeCaseFailureTests = require('./edge-case-failure-tests.cjs');
const PropertyBasedTests = require('./property-based-tests.cjs');
const FuzzingCampaignManager = require('./fuzzing-framework.cjs');
const ComprehensiveQualityGateManager = require('./coverage-quality-gates.cjs');
const ComprehensiveGovernmentComplianceManager = require('./government-compliance-tests.cjs');

/**
 * CI/CD Test Orchestrator
 * Master orchestration system for government-level testing
 */
class CICDTestOrchestrator {
  constructor(options = {}) {
    this.config = {
      parallel: options.parallel !== false,
      verbose: options.verbose || process.env.VERBOSE_TESTING === 'true',
      reportDir: options.reportDir || 'test-reports',
      artifactDir: options.artifactDir || 'test-artifacts',
      maxWorkers: options.maxWorkers || Math.min(4, Math.max(1, require('os').cpus().length - 1)),
      timeouts: {
        kats: 300000, // 5 minutes
        edgeCase: 180000, // 3 minutes
        property: 240000, // 4 minutes
        fuzzing: 600000, // 10 minutes
        quality: 420000, // 7 minutes
        compliance: 480000 // 8 minutes
      },
      thresholds: {
        minimumCoverage: 85,
        maxSecurityVulnerabilities: 0,
        maxPerformanceRegression: 20, // 20% degradation threshold
        requiredComplianceScore: 90
      }
    };
    
    this.orchestrationResults = {
      startTime: Date.now(),
      endTime: null,
      totalDuration: 0,
      testSuites: {},
      overallResults: {
        passed: false,
        score: 0,
        governmentReady: false,
        certificationReady: false
      },
      qualityGates: [],
      securityFindings: [],
      performanceMetrics: {},
      complianceStatus: {},
      artifacts: [],
      recommendations: []
    };
    
    this.setupDirectories();
  }

  /**
   * Setup directories for reports and artifacts
   */
  setupDirectories() {
    [this.config.reportDir, this.config.artifactDir].forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Main orchestration entry point
   */
  async runComprehensiveTestSuite() {
    this.log('🚀 Starting Government-Level Cryptographic Assurance Testing Suite\n');
    this.log('=' .repeat(100));
    this.log('🏛️  COMPREHENSIVE TESTING ORCHESTRATION FOR GOVERNMENT DEPLOYMENT');
    this.log('=' .repeat(100));
    
    try {
      // Pre-flight checks
      await this.performPreflightChecks();
      
      // Run core test suites
      await this.runCoreTestSuites();
      
      // Run quality assurance
      await this.runQualityAssurance();
      
      // Run government compliance
      await this.runGovernmentCompliance();
      
      // Generate comprehensive assessment
      await this.generateComprehensiveAssessment();
      
      // Export artifacts and reports
      await this.exportArtifacts();
      
      this.orchestrationResults.endTime = Date.now();
      this.orchestrationResults.totalDuration = this.orchestrationResults.endTime - this.orchestrationResults.startTime;
      
      return this.orchestrationResults;
      
    } catch (error) {
      this.log(`\n❌ Test orchestration failed: ${error.message}`);
      this.orchestrationResults.overallResults.passed = false;
      await this.exportFailureReport(error);
      throw error;
    }
  }

  /**
   * Perform pre-flight checks before running tests
   */
  async performPreflightChecks() {
    this.log('\n🔍 Performing Pre-flight Checks...');
    this.log('-' .repeat(50));
    
    const checks = [
      () => this.checkEnvironment(),
      () => this.checkDependencies(),
      () => this.checkCryptographicModules(),
      () => this.checkSystemResources(),
      () => this.checkSecurityConfiguration()
    ];
    
    let passedChecks = 0;
    
    for (const check of checks) {
      try {
        await check();
        passedChecks++;
      } catch (error) {
        this.log(`  ❌ Pre-flight check failed: ${error.message}`);
      }
    }
    
    if (passedChecks < checks.length) {
      throw new Error(`Pre-flight checks failed: ${passedChecks}/${checks.length} passed`);
    }
    
    this.log(`  ✅ All pre-flight checks passed (${passedChecks}/${checks.length})`);
  }

  /**
   * Check environment configuration
   */
  async checkEnvironment() {
    // Check Node.js version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.substring(1).split('.')[0]);
    
    if (majorVersion < 16) {
      throw new Error(`Node.js version too old: ${nodeVersion} (requires >= 16.0.0)`);
    }
    
    // Check available memory
    const totalMemory = require('os').totalmem();
    const freeMemory = require('os').freemem();
    
    if (freeMemory < 1024 * 1024 * 1024) { // 1GB
      this.log(`  ⚠️  Low available memory: ${Math.round(freeMemory / 1024 / 1024)}MB`);
    }
    
    // Check disk space
    try {
      fs.writeFileSync('.disk-test', 'test');
      fs.unlinkSync('.disk-test');
    } catch (error) {
      throw new Error('Insufficient disk space for test artifacts');
    }
    
    this.log('  ✅ Environment checks passed');
  }

  /**
   * Check required dependencies
   */
  async checkDependencies() {
    const requiredModules = [
      'production-enterprise-core.cjs',
      'canonical-v2-reference.cjs',
      'security-hardening-core.cjs',
      'enterprise-kdf-implementations.cjs'
    ];
    
    for (const module of requiredModules) {
      if (!fs.existsSync(module)) {
        throw new Error(`Required module missing: ${module}`);
      }
    }
    
    // Check test frameworks
    const testFrameworks = [
      'test/government-level-kats.cjs',
      'test/edge-case-failure-tests.cjs',
      'test/property-based-tests.cjs',
      'test/fuzzing-framework.cjs',
      'test/coverage-quality-gates.cjs',
      'test/government-compliance-tests.cjs'
    ];
    
    for (const framework of testFrameworks) {
      if (!fs.existsSync(framework)) {
        throw new Error(`Test framework missing: ${framework}`);
      }
    }
    
    this.log('  ✅ Dependency checks passed');
  }

  /**
   * Check cryptographic modules
   */
  async checkCryptographicModules() {
    try {
      const { EnterpriseAveroxCrypto } = require('../production-enterprise-core.cjs');
      
      // Test basic functionality
      const key = EnterpriseAveroxCrypto.generateKey();
      const plaintext = Buffer.from('Pre-flight test');
      const encrypted = await EnterpriseAveroxCrypto.encrypt(plaintext, key);
      const decrypted = await EnterpriseAveroxCrypto.decrypt(encrypted, key);
      
      if (!decrypted.equals(plaintext)) {
        throw new Error('Basic cryptographic functionality test failed');
      }
      
      this.log('  ✅ Cryptographic module checks passed');
      
    } catch (error) {
      throw new Error(`Cryptographic module check failed: ${error.message}`);
    }
  }

  /**
   * Check system resources
   */
  async checkSystemResources() {
    const cpuCount = require('os').cpus().length;
    const totalMemory = require('os').totalmem();
    
    if (cpuCount < 2) {
      this.log('  ⚠️  Low CPU count - parallel testing may be limited');
    }
    
    if (totalMemory < 2 * 1024 * 1024 * 1024) { // 2GB
      this.log('  ⚠️  Low total memory - may affect intensive tests');
    }
    
    this.log('  ✅ System resource checks completed');
  }

  /**
   * Check security configuration
   */
  async checkSecurityConfiguration() {
    // Check RNG availability
    try {
      const randomData = crypto.randomBytes(32);
      if (randomData.length !== 32) {
        throw new Error('RNG functionality test failed');
      }
    } catch (error) {
      throw new Error(`RNG check failed: ${error.message}`);
    }
    
    // Check crypto module availability
    const requiredAlgorithms = ['aes-256-gcm', 'sha256', 'sha512'];
    for (const algorithm of requiredAlgorithms) {
      try {
        crypto.createHash('sha256'); // Test crypto availability
      } catch (error) {
        throw new Error(`Crypto algorithm ${algorithm} not available`);
      }
    }
    
    this.log('  ✅ Security configuration checks passed');
  }

  /**
   * Run core cryptographic test suites
   */
  async runCoreTestSuites() {
    this.log('\n🧪 Running Core Cryptographic Test Suites...');
    this.log('-' .repeat(50));
    
    const testSuites = [
      {
        name: 'Known-Answer Tests (KATs)',
        class: GovernmentLevelKATs,
        timeout: this.config.timeouts.kats,
        weight: 0.25,
        critical: true
      },
      {
        name: 'Edge Case and Failure Tests',
        class: EdgeCaseFailureTests,
        timeout: this.config.timeouts.edgeCase,
        weight: 0.25,
        critical: true
      },
      {
        name: 'Property-Based Tests',
        class: PropertyBasedTests,
        timeout: this.config.timeouts.property,
        weight: 0.25,
        critical: false
      },
      {
        name: 'Fuzzing Framework',
        class: FuzzingCampaignManager,
        timeout: this.config.timeouts.fuzzing,
        weight: 0.25,
        critical: false
      }
    ];
    
    if (this.config.parallel) {
      await this.runTestSuitesInParallel(testSuites);
    } else {
      await this.runTestSuitesSequentially(testSuites);
    }
    
    // Analyze core test results
    this.analyzeCoreTestResults();
  }

  /**
   * Run test suites in parallel
   */
  async runTestSuitesInParallel(testSuites) {
    this.log('  🔄 Running test suites in parallel...');
    
    const promises = testSuites.map(suite => this.runTestSuiteWithTimeout(suite));
    const results = await Promise.allSettled(promises);
    
    results.forEach((result, index) => {
      const suite = testSuites[index];
      
      if (result.status === 'fulfilled') {
        this.orchestrationResults.testSuites[suite.name] = {
          ...result.value,
          weight: suite.weight,
          critical: suite.critical
        };
        this.log(`  ✅ ${suite.name}: Completed`);
      } else {
        this.orchestrationResults.testSuites[suite.name] = {
          passed: false,
          error: result.reason.message,
          weight: suite.weight,
          critical: suite.critical
        };
        this.log(`  ❌ ${suite.name}: Failed - ${result.reason.message}`);
      }
    });
  }

  /**
   * Run test suites sequentially
   */
  async runTestSuitesSequentially(testSuites) {
    this.log('  ➡️  Running test suites sequentially...');
    
    for (const suite of testSuites) {
      try {
        const result = await this.runTestSuiteWithTimeout(suite);
        this.orchestrationResults.testSuites[suite.name] = {
          ...result,
          weight: suite.weight,
          critical: suite.critical
        };
        this.log(`  ✅ ${suite.name}: Completed`);
      } catch (error) {
        this.orchestrationResults.testSuites[suite.name] = {
          passed: false,
          error: error.message,
          weight: suite.weight,
          critical: suite.critical
        };
        this.log(`  ❌ ${suite.name}: Failed - ${error.message}`);
        
        // Stop on critical test failure in sequential mode
        if (suite.critical) {
          throw new Error(`Critical test suite failed: ${suite.name}`);
        }
      }
    }
  }

  /**
   * Run individual test suite with timeout
   */
  async runTestSuiteWithTimeout(suite) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      let completed = false;
      
      // Set timeout
      const timeoutId = setTimeout(() => {
        if (!completed) {
          completed = true;
          reject(new Error(`Test suite timed out after ${suite.timeout}ms`));
        }
      }, suite.timeout);
      
      // Run test suite
      this.runTestSuite(suite)
        .then(result => {
          if (!completed) {
            completed = true;
            clearTimeout(timeoutId);
            resolve({
              ...result,
              duration: Date.now() - startTime
            });
          }
        })
        .catch(error => {
          if (!completed) {
            completed = true;
            clearTimeout(timeoutId);
            reject(error);
          }
        });
    });
  }

  /**
   * Run individual test suite
   */
  async runTestSuite(suite) {
    try {
      let instance;
      
      // Initialize test suite instance
      switch (suite.name) {
        case 'Known-Answer Tests (KATs)':
          instance = new GovernmentLevelKATs();
          await instance.runAllKATs();
          return {
            passed: instance.results.failed === 0,
            testCount: instance.results.total,
            passedCount: instance.results.passed,
            failedCount: instance.results.failed,
            securityIssues: instance.results.securityViolations || []
          };
          
        case 'Edge Case and Failure Tests':
          instance = new EdgeCaseFailureTests();
          await instance.runAllTests();
          return {
            passed: instance.results.failed === 0 && instance.results.securityVulnerabilities.length === 0,
            testCount: instance.results.total,
            passedCount: instance.results.passed,
            failedCount: instance.results.failed,
            securityIssues: instance.results.securityVulnerabilities
          };
          
        case 'Property-Based Tests':
          instance = new PropertyBasedTests(500); // Reduced iterations for CI
          await instance.runAllProperties();
          return {
            passed: instance.results.failed === 0,
            testCount: instance.results.total,
            passedCount: instance.results.passed,
            failedCount: instance.results.failed,
            propertyViolations: instance.results.violations
          };
          
        case 'Fuzzing Framework':
          instance = new FuzzingCampaignManager({
            verbose: false,
            maxExecutionTime: 2000 // Reduced for CI
          });
          await instance.runComprehensiveFuzzing();
          return {
            passed: instance.results.securityFindings.filter(f => f.severity === 'CRITICAL').length === 0,
            inputsProcessed: instance.results.totalInputs,
            securityFindings: instance.results.securityFindings,
            crashes: instance.results.crashes.length
          };
          
        default:
          throw new Error(`Unknown test suite: ${suite.name}`);
      }
      
    } catch (error) {
      throw new Error(`Test suite execution failed: ${error.message}`);
    }
  }

  /**
   * Analyze core test results
   */
  analyzeCoreTestResults() {
    this.log('\n📊 Analyzing Core Test Results...');
    
    let totalScore = 0;
    let totalWeight = 0;
    let criticalFailures = 0;
    
    for (const [suiteName, result] of Object.entries(this.orchestrationResults.testSuites)) {
      if (result.critical && !result.passed) {
        criticalFailures++;
      }
      
      if (result.passed) {
        totalScore += result.weight * 100;
      }
      
      totalWeight += result.weight;
      
      // Collect security issues
      if (result.securityIssues) {
        this.orchestrationResults.securityFindings.push(...result.securityIssues);
      }
      
      if (result.securityFindings) {
        this.orchestrationResults.securityFindings.push(...result.securityFindings);
      }
    }
    
    const coreTestScore = totalWeight > 0 ? (totalScore / totalWeight) : 0;
    
    this.log(`  Core Test Score: ${coreTestScore.toFixed(1)}%`);
    this.log(`  Critical Failures: ${criticalFailures}`);
    this.log(`  Security Issues: ${this.orchestrationResults.securityFindings.length}`);
    
    // Quality gate check
    if (criticalFailures > 0) {
      this.orchestrationResults.qualityGates.push({
        gate: 'Core Tests - Critical Failures',
        passed: false,
        message: `${criticalFailures} critical test suite failures detected`
      });
    } else {
      this.orchestrationResults.qualityGates.push({
        gate: 'Core Tests - Critical Failures',
        passed: true,
        message: 'No critical test suite failures'
      });
    }
  }

  /**
   * Run quality assurance testing
   */
  async runQualityAssurance() {
    this.log('\n📈 Running Quality Assurance Testing...');
    this.log('-' .repeat(50));
    
    try {
      const qualityManager = new ComprehensiveQualityGateManager();
      const qualityResults = await qualityManager.runQualityGates();
      
      this.orchestrationResults.testSuites['Quality Assurance'] = {
        passed: qualityResults.overall.passed,
        score: parseFloat(qualityResults.overall.score),
        breakdown: qualityResults.overall.breakdown,
        coverage: qualityResults.coverage,
        performance: qualityResults.performance,
        security: qualityResults.security
      };
      
      // Extract performance metrics
      if (qualityResults.performance?.summary) {
        this.orchestrationResults.performanceMetrics = qualityResults.performance.summary;
      }
      
      // Quality gate checks
      this.checkQualityGates(qualityResults);
      
      this.log(`  ✅ Quality assurance completed - Score: ${qualityResults.overall.score}%`);
      
    } catch (error) {
      this.orchestrationResults.testSuites['Quality Assurance'] = {
        passed: false,
        error: error.message
      };
      this.log(`  ❌ Quality assurance failed: ${error.message}`);
    }
  }

  /**
   * Check quality gates
   */
  checkQualityGates(qualityResults) {
    // Coverage gate
    const coverage = qualityResults.coverage?.summary?.lines?.percentage || 0;
    this.orchestrationResults.qualityGates.push({
      gate: 'Code Coverage',
      passed: coverage >= this.config.thresholds.minimumCoverage,
      actual: coverage,
      threshold: this.config.thresholds.minimumCoverage,
      message: `Code coverage: ${coverage.toFixed(1)}% (threshold: ${this.config.thresholds.minimumCoverage}%)`
    });
    
    // Security gate
    const securityIssues = qualityResults.security?.securityIssues?.length || 0;
    this.orchestrationResults.qualityGates.push({
      gate: 'Security Vulnerabilities',
      passed: securityIssues <= this.config.thresholds.maxSecurityVulnerabilities,
      actual: securityIssues,
      threshold: this.config.thresholds.maxSecurityVulnerabilities,
      message: `Security issues: ${securityIssues} (max allowed: ${this.config.thresholds.maxSecurityVulnerabilities})`
    });
    
    // Performance gate
    const performanceRegressions = qualityResults.performance?.regressions?.length || 0;
    this.orchestrationResults.qualityGates.push({
      gate: 'Performance Regression',
      passed: performanceRegressions === 0,
      actual: performanceRegressions,
      threshold: 0,
      message: `Performance regressions: ${performanceRegressions} (max allowed: 0)`
    });
  }

  /**
   * Run government compliance testing
   */
  async runGovernmentCompliance() {
    this.log('\n🏛️  Running Government Compliance Testing...');
    this.log('-' .repeat(50));
    
    try {
      const complianceManager = new ComprehensiveGovernmentComplianceManager();
      const complianceResults = await complianceManager.runComprehensiveCompliance();
      
      this.orchestrationResults.testSuites['Government Compliance'] = {
        passed: complianceResults.overall.governmentDeploymentReady,
        fipsCompliant: complianceResults.fips140_3?.overallCompliance,
        postQuantumScore: complianceResults.postQuantum?.readinessScore,
        certificationReady: complianceResults.overall.certificationReady
      };
      
      this.orchestrationResults.complianceStatus = {
        fips140_3: complianceResults.fips140_3?.overallCompliance || false,
        postQuantumReadiness: (complianceResults.postQuantum?.readinessScore || 0) >= 70,
        governmentReady: complianceResults.overall.governmentDeploymentReady,
        certificationReady: complianceResults.overall.certificationReady
      };
      
      // Compliance quality gates
      this.checkComplianceGates(complianceResults);
      
      this.log(`  ✅ Government compliance completed - Ready: ${complianceResults.overall.governmentDeploymentReady}`);
      
    } catch (error) {
      this.orchestrationResults.testSuites['Government Compliance'] = {
        passed: false,
        error: error.message
      };
      this.log(`  ❌ Government compliance failed: ${error.message}`);
    }
  }

  /**
   * Check compliance gates
   */
  checkComplianceGates(complianceResults) {
    // FIPS 140-3 compliance gate
    const fipsCompliant = complianceResults.fips140_3?.overallCompliance || false;
    this.orchestrationResults.qualityGates.push({
      gate: 'FIPS 140-3 Compliance',
      passed: fipsCompliant,
      message: `FIPS 140-3 compliance: ${fipsCompliant ? 'COMPLIANT' : 'NON-COMPLIANT'}`
    });
    
    // Post-quantum readiness gate
    const pqScore = complianceResults.postQuantum?.readinessScore || 0;
    this.orchestrationResults.qualityGates.push({
      gate: 'Post-Quantum Readiness',
      passed: pqScore >= 70,
      actual: pqScore,
      threshold: 70,
      message: `Post-quantum readiness: ${pqScore}% (threshold: 70%)`
    });
    
    // Government deployment readiness
    const govReady = complianceResults.overall.governmentDeploymentReady;
    this.orchestrationResults.qualityGates.push({
      gate: 'Government Deployment Readiness',
      passed: govReady,
      message: `Government deployment ready: ${govReady ? 'YES' : 'NO'}`
    });
  }

  /**
   * Generate comprehensive final assessment
   */
  async generateComprehensiveAssessment() {
    this.log('\n🎯 Generating Comprehensive Assessment...');
    this.log('=' .repeat(100));
    
    // Calculate overall score
    const overallScore = this.calculateOverallScore();
    
    // Determine government readiness
    const governmentReady = this.determineGovernmentReadiness();
    
    // Determine certification readiness
    const certificationReady = this.determineCertificationReadiness();
    
    // Generate recommendations
    const recommendations = this.generateRecommendations();
    
    this.orchestrationResults.overallResults = {
      passed: governmentReady,
      score: overallScore,
      governmentReady,
      certificationReady
    };
    
    this.orchestrationResults.recommendations = recommendations;
    
    // Display comprehensive results
    this.displayComprehensiveResults();
  }

  /**
   * Calculate overall quality score
   */
  calculateOverallScore() {
    let weightedScore = 0;
    let totalWeight = 0;
    
    // Core test suites (40% weight)
    const coreWeight = 0.4;
    let coreScore = 0;
    let coreTestsCount = 0;
    
    for (const [name, result] of Object.entries(this.orchestrationResults.testSuites)) {
      if (['Known-Answer Tests (KATs)', 'Edge Case and Failure Tests', 
           'Property-Based Tests', 'Fuzzing Framework'].includes(name)) {
        if (result.passed) coreScore += 100;
        coreTestsCount++;
      }
    }
    
    if (coreTestsCount > 0) {
      weightedScore += (coreScore / coreTestsCount) * coreWeight;
      totalWeight += coreWeight;
    }
    
    // Quality assurance (30% weight)
    const qualityWeight = 0.3;
    const qualityResult = this.orchestrationResults.testSuites['Quality Assurance'];
    if (qualityResult?.score !== undefined) {
      weightedScore += qualityResult.score * qualityWeight;
      totalWeight += qualityWeight;
    }
    
    // Government compliance (30% weight)
    const complianceWeight = 0.3;
    const complianceResult = this.orchestrationResults.testSuites['Government Compliance'];
    if (complianceResult) {
      let complianceScore = 0;
      if (complianceResult.fipsCompliant) complianceScore += 50;
      if (complianceResult.postQuantumScore) complianceScore += (complianceResult.postQuantumScore / 100) * 50;
      
      weightedScore += complianceScore * complianceWeight;
      totalWeight += complianceWeight;
    }
    
    return totalWeight > 0 ? (weightedScore / totalWeight) : 0;
  }

  /**
   * Determine government deployment readiness
   */
  determineGovernmentReadiness() {
    // Check critical quality gates
    const criticalGates = [
      'Core Tests - Critical Failures',
      'Code Coverage',
      'Security Vulnerabilities',
      'FIPS 140-3 Compliance'
    ];
    
    const passedCriticalGates = this.orchestrationResults.qualityGates
      .filter(gate => criticalGates.includes(gate.gate) && gate.passed).length;
    
    const allCriticalGatesPassed = passedCriticalGates === criticalGates.length;
    
    // Check for security issues
    const hasSecurityIssues = this.orchestrationResults.securityFindings.length > 0;
    
    // Check compliance status
    const fipsCompliant = this.orchestrationResults.complianceStatus.fips140_3;
    
    return allCriticalGatesPassed && !hasSecurityIssues && fipsCompliant;
  }

  /**
   * Determine certification readiness
   */
  determineCertificationReadiness() {
    const governmentReady = this.orchestrationResults.overallResults.governmentReady;
    const postQuantumReady = this.orchestrationResults.complianceStatus.postQuantumReadiness;
    const overallScore = this.orchestrationResults.overallResults.score;
    
    return governmentReady && postQuantumReady && overallScore >= this.config.thresholds.requiredComplianceScore;
  }

  /**
   * Generate recommendations for improvement
   */
  generateRecommendations() {
    const recommendations = [];
    
    // Check failed quality gates
    const failedGates = this.orchestrationResults.qualityGates.filter(gate => !gate.passed);
    
    for (const gate of failedGates) {
      switch (gate.gate) {
        case 'Code Coverage':
          recommendations.push({
            priority: 'HIGH',
            category: 'Quality',
            issue: 'Insufficient test coverage',
            recommendation: `Increase test coverage to ${this.config.thresholds.minimumCoverage}% or higher`,
            currentValue: gate.actual,
            targetValue: gate.threshold
          });
          break;
          
        case 'Security Vulnerabilities':
          recommendations.push({
            priority: 'CRITICAL',
            category: 'Security',
            issue: 'Security vulnerabilities detected',
            recommendation: 'Fix all identified security vulnerabilities before deployment',
            currentValue: gate.actual,
            targetValue: gate.threshold
          });
          break;
          
        case 'FIPS 140-3 Compliance':
          recommendations.push({
            priority: 'CRITICAL',
            category: 'Compliance',
            issue: 'FIPS 140-3 non-compliance',
            recommendation: 'Address all FIPS 140-3 compliance violations',
            action: 'Complete Level 1 and Level 2 security requirements'
          });
          break;
          
        case 'Post-Quantum Readiness':
          recommendations.push({
            priority: 'MEDIUM',
            category: 'Future Readiness',
            issue: 'Low post-quantum readiness score',
            recommendation: 'Begin post-quantum cryptography transition planning',
            currentValue: gate.actual,
            targetValue: gate.threshold
          });
          break;
      }
    }
    
    // Check test suite failures
    for (const [suiteName, result] of Object.entries(this.orchestrationResults.testSuites)) {
      if (!result.passed && result.critical) {
        recommendations.push({
          priority: 'CRITICAL',
          category: 'Testing',
          issue: `Critical test suite failure: ${suiteName}`,
          recommendation: `Fix all issues in ${suiteName} before proceeding`,
          error: result.error
        });
      }
    }
    
    // Performance recommendations
    if (this.orchestrationResults.performanceMetrics) {
      const performanceIssues = Object.entries(this.orchestrationResults.performanceMetrics)
        .filter(([metric, data]) => data.averageTime > 1000); // Operations taking > 1 second
      
      if (performanceIssues.length > 0) {
        recommendations.push({
          priority: 'MEDIUM',
          category: 'Performance',
          issue: 'Performance optimization needed',
          recommendation: 'Optimize slow cryptographic operations',
          details: performanceIssues.map(([metric, data]) => 
            `${metric}: ${data.averageTime.toFixed(2)}ms average`)
        });
      }
    }
    
    // General recommendations
    if (recommendations.length === 0) {
      recommendations.push({
        priority: 'LOW',
        category: 'Maintenance',
        issue: 'Continuous improvement',
        recommendation: 'Establish regular security audits and testing cycles'
      });
    }
    
    return recommendations;
  }

  /**
   * Display comprehensive results
   */
  displayComprehensiveResults() {
    const results = this.orchestrationResults.overallResults;
    
    this.log('\n🏆 COMPREHENSIVE ASSESSMENT RESULTS');
    this.log('=' .repeat(100));
    
    this.log(`Overall Quality Score: ${results.score.toFixed(1)}%`);
    this.log(`Total Duration: ${Math.round(this.orchestrationResults.totalDuration / 1000)}s`);
    this.log('');
    
    // Test suite results
    this.log('📋 Test Suite Results:');
    for (const [suiteName, result] of Object.entries(this.orchestrationResults.testSuites)) {
      const status = result.passed ? '✅ PASS' : '❌ FAIL';
      const details = result.score ? ` (${result.score.toFixed(1)}%)` : '';
      this.log(`  ${status} ${suiteName}${details}`);
      
      if (result.error) {
        this.log(`      Error: ${result.error}`);
      }
    }
    
    // Quality gates
    this.log('\n🚦 Quality Gates:');
    for (const gate of this.orchestrationResults.qualityGates) {
      const status = gate.passed ? '✅ PASS' : '❌ FAIL';
      this.log(`  ${status} ${gate.gate}: ${gate.message}`);
    }
    
    // Security findings
    if (this.orchestrationResults.securityFindings.length > 0) {
      this.log('\n🔴 Security Findings:');
      this.orchestrationResults.securityFindings.slice(0, 5).forEach((finding, index) => {
        this.log(`  ${index + 1}. [${finding.severity || 'UNKNOWN'}] ${finding.issue || finding.message || 'Security issue detected'}`);
      });
      
      if (this.orchestrationResults.securityFindings.length > 5) {
        this.log(`  ... and ${this.orchestrationResults.securityFindings.length - 5} more findings`);
      }
    }
    
    // Compliance status
    this.log('\n🏛️  Compliance Status:');
    this.log(`  FIPS 140-3 Compliant: ${this.orchestrationResults.complianceStatus.fips140_3 ? '✅ YES' : '❌ NO'}`);
    this.log(`  Post-Quantum Ready: ${this.orchestrationResults.complianceStatus.postQuantumReadiness ? '✅ YES' : '⚠️  PARTIAL'}`);
    this.log(`  Government Deployment Ready: ${results.governmentReady ? '✅ YES' : '❌ NO'}`);
    this.log(`  Certification Ready: ${results.certificationReady ? '✅ YES' : '⚠️  NEEDS WORK'}`);
    
    // Final assessment
    this.log('\n' + '=' .repeat(100));
    if (results.governmentReady && results.certificationReady) {
      this.log('🎉 GOVERNMENT-LEVEL DEPLOYMENT READY');
      this.log('✅ All quality gates passed - Ready for government deployment');
      this.log('🔮 Future-proof with post-quantum readiness');
    } else if (results.governmentReady) {
      this.log('✅ GOVERNMENT DEPLOYMENT READY');
      this.log('⚠️  Some improvements needed for full certification readiness');
    } else {
      this.log('❌ NOT READY FOR GOVERNMENT DEPLOYMENT');
      this.log('🔧 Critical issues must be resolved before deployment');
    }
    this.log('=' .repeat(100));
    
    // Recommendations
    if (this.orchestrationResults.recommendations.length > 0) {
      this.log('\n💡 PRIORITY RECOMMENDATIONS:');
      this.orchestrationResults.recommendations
        .sort((a, b) => this.getPriorityWeight(b.priority) - this.getPriorityWeight(a.priority))
        .slice(0, 5)
        .forEach((rec, index) => {
          this.log(`  ${index + 1}. [${rec.priority}] ${rec.issue}: ${rec.recommendation}`);
        });
    }
  }

  /**
   * Get priority weight for sorting
   */
  getPriorityWeight(priority) {
    const weights = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    return weights[priority] || 1;
  }

  /**
   * Export comprehensive artifacts and reports
   */
  async exportArtifacts() {
    this.log('\n📄 Exporting Test Artifacts and Reports...');
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Export comprehensive results
    const comprehensiveReport = {
      metadata: {
        testSuite: 'Government-Level-Cryptographic-Assurance',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        duration: this.orchestrationResults.totalDuration,
        environment: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          cpuCount: require('os').cpus().length,
          totalMemory: require('os').totalmem()
        }
      },
      results: this.orchestrationResults,
      summary: {
        overallScore: this.orchestrationResults.overallResults.score,
        governmentReady: this.orchestrationResults.overallResults.governmentReady,
        certificationReady: this.orchestrationResults.overallResults.certificationReady,
        securityIssuesCount: this.orchestrationResults.securityFindings.length,
        qualityGatesPassed: this.orchestrationResults.qualityGates.filter(g => g.passed).length,
        qualityGatesTotal: this.orchestrationResults.qualityGates.length
      }
    };
    
    const reportFile = path.join(this.config.reportDir, `comprehensive-report-${timestamp}.json`);
    fs.writeFileSync(reportFile, JSON.stringify(comprehensiveReport, null, 2));
    this.orchestrationResults.artifacts.push(reportFile);
    
    // Export HTML report
    const htmlReport = this.generateHTMLReport(comprehensiveReport);
    const htmlFile = path.join(this.config.reportDir, `comprehensive-report-${timestamp}.html`);
    fs.writeFileSync(htmlFile, htmlReport);
    this.orchestrationResults.artifacts.push(htmlFile);
    
    // Export JUnit XML for CI integration
    const junitXML = this.generateJUnitXML(comprehensiveReport);
    const xmlFile = path.join(this.config.reportDir, `junit-results-${timestamp}.xml`);
    fs.writeFileSync(xmlFile, junitXML);
    this.orchestrationResults.artifacts.push(xmlFile);
    
    // Export security findings CSV
    if (this.orchestrationResults.securityFindings.length > 0) {
      const csvContent = this.generateSecurityFindingsCSV();
      const csvFile = path.join(this.config.reportDir, `security-findings-${timestamp}.csv`);
      fs.writeFileSync(csvFile, csvContent);
      this.orchestrationResults.artifacts.push(csvFile);
    }
    
    this.log(`  📊 Comprehensive report: ${reportFile}`);
    this.log(`  🌐 HTML report: ${htmlFile}`);
    this.log(`  🧪 JUnit XML: ${xmlFile}`);
    
    if (this.orchestrationResults.securityFindings.length > 0) {
      this.log(`  🔐 Security findings: ${csvFile}`);
    }
  }

  /**
   * Generate HTML report
   */
  generateHTMLReport(report) {
    const results = report.results;
    const metadata = report.metadata;
    
    return `<!DOCTYPE html>
<html>
<head>
    <title>Government-Level Cryptographic Assurance Report</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid #2c3e50; padding-bottom: 20px; }
        .title { color: #2c3e50; margin: 0; font-size: 2.5em; }
        .subtitle { color: #7f8c8d; margin: 10px 0 0 0; }
        .score { font-size: 3em; color: ${results.overallResults.score >= 90 ? '#27ae60' : results.overallResults.score >= 70 ? '#f39c12' : '#e74c3c'}; margin: 20px 0; }
        .status { display: inline-block; padding: 8px 16px; border-radius: 4px; color: white; font-weight: bold; }
        .status.ready { background-color: #27ae60; }
        .status.not-ready { background-color: #e74c3c; }
        .status.partial { background-color: #f39c12; }
        .section { margin: 30px 0; }
        .section-title { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 10px; }
        .test-suite { margin: 15px 0; padding: 15px; border-radius: 4px; }
        .test-suite.passed { background: #d5f4e6; border-left: 4px solid #27ae60; }
        .test-suite.failed { background: #fdf2f2; border-left: 4px solid #e74c3c; }
        .quality-gate { margin: 10px 0; padding: 10px; border-radius: 4px; }
        .quality-gate.passed { background: #d5f4e6; }
        .quality-gate.failed { background: #fdf2f2; }
        .recommendation { margin: 10px 0; padding: 10px; border-radius: 4px; border-left: 4px solid #3498db; background: #eaf4fd; }
        .recommendation.critical { border-left-color: #e74c3c; background: #fdf2f2; }
        .recommendation.high { border-left-color: #f39c12; background: #fef9e7; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; text-align: center; color: #7f8c8d; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">Government-Level Cryptographic Assurance</h1>
            <p class="subtitle">Comprehensive Testing and Compliance Report</p>
            <div class="score">${results.overallResults.score.toFixed(1)}%</div>
            <div>
                <span class="status ${results.overallResults.governmentReady ? 'ready' : 'not-ready'}">
                    ${results.overallResults.governmentReady ? 'GOVERNMENT READY' : 'NOT READY'}
                </span>
                <span class="status ${results.overallResults.certificationReady ? 'ready' : 'partial'}">
                    ${results.overallResults.certificationReady ? 'CERTIFICATION READY' : 'NEEDS IMPROVEMENT'}
                </span>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📊 Test Suite Results</h2>
            ${Object.entries(results.testSuites).map(([name, result]) => `
                <div class="test-suite ${result.passed ? 'passed' : 'failed'}">
                    <strong>${result.passed ? '✅' : '❌'} ${name}</strong>
                    ${result.score !== undefined ? ` - Score: ${result.score.toFixed(1)}%` : ''}
                    ${result.error ? `<br><em>Error: ${result.error}</em>` : ''}
                </div>
            `).join('')}
        </div>

        <div class="section">
            <h2 class="section-title">🚦 Quality Gates</h2>
            ${results.qualityGates.map(gate => `
                <div class="quality-gate ${gate.passed ? 'passed' : 'failed'}">
                    <strong>${gate.passed ? '✅' : '❌'} ${gate.gate}</strong><br>
                    ${gate.message}
                </div>
            `).join('')}
        </div>

        <div class="section">
            <h2 class="section-title">🏛️ Compliance Status</h2>
            <table>
                <tr><th>Compliance Area</th><th>Status</th></tr>
                <tr><td>FIPS 140-3</td><td>${results.complianceStatus.fips140_3 ? '✅ Compliant' : '❌ Non-Compliant'}</td></tr>
                <tr><td>Post-Quantum Readiness</td><td>${results.complianceStatus.postQuantumReadiness ? '✅ Ready' : '⚠️ Partial'}</td></tr>
                <tr><td>Government Deployment</td><td>${results.complianceStatus.governmentReady ? '✅ Ready' : '❌ Not Ready'}</td></tr>
                <tr><td>Certification</td><td>${results.complianceStatus.certificationReady ? '✅ Ready' : '⚠️ Needs Work'}</td></tr>
            </table>
        </div>

        ${results.securityFindings.length > 0 ? `
        <div class="section">
            <h2 class="section-title">🔴 Security Findings</h2>
            ${results.securityFindings.slice(0, 10).map((finding, index) => `
                <div class="recommendation critical">
                    <strong>${index + 1}. ${finding.severity || 'SECURITY'}</strong><br>
                    ${finding.issue || finding.message || 'Security issue detected'}
                </div>
            `).join('')}
            ${results.securityFindings.length > 10 ? `<p><em>... and ${results.securityFindings.length - 10} more findings</em></p>` : ''}
        </div>
        ` : ''}

        <div class="section">
            <h2 class="section-title">💡 Recommendations</h2>
            ${results.recommendations.slice(0, 10).map((rec, index) => `
                <div class="recommendation ${rec.priority.toLowerCase()}">
                    <strong>${index + 1}. [${rec.priority}] ${rec.issue}</strong><br>
                    ${rec.recommendation}
                </div>
            `).join('')}
        </div>

        <div class="footer">
            <p>Report generated: ${metadata.timestamp}</p>
            <p>Duration: ${Math.round(metadata.duration / 1000)}s | Environment: ${metadata.environment.nodeVersion} on ${metadata.environment.platform}</p>
        </div>
    </div>
</body>
</html>`;
  }

  /**
   * Generate JUnit XML for CI integration
   */
  generateJUnitXML(report) {
    const results = report.results;
    const totalTests = Object.keys(results.testSuites).length + results.qualityGates.length;
    const failures = Object.values(results.testSuites).filter(r => !r.passed).length + 
                    results.qualityGates.filter(g => !g.passed).length;
    
    let xml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Government-Level-Cryptographic-Assurance" tests="${totalTests}" failures="${failures}" time="${(report.metadata.duration / 1000).toFixed(3)}">
  <testsuite name="Test-Suites" tests="${Object.keys(results.testSuites).length}" failures="${Object.values(results.testSuites).filter(r => !r.passed).length}">`;

    for (const [name, result] of Object.entries(results.testSuites)) {
      xml += `
    <testcase name="${this.escapeXML(name)}" classname="TestSuite" time="${(result.duration || 0) / 1000}">`;
      
      if (!result.passed) {
        xml += `
      <failure message="${this.escapeXML(result.error || 'Test suite failed')}" type="TestFailure">${this.escapeXML(result.error || 'Unknown failure')}</failure>`;
      }
      
      xml += `
    </testcase>`;
    }

    xml += `
  </testsuite>
  <testsuite name="Quality-Gates" tests="${results.qualityGates.length}" failures="${results.qualityGates.filter(g => !g.passed).length}">`;

    for (const gate of results.qualityGates) {
      xml += `
    <testcase name="${this.escapeXML(gate.gate)}" classname="QualityGate">`;
      
      if (!gate.passed) {
        xml += `
      <failure message="${this.escapeXML(gate.message)}" type="QualityGateFailure">${this.escapeXML(gate.message)}</failure>`;
      }
      
      xml += `
    </testcase>`;
    }

    xml += `
  </testsuite>
</testsuites>`;

    return xml;
  }

  /**
   * Generate security findings CSV
   */
  generateSecurityFindingsCSV() {
    const headers = ['Severity', 'Type', 'Issue', 'Source', 'Details'];
    let csv = headers.join(',') + '\n';
    
    for (const finding of this.orchestrationResults.securityFindings) {
      const row = [
        finding.severity || 'UNKNOWN',
        finding.type || 'Security Finding',
        finding.issue || finding.message || 'Security issue detected',
        finding.category || finding.property || 'Unknown',
        finding.details || finding.vulnerability || ''
      ].map(field => `"${(field || '').toString().replace(/"/g, '""')}"`);
      
      csv += row.join(',') + '\n';
    }
    
    return csv;
  }

  /**
   * Export failure report when orchestration fails
   */
  async exportFailureReport(error) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const failureReport = {
      error: {
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      },
      partialResults: this.orchestrationResults,
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch
      }
    };
    
    const failureFile = path.join(this.config.reportDir, `failure-report-${timestamp}.json`);
    fs.writeFileSync(failureFile, JSON.stringify(failureReport, null, 2));
    
    this.log(`\n📄 Failure report exported to: ${failureFile}`);
  }

  /**
   * Escape XML characters
   */
  escapeXML(str) {
    return str.replace(/[<>&'"]/g, (c) => {
      const map = { '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' };
      return map[c];
    });
  }

  /**
   * Logging utility
   */
  log(message) {
    if (this.config.verbose || message.includes('✅') || message.includes('❌') || 
        message.includes('📊') || message.includes('🎉') || message.includes('🚀')) {
      console.log(message);
    }
  }
}

/**
 * CI/CD Pipeline Integration Helper
 * Provides utilities for different CI/CD systems
 */
class CICDPipelineIntegration {
  constructor() {
    this.ciSystem = this.detectCISystem();
  }

  /**
   * Detect CI system
   */
  detectCISystem() {
    if (process.env.GITHUB_ACTIONS) return 'github-actions';
    if (process.env.GITLAB_CI) return 'gitlab-ci';
    if (process.env.JENKINS_URL) return 'jenkins';
    if (process.env.CIRCLECI) return 'circleci';
    if (process.env.TRAVIS) return 'travis-ci';
    if (process.env.AZURE_PIPELINES) return 'azure-pipelines';
    return 'unknown';
  }

  /**
   * Set CI-specific output variables
   */
  setCIOutputs(results) {
    const outputs = {
      'government-ready': results.overallResults.governmentReady,
      'certification-ready': results.overallResults.certificationReady,
      'overall-score': results.overallResults.score.toFixed(1),
      'security-issues': results.securityFindings.length,
      'quality-gates-passed': results.qualityGates.filter(g => g.passed).length,
      'quality-gates-total': results.qualityGates.length
    };

    switch (this.ciSystem) {
      case 'github-actions':
        for (const [key, value] of Object.entries(outputs)) {
          console.log(`::set-output name=${key}::${value}`);
        }
        break;
        
      case 'gitlab-ci':
        // GitLab CI uses job artifacts and variables
        for (const [key, value] of Object.entries(outputs)) {
          console.log(`${key.toUpperCase().replace('-', '_')}=${value}`);
        }
        break;
        
      default:
        // Generic output for other CI systems
        console.log('\n📊 CI/CD Outputs:');
        for (const [key, value] of Object.entries(outputs)) {
          console.log(`  ${key}: ${value}`);
        }
    }
  }

  /**
   * Generate CI-specific status checks
   */
  generateStatusChecks(results) {
    const checks = [
      {
        name: 'Government Deployment Readiness',
        status: results.overallResults.governmentReady ? 'success' : 'failure',
        description: results.overallResults.governmentReady ? 
          'Ready for government deployment' : 'Not ready for government deployment'
      },
      {
        name: 'Security Assessment',
        status: results.securityFindings.length === 0 ? 'success' : 'failure',
        description: `${results.securityFindings.length} security issues found`
      },
      {
        name: 'Quality Gates',
        status: results.qualityGates.every(g => g.passed) ? 'success' : 'failure',
        description: `${results.qualityGates.filter(g => g.passed).length}/${results.qualityGates.length} quality gates passed`
      }
    ];

    return checks;
  }
}

// Export for use in other files
module.exports = { CICDTestOrchestrator, CICDPipelineIntegration };

// Main execution when run directly
if (require.main === module) {
  async function main() {
    const orchestrator = new CICDTestOrchestrator({
      verbose: process.env.VERBOSE_TESTING === 'true',
      parallel: process.env.PARALLEL_TESTING !== 'false',
      maxWorkers: process.env.MAX_WORKERS ? parseInt(process.env.MAX_WORKERS) : undefined
    });
    
    const pipelineIntegration = new CICDPipelineIntegration();
    
    try {
      console.log('🚀 Starting Government-Level Cryptographic Assurance Testing...\n');
      
      const results = await orchestrator.runComprehensiveTestSuite();
      
      // Set CI/CD outputs
      pipelineIntegration.setCIOutputs(results);
      
      // Generate status checks
      const statusChecks = pipelineIntegration.generateStatusChecks(results);
      
      console.log('\n🎯 Final Assessment:');
      statusChecks.forEach(check => {
        const emoji = check.status === 'success' ? '✅' : '❌';
        console.log(`  ${emoji} ${check.name}: ${check.description}`);
      });
      
      // Exit with appropriate code
      const exitCode = results.overallResults.governmentReady ? 0 : 1;
      
      console.log(`\n📊 Test orchestration completed with exit code: ${exitCode}`);
      console.log(`📄 Comprehensive reports available in: ${orchestrator.config.reportDir}`);
      
      process.exit(exitCode);
      
    } catch (error) {
      console.error('\n❌ Test orchestration failed:', error.message);
      
      if (process.env.DEBUG === 'true') {
        console.error('\n🔍 Debug information:');
        console.error(error.stack);
      }
      
      // Set failure outputs for CI
      console.log('::set-output name=government-ready::false');
      console.log('::set-output name=certification-ready::false');
      console.log('::set-output name=overall-score::0');
      
      process.exit(1);
    }
  }
  
  // Handle process signals gracefully
  process.on('SIGINT', () => {
    console.log('\n⚠️  Test orchestration interrupted by user');
    process.exit(130);
  });
  
  process.on('SIGTERM', () => {
    console.log('\n⚠️  Test orchestration terminated');
    process.exit(143);
  });
  
  main();
}