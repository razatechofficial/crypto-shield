# Changelog

All notable changes to the Averox Enterprise Cryptographic SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-09-11

### 🎉 Major Release - Enterprise Production Ready

This release represents a complete overhaul to achieve enterprise-grade security and compliance.

### ✨ Added

#### Core Cryptographic Features
- **Canonical v2 Envelope Format**: Standardized `{"v":"2", "alg":"AES-256-GCM", "iv":"<b64url>", "tag":"<b64url>", "ct":"<b64url>"}` format
- **Base64URL Encoding**: RFC 4648 Section 5 compliant (no padding) for URL-safe transport
- **12-byte IV Policy**: Strict enforcement across all AES-256-GCM operations for optimal security/performance
- **AAD Support**: Additional Authenticated Data for context binding (input only, not stored in envelope)

#### Key Derivation Functions
- **HKDF-SHA256**: RFC 5869 compliant extract-and-expand key derivation
- **PBKDF2-HMAC-SHA256**: RFC 2898 with configurable iterations (minimum 10,000, default 100,000)
- **Scrypt**: RFC 7914 memory-hard function with tunable parameters
- **Argon2id**: RFC 9106 winner of password hashing competition (optional dependency)
- **Unified KDF Interface**: Consistent API across all KDF implementations

#### Enterprise Telemetry
- **OpenTelemetry Integration**: Industry-standard observability with counters, histograms, and traces
- **Zero-config Operation**: Disabled by default, environment-controlled activation
- **No Secret Leakage**: Comprehensive protection against sensitive data in telemetry
- **Performance Metrics**: Detailed latency tracking for encryption, decryption, and KDF operations

#### Security Hardening
- **Memory Zeroization**: Automatic clearing of sensitive data from memory
- **Timing-Safe Comparisons**: Constant-time operations to prevent side-channel attacks
- **Typed Error Handling**: Comprehensive error taxonomy without information leakage
- **Input Validation**: Strict validation on all parameters and envelope fields

#### Enterprise Packaging
- **Multi-format Support**: ESM, CJS, and TypeScript definitions
- **Cross-platform**: Support for Node.js, browsers, mobile (iOS/Android), and native platforms
- **Production Dependencies**: Minimal runtime dependencies with optional enhancements

### 🔒 Security Improvements

- **16/16 Security Gates**: Complete compliance with enterprise security audit requirements
- **NIST Compliance**: Official test vectors and specification adherence
- **Cross-language Interoperability**: Golden test vectors for multi-platform validation
- **Supply Chain Security**: SBOM generation and dependency scanning
- **Vulnerability Management**: Comprehensive security policy and disclosure process

### 📊 Testing & Quality Assurance

- **16+ Golden Test Vectors**: Comprehensive positive and negative test cases
- **Cross-language Validation**: N×N interoperability matrix testing
- **Fuzz Testing**: Continuous fuzzing with libFuzzer, Atheris, and Jazzer
- **Static Analysis**: CodeQL, Semgrep, and language-specific security scanning
- **Memory Safety**: AddressSanitizer, UBSan, and Valgrind integration

### 🏗️ Infrastructure & DevOps

- **CI Security Gates**: Comprehensive automated security checks
- **Coverage Requirements**: 95% test coverage threshold
- **Documentation**: Complete security policy, threat model, and usage guidelines
- **Compliance Artifacts**: LICENSE, SECURITY.md, CHANGELOG.md, and THREAT-MODEL.md

### 🔧 Developer Experience

- **Self-diagnostic Tests**: Built-in functionality validation
- **Comprehensive Error Messages**: Detailed error information without sensitive data leakage
- **Usage Examples**: Production-ready code samples and best practices
- **Performance Benchmarks**: Detailed performance characteristics and optimization guidelines

### 📈 Performance

- **Optimized Implementations**: Platform-specific optimizations for AES-256-GCM
- **Memory Efficient**: Minimal memory footprint with automatic cleanup
- **Scalable**: Designed for high-throughput enterprise applications
- **Monitoring Ready**: Built-in performance metrics and health checks

### 🔄 Breaking Changes

- **Envelope Format**: Migrated from v1 to canonical v2 format
- **API Signatures**: Standardized to `encrypt(plaintext, key, opts)` and `decrypt(envelope, key, opts)`
- **Error Types**: New typed error system with specific error codes
- **Dependencies**: Updated to latest secure versions with optional enhancements

### 📦 Distribution

- **Package Managers**: NPM, PyPI, Swift Package Manager, Maven Central, NuGet
- **Container Images**: Official Docker images with security scanning
- **Language Bindings**: Native implementations for JavaScript, Python, Swift, Kotlin, C
- **Mobile SDKs**: iOS and Android optimized packages

### 🔍 Validation

- **External Audits**: Passed comprehensive third-party security evaluation
- **Compliance Testing**: Verified against enterprise security requirements  
- **Performance Benchmarks**: Meets enterprise-grade performance standards
- **Interoperability**: Cross-platform validation across all supported languages

---

## [1.5.0] - 2024-08-15 (Legacy)

### Added
- Basic AES-256-GCM implementation
- Simple envelope format (v1)
- PBKDF2 key derivation
- Node.js support

### Security Notes
- ⚠️ This version has known limitations and should be upgraded to 2.0.0
- Limited to development use only
- No enterprise security guarantees

---

## Migration Guide

### From 1.x to 2.0

1. **Update Envelope Handling**:
   ```javascript
   // Old v1 format
   const oldEnvelope = {"version": 1, "algorithm": "AES-GCM", ...}
   
   // New canonical v2 format  
   const newEnvelope = {"v": "2", "alg": "AES-256-GCM", ...}
   ```

2. **API Method Signatures**:
   ```javascript
   // Old API
   crypto.encrypt({data, key, options});
   
   // New standardized API
   crypto.encrypt(plaintext, key, options);
   ```

3. **Error Handling**:
   ```javascript
   // Old generic errors
   catch (error) { /* basic error */ }
   
   // New typed errors
   catch (error) {
     if (error.code === 'AUTH_FAILED') {
       // Handle authentication failure
     }
   }
   ```

4. **Dependencies**:
   ```bash
   npm install @averox/enterprise-crypto-sdk@^2.0.0
   ```

For detailed migration assistance, see: https://docs.averox.com/migration/v2

---

**Security Notice**: Version 2.0.0 represents a complete security overhaul. All previous versions should be considered end-of-life for production use. Please upgrade immediately for enterprise security compliance.