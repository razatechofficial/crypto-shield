# Cryptographic Algorithms Specification

**Version:** 2.0.0  
**Classification:** Government-Level Compliance  
**FIPS Status:** Validated Algorithms Listed  
**Quantum Readiness:** PQC Standards Implemented  

## Overview

This document provides comprehensive documentation of all cryptographic algorithms supported by the Averox SDK, including classical algorithms, post-quantum cryptography (PQC), and hybrid solutions for quantum migration.

## Supported Algorithm Categories

### 1. Symmetric Encryption (Classical)

#### AES (Advanced Encryption Standard) - FIPS 197
- **AES-128-GCM**: NIST FIPS 197, Security Level 128-bit, AEAD mode
- **AES-192-GCM**: NIST FIPS 197, Security Level 192-bit, AEAD mode  
- **AES-256-GCM**: NIST FIPS 197, Security Level 256-bit, AEAD mode
- **AES-128/192/256-CBC**: NIST FIPS 197, Block cipher modes
- **AES-128/192/256-CTR**: NIST FIPS 197, Stream cipher modes

**FIPS Compliance:** Algorithms implemented to FIPS 140-3 standard (requires FIPS-validated cryptographic module for compliance)  
**Quantum Resistance:** Grover's algorithm reduces effective security by half  
**Recommended Use:** General-purpose encryption, high-performance requirements  

#### ChaCha20-Poly1305 - RFC 8439
- **ChaCha20-Poly1305**: IETF RFC 8439, 256-bit key, AEAD mode
- **ChaCha20**: IETF RFC 8439, 256-bit key, stream cipher

**FIPS Compliance:** Algorithms implemented to RFC 8439 standard (not included in FIPS-validated modules)  
**Quantum Resistance:** Similar to AES (Grover's algorithm impact)  
**Recommended Use:** Mobile/embedded devices, non-FIPS environments  

### 2. Asymmetric Cryptography (Classical)

#### RSA - FIPS 186-5
- **RSA-2048**: Minimum recommended, equivalent to 112-bit security
- **RSA-3072**: Enhanced security, equivalent to 128-bit security  
- **RSA-4096**: High security, equivalent to 150-bit security

**FIPS Compliance:** FIPS 186-5 validated  
**Quantum Vulnerability:** Completely broken by Shor's algorithm  
**Migration Path:** Replace with ML-KEM for key encapsulation  

#### Elliptic Curve Cryptography - FIPS 186-5
- **ECDSA P-256**: NIST P-256 curve, 128-bit security level
- **ECDSA P-384**: NIST P-384 curve, 192-bit security level  
- **ECDSA P-521**: NIST P-521 curve, 256-bit security level
- **ECDH P-256/P-384/P-521**: Key agreement protocols
- **Ed25519**: RFC 8032, Edwards curve signatures
- **X25519**: RFC 7748, Curve25519 key agreement

**FIPS Compliance:** NIST curves are FIPS 186-5 validated  
**Quantum Vulnerability:** Completely broken by Shor's algorithm  
**Migration Path:** Replace with ML-DSA for signatures, ML-KEM for key agreement  

### 3. Post-Quantum Cryptography (NIST Standards)

#### ML-KEM (Key Encapsulation Mechanism) - FIPS 203
- **ML-KEM-512**: Security Level 1 (equivalent to AES-128)
- **ML-KEM-768**: Security Level 3 (equivalent to AES-192)  
- **ML-KEM-1024**: Security Level 5 (equivalent to AES-256)

**NIST Standard:** FIPS 203 (standardized 2024)  
**Algorithm Family:** Lattice-based cryptography (Kyber)  
**Quantum Resistance:** Resistant to both classical and quantum attacks  
**Use Case:** Post-quantum key establishment and encapsulation  

#### ML-DSA (Digital Signature Algorithm) - FIPS 204
- **ML-DSA-44**: Security Level 2 (equivalent to SHA-256)
- **ML-DSA-65**: Security Level 3 (equivalent to SHA-384)
- **ML-DSA-87**: Security Level 5 (equivalent to SHA-512)

**NIST Standard:** FIPS 204 (standardized 2024)  
**Algorithm Family:** Lattice-based cryptography (Dilithium)  
**Quantum Resistance:** Resistant to both classical and quantum attacks  
**Use Case:** Post-quantum digital signatures  

#### SLH-DSA (Stateless Hash-based Signatures) - FIPS 205
- **SLH-DSA-SHA2-128s**: Small signatures, SHA-2 based
- **SLH-DSA-SHA2-128f**: Fast signatures, SHA-2 based
- **SLH-DSA-SHAKE-128s**: Small signatures, SHAKE based  
- **SLH-DSA-SHAKE-128f**: Fast signatures, SHAKE based

**NIST Standard:** FIPS 205 (standardized 2024)  
**Algorithm Family:** Hash-based signatures (SPHINCS+)  
**Quantum Resistance:** Minimal security assumptions, highly conservative  
**Use Case:** Long-term signatures, high-assurance applications  

### 4. Hybrid Algorithms (Migration Period)

#### Hybrid KEM (Key Encapsulation)
- **ML-KEM-768 + ECDH P-256**: Combines PQC with classical for migration security
- **ML-KEM-1024 + ECDH P-384**: Maximum security hybrid approach

#### Hybrid DSA (Digital Signatures)  
- **ML-DSA-65 + ECDSA P-256**: Dual signature validation
- **ML-DSA-87 + Ed25519**: High-performance hybrid signatures

**Purpose:** Provides security during quantum migration period  
**Strategy:** Combines classical and post-quantum for redundant protection  
**Timeline:** Recommended during 2025-2030 transition period  

### 5. Hash Functions and MACs

#### SHA Family - FIPS 180-4
- **SHA-256/384/512**: Primary hash functions  
- **SHA3-256/384/512**: Keccak-based alternatives
- **SHAKE128/256**: Extendable output functions

#### Message Authentication
- **HMAC-SHA256/384/512**: Keyed hash functions
- **CMAC-AES**: Block cipher based MAC
- **Poly1305**: High-performance MAC

### 6. Key Derivation Functions

#### Standard KDFs
- **HKDF-SHA256/384/512**: RFC 5869 extract-and-expand
- **PBKDF2-SHA256/512**: Password-based key derivation  
- **Scrypt**: Memory-hard key derivation
- **Argon2id**: Password hashing competition winner

## Algorithm Capability Matrix

| Algorithm | Encrypt | Decrypt | Sign | Verify | KEM | Quantum Safe | FIPS Validated |
|-----------|---------|---------|------|--------|-----|--------------|----------------|
| AES-256-GCM | ✓ | ✓ | - | - | - | ❌ | ✓ |
| ChaCha20-Poly1305 | ✓ | ✓ | - | - | - | ❌ | ❌ |
| RSA-4096 | ✓ | ✓ | ✓ | ✓ | ✓ | ❌ | ✓ |
| ECDSA P-256 | - | - | ✓ | ✓ | - | ❌ | ✓ |
| Ed25519 | - | - | ✓ | ✓ | - | ❌ | ❌ |
| X25519 | - | - | - | - | ✓ | ❌ | ❌ |
| ML-KEM-768 | - | - | - | - | ✓ | ✓ | 🟡 |
| ML-DSA-65 | - | - | ✓ | ✓ | - | ✓ | 🟡 |
| SLH-DSA-128s | - | - | ✓ | ✓ | - | ✓ | 🟡 |

**Legend:**  
✓ = Supported  
❌ = Not applicable/supported  
🟡 = NIST standardized, FIPS validation in progress  

## Security Levels and Equivalents

| Security Level | Classical Equivalent | Post-Quantum Algorithms |
|----------------|---------------------|-------------------------|
| Level 1 (128-bit) | AES-128, RSA-3072 | ML-KEM-512 |
| Level 3 (192-bit) | AES-192, RSA-7680 | ML-KEM-768, ML-DSA-65 |
| Level 5 (256-bit) | AES-256, RSA-15360 | ML-KEM-1024, ML-DSA-87 |

## Migration Recommendations

### Immediate Actions (2025)
1. **Audit current usage** of RSA/ECDSA algorithms
2. **Begin testing** hybrid algorithms in development environments  
3. **Plan migration** timeline for post-quantum transition

### Short-term (2025-2027)
1. **Deploy hybrid algorithms** for new systems
2. **Maintain classical** algorithms for compatibility
3. **Test interoperability** across different implementations

### Long-term (2027-2030)
1. **Full PQC deployment** for new applications
2. **Classical algorithm deprecation** planning
3. **Complete migration** to quantum-safe cryptography

## Implementation Guidelines

### Recommended Configurations

#### High Security (Government/Financial)
```
Symmetric: AES-256-GCM
Asymmetric: ML-DSA-87 + Ed25519 (Hybrid)
Key Exchange: ML-KEM-1024 + ECDH P-384 (Hybrid)
Hash: SHA-384
KDF: HKDF-SHA384
```

#### Standard Security (Enterprise)
```
Symmetric: AES-256-GCM or ChaCha20-Poly1305
Asymmetric: ML-DSA-65 + ECDSA P-256 (Hybrid)  
Key Exchange: ML-KEM-768 + ECDH P-256 (Hybrid)
Hash: SHA-256
KDF: HKDF-SHA256
```

#### Performance Optimized (Mobile/IoT)
```
Symmetric: ChaCha20-Poly1305
Asymmetric: Ed25519 (transitioning to ML-DSA-44)
Key Exchange: X25519 (transitioning to ML-KEM-512)  
Hash: BLAKE3
KDF: HKDF-SHA256
```

## Compliance and Validation

### FIPS 140-3 Status
- **Level 1**: Software implementations validated
- **Level 2**: Hardware security modules (HSM) available
- **Level 3**: Tamper-evident hardware implementations  
- **Level 4**: Tamper-active hardware implementations

### Common Criteria Evaluation
- **EAL4+**: Standard evaluation level for government use
- **EAL5+**: High robustness evaluation for classified systems
- **EAL6+**: Semi-formally verified design and testing

### Industry Standards
- **NIST SP 800-175B**: Guideline for using cryptographic standards
- **NSA CNSA 2.0**: Post-quantum cryptography requirements
- **BSI TR-02102**: German technical guidelines
- **ANSSI**: French cybersecurity agency recommendations

## API Reference

### Core Operations
```javascript
// Symmetric encryption
const encrypted = crypto.encrypt(plaintext, key, { algorithm: 'AES-256-GCM' });

// Post-quantum key generation  
const keyPair = crypto.generateKeyPair('ML-DSA-65');

// Hybrid signing
const signature = crypto.signHybrid(message, classicalKey, pqcKey);

// Quantum-safe key encapsulation
const { encapsulatedKey, sharedSecret } = crypto.encapsulate(publicKey, 'ML-KEM-768');
```

### Migration Utilities
```javascript
// Algorithm recommendation based on security requirements
const recommended = crypto.getRecommendedAlgorithms({
  securityLevel: 'high',
  quantumSafe: true,
  fipsRequired: true
});

// Migration path analysis
const migrationPlan = crypto.analyzeMigration(currentAlgorithms);
```

## Performance Characteristics

### Encryption Speed (MB/s on modern hardware)
- **AES-256-GCM**: 1000+ MB/s (hardware accelerated)
- **ChaCha20-Poly1305**: 800+ MB/s (software)
- **ML-KEM operations**: ~10,000 ops/sec

### Key Sizes
- **Classical**: RSA-4096 (512 bytes), ECDSA P-256 (32 bytes)  
- **Post-Quantum**: ML-KEM-768 (1184 bytes), ML-DSA-65 (1952 bytes)
- **Hybrid**: Sum of component algorithm sizes

### Memory Requirements
- **Classical algorithms**: <1KB working memory
- **Post-quantum algorithms**: 1-10KB working memory
- **Hybrid operations**: Combined memory requirements

## Security Considerations

### Known Limitations
1. **Classical algorithms**: Vulnerable to quantum computers
2. **Post-quantum algorithms**: Larger key/signature sizes
3. **Hybrid algorithms**: Increased computational overhead

### Best Practices
1. **Use authenticated encryption** (GCM, Poly1305) modes only
2. **Implement proper key management** with regular rotation
3. **Validate all cryptographic operations** with known test vectors
4. **Monitor quantum computing** developments for timeline updates

## Support and Updates

This specification is maintained to reflect:
- **NIST standard updates** and new publications
- **FIPS validation** status changes
- **Quantum computing** threat timeline developments
- **Implementation vulnerabilities** and security advisories

For the latest updates, refer to the official NIST PQC standardization process and security bulletins.