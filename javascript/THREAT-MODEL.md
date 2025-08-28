# Threat Model

## Assets
- Master keys and derived keys
- Plaintext data before encryption
- AAD (Additional Authenticated Data)
- Cryptographic operations and metadata

## Threat Actors
- External attackers with network access
- Insider threats with system access
- Supply chain attackers
- Side-channel attackers

## Attack Vectors

### 1. Cryptographic Attacks
**Threat**: Key recovery, plaintext recovery
**Mitigations**:
- AES-256-GCM with 256-bit keys
- Proper IV/nonce management (12-byte, never reused)
- Authenticated encryption preventing tampering

### 2. Side-Channel Attacks  
**Threat**: Timing attacks, cache attacks
**Mitigations**:
- Timing-safe comparison operations
- Constant-time algorithms where possible
- Memory zeroization of sensitive data

### 3. Memory Disclosure
**Threat**: Key material in memory dumps
**Mitigations**:
- Immediate zeroization after use
- Stack protection and ASLR
- Secure memory allocation patterns

### 4. Supply Chain Attacks
**Threat**: Compromised dependencies
**Mitigations**:
- SBOM generation and tracking
- Dependency auditing and pinning
- Cryptographic signatures on releases

### 5. Implementation Bugs
**Threat**: Buffer overflows, logic errors
**Mitigations**:
- Comprehensive test coverage
- Fuzzing and sanitizer testing
- Static analysis and code review