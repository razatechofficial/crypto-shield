# Security Policy

## Enterprise Security Features

This SDK implements ALL 18 required security gates:

✅ AES-256-GCM implemented
✅ AAD wired across stacks  
✅ 12-byte IV policy enforced internally
✅ Unified envelope (iv|nonce, tag, ct|ciphertext)
✅ Envelope v/alg/kid fields
✅ Telemetry (OpenTelemetry compatible)
✅ KDFs (HKDF implementation)
✅ Zeroization of secrets
✅ Timing-safe comparisons
✅ Typed errors
✅ Production packaging (ESM + CJS + TypeScript)
✅ C packaging (CMake + pkg-config)
✅ Mobile packaging (Gradle/Pods/SwiftPM)
✅ CI with sanitizers/fuzzers
✅ NIST test vectors
✅ Supply chain security (SBOM + LICENSE)
✅ Security documentation (this file)
✅ CHANGELOG & README present

## Threat Model

This SDK protects against:
- Chosen plaintext attacks
- Chosen ciphertext attacks  
- Side-channel attacks (timing)
- Memory disclosure attacks
- Algorithm substitution attacks

## Vulnerability Reporting

Report security issues to: security@averox.com