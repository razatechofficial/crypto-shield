# Hardware Requirements for Confidential Computing SDKs

## Intel SGX (Trusted Execution Environment)

### Hardware Required:
- **Intel processors with SGX support** (6th gen Core and newer)
  - Intel Core i5/i7 (Skylake and later)
  - Intel Xeon E3/E5/SP series with SGX
  - Check: `cat /proc/cpuinfo | grep sgx`

### Without Hardware:
- **Software simulation mode** (development only)
- **Cloud TEE services** (Azure Confidential Computing, AWS Nitro Enclaves)
- **Simulation libraries** for testing and development

## Microsoft SEAL (Homomorphic Encryption)

### Hardware Recommendations:
- **Any modern CPU** (works on standard hardware)
- **Additional RAM** recommended for large computations (8GB+ recommended)
- **GPU acceleration** optional (CUDA support available)

### No Special Hardware Required:
- Runs on standard x86_64 processors
- Works in cloud environments
- Compatible with ARM processors

## SPDZ Multi-Party Computation

### Hardware Requirements:
- **Standard networking** between parties
- **Sufficient RAM** for large secret sharing (4GB+ recommended)
- **Reliable network connection** for multi-party protocols

### No Special Hardware Required:
- Works on any modern computer
- Cloud-friendly implementation
- Network-based protocol (no special chips needed)

## Production Deployment Options

### Option 1: Full Hardware Support
- Intel SGX-enabled servers
- Maximum security and performance
- Hardware attestation available

### Option 2: Cloud-Based TEE
- Azure Confidential Computing VMs
- AWS Nitro Enclaves
- Google Cloud Confidential Computing

### Option 3: Software-Only Mode
- TEE simulation for development
- Homomorphic encryption (full functionality)
- MPC protocols (standard networking)

## Checking Your System

Run this to check SGX support:
```bash
# Linux
lscpu | grep sgx
cat /proc/cpuinfo | grep flags | grep sgx

# Or use our detection script
node check-hardware-support.js
```