# Signing Keys Directory

⚠️ **CRITICAL SECURITY NOTICE** ⚠️

## NO PRIVATE KEYS ALLOWED

This directory is for **documentation and public key distribution only**. 

### 🚨 SECURITY POLICY

**NEVER commit private keys, passphrases, or secret material to this repository.**

All private key material must be:
- Generated in secure temporary locations (`/tmp`, `/dev/shm`, etc.)
- Stored in Hardware Security Modules (HSM) or Key Management Systems (KMS) for production
- Protected by secure environment variables
- Automatically cleaned up after use

### ✅ ALLOWED CONTENT

- Public keys (`.pub` files)
- Certificate chains (`.crt`, `.cer` files)
- Documentation and policies
- Key fingerprints and verification instructions

### ❌ PROHIBITED CONTENT

- Private keys (`.key`, `.pem`, `.sec` files)
- Passphrases or passwords
- GPG batch configuration files
- Any secret or sensitive material

### 🔐 PROPER KEY MANAGEMENT

For development:
```bash
# Generate keys in temporary location
export TEMP_DIR=$(mktemp -d)
minisign -G -p $TEMP_DIR/pub.key -s $TEMP_DIR/private.key

# Use for signing, then clean up
rm -rf $TEMP_DIR
```

For production:
```bash
# Use environment variables from secure key management
export AVEROX_SIGNING_PASSPHRASE="$(aws kms decrypt --key-id alias/averox-signing ...)"
export AVEROX_GPG_PASSPHRASE="$(vault kv get -field=passphrase secret/gpg)"
```

### 🛡️ INCIDENT RESPONSE

If a private key is accidentally committed:
1. **IMMEDIATELY** remove from repository
2. **REVOKE** the compromised key
3. **GENERATE** new key pair
4. **UPDATE** trust anchors and verification documentation
5. **DOCUMENT** incident in SECURITY.md

### 📞 SECURITY CONTACT

Report security issues to: security@averox.com
PGP Fingerprint: [TO BE ADDED]