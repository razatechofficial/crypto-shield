# HashiCorp Vault KMS Integration

## Overview

CryptoShield now integrates with HashiCorp Vault for enterprise-grade Key Management System (KMS) capabilities using **envelope encryption**. This implementation follows the sequence diagram provided and ensures that all generated SDKs have proper key management.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SDK Generation Flow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User requests SDK generation                               │
│  2. Backend checks/mounts Vault transit engine                 │
│  3. Create tenant-specific KEK in Vault                        │
│  4. Store KEK metadata in PostgreSQL                           │
│  5. Generate SDK with envelope encryption code                 │
│  6. SDK includes Vault KMS integration                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  Envelope Encryption Flow                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Encryption:                                                    │
│  1. Generate DEK (Data Encryption Key) locally - 32 bytes      │
│  2. Encrypt data with DEK using AES-256-GCM                    │
│  3. Encrypt DEK with KEK via Vault                             │
│  4. Store encrypted data + encrypted DEK                       │
│                                                                 │
│  Decryption:                                                    │
│  1. Retrieve encrypted data + encrypted DEK                    │
│  2. Decrypt DEK with KEK via Vault                             │
│  3. Decrypt data with DEK                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Details

### 1. Vault Configuration

**Vault Endpoint**: `https://kms.averox.com`  
**Root Token**: `your_vault_token_here`  
**Transit Mount**: `/transit`

### 2. Files Created/Modified

#### New Files:

- `server/services/vaultKms.ts` - Vault KMS service implementation
- `server/sdkTemplates/envelopeEncryption.ts` - Envelope encryption code templates
- `test-vault-integration.js` - Integration test script
- `VAULT_KMS_INTEGRATION.md` - This documentation

#### Modified Files:

- `server/routes.ts` - SDK generation endpoint with Vault integration
- `server/config.ts` - Added Vault configuration
- `shared/schema.ts` - Added KEK metadata fields to SDKs table

### 3. Database Schema Changes

Added to `sdks` table:

```typescript
vaultKekName: varchar("vault_kek_name"); // KEK name in Vault
vaultKekAlgorithm: varchar("vault_kek_algorithm"); // aes256-gcm96, etc.
vaultKekVersion: integer("vault_kek_version"); // Current KEK version
envelopeEncryptionEnabled: boolean; // Feature flag
```

### 4. Environment Variables

Add to `.env`:

```env
# Vault KMS Configuration
VAULT_ENDPOINT=https://kms.averox.com
VAULT_TOKEN=your_vault_token_here
VAULT_TRANSIT_MOUNT=transit
```

## API Flow

### SDK Generation Endpoint: `POST /api/sdks/generate`

**Before (without KMS):**

```
1. Validate user
2. Create SDK record
3. Generate SDK files
4. Return download URL
```

**After (with Vault KMS):**

```
1. Validate user
2. Initialize Vault KMS service
3. Ensure transit engine is mounted
4. Create tenant-specific KEK in Vault
   - KEK name: kek-{tenantId}
   - Algorithm: aes256-gcm96
5. Store KEK metadata in database
6. Create SDK record with KEK metadata
7. Generate SDK files + envelope encryption code
8. Log security event
9. Return download URL
```

### SDK Download Endpoint: `GET /api/sdks/:id/download`

**Enhanced with:**

- Envelope encryption JavaScript/TypeScript code
- Envelope encryption Python code
- Usage examples
- README with tenant-specific KEK details

## Envelope Encryption Implementation

### JavaScript/TypeScript

Generated SDKs include `envelope-encryption.js`:

```javascript
class EnvelopeEncryption {
  constructor(vaultConfig) {
    this.vaultClient = new VaultKmsClient(vaultConfig);
  }

  async encrypt(plaintext, context = {}) {
    // 1. Generate DEK locally
    const dek = crypto.randomBytes(32);

    // 2. Encrypt data with DEK
    const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
    const encryptedData = cipher.update(plaintext) + cipher.final();

    // 3. Encrypt DEK with KEK via Vault
    const encryptedDEK = await this.vaultClient.encryptDEK(dek);

    // 4. Return envelope
    return { encryptedData, encryptedDEK, iv, tag };
  }

  async decrypt(envelope) {
    // 1. Decrypt DEK with Vault
    const dek = await this.vaultClient.decryptDEK(envelope.encryptedDEK);

    // 2. Decrypt data with DEK
    const decipher = crypto.createDecipheriv("aes-256-gcm", dek, envelope.iv);
    return decipher.update(envelope.encryptedData) + decipher.final();
  }
}
```

### Python

Generated SDKs include `envelope_encryption.py`:

```python
class EnvelopeEncryption:
    def encrypt(self, plaintext, context=None):
        # 1. Generate DEK locally
        dek = os.urandom(32)

        # 2. Encrypt data with DEK
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        # 3. Encrypt DEK with KEK via Vault
        encrypted_dek = self.vault_client.encrypt_dek(dek, context)

        # 4. Return envelope
        return {
            'encryptedData': ciphertext,
            'encryptedDEK': encrypted_dek,
            'nonce': nonce
        }
```

## Security Benefits

### 1. Key Separation

- **KEK (Key Encryption Key)**: Stored in Vault, never leaves the KMS
- **DEK (Data Encryption Key)**: Generated locally, encrypted before storage
- **Data**: Encrypted with DEK, stored with encrypted DEK

### 2. Compliance

- **FIPS 140-2 Level 3**: Vault provides hardware security module (HSM) integration
- **Audit Trail**: All key operations logged in Vault
- **Key Rotation**: Automatic KEK rotation without re-encrypting data
- **Access Control**: Fine-grained permissions in Vault

### 3. Operational Security

- **No Key Exposure**: KEK never transmitted in plaintext
- **Automatic Versioning**: Vault manages key versions
- **Disaster Recovery**: Vault backup/restore capabilities
- **Multi-tenancy**: Each tenant has isolated KEK

## Key Rotation

### Automatic KEK Rotation

```javascript
// Rotate KEK in Vault
await encryption.rotateKEK();

// Old encrypted DEKs still work (Vault uses versioned keys)
// New encryptions use latest KEK version
```

### Re-encryption (Optional)

```javascript
// Re-encrypt data with new KEK version
const newEnvelope = await encryption.reEncrypt(oldEnvelope);
```

## Testing

### Run Integration Tests

```bash
node test-vault-integration.js
```

**Test Coverage:**

1. ✅ Vault health check
2. ✅ Transit engine mounting
3. ✅ KEK creation
4. ✅ DEK encryption
5. ✅ DEK decryption
6. ✅ KEK rotation
7. ✅ Cleanup

### Manual Testing

1. **Generate SDK with KMS:**

   ```bash
   POST /api/sdks/generate
   {
     "name": "Test SDK",
     "languages": ["javascript"],
     "algorithms": ["aes-256-gcm"]
   }
   ```

2. **Check Vault:**

   ```bash
   curl -H "X-Vault-Token: your_vault_token_here" \
        https://kms.averox.com/v1/transit/keys
   ```

3. **Download SDK:**

   ```bash
   GET /api/sdks/{id}/download
   ```

4. **Verify envelope encryption files:**
   - `javascript/envelope-encryption.js`
   - `javascript/ENVELOPE_ENCRYPTION_EXAMPLE.js`
   - `javascript/ENVELOPE_ENCRYPTION_README.md`

## Troubleshooting

### Issue: Transit engine not mounted

**Solution:**

```javascript
const vaultKms = getVaultKmsService();
await vaultKms.ensureTransitMounted();
```

### Issue: KEK already exists

**Error:** `Key already exists`

**Solution:** This is expected behavior. The system checks for existing KEKs before creating new ones.

### Issue: Vault connection timeout

**Check:**

1. Vault endpoint is accessible: `https://kms.averox.com`
2. Token is valid
3. Network connectivity

### Issue: Permission denied

**Check:**

1. Vault token has correct permissions
2. Token is not expired
3. Transit engine policies are configured

## Production Considerations

### 1. Token Management

⚠️ **Current Implementation**: Root token hardcoded (for development)

**Production Recommendations:**

- Use AppRole authentication
- Implement token renewal
- Use short-lived tokens
- Store tokens in secure vault (not in code)

### 2. High Availability

- Deploy Vault in HA mode
- Use Vault Enterprise for replication
- Implement retry logic with exponential backoff
- Monitor Vault health

### 3. Monitoring

**Key Metrics:**

- KEK creation rate
- Encryption/decryption latency
- Vault API errors
- Token expiration warnings

**Logging:**

```javascript
// All Vault operations are logged
console.log("🔐 KEK created:", kekMetadata.kekName);
console.log("✅ DEK encrypted successfully");
```

### 4. Backup & Recovery

**KEK Backup:**

- Vault handles KEK backup automatically
- Configure Vault snapshots
- Test recovery procedures

**Metadata Backup:**

- PostgreSQL backups include KEK metadata
- Store tenant-KEK mappings redundantly

## API Reference

### VaultKmsService

```typescript
class VaultKmsService {
  // Check if transit engine is mounted
  async isTransitMounted(): Promise<boolean>;

  // Mount transit engine
  async ensureTransitMounted(): Promise<void>;

  // Create tenant KEK
  async createTenantKEK(
    tenantId: string,
    algorithm?: string
  ): Promise<TenantKEKMetadata>;

  // Encrypt DEK with KEK
  async encryptDEK(
    kekName: string,
    dekPlaintext: string,
    context?: object
  ): Promise<string>;

  // Decrypt DEK with KEK
  async decryptDEK(
    kekName: string,
    dekCiphertext: string,
    context?: object
  ): Promise<string>;

  // Rotate KEK
  async rotateKEK(kekName: string): Promise<number>;

  // Delete KEK
  async deleteKEK(kekName: string): Promise<void>;

  // Health check
  async healthCheck(): Promise<boolean>;
}
```

### EnvelopeEncryption (SDK)

```typescript
class EnvelopeEncryption {
  constructor(vaultConfig: VaultConfig);

  // Generate DEK
  generateDEK(): Buffer;

  // Encrypt data with envelope encryption
  async encrypt(plaintext: string, context?: object): Promise<Envelope>;

  // Decrypt data with envelope encryption
  async decrypt(envelope: Envelope): Promise<string>;

  // Rotate KEK
  async rotateKEK(): Promise<void>;

  // Re-encrypt with new KEK version
  async reEncrypt(envelope: Envelope): Promise<Envelope>;
}
```

## Next Steps

### Immediate

1. ✅ Implement Vault KMS service
2. ✅ Modify SDK generation endpoint
3. ✅ Add envelope encryption templates
4. ✅ Update database schema
5. ✅ Test integration

### Short-term

1. Implement AppRole authentication
2. Add token renewal logic
3. Implement retry mechanisms
4. Add comprehensive monitoring
5. Create admin dashboard for KEK management

### Long-term

1. Support multiple KMS providers (AWS KMS, Azure Key Vault)
2. Implement automatic key rotation policies
3. Add key usage analytics
4. Implement key escrow for compliance
5. Support hardware security modules (HSMs)

## References

- [HashiCorp Vault Transit Engine](https://www.vaultproject.io/docs/secrets/transit)
- [Envelope Encryption Best Practices](https://cloud.google.com/kms/docs/envelope-encryption)
- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [FIPS 140-2 Compliance](https://csrc.nist.gov/publications/detail/fips/140/2/final)

## Support

For issues or questions:

1. Check troubleshooting section
2. Review Vault logs
3. Check application logs
4. Contact DevOps team

---

**Last Updated**: January 2025  
**Version**: 1.0  
**Status**: ✅ Implemented and Tested
