# SDK Test Fixes

## Issues Found and Solutions

### 1. InvalidTagError Not Being Thrown Correctly

**Problem**: Tests expect `InvalidTagError` but SDK throws generic `AveroxCryptoError`.

**Fix**: Update error handling in SDK's decrypt methods to properly detect and throw `InvalidTagError`:

```typescript
// In src/index.ts - AveroxCrypto.decrypt() method
try {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encKey,
    Buffer.from(envelope.iv, "base64url")
  );

  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  decipher.setAAD(Buffer.from(aad));

  let decrypted = decipher.update(
    Buffer.from(envelope.ciphertext, "base64url")
  );
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString("utf8");
} catch (error) {
  // Detect authentication failure specifically
  if (
    error instanceof Error &&
    error.message.includes("Unsupported state or unable to authenticate data")
  ) {
    throw new InvalidTagError("Authentication tag verification failed");
  }
  if (error instanceof AveroxCryptoError) throw error;
  const finalErrorMessage =
    error instanceof Error ? error.message : "Unknown decryption error";
  throw new AveroxCryptoError(
    "DECRYPTION_FAILED",
    `Decryption failed: ${finalErrorMessage}`
  );
}
```

### 2. Zeroize Functionality Not Working

**Problem**: After calling `zeroize()`, the SDK should clear keys and fail subsequent operations, but it doesn't.

**Fix**: Implement proper zeroization with state tracking:

```typescript
export class AveroxCrypto {
  private _masterKey: Buffer;
  private _isZeroized: boolean = false;

  constructor(masterKey: Buffer) {
    if (!Buffer.isBuffer(masterKey)) {
      throw new BadInputError("Master key must be a Buffer");
    }
    if (masterKey.length !== 32) {
      throw new BadInputError("Master key must be 32 bytes");
    }
    // Create a copy to avoid external modifications
    this._masterKey = Buffer.from(masterKey);
  }

  encrypt(plaintext: string | Buffer, aad: string | Buffer): EncryptedEnvelope {
    if (this._isZeroized) {
      throw new AveroxCryptoError(
        "ZEROIZED",
        "Cannot encrypt: instance has been zeroized"
      );
    }
    // ... rest of encryption logic
  }

  decrypt(envelope: EncryptedEnvelope, aad: string | Buffer): string {
    if (this._isZeroized) {
      throw new AveroxCryptoError(
        "ZEROIZED",
        "Cannot decrypt: instance has been zeroized"
      );
    }
    // ... rest of decryption logic
  }

  zeroize(): void {
    if (!this._isZeroized) {
      // Zero out the key buffer
      this._masterKey.fill(0);
      this._isZeroized = true;
    }
  }
}
```

### 3. TypeScript Error Handling

**Problem**: TypeScript complains about `error.message` on unknown type.

**Fix**: Add type guards in test files:

```typescript
// In test/error-handling.test.ts
try {
  // ... test code
} catch (err) {
  const error = err as Error; // Type assertion
  expect(error.message).not.toContain("sensitive data");
  expect(error.message).not.toContain(key.toString("hex"));
}

// Or use type guard
try {
  // ... test code
} catch (error) {
  if (error instanceof Error) {
    expect(error.message).not.toContain("sensitive data");
  }
}
```

### 4. Missing Envelope Encryption Tests

**Solution**: Created comprehensive test suite in `test-envelope-encryption.test.ts` covering:

- Basic envelope encryption/decryption
- Context-based encryption
- Security features (tampering detection)
- KEK rotation
- Performance tests
- Error handling
- Compliance & audit requirements

## Updated Test Commands

### Run Envelope Encryption Tests Only

```bash
npm test -- test-envelope-encryption.test.ts
```

### Run All Tests with Vault Integration

```bash
# Set environment variables first
export VAULT_ENDPOINT=https://kms.averox.com
export VAULT_TOKEN=your_vault_token_here
export KEK_NAME=kek-test-tenant
export VAULT_TRANSIT_MOUNT=transit

# Run tests
npm test
```

### Run Tests with Coverage

```bash
npm test -- --coverage
```

## Implementation Checklist

- [ ] Fix InvalidTagError detection in decrypt methods
- [ ] Implement proper zeroize functionality with state tracking
- [ ] Fix TypeScript error handling in test files
- [ ] Add envelope encryption code to SDK
- [ ] Create Vault KMS client in SDK
- [ ] Add environment variable support for Vault config
- [ ] Update documentation with envelope encryption examples
- [ ] Add integration tests for hybrid mode (local + Vault)
- [ ] Implement DEK caching for performance
- [ ] Add telemetry for envelope operations

## Expected Test Results After Fixes

```
Test Suites: 7 passed, 7 total
Tests:       41 passed, 41 total
Snapshots:   0 total
Time:        ~20s
```

## Vault KMS Setup for Tests

Before running envelope encryption tests, ensure:

1. Vault is accessible at `https://kms.averox.com`
2. Transit engine is mounted at `/transit`
3. Test KEK exists: `kek-test-tenant`
4. Token has permissions:
   - `transit/encrypt/*`
   - `transit/decrypt/*`
   - `transit/keys/*`

### Create Test KEK

```bash
# Using curl
curl -X POST \
  https://kms.averox.com/v1/transit/keys/kek-test-tenant \
  -H "X-Vault-Token: your_vault_token_here" \
  -d '{
    "type": "aes256-gcm96",
    "exportable": false,
    "allow_plaintext_backup": false
  }'
```

## Performance Benchmarks

Expected performance (after implementation):

- Single encryption: < 200ms (including Vault round-trip)
- Single decryption: < 200ms
- 10 concurrent operations: < 1s
- 1MB payload: < 500ms

## Security Compliance

The envelope encryption implementation ensures:

1. **DEK Generation**: Cryptographically secure random 256-bit keys
2. **KEK Protection**: Never leaves Vault, all operations server-side
3. **Authentication**: AES-256-GCM provides authenticated encryption
4. **Context Binding**: Prevents key misuse across contexts
5. **Key Rotation**: Seamless KEK rotation without data re-encryption
6. **Audit Trail**: All operations logged with context
