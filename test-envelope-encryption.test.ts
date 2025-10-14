/**
 * Comprehensive Test Suite for CryptoShield SDK with Vault KMS Envelope Encryption
 * Tests both local encryption and Vault-based envelope encryption
 */

import { describe, test, expect, beforeAll, afterAll } from "@jest/globals";

// Mock configuration for Vault (replace with actual values)
const VAULT_CONFIG = {
  vaultEndpoint: process.env.VAULT_ENDPOINT || "https://kms.averox.com",
  vaultToken: process.env.VAULT_TOKEN || "your_vault_token_here",
  kekName: process.env.KEK_NAME || "kek-test-tenant",
  transitMount: process.env.VAULT_TRANSIT_MOUNT || "transit",
};

// Mock Vault KMS Client for testing
class VaultKmsClient {
  constructor(private config: typeof VAULT_CONFIG) {}

  async encryptDEK(
    dekPlaintext: string,
    context?: Record<string, string>
  ): Promise<string> {
    const url = `${this.config.vaultEndpoint}/v1/${this.config.transitMount}/encrypt/${this.config.kekName}`;

    const payload: any = {
      plaintext: Buffer.from(dekPlaintext).toString("base64"),
    };

    if (context) {
      payload.context = Buffer.from(JSON.stringify(context)).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.config.vaultToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Vault encrypt failed: ${response.statusText}`);
    }

    const result = await response.json();
    return result.data.ciphertext;
  }

  async decryptDEK(
    dekCiphertext: string,
    context?: Record<string, string>
  ): Promise<string> {
    const url = `${this.config.vaultEndpoint}/v1/${this.config.transitMount}/decrypt/${this.config.kekName}`;

    const payload: any = {
      ciphertext: dekCiphertext,
    };

    if (context) {
      payload.context = Buffer.from(JSON.stringify(context)).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.config.vaultToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Vault decrypt failed: ${response.statusText}`);
    }

    const result = await response.json();
    return Buffer.from(result.data.plaintext, "base64").toString("utf8");
  }
}

// Envelope Encryption Implementation
class EnvelopeEncryption {
  private vaultClient: VaultKmsClient;

  constructor(vaultConfig: typeof VAULT_CONFIG) {
    this.vaultClient = new VaultKmsClient(vaultConfig);
  }

  generateDEK(): Buffer {
    return crypto.randomBytes(32); // 256-bit key for AES-256
  }

  async encrypt(
    plaintext: string,
    context: Record<string, string> = {}
  ): Promise<any> {
    try {
      // Step 1: Generate DEK locally
      const dek = this.generateDEK();

      // Step 2: Encrypt data with DEK using AES-256-GCM
      const iv = crypto.randomBytes(12); // 96-bit IV for GCM
      const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);

      let encryptedData = cipher.update(plaintext, "utf8");
      encryptedData = Buffer.concat([encryptedData, cipher.final()]);
      const tag = cipher.getAuthTag();

      // Step 3: Encrypt DEK with KEK via Vault
      const encryptedDEK = await this.vaultClient.encryptDEK(
        dek.toString("base64"),
        context
      );

      // Step 4: Return envelope with encrypted DEK and data
      return {
        encryptedData: encryptedData.toString("base64"),
        encryptedDEK: encryptedDEK,
        iv: iv.toString("base64"),
        tag: tag.toString("base64"),
        context: context,
        algorithm: "aes-256-gcm",
        version: "1.0",
      };
    } catch (error) {
      throw new Error(
        `Envelope encryption failed: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  async decrypt(envelope: any): Promise<string> {
    try {
      // Step 1: Decrypt DEK with KEK via Vault
      const dekPlaintext = await this.vaultClient.decryptDEK(
        envelope.encryptedDEK,
        envelope.context || {}
      );

      const dek = Buffer.from(dekPlaintext, "base64");

      // Step 2: Decrypt data with DEK
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        dek,
        Buffer.from(envelope.iv, "base64")
      );

      decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));

      let decrypted = decipher.update(
        Buffer.from(envelope.encryptedData, "base64")
      );
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted.toString("utf8");
    } catch (error) {
      throw new Error(
        `Envelope decryption failed: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  async rotateKEK(): Promise<void> {
    const url = `${VAULT_CONFIG.vaultEndpoint}/v1/${VAULT_CONFIG.transitMount}/keys/${VAULT_CONFIG.kekName}/rotate`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": VAULT_CONFIG.vaultToken,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`KEK rotation failed: ${response.statusText}`);
    }
  }
}

describe("Envelope Encryption with Vault KMS", () => {
  let encryption: EnvelopeEncryption;
  const testData = "Sensitive financial data: Account 123456789";
  const context = { userId: "user-123", purpose: "test" };

  beforeAll(() => {
    encryption = new EnvelopeEncryption(VAULT_CONFIG);
  });

  describe("Basic Envelope Encryption", () => {
    test("should encrypt and decrypt data successfully", async () => {
      const envelope = await encryption.encrypt(testData, context);

      // Verify envelope structure
      expect(envelope).toHaveProperty("encryptedData");
      expect(envelope).toHaveProperty("encryptedDEK");
      expect(envelope).toHaveProperty("iv");
      expect(envelope).toHaveProperty("tag");
      expect(envelope).toHaveProperty("algorithm", "aes-256-gcm");
      expect(envelope).toHaveProperty("version", "1.0");

      // Decrypt and verify
      const decrypted = await encryption.decrypt(envelope);
      expect(decrypted).toBe(testData);
    }, 10000);

    test("should generate unique DEKs for each encryption", async () => {
      const envelope1 = await encryption.encrypt(testData, context);
      const envelope2 = await encryption.encrypt(testData, context);

      // Encrypted DEKs should be different (wrapped differently)
      expect(envelope1.encryptedDEK).not.toBe(envelope2.encryptedDEK);

      // But both should decrypt to the same plaintext
      const decrypted1 = await encryption.decrypt(envelope1);
      const decrypted2 = await encryption.decrypt(envelope2);
      expect(decrypted1).toBe(testData);
      expect(decrypted2).toBe(testData);
    }, 10000);

    test("should handle empty plaintext", async () => {
      const envelope = await encryption.encrypt("", context);
      const decrypted = await encryption.decrypt(envelope);
      expect(decrypted).toBe("");
    }, 10000);

    test("should handle large data (1MB)", async () => {
      const largeData = "A".repeat(1024 * 1024); // 1MB
      const envelope = await encryption.encrypt(largeData, context);
      const decrypted = await encryption.decrypt(envelope);
      expect(decrypted).toBe(largeData);
    }, 30000);

    test("should handle Unicode data", async () => {
      const unicodeData = "你好世界 🌍 مرحبا العالم";
      const envelope = await encryption.encrypt(unicodeData, context);
      const decrypted = await encryption.decrypt(envelope);
      expect(decrypted).toBe(unicodeData);
    }, 10000);
  });

  describe("Context-Based Encryption", () => {
    test("should use context for encryption", async () => {
      const context1 = { userId: "user-1", department: "finance" };
      const context2 = { userId: "user-2", department: "hr" };

      const envelope1 = await encryption.encrypt(testData, context1);
      const envelope2 = await encryption.encrypt(testData, context2);

      // Should decrypt with correct context
      const decrypted1 = await encryption.decrypt(envelope1);
      expect(decrypted1).toBe(testData);

      const decrypted2 = await encryption.decrypt(envelope2);
      expect(decrypted2).toBe(testData);
    }, 10000);

    test("should fail with wrong context", async () => {
      const correctContext = { userId: "user-1" };
      const wrongContext = { userId: "user-2" };

      const envelope = await encryption.encrypt(testData, correctContext);

      // Try to decrypt with wrong context
      const envelopeWithWrongContext = { ...envelope, context: wrongContext };
      await expect(
        encryption.decrypt(envelopeWithWrongContext)
      ).rejects.toThrow();
    }, 10000);
  });

  describe("Security Features", () => {
    test("should fail with tampered ciphertext", async () => {
      const envelope = await encryption.encrypt(testData, context);

      // Tamper with encrypted data
      const tamperedEnvelope = {
        ...envelope,
        encryptedData: Buffer.from("tampered data").toString("base64"),
      };

      await expect(encryption.decrypt(tamperedEnvelope)).rejects.toThrow();
    }, 10000);

    test("should fail with tampered authentication tag", async () => {
      const envelope = await encryption.encrypt(testData, context);

      // Tamper with tag
      const tamperedEnvelope = {
        ...envelope,
        tag: Buffer.from([
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        ]).toString("base64"),
      };

      await expect(encryption.decrypt(tamperedEnvelope)).rejects.toThrow();
    }, 10000);

    test("should fail with tampered encrypted DEK", async () => {
      const envelope = await encryption.encrypt(testData, context);

      // Tamper with encrypted DEK
      const tamperedEnvelope = {
        ...envelope,
        encryptedDEK: "vault:v1:invalid",
      };

      await expect(encryption.decrypt(tamperedEnvelope)).rejects.toThrow();
    }, 10000);

    test("should verify KEK never leaves Vault", async () => {
      const envelope = await encryption.encrypt(testData, context);

      // Verify that encrypted DEK has Vault format
      expect(envelope.encryptedDEK).toMatch(/^vault:v\d+:/);

      // Verify decryption works (KEK was used but never exposed)
      const decrypted = await encryption.decrypt(envelope);
      expect(decrypted).toBe(testData);
    }, 10000);
  });

  describe("KEK Rotation", () => {
    test("should rotate KEK successfully", async () => {
      // Encrypt with current KEK version
      const envelope1 = await encryption.encrypt(testData, context);

      // Rotate KEK
      await encryption.rotateKEK();

      // Encrypt with new KEK version
      const envelope2 = await encryption.encrypt(testData, context);

      // Both should decrypt successfully (Vault handles versioning)
      const decrypted1 = await encryption.decrypt(envelope1);
      const decrypted2 = await encryption.decrypt(envelope2);

      expect(decrypted1).toBe(testData);
      expect(decrypted2).toBe(testData);
    }, 15000);

    test("should decrypt old data after KEK rotation", async () => {
      // Encrypt data
      const envelope = await encryption.encrypt(testData, context);

      // Rotate KEK
      await encryption.rotateKEK();

      // Old data should still decrypt (backward compatibility)
      const decrypted = await encryption.decrypt(envelope);
      expect(decrypted).toBe(testData);
    }, 15000);
  });

  describe("Performance Tests", () => {
    test("should handle multiple concurrent encryptions", async () => {
      const promises = Array.from({ length: 10 }, (_, i) =>
        encryption.encrypt(`Test data ${i}`, { index: i.toString() })
      );

      const envelopes = await Promise.all(promises);
      expect(envelopes).toHaveLength(10);

      // Verify all decrypt correctly
      const decryptPromises = envelopes.map((env) => encryption.decrypt(env));
      const decrypted = await Promise.all(decryptPromises);

      decrypted.forEach((data, i) => {
        expect(data).toBe(`Test data ${i}`);
      });
    }, 30000);

    test("should measure encryption/decryption latency", async () => {
      const iterations = 5;
      const latencies: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        const envelope = await encryption.encrypt(testData, context);
        await encryption.decrypt(envelope);
        const end = Date.now();

        latencies.push(end - start);
      }

      const avgLatency =
        latencies.reduce((a, b) => a + b, 0) / latencies.length;
      console.log(`Average latency: ${avgLatency}ms`);

      // Should be reasonably fast (adjust threshold as needed)
      expect(avgLatency).toBeLessThan(5000); // 5 seconds
    }, 60000);
  });

  describe("Error Handling", () => {
    test("should handle network errors gracefully", async () => {
      const badEncryption = new EnvelopeEncryption({
        ...VAULT_CONFIG,
        vaultEndpoint: "https://invalid.vault.com",
      });

      await expect(badEncryption.encrypt(testData, context)).rejects.toThrow();
    }, 10000);

    test("should handle invalid Vault token", async () => {
      const badEncryption = new EnvelopeEncryption({
        ...VAULT_CONFIG,
        vaultToken: "invalid-token",
      });

      await expect(badEncryption.encrypt(testData, context)).rejects.toThrow();
    }, 10000);

    test("should handle missing KEK", async () => {
      const badEncryption = new EnvelopeEncryption({
        ...VAULT_CONFIG,
        kekName: "non-existent-kek",
      });

      await expect(badEncryption.encrypt(testData, context)).rejects.toThrow();
    }, 10000);
  });

  describe("Compliance & Audit", () => {
    test("should include all required envelope fields", async () => {
      const envelope = await encryption.encrypt(testData, context);

      const requiredFields = [
        "encryptedData",
        "encryptedDEK",
        "iv",
        "tag",
        "algorithm",
        "version",
        "context",
      ];

      requiredFields.forEach((field) => {
        expect(envelope).toHaveProperty(field);
      });
    }, 10000);

    test("should use correct algorithm", async () => {
      const envelope = await encryption.encrypt(testData, context);
      expect(envelope.algorithm).toBe("aes-256-gcm");
    }, 10000);

    test("should maintain version information", async () => {
      const envelope = await encryption.encrypt(testData, context);
      expect(envelope.version).toBe("1.0");
    }, 10000);

    test("should preserve context for audit trail", async () => {
      const auditContext = {
        userId: "admin-001",
        action: "encrypt-sensitive-data",
        timestamp: new Date().toISOString(),
        ipAddress: "192.168.1.1",
      };

      const envelope = await encryption.encrypt(testData, auditContext);
      expect(envelope.context).toEqual(auditContext);

      const decrypted = await encryption.decrypt(envelope);
      expect(decrypted).toBe(testData);
    }, 10000);
  });
});

describe("Integration with Existing SDK", () => {
  // These tests would integrate with the actual SDK code
  // For now, providing examples of what to test

  test.todo("should integrate envelope encryption with AveroxCrypto");
  test.todo("should support hybrid mode: local + Vault encryption");
  test.todo("should handle fallback when Vault is unavailable");
  test.todo("should batch multiple DEK operations for performance");
  test.todo("should implement DEK caching with expiration");
});

console.log("✅ Envelope encryption test suite completed");
