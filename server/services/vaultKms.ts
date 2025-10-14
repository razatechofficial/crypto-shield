/**
 * HashiCorp Vault KMS Service
 * Implements envelope encryption with Vault Transit Engine
 *
 * Architecture:
 * - KEK (Key Encryption Key) stored in Vault Transit Engine
 * - DEK (Data Encryption Key) generated locally in SDK
 * - DEK encrypted with KEK via Vault
 * - Encrypted DEK stored with ciphertext
 */

import { randomUUID } from "crypto";

export interface VaultConfig {
  endpoint: string;
  token: string;
  transitMount: string;
}

export interface TenantKEKMetadata {
  tenantId: string;
  kekName: string;
  algorithm: string;
  keyVersion: number;
  createdAt: Date;
  lastRotated?: Date;
}

export interface VaultKeyConfig {
  type: "aes256-gcm96" | "chacha20-poly1305" | "aes128-gcm96";
  derived?: boolean;
  exportable?: boolean;
  allow_plaintext_backup?: boolean;
  convergent_encryption?: boolean;
}

export class VaultKmsService {
  private readonly endpoint: string;
  private readonly token: string;
  private readonly transitMount: string;

  constructor(config: VaultConfig) {
    this.endpoint = config.endpoint;
    this.token = config.token;
    this.transitMount = config.transitMount || "transit";
  }

  /**
   * Check if transit engine is mounted
   */
  async isTransitMounted(): Promise<boolean> {
    try {
      const response = await fetch(`${this.endpoint}/v1/sys/mounts`, {
        method: "GET",
        headers: {
          "X-Vault-Token": this.token,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to check mounts: ${response.statusText}`);
      }

      const mounts = await response.json();
      return `${this.transitMount}/` in mounts.data;
    } catch (error) {
      console.error("Error checking transit mount:", error);
      return false;
    }
  }

  /**
   * Mount transit engine if not already mounted
   */
  async ensureTransitMounted(): Promise<void> {
    const isMounted = await this.isTransitMounted();

    if (isMounted) {
      console.log(`✅ Transit engine already mounted at /${this.transitMount}`);
      return;
    }

    console.log(`🔧 Mounting transit engine at /${this.transitMount}...`);

    try {
      const response = await fetch(
        `${this.endpoint}/v1/sys/mounts/${this.transitMount}`,
        {
          method: "POST",
          headers: {
            "X-Vault-Token": this.token,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            type: "transit",0
            description: "KMS for CryptoShield SDK envelope encryption",
            config: {
              default_lease_ttl: "0",
              max_lease_ttl: "0",
              force_no_cache: false,
            },
          }),
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to mount transit engine: ${error}`);
      }

      console.log(
        `✅ Transit engine mounted successfully at /${this.transitMount}`
      );
    } catch (error) {
      console.error("Error mounting transit engine:", error);
      throw error;
    }
  }

  /**
   * Create a tenant-specific KEK in Vault
   */
  async createTenantKEK(
    tenantId: string,
    algorithm: "aes256-gcm96" | "chacha20-poly1305" = "aes256-gcm96"
  ): Promise<TenantKEKMetadata> {
    const kekName = `kek-${tenantId}`;

    console.log(`🔑 Creating KEK for tenant ${tenantId}...`);

    try {
      // Ensure transit engine is mounted
      await this.ensureTransitMounted();

      // Create the key in Vault
      const keyConfig: VaultKeyConfig = {
        type: algorithm,
        derived: false,
        exportable: false,
        allow_plaintext_backup: false,
        convergent_encryption: false,
      };

      const response = await fetch(
        `${this.endpoint}/v1/${this.transitMount}/keys/${kekName}`,
        {
          method: "POST",
          headers: {
            "X-Vault-Token": this.token,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(keyConfig),
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to create KEK: ${error}`);
      }

      console.log(`✅ KEK created successfully: ${kekName}`);

      // Get key info
      const keyInfo = await this.getKeyInfo(kekName);

      return {
        tenantId,
        kekName,
        algorithm,
        keyVersion: keyInfo.latest_version,
        createdAt: new Date(),
      };
    } catch (error) {
      console.error("Error creating tenant KEK:", error);
      throw error;
    }
  }

  /**
   * Get key information from Vault
   */
  async getKeyInfo(kekName: string): Promise<any> {
    try {
      const response = await fetch(
        `${this.endpoint}/v1/${this.transitMount}/keys/${kekName}`,
        {
          method: "GET",
          headers: {
            "X-Vault-Token": this.token,
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.ok) {
        throw new Error(`Failed to get key info: ${response.statusText}`);
      }

      const result = await response.json();
      return result.data;
    } catch (error) {
      console.error("Error getting key info:", error);
      throw error;
    }
  }

  /**
   * Rotate a tenant's KEK
   */
  async rotateKEK(kekName: string): Promise<number> {
    console.log(`🔄 Rotating KEK: ${kekName}...`);

    try {
      const response = await fetch(
        `${this.endpoint}/v1/${this.transitMount}/keys/${kekName}/rotate`,
        {
          method: "POST",
          headers: {
            "X-Vault-Token": this.token,
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to rotate KEK: ${error}`);
      }

      console.log(`✅ KEK rotated successfully: ${kekName}`);

      // Get updated key info
      const keyInfo = await this.getKeyInfo(kekName);
      return keyInfo.latest_version;
    } catch (error) {
      console.error("Error rotating KEK:", error);
      throw error;
    }
  }

  /**
   * Encrypt DEK with KEK (envelope encryption)
   */
  async encryptDEK(
    kekName: string,
    dekPlaintext: string,
    context?: Record<string, string>
  ): Promise<string> {
    try {
      const payload: any = {
        plaintext: Buffer.from(dekPlaintext).toString("base64"),
      };

      if (context) {
        payload.context = Buffer.from(JSON.stringify(context)).toString(
          "base64"
        );
      }

      const response = await fetch(
        `${this.endpoint}/v1/${this.transitMount}/encrypt/${kekName}`,
        {
          method: "POST",
          headers: {
            "X-Vault-Token": this.token,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to encrypt DEK: ${error}`);
      }

      const result = await response.json();
      return result.data.ciphertext;
    } catch (error) {
      console.error("Error encrypting DEK:", error);
      throw error;
    }
  }

  /**
   * Decrypt DEK with KEK (envelope encryption)
   */
  async decryptDEK(
    kekName: string,
    dekCiphertext: string,
    context?: Record<string, string>
  ): Promise<string> {
    try {
      const payload: any = {
        ciphertext: dekCiphertext,
      };

      if (context) {
        payload.context = Buffer.from(JSON.stringify(context)).toString(
          "base64"
        );
      }

      const response = await fetch(
        `${this.endpoint}/v1/${this.transitMount}/decrypt/${kekName}`,
        {
          method: "POST",
          headers: {
            "X-Vault-Token": this.token,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to decrypt DEK: ${error}`);
      }

      const result = await response.json();
      return Buffer.from(result.data.plaintext, "base64").toString("utf8");
    } catch (error) {
      console.error("Error decrypting DEK:", error);
      throw error;
    }
  }

  /**
   * Delete a tenant's KEK (schedule for deletion)
   */
  async deleteKEK(kekName: string): Promise<void> {
    console.log(`🗑️  Deleting KEK: ${kekName}...`);

    try {
      const response = await fetch(
        `${this.endpoint}/v1/${this.transitMount}/keys/${kekName}`,
        {
          method: "DELETE",
          headers: {
            "X-Vault-Token": this.token,
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to delete KEK: ${error}`);
      }

      console.log(`✅ KEK deleted successfully: ${kekName}`);
    } catch (error) {
      console.error("Error deleting KEK:", error);
      throw error;
    }
  }

  /**
   * Health check for Vault connection
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await fetch(`${this.endpoint}/v1/sys/health`, {
        method: "GET",
      });

      return response.ok || response.status === 429 || response.status === 473;
    } catch (error) {
      console.error("Vault health check failed:", error);
      return false;
    }
  }
}

// Singleton instance
let vaultKmsInstance: VaultKmsService | null = null;

export function getVaultKmsService(): VaultKmsService {
  if (!vaultKmsInstance) {
    const config: VaultConfig = {
      endpoint: process.env.VAULT_ENDPOINT || "https://kms.averox.com",
      token: process.env.VAULT_TOKEN || "your_vault_token_here",
      transitMount: process.env.VAULT_TRANSIT_MOUNT || "transit",
    };

    vaultKmsInstance = new VaultKmsService(config);
  }

  return vaultKmsInstance;
}
