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
            type: "transit",
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
    console.log(`🔄 Vault endpoint: ${this.endpoint}`);
    console.log(`🔄 Transit mount: ${this.transitMount}`);
    console.log(`🔄 Token present: ${this.token ? "yes" : "no"}`);

    try {
      const url = `${this.endpoint}/v1/${this.transitMount}/keys/${kekName}/rotate`;
      console.log(`🔄 Rotation URL: ${url}`);

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "X-Vault-Token": this.token,
          "Content-Type": "application/json",
        },
      });

      console.log(`🔄 Rotation response status: ${response.status}`);
      console.log(`🔄 Rotation response headers:`, response.headers);

      if (!response.ok) {
        const error = await response.text();
        console.error(
          `🔄 Rotation failed with status ${response.status}:`,
          error
        );
        throw new Error(`Failed to rotate KEK: ${error}`);
      }

      console.log(`✅ KEK rotated successfully: ${kekName}`);

      // Get updated key info
      const keyInfo = await this.getKeyInfo(kekName);
      console.log(`🔄 New key info after rotation:`, keyInfo);
      return keyInfo.latest_version;
    } catch (error) {
      console.error("🔥 Error rotating KEK:", error);
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
   * List all keys in the transit engine
   */
  async listAllKeys(): Promise<string[]> {
    const url = `${this.endpoint}/v1/${this.transitMount}/keys?list=true`;
    console.log("🔍 Vault listAllKeys - URL:", url);
    console.log(
      "🔍 Vault listAllKeys - Token:",
      this.token ? "present" : "missing"
    );

    // Use GET with ?list=true parameter for Vault LIST operation
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "X-Vault-Token": this.token,
        "Content-Type": "application/json",
      },
    });

    console.log("🔍 Vault listAllKeys - Response status:", response.status);
    console.log("🔍 Vault listAllKeys - Response headers:", response.headers);

    if (!response.ok) {
      const error = await response.text();
      console.error("🔍 Vault listAllKeys - Error response:", error);
      throw new Error(`Failed to list keys: ${error}`);
    }

    const data = await response.json();
    console.log("🔍 Vault listAllKeys - Success data:", data);
    return data.data?.keys || [];
  }

  /**
   * Get all KEKs for a specific tenant
   */
  async getTenantKEKs(tenantId: string): Promise<any[]> {
    try {
      console.log(`🔍 Getting KEKs for tenant: ${tenantId}`);

      // First, try to list all keys from Vault
      let allKeys: string[] = [];
      try {
        allKeys = await this.listAllKeys();
        console.log(`🔍 Found ${allKeys.length} total keys in Vault:`, allKeys);
      } catch (error) {
        console.warn(
          "🔍 Failed to list all keys, falling back to known KEKs:",
          error
        );
        // Fallback to known KEKs if listing fails
        allKeys = [
          "kek-67016887-7471-4ac4-abae-021d05f09e2a",
          "kek-d1c24b6f-08ed-4b0e-ad01-56c2e9e2f0ff",
        ];
      }

      // Filter keys that belong to this tenant (contain tenant ID or start with 'kek-')
      const tenantKEKs = allKeys.filter(
        (keyName) => keyName.includes(tenantId) || keyName.startsWith("kek-")
      );

      console.log(
        `🔍 Found ${tenantKEKs.length} KEKs for tenant ${tenantId}:`,
        tenantKEKs
      );

      const kekDetails = [];
      for (const kekName of tenantKEKs) {
        try {
          console.log(`🔍 Getting info for KEK: ${kekName}`);
          const keyInfo = await this.getKeyInfo(kekName);
          console.log(`🔍 Successfully got info for KEK: ${kekName}`, keyInfo);
          console.log(
            `🔍 Creation time for ${kekName}:`,
            keyInfo.creation_time,
            typeof keyInfo.creation_time
          );

          kekDetails.push({
            id: kekName,
            kekName,
            algorithm: keyInfo.type,
            keyVersion: keyInfo.latest_version,
            minAvailableVersion: keyInfo.min_available_version,
            minDecryptionVersion: keyInfo.min_decryption_version,
            supportsEncryption: keyInfo.supports_encryption,
            supportsDecryption: keyInfo.supports_decryption,
            supportsSigning: keyInfo.supports_signing,
            supportsDerivation: keyInfo.derived,
            createdAt: keyInfo.creation_time
              ? new Date(keyInfo.creation_time * 1000).toISOString()
              : new Date().toISOString(),
            tenantId,
            keyType: "primary",
            status: "active",
            usageCount: 0,
            maxUsage: null,
            usagePercentage: null,
          });
        } catch (error) {
          console.warn(`🔍 Failed to get info for KEK ${kekName}:`, error);
          // Skip deleted or non-existent KEKs instead of including them
          console.log(
            `🔍 Skipping KEK ${kekName} as it doesn't exist or is inaccessible`
          );
        }
      }

      console.log(
        `🔍 Returning ${kekDetails.length} valid KEKs for tenant ${tenantId}`
      );
      return kekDetails;
    } catch (error) {
      console.error("Error getting tenant KEKs:", error);
      throw error;
    }
  }

  /**
   * Encrypt data using a KEK
   */
  async encryptData(
    kekName: string,
    plaintext: string,
    context?: string
  ): Promise<string> {
    const url = `${this.endpoint}/v1/${this.transitMount}/encrypt/${kekName}`;

    const payload: any = {
      plaintext: Buffer.from(plaintext).toString("base64"),
    };

    if (context) {
      payload.context = Buffer.from(context).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to encrypt data: ${error}`);
    }

    const data = await response.json();
    return data.data.ciphertext;
  }

  /**
   * Decrypt data using a KEK
   */
  async decryptData(
    kekName: string,
    ciphertext: string,
    context?: string
  ): Promise<string> {
    const url = `${this.endpoint}/v1/${this.transitMount}/decrypt/${kekName}`;

    const payload: any = {
      ciphertext,
    };

    if (context) {
      payload.context = Buffer.from(context).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to decrypt data: ${error}`);
    }

    const data = await response.json();
    // Return the base64 plaintext directly to preserve binary data
    return data.data.plaintext;
  }

  /**
   * Generate a new Data Encryption Key (DEK) and encrypt it with the KEK
   */
  async generateDatakey(
    kekName: string,
    context?: string
  ): Promise<{ plaintext: string; ciphertext: string }> {
    const url = `${this.endpoint}/v1/${this.transitMount}/datakey/plaintext/${kekName}`;

    const payload: any = {};
    if (context) {
      payload.context = Buffer.from(context).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to generate datakey: ${error}`);
    }

    const data = await response.json();
    return {
      plaintext: data.data.plaintext,
      ciphertext: data.data.ciphertext,
    };
  }

  /**
   * Rewrap ciphertext with the latest version of the KEK
   */
  async rewrapCiphertext(
    kekName: string,
    ciphertext: string,
    context?: string
  ): Promise<string> {
    const url = `${this.endpoint}/v1/${this.transitMount}/rewrap/${kekName}`;

    const payload: any = {
      ciphertext,
    };

    if (context) {
      payload.context = Buffer.from(context).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to rewrap ciphertext: ${error}`);
    }

    const data = await response.json();
    return data.data.ciphertext;
  }

  /**
   * Generate HMAC for data integrity verification
   */
  async generateHmac(
    kekName: string,
    data: string,
    context?: string
  ): Promise<string> {
    const url = `${this.endpoint}/v1/${this.transitMount}/hmac/${kekName}`;

    const payload: any = {
      input: Buffer.from(data).toString("base64"),
    };

    if (context) {
      payload.context = Buffer.from(context).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to generate HMAC: ${error}`);
    }

    const responseData = await response.json();
    return responseData.data.hmac;
  }

  /**
   * Verify HMAC for data integrity
   */
  async verifyHmac(
    kekName: string,
    data: string,
    hmac: string,
    context?: string
  ): Promise<boolean> {
    const url = `${this.endpoint}/v1/${this.transitMount}/verify/${kekName}`;

    const payload: any = {
      input: Buffer.from(data).toString("base64"),
      hmac,
    };

    if (context) {
      payload.context = Buffer.from(context).toString("base64");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-Vault-Token": this.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to verify HMAC: ${error}`);
    }

    const responseData = await response.json();
    return responseData.data.valid === true;
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
