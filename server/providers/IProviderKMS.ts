/**
 * Multi-Cloud Key Management Service Provider Interface
 * 
 * Provides a unified abstraction layer for managing encryption keys across
 * AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault, and other providers.
 * 
 * Implements enterprise-grade features:
 * - Key lifecycle management (create, enable, disable, rotate, delete)
 * - Cross-provider key distribution and synchronization
 * - BYOK (Bring Your Own Key) import and wrapping
 * - Multi-region replication
 * - Drift detection and auto-healing
 * - Policy enforcement and compliance
 */

import { ProviderKeyResult, ProviderHealthResult } from '@shared/schema';

export interface KeyCreateOptions {
  keyType: 'symmetric' | 'asymmetric';
  keyUsage: 'encrypt_decrypt' | 'sign_verify';
  keySize?: number;
  algorithm?: string;
  description?: string;
  alias?: string;
  tags?: Record<string, string>;
  policy?: any;
  multiRegion?: boolean;
  origin?: 'aws_kms' | 'external' | 'aws_cloudhsm';
}

export interface KeyRotateOptions {
  keyId: string;
  description?: string;
  tags?: Record<string, string>;
}

export interface KeyImportOptions {
  keyId: string;
  keyMaterial: Buffer;
  wrappingAlgorithm: 'RSAES_PKCS1_V1_5' | 'RSAES_OAEP_SHA_1' | 'RSAES_OAEP_SHA_256';
  wrappingKeySpec: 'RSA_2048' | 'RSA_3072' | 'RSA_4096';
  origin: 'external';
  expirationModel?: 'key_material_expires' | 'key_material_does_not_expire';
  validTo?: Date;
}

export interface KeyReplicationTarget {
  region: string;
  policy?: any;
  description?: string;
  tags?: Record<string, string>;
}

/**
 * Provider-agnostic KMS interface for enterprise key management
 */
export interface IProviderKMS {
  readonly providerId: string;
  readonly providerType: 'aws_kms' | 'azure_key_vault' | 'gcp_kms' | 'hashicorp_vault' | 'ibm_key_protect';
  readonly region: string;

  // ============================================================================
  // KEY LIFECYCLE MANAGEMENT
  // ============================================================================

  /**
   * Create a new encryption key in the provider
   */
  createKey(options: KeyCreateOptions): Promise<ProviderKeyResult>;

  /**
   * Import customer-provided key material (BYOK)
   */
  importKey(options: KeyImportOptions): Promise<ProviderKeyResult>;

  /**
   * Get key information and metadata
   */
  getKey(keyId: string): Promise<ProviderKeyResult>;

  /**
   * Enable a disabled key
   */
  enableKey(keyId: string): Promise<ProviderKeyResult>;

  /**
   * Disable a key (reversible)
   */
  disableKey(keyId: string): Promise<ProviderKeyResult>;

  /**
   * Schedule key deletion (irreversible after waiting period)
   */
  scheduleKeyDeletion(keyId: string, pendingWindowInDays?: number): Promise<ProviderKeyResult>;

  /**
   * Cancel scheduled key deletion
   */
  cancelKeyDeletion(keyId: string): Promise<ProviderKeyResult>;

  /**
   * Rotate key to new version (automatic key rotation)
   */
  rotateKey(options: KeyRotateOptions): Promise<ProviderKeyResult>;

  // ============================================================================
  // KEY OPERATIONS
  // ============================================================================

  /**
   * Encrypt data using the specified key
   */
  encrypt(keyId: string, plaintext: Buffer, context?: Record<string, string>): Promise<{
    ciphertext: Buffer;
    keyId: string;
    algorithm?: string;
  }>;

  /**
   * Decrypt data using the specified key
   */
  decrypt(ciphertext: Buffer, context?: Record<string, string>): Promise<{
    plaintext: Buffer;
    keyId: string;
    algorithm?: string;
  }>;

  /**
   * Generate data key for envelope encryption
   */
  generateDataKey(keyId: string, keySpec: string, context?: Record<string, string>): Promise<{
    keyId: string;
    plaintext: Buffer;
    ciphertext: Buffer;
  }>;

  /**
   * Generate data key without plaintext (for caching)
   */
  generateDataKeyWithoutPlaintext(keyId: string, keySpec: string, context?: Record<string, string>): Promise<{
    keyId: string;
    ciphertext: Buffer;
  }>;

  // ============================================================================
  // MULTI-REGION REPLICATION
  // ============================================================================

  /**
   * Replicate key to additional regions
   */
  replicateKey(keyId: string, targets: KeyReplicationTarget[]): Promise<ProviderKeyResult[]>;

  /**
   * Update replica key policy or configuration
   */
  updateReplicaKey(keyId: string, region: string, policy?: any, description?: string): Promise<ProviderKeyResult>;

  // ============================================================================
  // ALIASES AND METADATA
  // ============================================================================

  /**
   * Create an alias for the key
   */
  createAlias(aliasName: string, keyId: string): Promise<ProviderKeyResult>;

  /**
   * Update alias to point to different key
   */
  updateAlias(aliasName: string, keyId: string): Promise<ProviderKeyResult>;

  /**
   * Delete an alias
   */
  deleteAlias(aliasName: string): Promise<ProviderKeyResult>;

  /**
   * List all aliases
   */
  listAliases(): Promise<Array<{ aliasName: string; keyId: string; arn?: string }>>;

  /**
   * Add or update tags on a key
   */
  tagResource(keyId: string, tags: Record<string, string>): Promise<ProviderKeyResult>;

  /**
   * Remove tags from a key
   */
  untagResource(keyId: string, tagKeys: string[]): Promise<ProviderKeyResult>;

  // ============================================================================
  // POLICY AND PERMISSIONS
  // ============================================================================

  /**
   * Get key policy
   */
  getKeyPolicy(keyId: string): Promise<{ policy: any }>;

  /**
   * Set key policy
   */
  putKeyPolicy(keyId: string, policy: any): Promise<ProviderKeyResult>;

  /**
   * List grants for a key
   */
  listGrants(keyId: string): Promise<Array<{
    grantId: string;
    grantToken?: string;
    granteePrincipal: string;
    operations: string[];
    constraints?: any;
  }>>;

  /**
   * Create a grant for a key
   */
  createGrant(keyId: string, granteePrincipal: string, operations: string[], constraints?: any): Promise<{
    grantId: string;
    grantToken: string;
  }>;

  /**
   * Revoke a grant
   */
  revokeGrant(keyId: string, grantId: string): Promise<ProviderKeyResult>;

  // ============================================================================
  // MONITORING AND HEALTH
  // ============================================================================

  /**
   * List all keys in the provider
   */
  listKeys(): Promise<Array<{ keyId: string; arn?: string; description?: string }>>;

  /**
   * Check provider connectivity and health
   */
  healthCheck(): Promise<ProviderHealthResult>;

  /**
   * Get provider-specific metrics and usage
   */
  getUsageMetrics(startDate: Date, endDate: Date): Promise<{
    keyCount: number;
    operations: number;
    errors: number;
    costs?: number;
  }>;

  // ============================================================================
  // COMPLIANCE AND AUDIT
  // ============================================================================

  /**
   * Get audit logs for key operations
   */
  getAuditLogs(keyId: string, startDate: Date, endDate: Date): Promise<Array<{
    timestamp: Date;
    operation: string;
    principal: string;
    sourceIp?: string;
    userAgent?: string;
    result: 'success' | 'failure';
    errorCode?: string;
  }>>;

  /**
   * Validate key compliance with policies
   */
  validateCompliance(keyId: string, policies: string[]): Promise<{
    compliant: boolean;
    violations: Array<{ policy: string; violation: string; severity: 'low' | 'medium' | 'high' }>;
  }>;

  // ============================================================================
  // BACKUP AND RECOVERY
  // ============================================================================

  /**
   * Create a backup of key metadata and policy
   */
  backupKey(keyId: string): Promise<{
    backupId: string;
    backupArn?: string;
    metadata: any;
  }>;

  /**
   * Restore a key from backup
   */
  restoreKey(backupId: string, targetKeyId?: string): Promise<ProviderKeyResult>;
}

/**
 * Provider factory interface for creating KMS providers
 */
export interface IProviderFactory {
  createProvider(
    providerType: string,
    config: any,
    region: string
  ): Promise<IProviderKMS>;

  validateConfig(providerType: string, config: any): Promise<boolean>;
}

/**
 * Key sync engine for maintaining consistency across providers
 */
export interface IKeySyncEngine {
  /**
   * Sync a key across all configured providers
   */
  syncKey(keyId: string, tenantId: string): Promise<void>;

  /**
   * Detect drift between Averox and provider keys
   */
  detectDrift(keyId: string, tenantId: string): Promise<{
    hasDrift: boolean;
    driftDetails: Array<{
      provider: string;
      property: string;
      averoxValue: any;
      providerValue: any;
    }>;
  }>;

  /**
   * Auto-heal detected drift
   */
  healDrift(keyId: string, tenantId: string): Promise<void>;

  /**
   * Batch sync all keys for a tenant
   */
  syncAllKeys(tenantId: string): Promise<{
    synced: number;
    failed: number;
    errors: Array<{ keyId: string; error: string }>;
  }>;
}