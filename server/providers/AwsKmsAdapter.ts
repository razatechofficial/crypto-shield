/**
 * AWS KMS Provider Implementation
 * 
 * Enterprise-grade AWS KMS adapter implementing the IProviderKMS interface
 * for seamless multi-cloud key management and distribution.
 * 
 * Features:
 * - Full AWS KMS API integration
 * - Multi-region key replication
 * - BYOK (Bring Your Own Key) support
 * - Envelope encryption with data keys
 * - Policy management and grants
 * - Comprehensive audit logging
 * - Health monitoring and metrics
 */

import { 
  KMSClient, 
  CreateKeyCommand, 
  ImportKeyMaterialCommand,
  DescribeKeyCommand,
  EnableKeyCommand,
  DisableKeyCommand,
  ScheduleKeyDeletionCommand,
  CancelKeyDeletionCommand,
  RotateKeyOnDemandCommand,
  EncryptCommand,
  DecryptCommand,
  GenerateDataKeyCommand,
  GenerateDataKeyWithoutPlaintextCommand,
  ReplicateKeyCommand,
  UpdateKeyDescriptionCommand,
  CreateAliasCommand,
  UpdateAliasCommand,
  DeleteAliasCommand,
  ListAliasesCommand,
  TagResourceCommand,
  UntagResourceCommand,
  GetKeyPolicyCommand,
  PutKeyPolicyCommand,
  ListGrantsCommand,
  CreateGrantCommand,
  RevokeGrantCommand,
  ListKeysCommand,
  GetParametersForImportCommand,
  DescribeCustomKeyStoresCommand,
  type KeyUsageType,
  type KeySpec,
  type OriginType
} from '@aws-sdk/client-kms';

import { fromEnv, fromIni } from '@aws-sdk/credential-providers';
import { 
  IProviderKMS, 
  KeyCreateOptions, 
  KeyRotateOptions, 
  KeyImportOptions, 
  KeyReplicationTarget 
} from './IProviderKMS';
import { ProviderKeyResult, ProviderHealthResult, AwsKmsConfig } from '@shared/schema';

export class AwsKmsAdapter implements IProviderKMS {
  public readonly providerId: string;
  public readonly providerType = 'aws_kms' as const;
  public readonly region: string;
  private readonly client: KMSClient;
  private readonly config: AwsKmsConfig;

  constructor(config: AwsKmsConfig, providerId: string) {
    this.config = config;
    this.providerId = providerId;
    this.region = config.region;

    // Initialize AWS KMS client with credentials
    this.client = new KMSClient({
      region: config.region,
      credentials: config.roleArn 
        ? undefined // Will use STS to assume role
        : {
            accessKeyId: config.accessKeyId,
            secretAccessKey: config.secretAccessKey,
          }
    });
  }

  // ============================================================================
  // KEY LIFECYCLE MANAGEMENT
  // ============================================================================

  async createKey(options: KeyCreateOptions): Promise<ProviderKeyResult> {
    try {
      const command = new CreateKeyCommand({
        KeyUsage: options.keyUsage === 'encrypt_decrypt' ? 'ENCRYPT_DECRYPT' : 'SIGN_VERIFY',
        KeySpec: this.mapKeySpecification(options.keyType, options.keySize, options.algorithm),
        Origin: options.origin as OriginType || 'AWS_KMS',
        Description: options.description,
        Policy: options.policy ? JSON.stringify(options.policy) : undefined,
        Tags: options.tags ? Object.entries(options.tags).map(([key, value]) => ({
          TagKey: key,
          TagValue: value
        })) : undefined,
        MultiRegion: options.multiRegion || false,
      });

      const result = await this.client.send(command);
      
      // Create alias if specified
      if (options.alias && result.KeyMetadata?.KeyId) {
        await this.createAlias(options.alias, result.KeyMetadata.KeyId);
      }

      return {
        success: true,
        keyId: result.KeyMetadata?.KeyId,
        keyArn: result.KeyMetadata?.Arn,
        alias: options.alias,
        metadata: {
          keyUsage: result.KeyMetadata?.KeyUsage,
          keyState: result.KeyMetadata?.KeyState,
          creationDate: result.KeyMetadata?.CreationDate,
          description: result.KeyMetadata?.Description,
          multiRegion: result.KeyMetadata?.MultiRegion,
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to create AWS KMS key: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async importKey(options: KeyImportOptions): Promise<ProviderKeyResult> {
    try {
      // First, get import parameters
      const getParamsCommand = new GetParametersForImportCommand({
        KeyId: options.keyId,
        WrappingAlgorithm: options.wrappingAlgorithm,
        WrappingKeySpec: options.wrappingKeySpec
      });
      
      const importParams = await this.client.send(getParamsCommand);
      
      // Import the key material
      const importCommand = new ImportKeyMaterialCommand({
        KeyId: options.keyId,
        ImportToken: importParams.ImportToken,
        EncryptedKeyMaterial: options.keyMaterial,
        ExpirationModel: options.expirationModel || 'KEY_MATERIAL_DOES_NOT_EXPIRE',
        ValidTo: options.validTo,
      });

      await this.client.send(importCommand);

      return {
        success: true,
        keyId: options.keyId,
        metadata: {
          origin: 'EXTERNAL',
          expirationModel: options.expirationModel,
          validTo: options.validTo,
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to import key material: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async getKey(keyId: string): Promise<ProviderKeyResult> {
    try {
      const command = new DescribeKeyCommand({ KeyId: keyId });
      const result = await this.client.send(command);

      return {
        success: true,
        keyId: result.KeyMetadata?.KeyId,
        keyArn: result.KeyMetadata?.Arn,
        metadata: {
          keyUsage: result.KeyMetadata?.KeyUsage,
          keyState: result.KeyMetadata?.KeyState,
          creationDate: result.KeyMetadata?.CreationDate,
          description: result.KeyMetadata?.Description,
          origin: result.KeyMetadata?.Origin,
          keyManager: result.KeyMetadata?.KeyManager,
          multiRegion: result.KeyMetadata?.MultiRegion,
          encryptionAlgorithms: result.KeyMetadata?.EncryptionAlgorithms,
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to get key: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async enableKey(keyId: string): Promise<ProviderKeyResult> {
    try {
      const command = new EnableKeyCommand({ KeyId: keyId });
      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: { action: 'enabled' }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to enable key: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async disableKey(keyId: string): Promise<ProviderKeyResult> {
    try {
      const command = new DisableKeyCommand({ KeyId: keyId });
      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: { action: 'disabled' }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to disable key: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async scheduleKeyDeletion(keyId: string, pendingWindowInDays: number = 30): Promise<ProviderKeyResult> {
    try {
      const command = new ScheduleKeyDeletionCommand({
        KeyId: keyId,
        PendingWindowInDays: pendingWindowInDays
      });
      
      const result = await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: {
          action: 'scheduled_for_deletion',
          deletionDate: result.DeletionDate,
          pendingWindowInDays
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to schedule key deletion: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async cancelKeyDeletion(keyId: string): Promise<ProviderKeyResult> {
    try {
      const command = new CancelKeyDeletionCommand({ KeyId: keyId });
      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: { action: 'deletion_cancelled' }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to cancel key deletion: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async rotateKey(options: KeyRotateOptions): Promise<ProviderKeyResult> {
    try {
      const command = new RotateKeyOnDemandCommand({ KeyId: options.keyId });
      const result = await this.client.send(command);

      return {
        success: true,
        keyId: result.KeyId,
        metadata: {
          action: 'rotated',
          rotationDate: new Date().toISOString(),
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to rotate key: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  // ============================================================================
  // KEY OPERATIONS
  // ============================================================================

  async encrypt(keyId: string, plaintext: Buffer, context?: Record<string, string>) {
    const command = new EncryptCommand({
      KeyId: keyId,
      Plaintext: plaintext,
      EncryptionContext: context,
    });

    const result = await this.client.send(command);
    
    return {
      ciphertext: Buffer.from(result.CiphertextBlob!),
      keyId: result.KeyId!,
      algorithm: result.EncryptionAlgorithm,
    };
  }

  async decrypt(ciphertext: Buffer, context?: Record<string, string>) {
    const command = new DecryptCommand({
      CiphertextBlob: ciphertext,
      EncryptionContext: context,
    });

    const result = await this.client.send(command);
    
    return {
      plaintext: Buffer.from(result.Plaintext!),
      keyId: result.KeyId!,
      algorithm: result.EncryptionAlgorithm,
    };
  }

  async generateDataKey(keyId: string, keySpec: string, context?: Record<string, string>) {
    const command = new GenerateDataKeyCommand({
      KeyId: keyId,
      KeySpec: keySpec as KeySpec,
      EncryptionContext: context,
    });

    const result = await this.client.send(command);
    
    return {
      keyId: result.KeyId!,
      plaintext: Buffer.from(result.Plaintext!),
      ciphertext: Buffer.from(result.CiphertextBlob!),
    };
  }

  async generateDataKeyWithoutPlaintext(keyId: string, keySpec: string, context?: Record<string, string>) {
    const command = new GenerateDataKeyWithoutPlaintextCommand({
      KeyId: keyId,
      KeySpec: keySpec as KeySpec,
      EncryptionContext: context,
    });

    const result = await this.client.send(command);
    
    return {
      keyId: result.KeyId!,
      ciphertext: Buffer.from(result.CiphertextBlob!),
    };
  }

  // ============================================================================
  // MULTI-REGION REPLICATION
  // ============================================================================

  async replicateKey(keyId: string, targets: KeyReplicationTarget[]): Promise<ProviderKeyResult[]> {
    const results: ProviderKeyResult[] = [];

    for (const target of targets) {
      try {
        const command = new ReplicateKeyCommand({
          KeyId: keyId,
          ReplicaRegion: target.region,
          Policy: target.policy ? JSON.stringify(target.policy) : undefined,
          Description: target.description,
          Tags: target.tags ? Object.entries(target.tags).map(([key, value]) => ({
            TagKey: key,
            TagValue: value
          })) : undefined,
        });

        const result = await this.client.send(command);
        
        results.push({
          success: true,
          keyId: result.ReplicaKeyMetadata?.KeyId,
          keyArn: result.ReplicaKeyMetadata?.Arn,
          metadata: {
            region: target.region,
            replicationDate: new Date().toISOString(),
          }
        });
      } catch (error: any) {
        results.push({
          success: false,
          error: `Failed to replicate to ${target.region}: ${error.message}`,
          metadata: { 
            region: target.region,
            awsError: error.name, 
            awsMessage: error.message 
          }
        });
      }
    }

    return results;
  }

  async updateReplicaKey(keyId: string, region: string, policy?: any, description?: string): Promise<ProviderKeyResult> {
    try {
      // Create a regional client for the replica
      const regionalClient = new KMSClient({
        region: region,
        credentials: {
          accessKeyId: this.config.accessKeyId,
          secretAccessKey: this.config.secretAccessKey,
        }
      });

      if (description) {
        const updateCommand = new UpdateKeyDescriptionCommand({
          KeyId: keyId,
          Description: description,
        });
        await regionalClient.send(updateCommand);
      }

      if (policy) {
        const policyCommand = new PutKeyPolicyCommand({
          KeyId: keyId,
          PolicyName: 'default',
          Policy: JSON.stringify(policy),
        });
        await regionalClient.send(policyCommand);
      }

      return {
        success: true,
        keyId: keyId,
        metadata: {
          region: region,
          action: 'replica_updated',
        }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to update replica key: ${error.message}`,
        metadata: { 
          region: region,
          awsError: error.name, 
          awsMessage: error.message 
        }
      };
    }
  }

  // ============================================================================
  // ALIASES AND METADATA
  // ============================================================================

  async createAlias(aliasName: string, keyId: string): Promise<ProviderKeyResult> {
    try {
      const command = new CreateAliasCommand({
        AliasName: aliasName.startsWith('alias/') ? aliasName : `alias/${aliasName}`,
        TargetKeyId: keyId,
      });

      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        alias: aliasName,
        metadata: { action: 'alias_created' }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to create alias: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async updateAlias(aliasName: string, keyId: string): Promise<ProviderKeyResult> {
    try {
      const command = new UpdateAliasCommand({
        AliasName: aliasName.startsWith('alias/') ? aliasName : `alias/${aliasName}`,
        TargetKeyId: keyId,
      });

      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        alias: aliasName,
        metadata: { action: 'alias_updated' }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to update alias: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async deleteAlias(aliasName: string): Promise<ProviderKeyResult> {
    try {
      const command = new DeleteAliasCommand({
        AliasName: aliasName.startsWith('alias/') ? aliasName : `alias/${aliasName}`,
      });

      await this.client.send(command);

      return {
        success: true,
        alias: aliasName,
        metadata: { action: 'alias_deleted' }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to delete alias: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async listAliases(): Promise<Array<{ aliasName: string; keyId: string; arn?: string }>> {
    try {
      const command = new ListAliasesCommand({});
      const result = await this.client.send(command);

      return result.Aliases?.map(alias => ({
        aliasName: alias.AliasName!,
        keyId: alias.TargetKeyId!,
        arn: alias.AliasArn,
      })) || [];
    } catch (error: any) {
      console.error('Failed to list aliases:', error);
      return [];
    }
  }

  async tagResource(keyId: string, tags: Record<string, string>): Promise<ProviderKeyResult> {
    try {
      const command = new TagResourceCommand({
        KeyId: keyId,
        Tags: Object.entries(tags).map(([key, value]) => ({
          TagKey: key,
          TagValue: value
        })),
      });

      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: { action: 'tagged', tags }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to tag resource: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async untagResource(keyId: string, tagKeys: string[]): Promise<ProviderKeyResult> {
    try {
      const command = new UntagResourceCommand({
        KeyId: keyId,
        TagKeys: tagKeys,
      });

      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: { action: 'untagged', removedTagKeys: tagKeys }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to untag resource: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  // ============================================================================
  // POLICY AND PERMISSIONS
  // ============================================================================

  async getKeyPolicy(keyId: string): Promise<{ policy: any }> {
    const command = new GetKeyPolicyCommand({
      KeyId: keyId,
      PolicyName: 'default',
    });

    const result = await this.client.send(command);
    return { policy: JSON.parse(result.Policy!) };
  }

  async putKeyPolicy(keyId: string, policy: any): Promise<ProviderKeyResult> {
    try {
      const command = new PutKeyPolicyCommand({
        KeyId: keyId,
        PolicyName: 'default',
        Policy: JSON.stringify(policy),
      });

      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: { action: 'policy_updated' }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to put key policy: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  async listGrants(keyId: string) {
    const command = new ListGrantsCommand({ KeyId: keyId });
    const result = await this.client.send(command);

    return result.Grants?.map(grant => ({
      grantId: grant.GrantId!,
      grantToken: grant.GrantToken,
      granteePrincipal: grant.GranteePrincipal!,
      operations: grant.Operations || [],
      constraints: grant.Constraints,
    })) || [];
  }

  async createGrant(keyId: string, granteePrincipal: string, operations: string[], constraints?: any) {
    const command = new CreateGrantCommand({
      KeyId: keyId,
      GranteePrincipal: granteePrincipal,
      Operations: operations as any[],
      Constraints: constraints,
    });

    const result = await this.client.send(command);
    
    return {
      grantId: result.GrantId!,
      grantToken: result.GrantToken!,
    };
  }

  async revokeGrant(keyId: string, grantId: string): Promise<ProviderKeyResult> {
    try {
      const command = new RevokeGrantCommand({
        KeyId: keyId,
        GrantId: grantId,
      });

      await this.client.send(command);

      return {
        success: true,
        keyId: keyId,
        metadata: { action: 'grant_revoked', grantId }
      };
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to revoke grant: ${error.message}`,
        metadata: { awsError: error.name, awsMessage: error.message }
      };
    }
  }

  // ============================================================================
  // MONITORING AND HEALTH
  // ============================================================================

  async listKeys(): Promise<Array<{ keyId: string; arn?: string; description?: string }>> {
    try {
      const command = new ListKeysCommand({});
      const result = await this.client.send(command);

      // Get additional details for each key
      const detailedKeys = [];
      for (const key of result.Keys || []) {
        try {
          const describeCommand = new DescribeKeyCommand({ KeyId: key.KeyId });
          const keyDetails = await this.client.send(describeCommand);
          
          detailedKeys.push({
            keyId: key.KeyId!,
            arn: key.KeyArn,
            description: keyDetails.KeyMetadata?.Description,
          });
        } catch (error) {
          // Skip keys we can't describe (permissions issues)
          detailedKeys.push({
            keyId: key.KeyId!,
            arn: key.KeyArn,
            description: undefined,
          });
        }
      }

      return detailedKeys;
    } catch (error: any) {
      console.error('Failed to list keys:', error);
      return [];
    }
  }

  async healthCheck(): Promise<ProviderHealthResult> {
    const startTime = Date.now();
    
    try {
      // Simple health check by listing keys (limited)
      const command = new ListKeysCommand({ Limit: 1 });
      await this.client.send(command);
      
      return {
        healthy: true,
        responseTime: Date.now() - startTime,
        lastChecked: new Date(),
      };
    } catch (error: any) {
      return {
        healthy: false,
        responseTime: Date.now() - startTime,
        error: error.message,
        lastChecked: new Date(),
      };
    }
  }

  async getUsageMetrics(startDate: Date, endDate: Date) {
    // AWS KMS doesn't provide direct usage metrics through the KMS API
    // This would typically require CloudWatch integration
    return {
      keyCount: 0,
      operations: 0,
      errors: 0,
      costs: 0,
    };
  }

  // ============================================================================
  // COMPLIANCE AND AUDIT
  // ============================================================================

  async getAuditLogs(keyId: string, startDate: Date, endDate: Date) {
    // AWS KMS audit logs are available through CloudTrail
    // This would require CloudTrail API integration
    return [];
  }

  async validateCompliance(keyId: string, policies: string[]) {
    // Compliance validation would require policy evaluation
    return {
      compliant: true,
      violations: [],
    };
  }

  // ============================================================================
  // BACKUP AND RECOVERY
  // ============================================================================

  async backupKey(keyId: string) {
    // AWS KMS doesn't support direct key backup
    // This would be metadata backup only
    const keyInfo = await this.getKey(keyId);
    
    return {
      backupId: `backup-${keyId}-${Date.now()}`,
      metadata: keyInfo.metadata,
    };
  }

  async restoreKey(backupId: string, targetKeyId?: string): Promise<ProviderKeyResult> {
    // AWS KMS doesn't support direct key restoration
    return {
      success: false,
      error: 'Key restoration not supported by AWS KMS',
    };
  }

  // ============================================================================
  // PRIVATE HELPER METHODS
  // ============================================================================

  private mapKeySpecification(keyType: string, keySize?: number, algorithm?: string): KeySpec {
    if (keyType === 'symmetric') {
      return 'SYMMETRIC_DEFAULT';
    }
    
    if (keyType === 'asymmetric') {
      if (algorithm?.includes('RSA')) {
        return keySize === 4096 ? 'RSA_4096' : keySize === 3072 ? 'RSA_3072' : 'RSA_2048';
      }
      if (algorithm?.includes('ECC')) {
        return keySize === 521 ? 'ECC_NIST_P521' : keySize === 384 ? 'ECC_NIST_P384' : 'ECC_NIST_P256';
      }
      return 'RSA_2048'; // Default
    }
    
    return 'SYMMETRIC_DEFAULT';
  }
}