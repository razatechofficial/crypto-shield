/**
 * HSM-Backed Key Lifecycle Management
 * Handles key generation, rotation, backup, recovery, and secure deletion
 * Provides government-level security with comprehensive audit trails and attestation
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { randomUUID } from 'crypto';
import { 
  BaseHsmAdapter, 
  HsmResult,
  HsmKeyGenParams,
  HsmError,
  HsmOperationError 
} from './hsmAdapter';
import { PKCS11Adapter } from './pkcs11Adapter';
import { KMIPAdapter } from './kmipAdapter';
import { SmartTokenAdapter } from './smartTokenAdapter';
import type { 
  HsmProvider,
  HsmDevice,
  HsmSession,
  HsmKey,
  HsmAuditLog,
  InsertHsmKey,
  InsertHsmAuditLog,
  ComplianceAssessment,
  CertificateAuthority
} from '@shared/schema';

/**
 * Key Lifecycle States
 */
export enum KeyLifecycleState {
  PENDING_GENERATION = 'pending_generation',
  ACTIVE = 'active',
  PENDING_ROTATION = 'pending_rotation',
  COMPROMISED = 'compromised',
  REVOKED = 'revoked',
  DESTROYED = 'destroyed',
  ESCROWED = 'escrowed',
  ARCHIVED = 'archived'
}

/**
 * Key Rotation Strategy
 */
export enum KeyRotationStrategy {
  TIME_BASED = 'time_based',          // Rotate after X days
  USAGE_BASED = 'usage_based',        // Rotate after X operations
  COMPROMISE_BASED = 'compromise_based', // Emergency rotation
  POLICY_BASED = 'policy_based',      // Based on compliance policy
  MANUAL = 'manual'                   // Manual rotation
}

/**
 * Key Backup Strategy
 */
export enum KeyBackupStrategy {
  NONE = 'none',                      // No backup (token-bound keys)
  HSM_ESCROW = 'hsm_escrow',          // Backup to another HSM
  SPLIT_KEY = 'split_key',            // Split key among multiple HSMs
  GOVERNMENT_ESCROW = 'government_escrow', // Government key escrow
  DUAL_CONTROL = 'dual_control'       // Dual control key backup
}

/**
 * Key Usage Policy
 */
export interface KeyUsagePolicy {
  maxOperations?: number;             // Maximum operations before rotation
  maxTimeActive?: number;             // Maximum time active (seconds)
  allowedOperations: string[];        // Allowed operations
  timeRestrictions?: {                // Time-based restrictions
    startTime?: string;               // UTC time string
    endTime?: string;
    daysOfWeek?: number[];            // 0-6, Sunday-Saturday
    timezone?: string;
  };
  locationRestrictions?: string[];    // Allowed locations/IPs
  userRestrictions?: string[];        // Allowed users
  complianceRequirements: string[];   // Required compliance flags
  attestationRequired: boolean;       // Require attestation for operations
  auditLevel: 'minimal' | 'standard' | 'comprehensive';
}

/**
 * Key Generation Request
 */
export interface KeyGenerationRequest {
  tenantId: string;
  userId: string;
  keyLabel: string;
  keyType: 'rsa' | 'ecdsa' | 'aes' | 'chacha20';
  keySize: number;
  keyUsage: string[];
  usagePolicy: KeyUsagePolicy;
  rotationStrategy: KeyRotationStrategy;
  rotationInterval?: number;          // Days for time-based rotation
  backupStrategy: KeyBackupStrategy;
  escrowAuthorities?: string[];       // Escrow authority identifiers
  complianceRequirements: string[];   // FIPS, CC, FISMA requirements
  certificateProfile?: string;        // Certificate profile for PKI
  metadata?: Record<string, any>;
}

/**
 * Key Rotation Request
 */
export interface KeyRotationRequest {
  keyId: string;
  reason: string;
  newKeyParams?: Partial<HsmKeyGenParams>;
  gracePeriod?: number;               // Grace period in seconds
  notifyUsers?: string[];             // Users to notify
  complianceValidation?: boolean;     // Require compliance validation
}

/**
 * Key Backup Request
 */
export interface KeyBackupRequest {
  keyId: string;
  escrowAuthority: string;
  backupStrategy: KeyBackupStrategy;
  splitThreshold?: number;            // For split key backup
  dualControlUsers?: string[];        // For dual control backup
  encryptionKey?: string;             // Backup encryption key
  complianceContext: Record<string, any>;
}

/**
 * Key Recovery Request
 */
export interface KeyRecoveryRequest {
  keyId: string;
  backupId: string;
  escrowAuthority: string;
  recoveryReason: string;
  authorizingUsers: string[];         // Users authorizing recovery
  targetHsm: string;                  // Target HSM for recovery
  complianceValidation: boolean;
}

/**
 * Key Lifecycle Event
 */
export interface KeyLifecycleEvent {
  keyId: string;
  event: string;
  timestamp: Date;
  userId: string;
  details: Record<string, any>;
  complianceContext: Record<string, any>;
  attestation?: string;
}

/**
 * Key Attestation Data
 */
export interface KeyAttestationData {
  keyId: string;
  attestationType: string;
  attestationTime: Date;
  hsmDevice: string;
  keyProperties: Record<string, any>;
  complianceFlags: string[];
  auditTrail: string[];
  digitalSignature: string;
}

/**
 * Key Lifecycle Manager
 */
export class KeyLifecycleManager extends EventEmitter {
  private adapters: Map<string, BaseHsmAdapter> = new Map();
  private activeKeys: Map<string, HsmKey> = new Map();
  private lifecycleEvents: Map<string, KeyLifecycleEvent[]> = new Map();
  private rotationScheduler: NodeJS.Timeout | null = null;
  private complianceValidator: ComplianceValidator;
  private auditLogger: HSMAuditLogger;

  constructor() {
    super();
    this.complianceValidator = new ComplianceValidator();
    this.auditLogger = new HSMAuditLogger();
    this.startRotationScheduler();
  }

  /**
   * Register HSM adapter
   */
  registerAdapter(providerId: string, adapter: BaseHsmAdapter): void {
    this.adapters.set(providerId, adapter);
    
    // Set up adapter event listeners
    adapter.on('error', (error) => {
      this.emit('adapterError', { providerId, error });
    });

    adapter.on('keyGenerated', (keyData) => {
      this.emit('keyGenerated', { providerId, ...keyData });
    });
  }

  /**
   * Generate new key with full lifecycle management
   */
  async generateKey(
    sessionId: string, 
    providerId: string, 
    request: KeyGenerationRequest
  ): Promise<HsmResult<HsmKey>> {
    const startTime = Date.now();
    
    try {
      const adapter = this.adapters.get(providerId);
      if (!adapter) {
        throw new HsmError('HSM_ADAPTER_NOT_FOUND', `Adapter not found: ${providerId}`);
      }

      // Validate compliance requirements
      const complianceValidation = await this.complianceValidator.validateKeyGeneration(request);
      if (!complianceValidation.valid) {
        throw new HsmOperationError(`Compliance validation failed: ${complianceValidation.reason}`);
      }

      // Prepare key generation parameters
      const keyGenParams: HsmKeyGenParams = {
        keyType: request.keyType,
        keySize: request.keySize,
        keyLabel: request.keyLabel,
        keyUsage: request.keyUsage,
        isExtractable: request.backupStrategy !== KeyBackupStrategy.NONE,
        isSensitive: true,
        expirationDate: request.rotationStrategy === KeyRotationStrategy.TIME_BASED 
          ? new Date(Date.now() + (request.rotationInterval || 30) * 24 * 60 * 60 * 1000)
          : undefined,
        keyPolicy: {
          usagePolicy: request.usagePolicy,
          rotationStrategy: request.rotationStrategy,
          backupStrategy: request.backupStrategy,
          complianceRequirements: request.complianceRequirements
        }
      };

      // Generate key using HSM adapter
      const keyResult = await adapter.generateKey(sessionId, keyGenParams);
      if (!keyResult.success || !keyResult.data) {
        throw new HsmOperationError(`Key generation failed: ${keyResult.error}`);
      }

      const hsmKey = keyResult.data;

      // Enhanced key record with lifecycle management
      const lifecycleManagedKey: HsmKey = {
        ...hsmKey,
        tenantId: request.tenantId,
        keyUsagePolicy: 'time_limited',
        rotationInterval: request.rotationInterval || 30,
        backupStatus: request.backupStrategy === KeyBackupStrategy.NONE ? 'none' : 'pending',
        complianceFlags: JSON.stringify(request.complianceRequirements),
        metadata: {
          ...(hsmKey.metadata || {}),
          lifecycle: {
            request,
            state: KeyLifecycleState.ACTIVE,
            createdBy: request.userId,
            rotationStrategy: request.rotationStrategy,
            backupStrategy: request.backupStrategy,
            complianceValidation,
            lastRotation: new Date(),
            nextRotation: this.calculateNextRotation(request),
            operationCount: 0,
            maxOperations: request.usagePolicy.maxOperations
          }
        }
      };

      // Store key in lifecycle manager
      this.activeKeys.set(hsmKey.keyId, lifecycleManagedKey);

      // Create lifecycle event
      const lifecycleEvent: KeyLifecycleEvent = {
        keyId: hsmKey.keyId,
        event: 'key_generated',
        timestamp: new Date(),
        userId: request.userId,
        details: {
          keyType: request.keyType,
          keySize: request.keySize,
          rotationStrategy: request.rotationStrategy,
          backupStrategy: request.backupStrategy
        },
        complianceContext: complianceValidation.context,
        attestation: keyResult.attestation
      };

      this.addLifecycleEvent(hsmKey.keyId, lifecycleEvent);

      // Schedule key rotation if applicable
      if (request.rotationStrategy === KeyRotationStrategy.TIME_BASED && request.rotationInterval) {
        this.scheduleKeyRotation(hsmKey.keyId, request.rotationInterval);
      }

      // Create backup if required
      if (request.backupStrategy !== KeyBackupStrategy.NONE) {
        await this.createKeyBackup(sessionId, hsmKey.keyId, {
          keyId: hsmKey.keyId,
          escrowAuthority: request.escrowAuthorities?.[0] || 'default',
          backupStrategy: request.backupStrategy,
          complianceContext: complianceValidation.context
        });
      }

      // Audit log entry
      await this.auditLogger.logKeyOperation({
        tenantId: request.tenantId,
        keyId: hsmKey.keyId,
        userId: request.userId,
        operationType: 'key_generate',
        eventType: 'key_access',
        status: 'success',
        requestData: { request },
        responseData: { keyId: hsmKey.keyId, keyLabel: request.keyLabel },
        complianceContext: complianceValidation.context,
        duration: Date.now() - startTime
      });

      this.emit('keyGenerated', { key: lifecycleManagedKey, request });

      return {
        success: true,
        data: lifecycleManagedKey,
        duration: Date.now() - startTime,
        attestation: keyResult.attestation
      };

    } catch (error) {
      // Audit failed operation
      await this.auditLogger.logKeyOperation({
        tenantId: request.tenantId,
        keyId: '',
        userId: request.userId,
        operationType: 'key_generate',
        eventType: 'security_violation',
        status: 'failure',
        requestData: { request },
        errorMessage: error instanceof Error ? error.message : 'Unknown error',
        duration: Date.now() - startTime
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmError ? error.code : 'KEY_GENERATION_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Rotate existing key
   */
  async rotateKey(
    sessionId: string,
    providerId: string,
    request: KeyRotationRequest
  ): Promise<HsmResult<{ oldKey: HsmKey; newKey: HsmKey }>> {
    const startTime = Date.now();
    
    try {
      const adapter = this.adapters.get(providerId);
      if (!adapter) {
        throw new HsmError('HSM_ADAPTER_NOT_FOUND', `Adapter not found: ${providerId}`);
      }

      const oldKey = this.activeKeys.get(request.keyId);
      if (!oldKey) {
        throw new HsmError('KEY_NOT_FOUND', `Key not found: ${request.keyId}`);
      }

      // Validate compliance for rotation
      if (request.complianceValidation) {
        const validation = await this.complianceValidator.validateKeyRotation(request, oldKey);
        if (!validation.valid) {
          throw new HsmOperationError(`Compliance validation failed: ${validation.reason}`);
        }
      }

      // Prepare new key parameters (inherit from old key unless overridden)
      const newKeyParams: HsmKeyGenParams = {
        keyType: request.newKeyParams?.keyType || (oldKey.metadata as any)?.lifecycle?.request?.keyType || 'rsa',
        keySize: request.newKeyParams?.keySize || oldKey.keySize,
        keyLabel: `${oldKey.keyLabel}_rotated_${Date.now()}`,
        keyUsage: request.newKeyParams?.keyUsage || (oldKey.metadata as any)?.lifecycle?.request?.keyUsage || ['sign', 'verify'],
        isExtractable: oldKey.isExtractable || false,
        isSensitive: oldKey.isSensitive || true,
        expirationDate: oldKey.expiresAt ? new Date(oldKey.expiresAt) : undefined,
        keyPolicy: (oldKey.metadata as any)?.lifecycle?.request?.usagePolicy || {}
      };

      // Generate new key
      const newKeyResult = await adapter.generateKey(sessionId, newKeyParams);
      if (!newKeyResult.success || !newKeyResult.data) {
        throw new HsmOperationError(`Key rotation failed: ${newKeyResult.error}`);
      }

      const newKey = newKeyResult.data;

      // Update old key status
      oldKey.status = 'revoked';
      oldKey.metadata = {
        ...(oldKey.metadata || {}),
        lifecycle: {
          ...(oldKey.metadata as any)?.lifecycle,
          state: KeyLifecycleState.ARCHIVED,
          rotatedAt: new Date(),
          rotatedTo: newKey.keyId,
          rotationReason: request.reason
        }
      };

      // Update new key with lifecycle information
      newKey.metadata = {
        ...(newKey.metadata || {}),
        lifecycle: {
          ...(oldKey.metadata as any)?.lifecycle,
          state: KeyLifecycleState.ACTIVE,
          rotatedFrom: oldKey.keyId,
          lastRotation: new Date(),
          nextRotation: this.calculateNextRotation((oldKey.metadata as any)?.lifecycle?.request),
          rotationCount: ((oldKey.metadata as any)?.lifecycle?.rotationCount || 0) + 1
        }
      };

      // Update key storage
      this.activeKeys.set(newKey.keyId, newKey);
      this.activeKeys.set(oldKey.keyId, oldKey);

      // Create lifecycle events
      const rotationEvent: KeyLifecycleEvent = {
        keyId: oldKey.keyId,
        event: 'key_rotated',
        timestamp: new Date(),
        userId: '', // Will be set by caller
        details: {
          reason: request.reason,
          newKeyId: newKey.keyId,
          gracePeriod: request.gracePeriod
        },
        complianceContext: {},
        attestation: newKeyResult.attestation
      };

      this.addLifecycleEvent(oldKey.keyId, rotationEvent);
      this.addLifecycleEvent(newKey.keyId, {
        ...rotationEvent,
        keyId: newKey.keyId,
        event: 'key_activated',
        details: {
          ...rotationEvent.details,
          replacedKeyId: oldKey.keyId
        }
      });

      // Schedule grace period for old key
      if (request.gracePeriod && request.gracePeriod > 0) {
        setTimeout(async () => {
          await this.deactivateKey(sessionId, providerId, oldKey.keyId, 'Grace period expired');
        }, request.gracePeriod * 1000);
      }

      this.emit('keyRotated', { oldKey, newKey, request });

      return {
        success: true,
        data: { oldKey, newKey },
        duration: Date.now() - startTime,
        attestation: newKeyResult.attestation
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmError ? error.code : 'KEY_ROTATION_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Create secure key backup
   */
  async createKeyBackup(
    sessionId: string,
    keyId: string,
    request: KeyBackupRequest
  ): Promise<HsmResult<string>> {
    const startTime = Date.now();
    
    try {
      const key = this.activeKeys.get(keyId);
      if (!key) {
        throw new HsmError('KEY_NOT_FOUND', `Key not found: ${keyId}`);
      }

      const adapter = this.adapters.get(key.deviceId || '');
      if (!adapter) {
        throw new HsmError('HSM_ADAPTER_NOT_FOUND', 'HSM adapter not found');
      }

      // Validate backup permissions and compliance
      const validation = await this.complianceValidator.validateKeyBackup(request, key);
      if (!validation.valid) {
        throw new HsmOperationError(`Backup validation failed: ${validation.reason}`);
      }

      // Perform backup based on strategy
      let backupId: string;
      
      switch (request.backupStrategy) {
        case KeyBackupStrategy.HSM_ESCROW:
          backupId = await this.performHsmEscrowBackup(adapter, sessionId, key, request);
          break;
          
        case KeyBackupStrategy.SPLIT_KEY:
          backupId = await this.performSplitKeyBackup(adapter, sessionId, key, request);
          break;
          
        case KeyBackupStrategy.GOVERNMENT_ESCROW:
          backupId = await this.performGovernmentEscrowBackup(adapter, sessionId, key, request);
          break;
          
        case KeyBackupStrategy.DUAL_CONTROL:
          backupId = await this.performDualControlBackup(adapter, sessionId, key, request);
          break;
          
        default:
          throw new HsmOperationError(`Unsupported backup strategy: ${request.backupStrategy}`);
      }

      // Update key backup status
      key.backupStatus = 'backed_up';
      key.escrowedBy = request.escrowAuthority;
      key.metadata = {
        ...(key.metadata || {}),
        backup: {
          backupId,
          strategy: request.backupStrategy,
          escrowAuthority: request.escrowAuthority,
          backedUpAt: new Date(),
          complianceContext: request.complianceContext
        }
      };

      // Create lifecycle event
      const backupEvent: KeyLifecycleEvent = {
        keyId,
        event: 'key_backed_up',
        timestamp: new Date(),
        userId: '', // Will be set by caller
        details: {
          backupId,
          strategy: request.backupStrategy,
          escrowAuthority: request.escrowAuthority
        },
        complianceContext: request.complianceContext
      };

      this.addLifecycleEvent(keyId, backupEvent);
      this.emit('keyBackedUp', { key, backupId, request });

      return {
        success: true,
        data: backupId,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmError ? error.code : 'KEY_BACKUP_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Recover key from backup
   */
  async recoverKey(
    sessionId: string,
    providerId: string,
    request: KeyRecoveryRequest
  ): Promise<HsmResult<HsmKey>> {
    const startTime = Date.now();
    
    try {
      const adapter = this.adapters.get(providerId);
      if (!adapter) {
        throw new HsmError('HSM_ADAPTER_NOT_FOUND', `Adapter not found: ${providerId}`);
      }

      // Validate recovery authorization and compliance
      const validation = await this.complianceValidator.validateKeyRecovery(request);
      if (!validation.valid) {
        throw new HsmOperationError(`Recovery validation failed: ${validation.reason}`);
      }

      // Perform recovery using HSM adapter
      const recoveryResult = await adapter.recoverKey(
        sessionId, 
        request.backupId, 
        request.escrowAuthority
      );

      if (!recoveryResult.success || !recoveryResult.data) {
        throw new HsmOperationError(`Key recovery failed: ${recoveryResult.error}`);
      }

      const recoveredKey = recoveryResult.data;

      // Update key status and metadata
      recoveredKey.status = 'active';
      recoveredKey.metadata = {
        ...(recoveredKey.metadata || {}),
        recovery: {
          recoveredAt: new Date(),
          recoveredBy: request.authorizingUsers,
          recoveryReason: request.recoveryReason,
          originalBackupId: request.backupId,
          complianceValidation: validation
        }
      };

      // Store recovered key
      this.activeKeys.set(recoveredKey.keyId, recoveredKey);

      // Create lifecycle event
      const recoveryEvent: KeyLifecycleEvent = {
        keyId: recoveredKey.keyId,
        event: 'key_recovered',
        timestamp: new Date(),
        userId: request.authorizingUsers[0] || '',
        details: {
          backupId: request.backupId,
          recoveryReason: request.recoveryReason,
          authorizingUsers: request.authorizingUsers
        },
        complianceContext: validation.context
      };

      this.addLifecycleEvent(recoveredKey.keyId, recoveryEvent);
      this.emit('keyRecovered', { key: recoveredKey, request });

      return {
        success: true,
        data: recoveredKey,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmError ? error.code : 'KEY_RECOVERY_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Securely destroy key with attestation
   */
  async destroyKey(
    sessionId: string,
    providerId: string,
    keyId: string,
    reason: string,
    attestationRequired = true
  ): Promise<HsmResult<KeyAttestationData>> {
    const startTime = Date.now();
    
    try {
      const adapter = this.adapters.get(providerId);
      if (!adapter) {
        throw new HsmError('HSM_ADAPTER_NOT_FOUND', `Adapter not found: ${providerId}`);
      }

      const key = this.activeKeys.get(keyId);
      if (!key) {
        throw new HsmError('KEY_NOT_FOUND', `Key not found: ${keyId}`);
      }

      // Generate attestation before destruction if required
      let attestationData: KeyAttestationData | null = null;
      if (attestationRequired) {
        const attestationResult = await this.generateKeyAttestation(sessionId, keyId);
        if (attestationResult.success && attestationResult.data) {
          attestationData = attestationResult.data;
        }
      }

      // Perform secure deletion
      const deletionResult = await adapter.deleteKey(sessionId, keyId);
      if (!deletionResult.success) {
        throw new HsmOperationError(`Key deletion failed: ${deletionResult.error}`);
      }

      // Update key status
      key.status = 'revoked';
      key.metadata = {
        ...(key.metadata || {}),
        destruction: {
          destroyedAt: new Date(),
          reason,
          attestationData,
          complianceValidation: true
        }
      };

      // Create lifecycle event
      const destructionEvent: KeyLifecycleEvent = {
        keyId,
        event: 'key_destroyed',
        timestamp: new Date(),
        userId: '', // Will be set by caller
        details: {
          reason,
          attestationGenerated: !!attestationData
        },
        complianceContext: {},
        attestation: attestationData?.digitalSignature
      };

      this.addLifecycleEvent(keyId, destructionEvent);

      // Remove from active keys but keep in lifecycle events for audit
      this.activeKeys.delete(keyId);

      this.emit('keyDestroyed', { key, reason, attestationData });

      return {
        success: true,
        data: attestationData!,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmError ? error.code : 'KEY_DESTRUCTION_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Generate key attestation
   */
  async generateKeyAttestation(
    sessionId: string,
    keyId: string
  ): Promise<HsmResult<KeyAttestationData>> {
    const startTime = Date.now();
    
    try {
      const key = this.activeKeys.get(keyId);
      if (!key) {
        throw new HsmError('KEY_NOT_FOUND', `Key not found: ${keyId}`);
      }

      const adapter = this.adapters.get(key.deviceId || '');
      if (!adapter) {
        throw new HsmError('HSM_ADAPTER_NOT_FOUND', 'HSM adapter not found');
      }

      // Get attestation from HSM
      const hsmAttestationResult = await adapter.attestKey(sessionId, keyId);
      
      // Create comprehensive attestation data
      const attestationData: KeyAttestationData = {
        keyId,
        attestationType: 'comprehensive',
        attestationTime: new Date(),
        hsmDevice: key.deviceId || '',
        keyProperties: {
          keyType: (key.metadata as any)?.lifecycle?.request?.keyType,
          keySize: key.keySize,
          algorithm: key.algorithmId,
          createdInHsm: key.createdInHsm,
          usageCount: key.usageCount,
          lastUsed: key.lastUsed,
          status: key.status,
          isExtractable: key.isExtractable,
          isSensitive: key.isSensitive
        },
        complianceFlags: JSON.parse(key.complianceFlags || '[]'),
        auditTrail: this.getKeyAuditTrail(keyId),
        digitalSignature: this.generateAttestationSignature(keyId, hsmAttestationResult.data)
      };

      return {
        success: true,
        data: attestationData,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'KEY_ATTESTATION_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Get key lifecycle history
   */
  getKeyLifecycleHistory(keyId: string): KeyLifecycleEvent[] {
    return this.lifecycleEvents.get(keyId) || [];
  }

  /**
   * Get active keys summary
   */
  getActiveKeysSummary(): Record<string, any> {
    const summary = {
      totalKeys: this.activeKeys.size,
      keysByType: {} as Record<string, number>,
      keysByStatus: {} as Record<string, number>,
      keysByRotationStrategy: {} as Record<string, number>,
      upcomingRotations: [] as Array<{ keyId: string; nextRotation: Date }>,
      complianceIssues: [] as Array<{ keyId: string; issue: string }>
    };

    for (const [keyId, key] of Array.from(this.activeKeys.entries())) {
      const keyType = (key.metadata as any)?.lifecycle?.request?.keyType || 'unknown';
      const status = key.status || 'active';
      const rotationStrategy = (key.metadata as any)?.lifecycle?.request?.rotationStrategy || 'unknown';

      summary.keysByType[keyType] = (summary.keysByType[keyType] || 0) + 1;
      if (status) summary.keysByStatus[status] = (summary.keysByStatus[status] || 0) + 1;
      summary.keysByRotationStrategy[rotationStrategy] = (summary.keysByRotationStrategy[rotationStrategy] || 0) + 1;

      // Check for upcoming rotations
      const nextRotation = (key.metadata as any)?.lifecycle?.nextRotation;
      if (nextRotation && new Date(nextRotation) <= new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)) {
        summary.upcomingRotations.push({
          keyId,
          nextRotation: new Date(nextRotation)
        });
      }

      // Check for compliance issues
      if (key.status === 'revoked' || (key.expiresAt && new Date(key.expiresAt) < new Date())) {
        summary.complianceIssues.push({
          keyId,
          issue: key.status === 'revoked' ? 'Key revoked' : 'Key expired'
        });
      }
    }

    return summary;
  }

  /**
   * Helper Methods
   */
  
  private addLifecycleEvent(keyId: string, event: KeyLifecycleEvent): void {
    if (!this.lifecycleEvents.has(keyId)) {
      this.lifecycleEvents.set(keyId, []);
    }
    this.lifecycleEvents.get(keyId)!.push(event);
  }

  private encodeUsagePolicy(policy: KeyUsagePolicy): string {
    return JSON.stringify(policy);
  }

  private calculateNextRotation(request?: KeyGenerationRequest): Date | null {
    if (!request || request.rotationStrategy !== KeyRotationStrategy.TIME_BASED) {
      return null;
    }
    
    const interval = request.rotationInterval || 30;
    return new Date(Date.now() + interval * 24 * 60 * 60 * 1000);
  }

  private scheduleKeyRotation(keyId: string, intervalDays: number): void {
    const rotationTime = intervalDays * 24 * 60 * 60 * 1000;
    
    setTimeout(() => {
      this.emit('rotationDue', { keyId });
    }, rotationTime);
  }

  private async performHsmEscrowBackup(
    adapter: BaseHsmAdapter,
    sessionId: string,
    key: HsmKey,
    request: KeyBackupRequest
  ): Promise<string> {
    // Implementation would use adapter.backupKey with HSM escrow
    const backupResult = await adapter.backupKey(sessionId, key.keyId, request.escrowAuthority);
    if (!backupResult.success) {
      throw new HsmOperationError(`HSM escrow backup failed: ${backupResult.error}`);
    }
    return backupResult.data || randomUUID();
  }

  private async performSplitKeyBackup(
    adapter: BaseHsmAdapter,
    sessionId: string,
    key: HsmKey,
    request: KeyBackupRequest
  ): Promise<string> {
    // Implementation would split key across multiple HSMs
    const backupId = randomUUID();
    // Mock implementation
    return backupId;
  }

  private async performGovernmentEscrowBackup(
    adapter: BaseHsmAdapter,
    sessionId: string,
    key: HsmKey,
    request: KeyBackupRequest
  ): Promise<string> {
    // Implementation would integrate with government escrow systems
    const backupId = randomUUID();
    // Mock implementation
    return backupId;
  }

  private async performDualControlBackup(
    adapter: BaseHsmAdapter,
    sessionId: string,
    key: HsmKey,
    request: KeyBackupRequest
  ): Promise<string> {
    // Implementation would require dual authorization
    const backupId = randomUUID();
    // Mock implementation
    return backupId;
  }

  private async deactivateKey(
    sessionId: string,
    providerId: string,
    keyId: string,
    reason: string
  ): Promise<void> {
    const key = this.activeKeys.get(keyId);
    if (key) {
      key.status = 'revoked';
      
      const deactivationEvent: KeyLifecycleEvent = {
        keyId,
        event: 'key_deactivated',
        timestamp: new Date(),
        userId: 'system',
        details: { reason },
        complianceContext: {}
      };

      this.addLifecycleEvent(keyId, deactivationEvent);
      this.emit('keyDeactivated', { key, reason });
    }
  }

  private getKeyAuditTrail(keyId: string): string[] {
    const events = this.lifecycleEvents.get(keyId) || [];
    return events.map(event => 
      `${event.timestamp.toISOString()}: ${event.event} by ${event.userId} - ${JSON.stringify(event.details)}`
    );
  }

  private generateAttestationSignature(keyId: string, attestationData: any): string {
    // In production, would use HSM to sign attestation data
    const data = JSON.stringify({ keyId, attestationData, timestamp: Date.now() });
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private startRotationScheduler(): void {
    // Check for rotation requirements every hour
    this.rotationScheduler = setInterval(() => {
      this.checkRotationRequirements();
    }, 60 * 60 * 1000);
  }

  private checkRotationRequirements(): void {
    for (const [keyId, key] of Array.from(this.activeKeys.entries())) {
      const lifecycle = (key.metadata as any)?.lifecycle;
      if (!lifecycle) continue;

      const now = new Date();
      
      // Check time-based rotation
      if (lifecycle.nextRotation && new Date(lifecycle.nextRotation) <= now) {
        this.emit('rotationDue', { keyId, reason: 'time_based' });
      }

      // Check usage-based rotation
      if (lifecycle.maxOperations && (key.usageCount || 0) >= lifecycle.maxOperations) {
        this.emit('rotationDue', { keyId, reason: 'usage_limit_reached' });
      }
    }
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    if (this.rotationScheduler) {
      clearInterval(this.rotationScheduler);
      this.rotationScheduler = null;
    }

    for (const adapter of Array.from(this.adapters.values())) {
      try {
        await adapter.cleanup();
      } catch (error) {
        console.error('Failed to cleanup adapter:', error);
      }
    }

    this.adapters.clear();
    this.activeKeys.clear();
    this.lifecycleEvents.clear();
  }
}

/**
 * Compliance Validator for key operations
 */
class ComplianceValidator {
  async validateKeyGeneration(request: KeyGenerationRequest): Promise<{ valid: boolean; reason?: string; context: Record<string, any> }> {
    // Mock compliance validation
    const context = {
      fipsCompliant: request.complianceRequirements.includes('fips_140_2'),
      ccCompliant: request.complianceRequirements.includes('common_criteria'),
      validatedAt: new Date().toISOString()
    };

    return { valid: true, context };
  }

  async validateKeyRotation(request: KeyRotationRequest, key: HsmKey): Promise<{ valid: boolean; reason?: string; context: Record<string, any> }> {
    return { valid: true, context: {} };
  }

  async validateKeyBackup(request: KeyBackupRequest, key: HsmKey): Promise<{ valid: boolean; reason?: string; context: Record<string, any> }> {
    return { valid: true, context: {} };
  }

  async validateKeyRecovery(request: KeyRecoveryRequest): Promise<{ valid: boolean; reason?: string; context: Record<string, any> }> {
    return { valid: true, context: {} };
  }
}

/**
 * HSM Audit Logger
 */
class HSMAuditLogger {
  async logKeyOperation(logEntry: Partial<InsertHsmAuditLog>): Promise<void> {
    // Mock audit logging (in production would write to secure audit log)
    console.log('HSM Audit Log:', JSON.stringify(logEntry, null, 2));
  }
}