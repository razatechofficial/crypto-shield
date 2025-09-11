/**
 * HSM Adapter Base Classes and Interfaces
 * Provides abstraction layer for different HSM vendors and protocols
 * Supports PKCS#11, KMIP, REST APIs, and proprietary protocols
 */

import { EventEmitter } from 'events';
import type { 
  HsmProvider, 
  HsmDevice, 
  HsmSession, 
  HsmKey, 
  HsmAuditLog,
  InsertHsmAuditLog 
} from '@shared/schema';

/**
 * HSM Operation Result
 */
export interface HsmResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  errorCode?: string;
  duration?: number;
  attestation?: string;
}

/**
 * HSM Key Generation Parameters
 */
export interface HsmKeyGenParams {
  keyType: 'rsa' | 'ecdsa' | 'aes' | 'chacha20';
  keySize: number;
  keyLabel: string;
  keyUsage: string[];
  isExtractable?: boolean;
  isSensitive?: boolean;
  expirationDate?: Date;
  keyPolicy?: Record<string, any>;
}

/**
 * HSM Signing Parameters
 */
export interface HsmSignParams {
  keyId: string;
  algorithm: string;
  data: Buffer;
  additionalAuthData?: Buffer;
  saltLength?: number;
}

/**
 * HSM Encryption Parameters
 */
export interface HsmEncryptParams {
  keyId: string;
  algorithm: string;
  data: Buffer;
  iv?: Buffer;
  additionalAuthData?: Buffer;
}

/**
 * HSM Session Configuration
 */
export interface HsmSessionConfig {
  slotId?: number;
  userType: 'so' | 'user' | 'context_specific';
  pin?: string;
  timeout?: number;
  readOnly?: boolean;
}

/**
 * HSM Device Health Status
 */
export interface HsmHealthStatus {
  online: boolean;
  authenticated: boolean;
  tamperStatus: 'secure' | 'warning' | 'violated';
  temperature?: number;
  batteryLevel?: number;
  uptime?: number;
  operationsPerformed?: number;
  errorRate?: number;
  lastAttestation?: Date;
}

/**
 * Base HSM Adapter Interface
 * All HSM implementations must implement this interface
 */
export abstract class BaseHsmAdapter extends EventEmitter {
  protected provider: HsmProvider;
  protected isConnected: boolean = false;
  protected activeSessions: Map<string, HsmSession> = new Map();

  constructor(provider: HsmProvider) {
    super();
    this.provider = provider;
  }

  /**
   * Initialize HSM connection and discover devices
   */
  abstract initialize(): Promise<HsmResult<HsmDevice[]>>;

  /**
   * Create authenticated session with HSM
   */
  abstract createSession(deviceId: string, config: HsmSessionConfig): Promise<HsmResult<HsmSession>>;

  /**
   * Close HSM session
   */
  abstract closeSession(sessionId: string): Promise<HsmResult<void>>;

  /**
   * Generate cryptographic key in HSM
   */
  abstract generateKey(sessionId: string, params: HsmKeyGenParams): Promise<HsmResult<HsmKey>>;

  /**
   * Import external key into HSM
   */
  abstract importKey(sessionId: string, keyData: Buffer, params: Partial<HsmKeyGenParams>): Promise<HsmResult<HsmKey>>;

  /**
   * Delete key from HSM
   */
  abstract deleteKey(sessionId: string, keyId: string): Promise<HsmResult<void>>;

  /**
   * Sign data using HSM key
   */
  abstract sign(sessionId: string, params: HsmSignParams): Promise<HsmResult<Buffer>>;

  /**
   * Encrypt data using HSM key
   */
  abstract encrypt(sessionId: string, params: HsmEncryptParams): Promise<HsmResult<Buffer>>;

  /**
   * Decrypt data using HSM key
   */
  abstract decrypt(sessionId: string, keyId: string, encryptedData: Buffer, algorithm: string): Promise<HsmResult<Buffer>>;

  /**
   * Get HSM device health status
   */
  abstract getHealthStatus(deviceId: string): Promise<HsmResult<HsmHealthStatus>>;

  /**
   * Get key attestation data
   */
  abstract attestKey(sessionId: string, keyId: string): Promise<HsmResult<any>>;

  /**
   * List all keys in HSM
   */
  abstract listKeys(sessionId: string, filter?: Record<string, any>): Promise<HsmResult<HsmKey[]>>;

  /**
   * Backup key with escrow
   */
  abstract backupKey(sessionId: string, keyId: string, escrowAuthority?: string): Promise<HsmResult<string>>;

  /**
   * Recover key from backup
   */
  abstract recoverKey(sessionId: string, backupData: string, escrowAuth: string): Promise<HsmResult<HsmKey>>;

  /**
   * Get provider information
   */
  getProvider(): HsmProvider {
    return this.provider;
  }

  /**
   * Check if adapter is connected
   */
  isHsmConnected(): boolean {
    return this.isConnected;
  }

  /**
   * Get active sessions count
   */
  getActiveSessionsCount(): number {
    return this.activeSessions.size;
  }

  /**
   * Cleanup all sessions and connections
   */
  async cleanup(): Promise<void> {
    for (const sessionId of this.activeSessions.keys()) {
      try {
        await this.closeSession(sessionId);
      } catch (error) {
        this.emit('error', `Failed to close session ${sessionId}:`, error);
      }
    }
    this.activeSessions.clear();
    this.isConnected = false;
  }

  /**
   * Create audit log entry
   */
  protected createAuditEntry(operation: string, sessionId: string, result: HsmResult, additionalData?: Record<string, any>): InsertHsmAuditLog {
    return {
      tenantId: this.provider.tenantId,
      deviceId: sessionId, // Will be resolved to actual device
      sessionId,
      operationType: operation as any,
      eventType: 'key_access',
      status: result.success ? 'success' : 'failure',
      requestData: additionalData || {},
      responseData: result.data ? { hasData: true } : {},
      errorCode: result.errorCode,
      errorMessage: result.error,
      duration: result.duration,
      userId: '', // Will be filled by caller
      ipAddress: '', // Will be filled by caller
      complianceContext: {
        provider: this.provider.provider,
        fipsLevel: this.provider.fipsValidationLevel,
        attestation: result.attestation
      }
    };
  }
}

/**
 * HSM Error Types
 */
export class HsmError extends Error {
  constructor(
    public code: string,
    message: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'HsmError';
  }
}

export class HsmConnectionError extends HsmError {
  constructor(message: string, cause?: Error) {
    super('HSM_CONNECTION_ERROR', message, cause);
  }
}

export class HsmAuthenticationError extends HsmError {
  constructor(message: string, cause?: Error) {
    super('HSM_AUTH_ERROR', message, cause);
  }
}

export class HsmOperationError extends HsmError {
  constructor(message: string, cause?: Error) {
    super('HSM_OPERATION_ERROR', message, cause);
  }
}

export class HsmKeyNotFoundError extends HsmError {
  constructor(keyId: string) {
    super('HSM_KEY_NOT_FOUND', `Key not found: ${keyId}`);
  }
}

export class HsmSessionExpiredError extends HsmError {
  constructor(sessionId: string) {
    super('HSM_SESSION_EXPIRED', `Session expired: ${sessionId}`);
  }
}

export class HsmTamperError extends HsmError {
  constructor(deviceId: string) {
    super('HSM_TAMPER_DETECTED', `Tamper detected on device: ${deviceId}`);
  }
}

/**
 * HSM Session Pool for connection management
 */
export class HsmSessionPool {
  private pools: Map<string, HsmSession[]> = new Map();
  private maxSessionsPerDevice: number;
  private sessionTimeout: number;

  constructor(maxSessions = 10, timeout = 300000) { // 5 minutes default timeout
    this.maxSessionsPerDevice = maxSessions;
    this.sessionTimeout = timeout;
  }

  /**
   * Get or create session for device
   */
  async getSession(adapter: BaseHsmAdapter, deviceId: string, config: HsmSessionConfig): Promise<HsmSession> {
    const deviceSessions = this.pools.get(deviceId) || [];
    
    // Find available session
    const availableSession = deviceSessions.find(session => 
      session.status === 'idle' && 
      new Date().getTime() - new Date(session.lastActivity).getTime() < this.sessionTimeout
    );

    if (availableSession) {
      availableSession.status = 'active';
      availableSession.lastActivity = new Date();
      return availableSession;
    }

    // Create new session if under limit
    if (deviceSessions.length < this.maxSessionsPerDevice) {
      const result = await adapter.createSession(deviceId, config);
      if (!result.success || !result.data) {
        throw new HsmConnectionError(`Failed to create HSM session: ${result.error}`);
      }

      const newSession = result.data;
      deviceSessions.push(newSession);
      this.pools.set(deviceId, deviceSessions);
      
      return newSession;
    }

    throw new HsmError('HSM_SESSION_LIMIT', `Maximum sessions reached for device ${deviceId}`);
  }

  /**
   * Return session to pool
   */
  returnSession(deviceId: string, sessionId: string): void {
    const deviceSessions = this.pools.get(deviceId);
    if (deviceSessions) {
      const session = deviceSessions.find(s => s.sessionId === sessionId);
      if (session) {
        session.status = 'idle';
        session.lastActivity = new Date();
      }
    }
  }

  /**
   * Cleanup expired sessions
   */
  async cleanupExpiredSessions(adapter: BaseHsmAdapter): Promise<void> {
    const now = new Date().getTime();
    
    for (const [deviceId, sessions] of this.pools.entries()) {
      const expiredSessions = sessions.filter(session => 
        now - new Date(session.lastActivity).getTime() > this.sessionTimeout
      );

      for (const session of expiredSessions) {
        try {
          await adapter.closeSession(session.sessionId);
        } catch (error) {
          console.error(`Failed to close expired session ${session.sessionId}:`, error);
        }
      }

      // Remove expired sessions from pool
      const activeSessions = sessions.filter(session => 
        now - new Date(session.lastActivity).getTime() <= this.sessionTimeout
      );
      
      if (activeSessions.length === 0) {
        this.pools.delete(deviceId);
      } else {
        this.pools.set(deviceId, activeSessions);
      }
    }
  }

  /**
   * Close all sessions for device
   */
  async closeDeviceSessions(adapter: BaseHsmAdapter, deviceId: string): Promise<void> {
    const sessions = this.pools.get(deviceId);
    if (sessions) {
      for (const session of sessions) {
        try {
          await adapter.closeSession(session.sessionId);
        } catch (error) {
          console.error(`Failed to close session ${session.sessionId}:`, error);
        }
      }
      this.pools.delete(deviceId);
    }
  }
}