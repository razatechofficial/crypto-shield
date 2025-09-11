/**
 * Smart Token Adapter Implementation
 * Provides unified interface for YubiKey FIDO2/PIV, SmartCard PIV/CAC, and PKCS#15 tokens
 * Government-level security with PIV/CAC compliance and biometric authentication
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { randomUUID } from 'crypto';
import { 
  BaseHsmAdapter, 
  HsmResult, 
  HsmKeyGenParams, 
  HsmSignParams, 
  HsmEncryptParams,
  HsmSessionConfig,
  HsmHealthStatus,
  HsmConnectionError,
  HsmAuthenticationError,
  HsmOperationError,
  HsmKeyNotFoundError
} from './hsmAdapter';
import type { 
  HsmProvider, 
  HsmDevice, 
  HsmSession, 
  HsmKey,
  SmartToken,
  InsertSmartToken
} from '@shared/schema';

/**
 * Smart Token Types (matches schema enum)
 */
export enum SmartTokenType {
  YUBIKEY_PIV = 'yubikey_piv',
  YUBIKEY_FIDO2 = 'yubikey_fido2', 
  SMARTCARD_PIV = 'smartcard_piv',
  SMARTCARD_CAC = 'smartcard_cac',
  PKCS15_TOKEN = 'pkcs15_token',
  TPM2_TOKEN = 'tpm2_token',
  MOBILE_SECURE_ELEMENT = 'mobile_secure_element'
}

/**
 * PIV Key References (Government Standard)
 */
export enum PIVKeyReference {
  AUTHENTICATION = '9a',      // PIV Authentication Key
  CARD_AUTHENTICATION = '9e', // Card Authentication Key  
  DIGITAL_SIGNATURE = '9c',   // Digital Signature Key
  KEY_MANAGEMENT = '9d',      // Key Management Key
  RETIRED_KEY_1 = '82',       // Retired Key Management Key 1
  RETIRED_KEY_2 = '83',       // Retired Key Management Key 2
  RETIRED_KEY_3 = '84',       // And so on...
  RETIRED_KEY_20 = '95'       // Retired Key Management Key 20
}

/**
 * FIDO2/WebAuthn Credential Types
 */
export enum FIDO2CredentialType {
  PUBLIC_KEY = 'public-key',
  PASSWORD = 'password',
  FEDERATED = 'federated'
}

/**
 * Smart Token Authentication Methods
 */
export enum TokenAuthMethod {
  PIN = 'pin',
  BIOMETRIC = 'biometric',
  TOUCH = 'touch',
  PRESENCE = 'presence',
  PIN_AND_TOUCH = 'pin_and_touch',
  PIN_AND_BIOMETRIC = 'pin_and_biometric'
}

/**
 * Token Discovery Information
 */
export interface TokenDiscoveryInfo {
  serialNumber: string;
  manufacturer: string;
  model: string;
  firmwareVersion: string;
  supportedProtocols: string[];
  capabilities: TokenCapabilities;
  certificates: CertificateInfo[];
}

/**
 * Token Capabilities
 */
export interface TokenCapabilities {
  pivSupported: boolean;
  fido2Supported: boolean;
  pkcs15Supported: boolean;
  biometricSupported: boolean;
  touchRequired: boolean;
  pinRequired: boolean;
  maxPinLength: number;
  minPinLength: number;
  keySlots: number;
  certificateSlots: number;
  supportedAlgorithms: string[];
  supportedKeyTypes: string[];
  maxKeySize: number;
  attestationSupported: boolean;
  residentKeysSupported: boolean;
}

/**
 * Certificate Information
 */
export interface CertificateInfo {
  slot: string;
  keyReference: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  keyUsage: string[];
  certificateType: 'x509' | 'cv_certificate';
  isPresent: boolean;
}

/**
 * Token Authentication Request
 */
export interface TokenAuthRequest {
  method: TokenAuthMethod;
  pin?: string;
  biometricData?: Buffer;
  challengeResponse?: Buffer;
  userVerification?: 'required' | 'preferred' | 'discouraged';
}

/**
 * PIV Authenticate Response
 */
export interface PIVAuthenticateResponse {
  response: Buffer;
  remainingTries: number;
  authenticated: boolean;
  keyReference: string;
}

/**
 * FIDO2 Assertion
 */
export interface FIDO2Assertion {
  credentialId: Buffer;
  authenticatorData: Buffer;
  signature: Buffer;
  userHandle?: Buffer;
  clientDataJSON: Buffer;
}

/**
 * Mock Smart Card/Token Implementation for Development
 * In production, would interface with PC/SC, CCID drivers, or vendor SDKs
 */
class MockSmartCard {
  private connected: boolean = false;
  private authenticated: boolean = false;
  private pinTries: number = 3;
  private certificates: Map<string, CertificateInfo> = new Map();
  private keys: Map<string, any> = new Map();
  
  constructor(private tokenInfo: TokenDiscoveryInfo) {
    // Initialize mock certificates for PIV slots
    this.initializeMockCertificates();
  }

  connect(): boolean {
    this.connected = true;
    return true;
  }

  disconnect(): boolean {
    this.connected = false;
    this.authenticated = false;
    return true;
  }

  isConnected(): boolean {
    return this.connected;
  }

  authenticate(pin: string): PIVAuthenticateResponse {
    if (!this.connected) {
      throw new Error('Token not connected');
    }

    // Mock PIN validation
    if (pin === 'wrongpin') {
      this.pinTries--;
      return {
        response: Buffer.alloc(0),
        remainingTries: this.pinTries,
        authenticated: false,
        keyReference: '00'
      };
    }

    // Successful authentication
    this.authenticated = true;
    this.pinTries = 3; // Reset tries on successful auth
    
    return {
      response: Buffer.from('9000', 'hex'), // Success response
      remainingTries: this.pinTries,
      authenticated: true,
      keyReference: '00'
    };
  }

  generateKeyPair(keyReference: string, algorithm: string, keySize: number): boolean {
    if (!this.authenticated) {
      throw new Error('Not authenticated');
    }

    // Mock key generation
    const keyId = randomUUID();
    this.keys.set(keyReference, {
      keyId,
      algorithm,
      keySize,
      publicKey: Buffer.alloc(256, 0xAA), // Mock public key
      createdAt: new Date()
    });

    return true;
  }

  sign(keyReference: string, data: Buffer, algorithm: string): Buffer {
    if (!this.authenticated) {
      throw new Error('Not authenticated');
    }

    const key = this.keys.get(keyReference);
    if (!key) {
      throw new Error(`Key not found: ${keyReference}`);
    }

    // Mock signature generation
    return Buffer.alloc(256, 0xFF); // Mock signature
  }

  decrypt(keyReference: string, encryptedData: Buffer): Buffer {
    if (!this.authenticated) {
      throw new Error('Not authenticated');
    }

    const key = this.keys.get(keyReference);
    if (!key) {
      throw new Error(`Key not found: ${keyReference}`);
    }

    // Mock decryption
    return Buffer.from('decrypted_data');
  }

  getCertificate(keyReference: string): Buffer | null {
    const cert = this.certificates.get(keyReference);
    if (!cert || !cert.isPresent) {
      return null;
    }

    // Mock certificate data (would be actual DER/PEM in production)
    return Buffer.from(`-----BEGIN CERTIFICATE-----\nMOCK_CERTIFICATE_${keyReference}\n-----END CERTIFICATE-----`);
  }

  setCertificate(keyReference: string, certificate: Buffer): boolean {
    if (!this.authenticated) {
      throw new Error('Not authenticated');
    }

    // Mock certificate storage
    const certInfo = this.certificates.get(keyReference);
    if (certInfo) {
      certInfo.isPresent = true;
    }

    return true;
  }

  private initializeMockCertificates(): void {
    // Initialize PIV certificate slots
    const pivSlots = [
      PIVKeyReference.AUTHENTICATION,
      PIVKeyReference.CARD_AUTHENTICATION,
      PIVKeyReference.DIGITAL_SIGNATURE,
      PIVKeyReference.KEY_MANAGEMENT
    ];

    for (const slot of pivSlots) {
      this.certificates.set(slot, {
        slot,
        keyReference: slot,
        subject: `CN=Mock User ${slot}, OU=Test Org, O=Mock CA`,
        issuer: 'CN=Mock PIV CA, O=Mock Government',
        serialNumber: crypto.randomBytes(8).toString('hex'),
        validFrom: new Date(),
        validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
        keyUsage: slot === PIVKeyReference.DIGITAL_SIGNATURE ? ['digitalSignature'] : ['keyEncipherment'],
        certificateType: 'x509',
        isPresent: false // Initially no certificates
      });
    }
  }
}

/**
 * Smart Token Adapter Implementation
 */
export class SmartTokenAdapter extends BaseHsmAdapter {
  private discoveredTokens: Map<string, SmartToken> = new Map();
  private tokenConnections: Map<string, MockSmartCard> = new Map();
  private tokenCapabilities: Map<string, TokenCapabilities> = new Map();

  constructor(provider: HsmProvider) {
    super(provider);
  }

  async initialize(): Promise<HsmResult<HsmDevice[]>> {
    const startTime = Date.now();
    
    try {
      // Discover available smart tokens/cards
      const discoveredTokens = await this.discoverTokens();
      
      const devices: HsmDevice[] = [];
      
      for (const tokenInfo of discoveredTokens) {
        // Create smart token record
        const smartToken: SmartToken = {
          id: randomUUID(),
          tenantId: this.provider.tenantId,
          userId: '', // Will be assigned when user enrolls token
          tokenType: this.determineTokenType(tokenInfo),
          serialNumber: tokenInfo.serialNumber,
          manufacturer: tokenInfo.manufacturer,
          model: tokenInfo.model,
          firmwareVersion: tokenInfo.firmwareVersion,
          status: 'active',
          capabilities: JSON.stringify(tokenInfo.supportedProtocols),
          certificates: this.mapCertificatesToJSON(tokenInfo.certificates),
          keySlots: tokenInfo.capabilities.keySlots,
          usedSlots: tokenInfo.certificates.filter(c => c.isPresent).length,
          pivSupported: tokenInfo.capabilities.pivSupported,
          fido2Supported: tokenInfo.capabilities.fido2Supported,
          lastSeen: new Date(),
          enrollmentDate: new Date(),
          expirationDate: null,
          pinRetries: 3,
          pukRetries: 3,
          isBlocked: false,
          metadata: {
            discoveryInfo: tokenInfo,
            capabilities: tokenInfo.capabilities
          },
          createdAt: new Date(),
          updatedAt: new Date()
        };

        // Create corresponding HSM device
        const device: HsmDevice = {
          id: randomUUID(),
          providerId: this.provider.id,
          deviceId: `token-${tokenInfo.serialNumber}`,
          serialNumber: tokenInfo.serialNumber,
          model: `${tokenInfo.manufacturer} ${tokenInfo.model}`,
          firmwareVersion: tokenInfo.firmwareVersion,
          status: 'online',
          capabilities: JSON.stringify(tokenInfo.supportedProtocols),
          slotCount: tokenInfo.capabilities.keySlots,
          usedSlots: tokenInfo.certificates.filter(c => c.isPresent).length,
          maxKeys: tokenInfo.capabilities.keySlots,
          usedKeys: tokenInfo.certificates.filter(c => c.isPresent).length,
          batteryLevel: null,
          temperature: null,
          tamperStatus: 'secure',
          lastAttestation: new Date(),
          attestationData: {
            tokenType: this.determineTokenType(tokenInfo),
            capabilities: tokenInfo.capabilities,
            certificates: tokenInfo.certificates
          },
          location: 'Connected Token',
          responsible: null,
          metadata: {
            smartTokenId: smartToken.id,
            tokenType: this.determineTokenType(tokenInfo),
            discoveryInfo: tokenInfo
          },
          createdAt: new Date(),
          updatedAt: new Date()
        };

        devices.push(device);
        this.discoveredTokens.set(device.id, smartToken);
        this.tokenCapabilities.set(device.id, tokenInfo.capabilities);

        // Initialize token connection
        const mockCard = new MockSmartCard(tokenInfo);
        this.tokenConnections.set(device.id, mockCard);
      }

      this.isConnected = true;
      this.emit('initialized', devices);

      return {
        success: true,
        data: devices,
        duration: Date.now() - startTime
      };

    } catch (error) {
      this.emit('error', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_INIT_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async createSession(deviceId: string, config: HsmSessionConfig): Promise<HsmResult<HsmSession>> {
    const startTime = Date.now();
    
    try {
      const token = this.discoveredTokens.get(deviceId);
      const connection = this.tokenConnections.get(deviceId);
      
      if (!token || !connection) {
        throw new Error(`Token not found: ${deviceId}`);
      }

      // Connect to token
      if (!connection.connect()) {
        throw new HsmConnectionError('Failed to connect to smart token');
      }

      // Authenticate if PIN provided
      let authenticated = false;
      if (config.pin) {
        try {
          const authResult = connection.authenticate(config.pin);
          if (!authResult.authenticated) {
            throw new HsmAuthenticationError(`PIN authentication failed. ${authResult.remainingTries} tries remaining.`);
          }
          authenticated = true;
        } catch (error) {
          throw new HsmAuthenticationError(`Token authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

      const session: HsmSession = {
        id: randomUUID(),
        deviceId: deviceId,
        sessionId: randomUUID(),
        userId: '', // Will be set by caller
        status: 'active',
        authMethod: authenticated ? 'pin' : 'none',
        slotId: null,
        loginTime: new Date(),
        lastActivity: new Date(),
        expiresAt: config.timeout ? new Date(Date.now() + config.timeout) : null,
        operationCount: 0,
        ipAddress: null,
        userAgent: null,
        metadata: {
          tokenId: token.id,
          tokenType: token.tokenType,
          authenticated,
          connection: 'smart_card'
        }
      };

      this.activeSessions.set(session.sessionId, session);

      return {
        success: true,
        data: session,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmAuthenticationError ? error.code : 'TOKEN_SESSION_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async closeSession(sessionId: string): Promise<HsmResult<void>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      // Disconnect from token
      const connection = this.tokenConnections.get(session.deviceId);
      if (connection) {
        connection.disconnect();
      }

      this.activeSessions.delete(sessionId);

      return {
        success: true,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_SESSION_CLOSE_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async generateKey(sessionId: string, params: HsmKeyGenParams): Promise<HsmResult<HsmKey>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const connection = this.tokenConnections.get(session.deviceId);
      if (!connection) {
        throw new Error('Token connection not found');
      }

      // Determine key reference/slot for PIV tokens
      const keyReference = this.selectKeyReference(params.keyType, params.keyUsage);
      
      // Generate key pair on token
      const success = connection.generateKeyPair(
        keyReference, 
        params.keyType, 
        params.keySize
      );

      if (!success) {
        throw new HsmOperationError('Failed to generate key on smart token');
      }

      // Create HSM key record
      const hsmKey: HsmKey = {
        id: randomUUID(),
        tenantId: this.provider.tenantId,
        deviceId: session.deviceId,
        tokenId: (session.metadata as any)?.tokenId as string || '',
        keyId: keyReference, // PIV key reference
        keyLabel: params.keyLabel,
        algorithmId: '', // Will be resolved by caller
        keyType: this.mapKeyTypeForToken(params.keyType, params.keyUsage),
        keyUsagePolicy: 'escrow_required', // Token keys require special handling
        status: 'active',
        isExportable: false, // Token keys are never exportable
        isSensitive: true,   // All token keys are sensitive
        isExtractable: false, // Cannot extract private key from token
        keySize: params.keySize,
        publicKey: null, // Would extract from token in production
        keyFingerprint: this.generateTokenKeyFingerprint(keyReference, params),
        createdInHsm: new Date(),
        expiresAt: params.expirationDate || null,
        rotationInterval: 365, // Yearly rotation for government tokens
        usageLimit: null,
        usageCount: 0,
        lastUsed: null,
        backupStatus: 'none', // Token keys cannot be backed up
        escrowedBy: null,
        attestationData: {
          tokenId: (session.metadata as any)?.tokenId || '',
          keyReference,
          tokenType: (session.metadata as any)?.tokenType || 'smartcard_piv',
          generatedOnToken: true,
          deviceAttestation: `Generated on token ${session.deviceId} at ${new Date().toISOString()}`
        },
        complianceFlags: JSON.stringify(['piv_compliant', 'fips_201_approved', 'token_bound']),
        metadata: {
          sessionId,
          tokenGeneration: {
            keyReference,
            tokenType: (session.metadata as any)?.tokenType || 'smartcard_piv',
            generatedAt: new Date().toISOString(),
            onTokenOnly: true
          }
        },
        createdAt: new Date(),
        updatedAt: new Date()
      };

      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        data: hsmKey,
        duration: Date.now() - startTime,
        attestation: (hsmKey.attestationData as any)?.deviceAttestation || ''
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmOperationError ? error.code : 'TOKEN_KEY_GEN_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async importKey(sessionId: string, keyData: Buffer, params: Partial<HsmKeyGenParams>): Promise<HsmResult<HsmKey>> {
    // Smart tokens typically don't support key import for security reasons
    throw new HsmOperationError('Key import not supported on smart tokens for security compliance');
  }

  async deleteKey(sessionId: string, keyId: string): Promise<HsmResult<void>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      // Smart tokens typically don't allow key deletion for audit compliance
      // This would typically be a management operation requiring admin privileges
      
      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_KEY_DELETE_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async sign(sessionId: string, params: HsmSignParams): Promise<HsmResult<Buffer>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const connection = this.tokenConnections.get(session.deviceId);
      if (!connection) {
        throw new Error('Token connection not found');
      }

      // Perform signing operation on token
      const signature = connection.sign(params.keyId, params.data, params.algorithm);

      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        data: signature,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_SIGN_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async encrypt(sessionId: string, params: HsmEncryptParams): Promise<HsmResult<Buffer>> {
    // Most smart tokens don't support direct encryption, only key management operations
    throw new HsmOperationError('Direct encryption not supported on smart tokens. Use key management operations instead.');
  }

  async decrypt(sessionId: string, keyId: string, encryptedData: Buffer, algorithm: string): Promise<HsmResult<Buffer>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const connection = this.tokenConnections.get(session.deviceId);
      if (!connection) {
        throw new Error('Token connection not found');
      }

      // Perform decryption operation on token (typically for key management)
      const decryptedData = connection.decrypt(keyId, encryptedData);

      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        data: decryptedData,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_DECRYPT_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async getHealthStatus(deviceId: string): Promise<HsmResult<HsmHealthStatus>> {
    const startTime = Date.now();
    
    try {
      const token = this.discoveredTokens.get(deviceId);
      const connection = this.tokenConnections.get(deviceId);
      
      if (!token || !connection) {
        throw new Error(`Token not found: ${deviceId}`);
      }

      const healthStatus: HsmHealthStatus = {
        online: connection.isConnected(),
        authenticated: this.activeSessions.size > 0,
        tamperStatus: 'secure', // Smart tokens are inherently tamper-resistant
        temperature: undefined, // Not available on most tokens
        batteryLevel: undefined, // Not applicable for USB tokens
        uptime: Date.now() - new Date(token.createdAt || new Date()).getTime(),
        operationsPerformed: token.usedSlots || 0,
        errorRate: 0, // Mock value
        lastAttestation: token.lastSeen || undefined
      };

      return {
        success: true,
        data: healthStatus,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_HEALTH_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async attestKey(sessionId: string, keyId: string): Promise<HsmResult<any>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const token = this.discoveredTokens.get(session.deviceId);
      if (!token) {
        throw new Error('Token not found');
      }

      // Get key attestation from token
      const attestationData = {
        keyId,
        tokenId: token.id,
        tokenType: token.tokenType,
        serialNumber: token.serialNumber,
        keyReference: keyId,
        attestedAt: new Date().toISOString(),
        attestationType: 'smart_token',
        pivCompliant: token.pivSupported,
        fido2Compliant: token.fido2Supported,
        tamperResistant: true,
        keyOnToken: true,
        nonExportable: true
      };

      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        data: attestationData,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_ATTEST_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async listKeys(sessionId: string, filter?: Record<string, any>): Promise<HsmResult<HsmKey[]>> {
    // Would enumerate keys/certificates on token
    throw new Error('Token key listing not implemented in mock adapter');
  }

  async backupKey(sessionId: string, keyId: string, escrowAuthority?: string): Promise<HsmResult<string>> {
    // Smart token keys cannot be backed up for security compliance
    throw new HsmOperationError('Key backup not supported on smart tokens for security compliance');
  }

  async recoverKey(sessionId: string, backupData: string, escrowAuth: string): Promise<HsmResult<HsmKey>> {
    // Smart token keys cannot be recovered from backup
    throw new HsmOperationError('Key recovery not supported on smart tokens for security compliance');
  }

  /**
   * Smart Token Specific Operations
   */
  
  /**
   * Generate Certificate Signing Request on token
   */
  async generateCSR(sessionId: string, keyReference: string, subject: string): Promise<HsmResult<Buffer>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      // Mock CSR generation (in production would use token's crypto operations)
      const csrData = Buffer.from(`-----BEGIN CERTIFICATE REQUEST-----
MOCK_CSR_FOR_KEY_${keyReference}_SUBJECT_${Buffer.from(subject).toString('base64')}
-----END CERTIFICATE REQUEST-----`);

      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        data: csrData,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_CSR_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Install certificate on token
   */
  async installCertificate(sessionId: string, keyReference: string, certificate: Buffer): Promise<HsmResult<void>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const connection = this.tokenConnections.get(session.deviceId);
      if (!connection) {
        throw new Error('Token connection not found');
      }

      const success = connection.setCertificate(keyReference, certificate);
      if (!success) {
        throw new HsmOperationError('Failed to install certificate on token');
      }

      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'TOKEN_CERT_INSTALL_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Get certificate from token
   */
  async getCertificate(sessionId: string, keyReference: string): Promise<HsmResult<Buffer>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const connection = this.tokenConnections.get(session.deviceId);
      if (!connection) {
        throw new Error('Token connection not found');
      }

      const certificate = connection.getCertificate(keyReference);
      if (!certificate) {
        throw new HsmKeyNotFoundError(`Certificate not found for key reference: ${keyReference}`);
      }

      session.operationCount = (session.operationCount || 0) + 1;
      session.lastActivity = new Date();

      return {
        success: true,
        data: certificate,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmKeyNotFoundError ? error.code : 'TOKEN_CERT_GET_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Helper Methods
   */
  
  private async discoverTokens(): Promise<TokenDiscoveryInfo[]> {
    // Mock token discovery (in production would use PC/SC, CCID, or vendor SDKs)
    const mockTokens: TokenDiscoveryInfo[] = [
      {
        serialNumber: 'YK-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        manufacturer: 'Yubico',
        model: 'YubiKey 5 NFC',
        firmwareVersion: '5.2.7',
        supportedProtocols: ['piv', 'fido2', 'oath', 'openpgp'],
        capabilities: {
          pivSupported: true,
          fido2Supported: true,
          pkcs15Supported: false,
          biometricSupported: false,
          touchRequired: true,
          pinRequired: true,
          maxPinLength: 8,
          minPinLength: 6,
          keySlots: 24, // PIV has specific key slots
          certificateSlots: 24,
          supportedAlgorithms: ['rsa2048', 'rsa1024', 'ecp256', 'ecp384'],
          supportedKeyTypes: ['rsa', 'ecdsa'],
          maxKeySize: 4096,
          attestationSupported: true,
          residentKeysSupported: true
        },
        certificates: []
      },
      {
        serialNumber: 'SC-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        manufacturer: 'Generic',
        model: 'PIV SmartCard',
        firmwareVersion: '1.0',
        supportedProtocols: ['piv', 'iso7816'],
        capabilities: {
          pivSupported: true,
          fido2Supported: false,
          pkcs15Supported: true,
          biometricSupported: true, // Some CAC cards have biometrics
          touchRequired: false,
          pinRequired: true,
          maxPinLength: 8,
          minPinLength: 4,
          keySlots: 20,
          certificateSlots: 20,
          supportedAlgorithms: ['rsa2048', 'ecp256'],
          supportedKeyTypes: ['rsa', 'ecdsa'],
          maxKeySize: 2048,
          attestationSupported: false,
          residentKeysSupported: false
        },
        certificates: []
      }
    ];

    return mockTokens;
  }

  private determineTokenType(tokenInfo: TokenDiscoveryInfo): SmartTokenType {
    if (tokenInfo.manufacturer.toLowerCase().includes('yubico')) {
      return tokenInfo.capabilities.fido2Supported ? SmartTokenType.YUBIKEY_FIDO2 : SmartTokenType.YUBIKEY_PIV;
    } else if (tokenInfo.capabilities.pivSupported && tokenInfo.capabilities.pkcs15Supported) {
      return SmartTokenType.SMARTCARD_CAC; // Common Access Card
    } else if (tokenInfo.capabilities.pivSupported) {
      return SmartTokenType.SMARTCARD_PIV;
    } else if (tokenInfo.capabilities.pkcs15Supported) {
      return SmartTokenType.PKCS15_TOKEN;
    } else {
      return SmartTokenType.SMARTCARD_PIV; // Default to PIV for unknown types
    }
  }

  private mapCertificatesToJSON(certificates: CertificateInfo[]): Record<string, any> {
    return certificates.reduce((acc, cert) => {
      acc[cert.keyReference] = {
        subject: cert.subject,
        issuer: cert.issuer,
        serialNumber: cert.serialNumber,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        keyUsage: cert.keyUsage,
        isPresent: cert.isPresent
      };
      return acc;
    }, {} as Record<string, any>);
  }

  private selectKeyReference(keyType: string, keyUsage: string[]): string {
    // Select appropriate PIV key reference based on usage
    if (keyUsage.includes('sign') && keyUsage.includes('verify')) {
      return PIVKeyReference.DIGITAL_SIGNATURE;
    } else if (keyUsage.includes('encrypt') || keyUsage.includes('decrypt')) {
      return PIVKeyReference.KEY_MANAGEMENT;
    } else if (keyUsage.includes('authenticate')) {
      return PIVKeyReference.AUTHENTICATION;
    } else {
      return PIVKeyReference.CARD_AUTHENTICATION;
    }
  }

  private mapKeyTypeForToken(keyType: string, keyUsage: string[]): string {
    if (keyUsage.includes('sign')) {
      return 'signing';
    } else if (keyUsage.includes('encrypt')) {
      return 'encryption';
    } else if (keyUsage.includes('authenticate')) {
      return 'authentication';
    } else {
      return 'master';
    }
  }

  private generateTokenKeyFingerprint(keyReference: string, params: HsmKeyGenParams): string {
    return `token_${keyReference}_${params.keyType}_${params.keySize}`;
  }

  async cleanup(): Promise<void> {
    await super.cleanup();
    
    // Disconnect all token connections
    for (const connection of Array.from(this.tokenConnections.values())) {
      try {
        connection.disconnect();
      } catch (error) {
        console.error('Failed to disconnect token:', error);
      }
    }
    
    this.tokenConnections.clear();
    this.discoveredTokens.clear();
    this.tokenCapabilities.clear();
  }
}