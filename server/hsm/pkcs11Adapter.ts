/**
 * PKCS#11 HSM Adapter Implementation
 * Provides PKCS#11 compliant interface for HSM operations
 * Supports SafeNet, Thales, nCipher, and other PKCS#11 compatible HSMs
 */

import { promisify } from 'util';
import * as path from 'path';
import * as fs from 'fs/promises';
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
  HsmKeyNotFoundError,
  HsmTamperError
} from './hsmAdapter';
import type { 
  HsmProvider, 
  HsmDevice, 
  HsmSession, 
  HsmKey 
} from '@shared/schema';

/**
 * PKCS#11 Object Classes
 */
const PKCS11_OBJECT_CLASSES = {
  CKO_DATA: 0x00000000,
  CKO_CERTIFICATE: 0x00000001,
  CKO_PUBLIC_KEY: 0x00000002,
  CKO_PRIVATE_KEY: 0x00000003,
  CKO_SECRET_KEY: 0x00000004,
  CKO_HW_FEATURE: 0x00000005,
  CKO_DOMAIN_PARAMETERS: 0x00000006
};

/**
 * PKCS#11 Key Types
 */
const PKCS11_KEY_TYPES = {
  CKK_RSA: 0x00000000,
  CKK_DSA: 0x00000001,
  CKK_DH: 0x00000002,
  CKK_ECDSA: 0x00000003,
  CKK_EC: 0x00000003,
  CKK_X9_42_DH: 0x00000004,
  CKK_KEA: 0x00000005,
  CKK_GENERIC_SECRET: 0x00000010,
  CKK_RC2: 0x00000011,
  CKK_RC4: 0x00000012,
  CKK_DES: 0x00000013,
  CKK_DES2: 0x00000014,
  CKK_DES3: 0x00000015,
  CKK_AES: 0x0000001F
};

/**
 * PKCS#11 Mechanisms
 */
const PKCS11_MECHANISMS = {
  CKM_RSA_PKCS: 0x00000001,
  CKM_RSA_PKCS_PSS: 0x0000000D,
  CKM_SHA256_RSA_PKCS: 0x00000040,
  CKM_SHA256_RSA_PKCS_PSS: 0x00000043,
  CKM_ECDSA: 0x00001041,
  CKM_ECDSA_SHA256: 0x00001042,
  CKM_AES_GCM: 0x00001087,
  CKM_AES_KEY_GEN: 0x00001080,
  CKM_RSA_PKCS_KEY_PAIR_GEN: 0x00000000
};

/**
 * PKCS#11 Attributes
 */
const PKCS11_ATTRIBUTES = {
  CKA_CLASS: 0x00000000,
  CKA_TOKEN: 0x00000001,
  CKA_PRIVATE: 0x00000002,
  CKA_LABEL: 0x00000003,
  CKA_APPLICATION: 0x00000010,
  CKA_VALUE: 0x00000011,
  CKA_OBJECT_ID: 0x00000012,
  CKA_CERTIFICATE_TYPE: 0x00000080,
  CKA_ISSUER: 0x00000081,
  CKA_SERIAL_NUMBER: 0x00000082,
  CKA_AC_ISSUER: 0x00000083,
  CKA_OWNER: 0x00000084,
  CKA_ATTR_TYPES: 0x00000085,
  CKA_TRUSTED: 0x00000086,
  CKA_CERTIFICATE_CATEGORY: 0x00000087,
  CKA_JAVA_MIDP_SECURITY_DOMAIN: 0x00000088,
  CKA_URL: 0x00000089,
  CKA_HASH_OF_SUBJECT_PUBLIC_KEY: 0x0000008A,
  CKA_HASH_OF_ISSUER_PUBLIC_KEY: 0x0000008B,
  CKA_NAME_HASH_ALGORITHM: 0x0000008C,
  CKA_CHECK_VALUE: 0x00000090,
  CKA_KEY_TYPE: 0x00000100,
  CKA_SUBJECT: 0x00000101,
  CKA_ID: 0x00000102,
  CKA_SENSITIVE: 0x00000103,
  CKA_ENCRYPT: 0x00000104,
  CKA_DECRYPT: 0x00000105,
  CKA_WRAP: 0x00000106,
  CKA_UNWRAP: 0x00000107,
  CKA_SIGN: 0x00000108,
  CKA_SIGN_RECOVER: 0x00000109,
  CKA_VERIFY: 0x0000010A,
  CKA_VERIFY_RECOVER: 0x0000010B,
  CKA_DERIVE: 0x0000010C,
  CKA_START_DATE: 0x00000110,
  CKA_END_DATE: 0x00000111,
  CKA_MODULUS: 0x00000120,
  CKA_MODULUS_BITS: 0x00000121,
  CKA_PUBLIC_EXPONENT: 0x00000122,
  CKA_PRIVATE_EXPONENT: 0x00000123,
  CKA_PRIME_1: 0x00000124,
  CKA_PRIME_2: 0x00000125,
  CKA_EXPONENT_1: 0x00000126,
  CKA_EXPONENT_2: 0x00000127,
  CKA_COEFFICIENT: 0x00000128,
  CKA_PRIME: 0x00000130,
  CKA_SUBPRIME: 0x00000131,
  CKA_BASE: 0x00000132,
  CKA_PRIME_BITS: 0x00000133,
  CKA_SUBPRIME_BITS: 0x00000134,
  CKA_SUB_PRIME_BITS: 0x00000134,
  CKA_VALUE_BITS: 0x00000160,
  CKA_VALUE_LEN: 0x00000161,
  CKA_EXTRACTABLE: 0x00000162,
  CKA_LOCAL: 0x00000163,
  CKA_NEVER_EXTRACTABLE: 0x00000164,
  CKA_ALWAYS_SENSITIVE: 0x00000165,
  CKA_KEY_GEN_MECHANISM: 0x00000166,
  CKA_MODIFIABLE: 0x00000170,
  CKA_COPYABLE: 0x00000171,
  CKA_EC_PARAMS: 0x00000180,
  CKA_EC_POINT: 0x00000181,
  CKA_SECONDARY_AUTH: 0x00000200,
  CKA_AUTH_PIN_FLAGS: 0x00000201,
  CKA_ALWAYS_AUTHENTICATE: 0x00000202,
  CKA_WRAP_WITH_TRUSTED: 0x00000210,
  CKA_WRAP_TEMPLATE: 0x00000211,
  CKA_UNWRAP_TEMPLATE: 0x00000212,
  CKA_OTP_FORMAT: 0x00000220,
  CKA_OTP_LENGTH: 0x00000221,
  CKA_OTP_TIME_INTERVAL: 0x00000222,
  CKA_OTP_USER_FRIENDLY_MODE: 0x00000223,
  CKA_OTP_CHALLENGE_REQUIREMENT: 0x00000224,
  CKA_OTP_TIME_REQUIREMENT: 0x00000225,
  CKA_OTP_COUNTER_REQUIREMENT: 0x00000226,
  CKA_OTP_PIN_REQUIREMENT: 0x00000227,
  CKA_OTP_COUNTER: 0x0000022E,
  CKA_OTP_TIME: 0x0000022F,
  CKA_OTP_USER_IDENTIFIER: 0x0000022A,
  CKA_OTP_SERVICE_IDENTIFIER: 0x0000022B,
  CKA_OTP_SERVICE_LOGO: 0x0000022C,
  CKA_OTP_SERVICE_LOGO_TYPE: 0x0000022D
};

/**
 * PKCS#11 Return Codes
 */
const PKCS11_RETURN_CODES = {
  CKR_OK: 0x00000000,
  CKR_CANCEL: 0x00000001,
  CKR_HOST_MEMORY: 0x00000002,
  CKR_SLOT_ID_INVALID: 0x00000003,
  CKR_GENERAL_ERROR: 0x00000005,
  CKR_FUNCTION_FAILED: 0x00000006,
  CKR_ARGUMENTS_BAD: 0x00000007,
  CKR_NO_EVENT: 0x00000008,
  CKR_NEED_TO_CREATE_THREADS: 0x00000009,
  CKR_CANT_LOCK: 0x0000000A,
  CKR_ATTRIBUTE_READ_ONLY: 0x00000010,
  CKR_ATTRIBUTE_SENSITIVE: 0x00000011,
  CKR_ATTRIBUTE_TYPE_INVALID: 0x00000012,
  CKR_ATTRIBUTE_VALUE_INVALID: 0x00000013,
  CKR_DATA_INVALID: 0x00000020,
  CKR_DATA_LEN_RANGE: 0x00000021,
  CKR_DEVICE_ERROR: 0x00000030,
  CKR_DEVICE_MEMORY: 0x00000031,
  CKR_DEVICE_REMOVED: 0x00000032,
  CKR_ENCRYPTED_DATA_INVALID: 0x00000040,
  CKR_ENCRYPTED_DATA_LEN_RANGE: 0x00000041,
  CKR_FUNCTION_CANCELED: 0x00000050,
  CKR_FUNCTION_NOT_PARALLEL: 0x00000051,
  CKR_FUNCTION_NOT_SUPPORTED: 0x00000054,
  CKR_KEY_HANDLE_INVALID: 0x00000060,
  CKR_KEY_SIZE_RANGE: 0x00000062,
  CKR_KEY_TYPE_INCONSISTENT: 0x00000063,
  CKR_KEY_NOT_NEEDED: 0x00000064,
  CKR_KEY_CHANGED: 0x00000065,
  CKR_KEY_NEEDED: 0x00000066,
  CKR_KEY_INDIGESTIBLE: 0x00000067,
  CKR_KEY_FUNCTION_NOT_PERMITTED: 0x00000068,
  CKR_KEY_NOT_WRAPPABLE: 0x00000069,
  CKR_KEY_UNEXTRACTABLE: 0x0000006A,
  CKR_MECHANISM_INVALID: 0x00000070,
  CKR_MECHANISM_PARAM_INVALID: 0x00000071,
  CKR_OBJECT_HANDLE_INVALID: 0x00000082,
  CKR_OPERATION_ACTIVE: 0x00000090,
  CKR_OPERATION_NOT_INITIALIZED: 0x00000091,
  CKR_PIN_INCORRECT: 0x000000A0,
  CKR_PIN_INVALID: 0x000000A1,
  CKR_PIN_LEN_RANGE: 0x000000A2,
  CKR_PIN_EXPIRED: 0x000000A3,
  CKR_PIN_LOCKED: 0x000000A4,
  CKR_SESSION_CLOSED: 0x000000B0,
  CKR_SESSION_COUNT: 0x000000B1,
  CKR_SESSION_HANDLE_INVALID: 0x000000B3,
  CKR_SESSION_PARALLEL_NOT_SUPPORTED: 0x000000B4,
  CKR_SESSION_READ_ONLY: 0x000000B5,
  CKR_SESSION_EXISTS: 0x000000B6,
  CKR_SESSION_READ_ONLY_EXISTS: 0x000000B7,
  CKR_SESSION_READ_WRITE_SO_EXISTS: 0x000000B8,
  CKR_SIGNATURE_INVALID: 0x000000C0,
  CKR_SIGNATURE_LEN_RANGE: 0x000000C1,
  CKR_TEMPLATE_INCOMPLETE: 0x000000D0,
  CKR_TEMPLATE_INCONSISTENT: 0x000000D1,
  CKR_TOKEN_NOT_PRESENT: 0x000000E0,
  CKR_TOKEN_NOT_RECOGNIZED: 0x000000E1,
  CKR_TOKEN_WRITE_PROTECTED: 0x000000E2,
  CKR_UNWRAPPING_KEY_HANDLE_INVALID: 0x000000F0,
  CKR_UNWRAPPING_KEY_SIZE_RANGE: 0x000000F1,
  CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: 0x000000F2,
  CKR_USER_ALREADY_LOGGED_IN: 0x00000100,
  CKR_USER_NOT_LOGGED_IN: 0x00000101,
  CKR_USER_PIN_NOT_INITIALIZED: 0x00000102,
  CKR_USER_TYPE_INVALID: 0x00000103,
  CKR_USER_ANOTHER_ALREADY_LOGGED_IN: 0x00000104,
  CKR_USER_TOO_MANY_TYPES: 0x00000105,
  CKR_WRAPPED_KEY_INVALID: 0x00000110,
  CKR_WRAPPED_KEY_LEN_RANGE: 0x00000112,
  CKR_WRAPPING_KEY_HANDLE_INVALID: 0x00000113,
  CKR_WRAPPING_KEY_SIZE_RANGE: 0x00000114,
  CKR_WRAPPING_KEY_TYPE_INCONSISTENT: 0x00000115,
  CKR_RANDOM_SEED_NOT_SUPPORTED: 0x00000120,
  CKR_RANDOM_NO_RNG: 0x00000121,
  CKR_DOMAIN_PARAMS_INVALID: 0x00000130,
  CKR_BUFFER_TOO_SMALL: 0x00000150,
  CKR_SAVED_STATE_INVALID: 0x00000160,
  CKR_INFORMATION_SENSITIVE: 0x00000170,
  CKR_STATE_UNSAVEABLE: 0x00000180,
  CKR_CRYPTOKI_NOT_INITIALIZED: 0x00000190,
  CKR_CRYPTOKI_ALREADY_INITIALIZED: 0x00000191,
  CKR_MUTEX_BAD: 0x000001A0,
  CKR_MUTEX_NOT_LOCKED: 0x000001A1,
  CKR_NEW_PIN_MODE: 0x000001B0,
  CKR_NEXT_OTP: 0x000001B1,
  CKR_EXCEEDED_MAX_ITERATIONS: 0x000001B5,
  CKR_FIPS_SELF_TEST_FAILED: 0x000001B6,
  CKR_LIBRARY_LOAD_FAILED: 0x000001B7,
  CKR_PIN_TOO_WEAK: 0x000001B8,
  CKR_PUBLIC_KEY_INVALID: 0x000001B9,
  CKR_FUNCTION_REJECTED: 0x00000200
};

/**
 * Mock PKCS#11 Implementation for Development
 * In production, this would use actual PKCS#11 native libraries
 */
class MockPKCS11 {
  private sessions: Map<string, any> = new Map();
  private keys: Map<string, any> = new Map();
  private initialized = false;

  initialize(): number {
    this.initialized = true;
    return PKCS11_RETURN_CODES.CKR_OK;
  }

  finalize(): number {
    this.initialized = false;
    this.sessions.clear();
    this.keys.clear();
    return PKCS11_RETURN_CODES.CKR_OK;
  }

  getSlotList(): { returnCode: number; slots: number[] } {
    return {
      returnCode: PKCS11_RETURN_CODES.CKR_OK,
      slots: [0, 1, 2] // Mock slots
    };
  }

  openSession(slotId: number, flags: number): { returnCode: number; sessionHandle?: string } {
    const sessionHandle = randomUUID();
    this.sessions.set(sessionHandle, {
      slotId,
      flags,
      authenticated: false,
      createdAt: new Date()
    });

    return {
      returnCode: PKCS11_RETURN_CODES.CKR_OK,
      sessionHandle
    };
  }

  closeSession(sessionHandle: string): number {
    if (!this.sessions.has(sessionHandle)) {
      return PKCS11_RETURN_CODES.CKR_SESSION_HANDLE_INVALID;
    }
    this.sessions.delete(sessionHandle);
    return PKCS11_RETURN_CODES.CKR_OK;
  }

  login(sessionHandle: string, userType: number, pin: string): number {
    const session = this.sessions.get(sessionHandle);
    if (!session) {
      return PKCS11_RETURN_CODES.CKR_SESSION_HANDLE_INVALID;
    }

    // Mock PIN validation
    if (pin === 'wrongpin') {
      return PKCS11_RETURN_CODES.CKR_PIN_INCORRECT;
    }

    session.authenticated = true;
    return PKCS11_RETURN_CODES.CKR_OK;
  }

  logout(sessionHandle: string): number {
    const session = this.sessions.get(sessionHandle);
    if (!session) {
      return PKCS11_RETURN_CODES.CKR_SESSION_HANDLE_INVALID;
    }

    session.authenticated = false;
    return PKCS11_RETURN_CODES.CKR_OK;
  }

  generateKeyPair(sessionHandle: string, mechanism: number, publicKeyTemplate: any, privateKeyTemplate: any): 
    { returnCode: number; publicKeyHandle?: string; privateKeyHandle?: string } {
    
    const session = this.sessions.get(sessionHandle);
    if (!session || !session.authenticated) {
      return { returnCode: PKCS11_RETURN_CODES.CKR_USER_NOT_LOGGED_IN };
    }

    const publicKeyHandle = randomUUID();
    const privateKeyHandle = randomUUID();

    this.keys.set(publicKeyHandle, {
      type: 'public',
      mechanism,
      template: publicKeyTemplate,
      createdAt: new Date()
    });

    this.keys.set(privateKeyHandle, {
      type: 'private',
      mechanism,
      template: privateKeyTemplate,
      createdAt: new Date()
    });

    return {
      returnCode: PKCS11_RETURN_CODES.CKR_OK,
      publicKeyHandle,
      privateKeyHandle
    };
  }

  sign(sessionHandle: string, keyHandle: string, data: Buffer): { returnCode: number; signature?: Buffer } {
    const session = this.sessions.get(sessionHandle);
    const key = this.keys.get(keyHandle);

    if (!session || !session.authenticated) {
      return { returnCode: PKCS11_RETURN_CODES.CKR_USER_NOT_LOGGED_IN };
    }

    if (!key || key.type !== 'private') {
      return { returnCode: PKCS11_RETURN_CODES.CKR_KEY_HANDLE_INVALID };
    }

    // Mock signature generation (in production, this would use actual cryptographic operations)
    const signature = Buffer.alloc(256, 0xFF); // Mock signature
    
    return {
      returnCode: PKCS11_RETURN_CODES.CKR_OK,
      signature
    };
  }

  encrypt(sessionHandle: string, keyHandle: string, data: Buffer): { returnCode: number; encryptedData?: Buffer } {
    const session = this.sessions.get(sessionHandle);
    const key = this.keys.get(keyHandle);

    if (!session || !session.authenticated) {
      return { returnCode: PKCS11_RETURN_CODES.CKR_USER_NOT_LOGGED_IN };
    }

    if (!key) {
      return { returnCode: PKCS11_RETURN_CODES.CKR_KEY_HANDLE_INVALID };
    }

    // Mock encryption (in production, this would use actual cryptographic operations)
    const encryptedData = Buffer.from(data.toString('base64'), 'base64');
    
    return {
      returnCode: PKCS11_RETURN_CODES.CKR_OK,
      encryptedData
    };
  }

  destroyObject(sessionHandle: string, objectHandle: string): number {
    const session = this.sessions.get(sessionHandle);
    if (!session || !session.authenticated) {
      return PKCS11_RETURN_CODES.CKR_USER_NOT_LOGGED_IN;
    }

    if (!this.keys.has(objectHandle)) {
      return PKCS11_RETURN_CODES.CKR_OBJECT_HANDLE_INVALID;
    }

    this.keys.delete(objectHandle);
    return PKCS11_RETURN_CODES.CKR_OK;
  }

  findObjects(sessionHandle: string, template: any): { returnCode: number; objects?: string[] } {
    const session = this.sessions.get(sessionHandle);
    if (!session || !session.authenticated) {
      return { returnCode: PKCS11_RETURN_CODES.CKR_USER_NOT_LOGGED_IN };
    }

    // Mock object search
    const objects = Array.from(this.keys.keys()).slice(0, 10); // Return first 10 objects
    
    return {
      returnCode: PKCS11_RETURN_CODES.CKR_OK,
      objects
    };
  }
}

/**
 * PKCS#11 Adapter Implementation
 */
export class PKCS11Adapter extends BaseHsmAdapter {
  private pkcs11: MockPKCS11;
  private libraryPath: string;
  private discoveredDevices: Map<string, HsmDevice> = new Map();

  constructor(provider: HsmProvider) {
    super(provider);
    
    // In production, load actual PKCS#11 library
    this.libraryPath = provider.configuration.libraryPath || '/usr/lib/libpkcs11.so';
    this.pkcs11 = new MockPKCS11(); // Replace with actual PKCS#11 library loading
  }

  async initialize(): Promise<HsmResult<HsmDevice[]>> {
    const startTime = Date.now();
    
    try {
      // Initialize PKCS#11 library
      const initResult = this.pkcs11.initialize();
      if (initResult !== PKCS11_RETURN_CODES.CKR_OK) {
        throw new HsmConnectionError(`Failed to initialize PKCS#11 library: ${initResult}`);
      }

      // Get available slots
      const slotsResult = this.pkcs11.getSlotList();
      if (slotsResult.returnCode !== PKCS11_RETURN_CODES.CKR_OK) {
        throw new HsmConnectionError(`Failed to get slots: ${slotsResult.returnCode}`);
      }

      const devices: HsmDevice[] = [];
      
      // Mock device discovery for each slot
      for (const slotId of slotsResult.slots) {
        const device: HsmDevice = {
          id: randomUUID(),
          providerId: this.provider.id,
          deviceId: `slot-${slotId}`,
          serialNumber: `HSM-${slotId}-${Math.random().toString(36).substring(7)}`,
          model: this.getModelForProvider(),
          firmwareVersion: '1.0.0',
          status: 'online',
          capabilities: JSON.stringify(['sign', 'encrypt', 'decrypt', 'key_generate', 'attestation']),
          slotCount: 1,
          usedSlots: 0,
          maxKeys: 1000,
          usedKeys: 0,
          batteryLevel: null,
          temperature: 35,
          tamperStatus: 'secure',
          lastAttestation: new Date(),
          attestationData: {
            slotId,
            fipsLevel: this.provider.fipsValidationLevel,
            certifications: this.provider.certifications
          },
          location: `Slot ${slotId}`,
          responsible: null,
          metadata: {
            pkcs11SlotId: slotId,
            libraryPath: this.libraryPath,
            mechanisms: Object.keys(PKCS11_MECHANISMS)
          },
          createdAt: new Date(),
          updatedAt: new Date()
        };

        devices.push(device);
        this.discoveredDevices.set(device.id, device);
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
        errorCode: error instanceof HsmConnectionError ? error.code : 'HSM_INIT_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async createSession(deviceId: string, config: HsmSessionConfig): Promise<HsmResult<HsmSession>> {
    const startTime = Date.now();
    
    try {
      const device = this.discoveredDevices.get(deviceId);
      if (!device) {
        throw new Error(`Device not found: ${deviceId}`);
      }

      const slotId = device.metadata.pkcs11SlotId as number;
      const sessionResult = this.pkcs11.openSession(slotId, config.readOnly ? 0x00000004 : 0x00000006);
      
      if (sessionResult.returnCode !== PKCS11_RETURN_CODES.CKR_OK || !sessionResult.sessionHandle) {
        throw new HsmConnectionError(`Failed to open session: ${sessionResult.returnCode}`);
      }

      // Authenticate if PIN provided
      if (config.pin) {
        const userType = config.userType === 'so' ? 0 : 1; // SO or Normal User
        const loginResult = this.pkcs11.login(sessionResult.sessionHandle, userType, config.pin);
        
        if (loginResult !== PKCS11_RETURN_CODES.CKR_OK) {
          // Clean up session
          this.pkcs11.closeSession(sessionResult.sessionHandle);
          throw new HsmAuthenticationError(`Authentication failed: ${loginResult}`);
        }
      }

      const session: HsmSession = {
        id: randomUUID(),
        deviceId: device.id,
        sessionId: sessionResult.sessionHandle,
        userId: '', // Will be set by caller
        status: 'active',
        authMethod: config.pin ? 'password' : 'none',
        slotId: slotId,
        loginTime: new Date(),
        lastActivity: new Date(),
        expiresAt: config.timeout ? new Date(Date.now() + config.timeout) : null,
        operationCount: 0,
        ipAddress: null,
        userAgent: null,
        metadata: {
          pkcs11Handle: sessionResult.sessionHandle,
          authenticated: !!config.pin,
          readOnly: config.readOnly || false
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
        errorCode: error instanceof HsmAuthenticationError ? error.code : 'HSM_SESSION_ERROR',
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

      const pkcs11Handle = session.metadata.pkcs11Handle as string;
      
      // Logout if authenticated
      if (session.metadata.authenticated) {
        this.pkcs11.logout(pkcs11Handle);
      }
      
      // Close PKCS#11 session
      const closeResult = this.pkcs11.closeSession(pkcs11Handle);
      if (closeResult !== PKCS11_RETURN_CODES.CKR_OK) {
        console.warn(`Failed to close PKCS#11 session: ${closeResult}`);
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
        errorCode: 'HSM_SESSION_CLOSE_ERROR',
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

      const pkcs11Handle = session.metadata.pkcs11Handle as string;
      
      // Prepare key generation parameters
      const mechanism = this.getMechanismForKeyType(params.keyType);
      const publicKeyTemplate = this.createPublicKeyTemplate(params);
      const privateKeyTemplate = this.createPrivateKeyTemplate(params);

      // Generate key pair
      const keyGenResult = this.pkcs11.generateKeyPair(
        pkcs11Handle, 
        mechanism, 
        publicKeyTemplate, 
        privateKeyTemplate
      );

      if (keyGenResult.returnCode !== PKCS11_RETURN_CODES.CKR_OK || 
          !keyGenResult.publicKeyHandle || !keyGenResult.privateKeyHandle) {
        throw new HsmOperationError(`Key generation failed: ${keyGenResult.returnCode}`);
      }

      // Create HSM key record
      const hsmKey: HsmKey = {
        id: randomUUID(),
        tenantId: this.provider.tenantId,
        deviceId: this.discoveredDevices.get(session.deviceId)?.id || session.deviceId,
        tokenId: null,
        keyId: keyGenResult.privateKeyHandle, // Use private key handle as key ID
        keyLabel: params.keyLabel,
        algorithmId: '', // Will be resolved by caller
        keyType: params.keyType === 'rsa' ? 'signing' : params.keyType === 'aes' ? 'encryption' : 'master',
        keyUsagePolicy: 'unrestricted',
        status: 'active',
        isExportable: params.isExtractable || false,
        isSensitive: params.isSensitive !== false,
        isExtractable: params.isExtractable || false,
        keySize: params.keySize,
        publicKey: null, // Would extract public key in production
        keyFingerprint: this.generateKeyFingerprint(keyGenResult.privateKeyHandle, params),
        createdInHsm: new Date(),
        expiresAt: params.expirationDate || null,
        rotationInterval: 30,
        usageLimit: null,
        usageCount: 0,
        lastUsed: null,
        backupStatus: 'none',
        escrowedBy: null,
        attestationData: {
          pkcs11PublicHandle: keyGenResult.publicKeyHandle,
          pkcs11PrivateHandle: keyGenResult.privateKeyHandle,
          mechanism: mechanism,
          deviceAttestation: `Generated on device ${session.deviceId} at ${new Date().toISOString()}`
        },
        complianceFlags: JSON.stringify(['fips_140_2', 'pkcs11_compliant']),
        metadata: {
          sessionId,
          keyGeneration: {
            mechanism,
            template: privateKeyTemplate,
            generatedAt: new Date().toISOString()
          }
        },
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Update session operation count
      session.operationCount++;
      session.lastActivity = new Date();

      return {
        success: true,
        data: hsmKey,
        duration: Date.now() - startTime,
        attestation: hsmKey.attestationData.deviceAttestation
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: error instanceof HsmOperationError ? error.code : 'HSM_KEY_GEN_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async importKey(sessionId: string, keyData: Buffer, params: Partial<HsmKeyGenParams>): Promise<HsmResult<HsmKey>> {
    // Implementation would import external key material into HSM
    throw new Error('Key import not implemented in mock adapter');
  }

  async deleteKey(sessionId: string, keyId: string): Promise<HsmResult<void>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const pkcs11Handle = session.metadata.pkcs11Handle as string;
      
      // Delete key object
      const deleteResult = this.pkcs11.destroyObject(pkcs11Handle, keyId);
      if (deleteResult !== PKCS11_RETURN_CODES.CKR_OK) {
        throw new HsmOperationError(`Key deletion failed: ${deleteResult}`);
      }

      session.operationCount++;
      session.lastActivity = new Date();

      return {
        success: true,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'HSM_KEY_DELETE_ERROR',
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

      const pkcs11Handle = session.metadata.pkcs11Handle as string;
      
      // Perform signing operation
      const signResult = this.pkcs11.sign(pkcs11Handle, params.keyId, params.data);
      if (signResult.returnCode !== PKCS11_RETURN_CODES.CKR_OK || !signResult.signature) {
        throw new HsmOperationError(`Signing failed: ${signResult.returnCode}`);
      }

      session.operationCount++;
      session.lastActivity = new Date();

      return {
        success: true,
        data: signResult.signature,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'HSM_SIGN_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async encrypt(sessionId: string, params: HsmEncryptParams): Promise<HsmResult<Buffer>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const pkcs11Handle = session.metadata.pkcs11Handle as string;
      
      // Perform encryption operation
      const encryptResult = this.pkcs11.encrypt(pkcs11Handle, params.keyId, params.data);
      if (encryptResult.returnCode !== PKCS11_RETURN_CODES.CKR_OK || !encryptResult.encryptedData) {
        throw new HsmOperationError(`Encryption failed: ${encryptResult.returnCode}`);
      }

      session.operationCount++;
      session.lastActivity = new Date();

      return {
        success: true,
        data: encryptResult.encryptedData,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'HSM_ENCRYPT_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async decrypt(sessionId: string, keyId: string, encryptedData: Buffer, algorithm: string): Promise<HsmResult<Buffer>> {
    // Implementation would decrypt using HSM key
    throw new Error('Decryption not implemented in mock adapter');
  }

  async getHealthStatus(deviceId: string): Promise<HsmResult<HsmHealthStatus>> {
    const startTime = Date.now();
    
    try {
      const device = this.discoveredDevices.get(deviceId);
      if (!device) {
        throw new Error(`Device not found: ${deviceId}`);
      }

      const healthStatus: HsmHealthStatus = {
        online: device.status === 'online',
        authenticated: this.activeSessions.size > 0,
        tamperStatus: device.tamperStatus as any,
        temperature: device.temperature || undefined,
        batteryLevel: device.batteryLevel || undefined,
        uptime: Date.now() - new Date(device.createdAt).getTime(),
        operationsPerformed: device.usedKeys,
        errorRate: 0, // Mock value
        lastAttestation: device.lastAttestation || undefined
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
        errorCode: 'HSM_HEALTH_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async attestKey(sessionId: string, keyId: string): Promise<HsmResult<any>> {
    // Implementation would generate key attestation
    throw new Error('Key attestation not implemented in mock adapter');
  }

  async listKeys(sessionId: string, filter?: Record<string, any>): Promise<HsmResult<HsmKey[]>> {
    const startTime = Date.now();
    
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      const pkcs11Handle = session.metadata.pkcs11Handle as string;
      
      // Find objects matching filter
      const findResult = this.pkcs11.findObjects(pkcs11Handle, filter || {});
      if (findResult.returnCode !== PKCS11_RETURN_CODES.CKR_OK) {
        throw new HsmOperationError(`Key listing failed: ${findResult.returnCode}`);
      }

      // Mock key objects (in production, would populate from actual PKCS#11 objects)
      const keys: HsmKey[] = [];

      return {
        success: true,
        data: keys,
        duration: Date.now() - startTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorCode: 'HSM_LIST_KEYS_ERROR',
        duration: Date.now() - startTime
      };
    }
  }

  async backupKey(sessionId: string, keyId: string, escrowAuthority?: string): Promise<HsmResult<string>> {
    // Implementation would create secure key backup
    throw new Error('Key backup not implemented in mock adapter');
  }

  async recoverKey(sessionId: string, backupData: string, escrowAuth: string): Promise<HsmResult<HsmKey>> {
    // Implementation would recover key from backup
    throw new Error('Key recovery not implemented in mock adapter');
  }

  /**
   * Helper Methods
   */
  private getModelForProvider(): string {
    const models: Record<string, string> = {
      safenet: 'Luna SA 7',
      thales: 'nShield Connect+',
      ncipher: 'nShield Edge',
      aws_cloudhsm: 'AWS CloudHSM',
      azure_dedicated_hsm: 'Azure Dedicated HSM',
      utimaco: 'CryptoServer Se'
    };
    return models[this.provider.provider] || 'Generic PKCS#11 Device';
  }

  private getMechanismForKeyType(keyType: string): number {
    const mechanisms: Record<string, number> = {
      rsa: PKCS11_MECHANISMS.CKM_RSA_PKCS_KEY_PAIR_GEN,
      ecdsa: PKCS11_MECHANISMS.CKM_ECDSA,
      aes: PKCS11_MECHANISMS.CKM_AES_KEY_GEN
    };
    return mechanisms[keyType] || PKCS11_MECHANISMS.CKM_RSA_PKCS_KEY_PAIR_GEN;
  }

  private createPublicKeyTemplate(params: HsmKeyGenParams): any {
    return {
      [PKCS11_ATTRIBUTES.CKA_CLASS]: PKCS11_OBJECT_CLASSES.CKO_PUBLIC_KEY,
      [PKCS11_ATTRIBUTES.CKA_TOKEN]: true,
      [PKCS11_ATTRIBUTES.CKA_LABEL]: params.keyLabel + '_public',
      [PKCS11_ATTRIBUTES.CKA_ENCRYPT]: params.keyUsage.includes('encrypt'),
      [PKCS11_ATTRIBUTES.CKA_VERIFY]: params.keyUsage.includes('verify'),
      [PKCS11_ATTRIBUTES.CKA_MODULUS_BITS]: params.keySize
    };
  }

  private createPrivateKeyTemplate(params: HsmKeyGenParams): any {
    return {
      [PKCS11_ATTRIBUTES.CKA_CLASS]: PKCS11_OBJECT_CLASSES.CKO_PRIVATE_KEY,
      [PKCS11_ATTRIBUTES.CKA_TOKEN]: true,
      [PKCS11_ATTRIBUTES.CKA_PRIVATE]: true,
      [PKCS11_ATTRIBUTES.CKA_LABEL]: params.keyLabel + '_private',
      [PKCS11_ATTRIBUTES.CKA_SENSITIVE]: params.isSensitive !== false,
      [PKCS11_ATTRIBUTES.CKA_EXTRACTABLE]: params.isExtractable || false,
      [PKCS11_ATTRIBUTES.CKA_DECRYPT]: params.keyUsage.includes('decrypt'),
      [PKCS11_ATTRIBUTES.CKA_SIGN]: params.keyUsage.includes('sign')
    };
  }

  private generateKeyFingerprint(keyHandle: string, params: HsmKeyGenParams): string {
    // In production, would generate actual key fingerprint
    return `fp_${keyHandle.substring(0, 8)}_${params.keyType}_${params.keySize}`;
  }

  async cleanup(): Promise<void> {
    await super.cleanup();
    
    // Finalize PKCS#11 library
    try {
      this.pkcs11.finalize();
    } catch (error) {
      console.error('Failed to finalize PKCS#11 library:', error);
    }
  }
}