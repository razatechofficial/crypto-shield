/**
 * Averox Production Cryptographic SDK TypeScript Definitions
 * Enterprise-grade encryption with comprehensive security features
 */

declare module '@averox/crypto-sdk' {
  
  // Error types for proper error handling
  export class AveroxCryptoError extends Error {
    readonly code: string;
    readonly cause?: Error;
    readonly timestamp: string;
    
    constructor(code: string, message: string, cause?: Error);
  }
  
  // Telemetry and metrics interface
  export interface AveroxMetrics {
    encryptionOps: number;
    decryptionOps: number;
    keyDerivations: number;
    errors: number;
  }
  
  export class AveroxTelemetry {
    static readonly metrics: AveroxMetrics;
    static recordOperation(operation: keyof AveroxMetrics, success?: boolean): void;
    static getMetrics(): AveroxMetrics;
  }
  
  // Envelope format interface
  export interface EnvelopeData {
    version: number;
    algorithm: string;
    kid: string;
    iv: Buffer;
    tag: Buffer;
    ciphertext: Buffer;
    aad: Buffer | null;
    timestamp: string;
  }
  
  export class AveroxEnvelope {
    static readonly VERSION: number;
    static readonly ALGORITHM: string;
    
    static create(
      iv: Buffer,
      tag: Buffer,
      ciphertext: Buffer,
      kid?: string | null,
      aad?: Buffer | null
    ): Buffer;
    
    static parse(envelopeBuffer: Buffer): EnvelopeData;
  }
  
  // Main cryptographic interface
  export class AveroxCrypto {
    constructor(masterKey: Buffer | Uint8Array | string, keyId?: string);
    
    generateIV(): Buffer;
    deriveKey(context?: string): Buffer;
    
    encrypt(plaintext: Buffer | string, aad?: Buffer | null): Buffer;
    decrypt(envelopeBuffer: Buffer): Buffer;
    
    destroy(): void;
  }
  
  // Utility functions
  export function timingSafeEqual(a: Buffer, b: Buffer): boolean;
  export function hkdf(
    ikm: Buffer,
    salt?: Buffer | null,
    info?: Buffer | null,
    length?: number
  ): Buffer;
  export function validateNISTCompliance(): boolean;
  
  // Configuration interfaces
  export interface CryptoConfig {
    keyDerivation: 'hkdf' | 'pbkdf2';
    ivLength: 12 | 16;
    tagLength: 16;
    telemetryEnabled: boolean;
  }
  
  export interface SecurityOptions {
    enforceAAD: boolean;
    requireKeyID: boolean;
    enableTelemetry: boolean;
    zeroizeMemory: boolean;
  }
  
  // Advanced factory for enterprise usage
  export class AveroxCryptoFactory {
    static create(config?: Partial<CryptoConfig>): AveroxCrypto;
    static createWithOptions(
      masterKey: Buffer,
      options?: Partial<SecurityOptions>
    ): AveroxCrypto;
  }
  
  // Constants
  export const SUPPORTED_ALGORITHMS: readonly string[];
  export const DEFAULT_CONFIG: CryptoConfig;
  export const NIST_COMPLIANCE_VERSION: string;
}

// Ambient module for Node.js crypto compatibility
declare global {
  namespace NodeJS {
    interface ProcessEnv {
      AVEROX_TELEMETRY?: 'enabled' | 'disabled';
      AVEROX_SECURITY_LEVEL?: 'standard' | 'high' | 'ultra';
    }
  }
}