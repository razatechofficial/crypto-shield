import {
  users,
  tenants,
  sdks,
  encryptionAlgorithms,
  encryptionKeys,
  securityEvents,
  apiUsage,
  type User,
  type UpsertUser,
  type Tenant,
  type InsertTenant,
  type Sdk,
  type InsertSdk,
  type EncryptionAlgorithm,
  type EncryptionKey,
  type InsertEncryptionKey,
  type SecurityEvent,
  type InsertSecurityEvent,
  type ApiUsage,
  type InsertApiUsage,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, count, sum } from "drizzle-orm";
import { randomUUID } from "crypto";

export interface IStorage {
  // User operations (required for Replit Auth)
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User>;
  
  // Tenant operations
  getTenant(id: string): Promise<Tenant | undefined>;
  getTenantByApiKey(apiKey: string): Promise<Tenant | undefined>;
  createTenant(tenant: InsertTenant): Promise<Tenant>;
  
  // SDK operations
  getSDKs(tenantId: string, userId?: string): Promise<Sdk[]>;
  createSDK(sdk: InsertSdk): Promise<Sdk>;
  getSDK(id: string): Promise<Sdk | undefined>;
  deleteSDK(id: string): Promise<void>;
  deleteAllSDKs(tenantId: string): Promise<void>;
  
  // Algorithm operations
  getEncryptionAlgorithms(): Promise<EncryptionAlgorithm[]>;
  getEncryptionAlgorithm(id: string): Promise<EncryptionAlgorithm | undefined>;
  getRecommendedAlgorithms(applicationConfig: {
    applicationType?: string;
    securityLevel?: string;
    complianceRequirements?: string[];
    deploymentEnvironment?: string;
  }): Promise<EncryptionAlgorithm[]>;
  
  // Key management operations
  getEncryptionKeys(tenantId: string): Promise<EncryptionKey[]>;
  createEncryptionKey(key: InsertEncryptionKey): Promise<EncryptionKey>;
  updateEncryptionKeyStatus(keyId: string, status: string): Promise<void>;
  
  // Security monitoring operations
  getSecurityEvents(tenantId: string, limit?: number): Promise<SecurityEvent[]>;
  createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent>;
  
  // API usage operations
  getApiUsage(tenantId: string, days?: number): Promise<ApiUsage[]>;
  recordApiUsage(usage: InsertApiUsage): Promise<ApiUsage>;
  
  // Dashboard statistics
  getDashboardStats(tenantId: string): Promise<{
    activeSDKs: number;
    encryptedRequests: number;
    keyRotations: number;
    threatBlocks: number;
  }>;
  
  // User management
  getTenantUsers(tenantId: string): Promise<User[]>;
  updateUserRole(userId: string, role: string): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  // User operations (required for Replit Auth)
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.id,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    const [user] = await db
      .update(users)
      .set({
        ...updates,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  // Tenant operations
  async getTenant(id: string): Promise<Tenant | undefined> {
    const [tenant] = await db.select().from(tenants).where(eq(tenants.id, id));
    return tenant;
  }

  async getTenantByApiKey(apiKey: string): Promise<Tenant | undefined> {
    const [tenant] = await db.select().from(tenants).where(eq(tenants.apiKey, apiKey));
    return tenant;
  }

  async createTenant(tenantData: InsertTenant): Promise<Tenant> {
    // Generate API key if not provided
    const apiKey = tenantData.apiKey || `ak_${randomUUID().replace(/-/g, '')}`;
    
    const [tenant] = await db
      .insert(tenants)
      .values({
        ...tenantData,
        apiKey,
      })
      .returning();
    return tenant;
  }

  // SDK operations
  async getSDKs(tenantId: string, userId?: string): Promise<Sdk[]> {
    // Check if SDKs exist, if not, seed some test data
    const existing = await db.select().from(sdks).where(eq(sdks.tenantId, tenantId)).limit(1);
    if (existing.length === 0 && userId) {
      await this.seedTestSDKs(tenantId, userId);
    }
    
    return await db
      .select()
      .from(sdks)
      .where(eq(sdks.tenantId, tenantId))
      .orderBy(desc(sdks.createdAt));
  }

  async createSDK(sdkData: InsertSdk): Promise<Sdk> {
    const [sdk] = await db.insert(sdks).values(sdkData).returning();
    return sdk;
  }

  async getSDK(id: string): Promise<Sdk | undefined> {
    const [sdk] = await db.select().from(sdks).where(eq(sdks.id, id));
    return sdk;
  }

  async deleteSDK(id: string): Promise<void> {
    await db.delete(sdks).where(eq(sdks.id, id));
  }

  async deleteAllSDKs(tenantId: string): Promise<void> {
    await db.delete(sdks).where(eq(sdks.tenantId, tenantId));
  }

  // Algorithm operations
  async getEncryptionAlgorithms(): Promise<EncryptionAlgorithm[]> {
    // Check if algorithms exist, if not, seed them
    const existing = await db.select().from(encryptionAlgorithms).limit(1);
    if (existing.length === 0) {
      await this.seedEncryptionAlgorithms();
    }
    
    return await db
      .select()
      .from(encryptionAlgorithms)
      .where(eq(encryptionAlgorithms.isActive, true))
      .orderBy(encryptionAlgorithms.name);
  }

  // Seed test SDKs for development
  private async seedTestSDKs(tenantId: string, userId: string): Promise<void> {
    const testSDKs = [
      {
        id: randomUUID(),
        tenantId: tenantId,
        userId: userId,
        name: 'FinanceSecure SDK',
        description: 'Enterprise-grade encryption SDK for financial applications with FIPS 140-2 compliance',
        version: '2.1.0',
        languages: JSON.stringify(['javascript', 'python', 'java', 'csharp']),
        algorithms: JSON.stringify(['AES-256-GCM', 'ChaCha20-Poly1305', 'RSA-4096']),
        dataTypes: JSON.stringify(['payment_data', 'pii', 'financial_records']),
        complianceRequirements: JSON.stringify(['FIPS-140-2', 'PCI-DSS', 'SOX']),
        confidentialFeatures: JSON.stringify(['hardware_security_module', 'secure_enclaves']),
        configuration: {
          encryptionMode: 'AES-256-GCM',
          keyRotationInterval: '90_days',
          auditLogging: true,
          multiTenant: true
        },
        features: {
          keyManagement: true,
          auditLogging: true,
          multiTenant: true,
          quantumSafe: false
        },
        downloadUrl: '/api/sdks/finance-secure-v2.1.0/download',
        isActive: true,
        createdAt: new Date(Date.now() - 86400000 * 7), // 7 days ago
        updatedAt: new Date(Date.now() - 86400000 * 2), // 2 days ago
      },
      {
        id: randomUUID(),
        tenantId: tenantId,
        userId: userId,
        name: 'HealthcareCrypto SDK',
        description: 'HIPAA-compliant encryption SDK for healthcare data with end-to-end encryption',
        version: '1.8.3',
        languages: JSON.stringify(['python', 'javascript', 'swift', 'kotlin']),
        algorithms: JSON.stringify(['AES-256-GCM', 'ChaCha20-Poly1305']),
        dataTypes: JSON.stringify(['medical_records', 'pii', 'phi']),
        complianceRequirements: JSON.stringify(['HIPAA', 'HITECH', 'FDA-21-CFR-11']),
        confidentialFeatures: JSON.stringify(['secure_multi_party_computation']),
        configuration: {
          encryptionMode: 'AES-256-GCM',
          keyRotationInterval: '30_days',
          auditLogging: true,
          multiTenant: false
        },
        features: {
          keyManagement: true,
          auditLogging: true,
          multiTenant: false,
          quantumSafe: false
        },
        downloadUrl: '/api/sdks/healthcare-crypto-v1.8.3/download',
        isActive: true,
        createdAt: new Date(Date.now() - 86400000 * 14), // 14 days ago
        updatedAt: new Date(Date.now() - 86400000 * 5), // 5 days ago
      },
      {
        id: randomUUID(),
        tenantId: tenantId,
        userId: userId,
        name: 'QuantumSafe Enterprise SDK',
        description: 'Next-generation quantum-resistant encryption SDK with NIST 2024 post-quantum algorithms',
        version: '3.0.0-beta',
        languages: JSON.stringify(['javascript', 'python', 'cpp', 'rust']),
        algorithms: JSON.stringify(['Kyber-1024', 'Dilithium-5', 'SPHINCS+-SHA256', 'AES-256-GCM']),
        dataTypes: JSON.stringify(['classified', 'defense', 'government', 'critical_infrastructure']),
        complianceRequirements: JSON.stringify(['NIST-PQC', 'FIPS-140-3', 'Common-Criteria']),
        confidentialFeatures: JSON.stringify(['post_quantum_cryptography', 'hardware_security_module', 'secure_enclaves']),
        configuration: {
          encryptionMode: 'Hybrid-PQC',
          keyRotationInterval: '7_days',
          auditLogging: true,
          multiTenant: true
        },
        features: {
          keyManagement: true,
          auditLogging: true,
          multiTenant: true,
          quantumSafe: true
        },
        downloadUrl: '/api/sdks/quantum-safe-enterprise-v3.0.0-beta/download',
        isActive: true,
        createdAt: new Date(Date.now() - 86400000 * 3), // 3 days ago
        updatedAt: new Date(Date.now() - 86400000 * 1), // 1 day ago
      },
      {
        id: randomUUID(),
        tenantId: tenantId,
        userId: userId,
        name: 'MobileCrypto SDK',
        description: 'Lightweight encryption SDK optimized for mobile applications with battery-efficient algorithms',
        version: '2.3.1',
        languages: JSON.stringify(['swift', 'kotlin', 'javascript', 'dart']),
        algorithms: JSON.stringify(['ChaCha20-Poly1305', 'AES-128-GCM']),
        dataTypes: JSON.stringify(['user_data', 'app_data', 'communications']),
        complianceRequirements: JSON.stringify(['GDPR', 'CCPA', 'App-Store-Guidelines']),
        confidentialFeatures: JSON.stringify(['biometric_encryption']),
        configuration: {
          encryptionMode: 'ChaCha20-Poly1305',
          keyRotationInterval: '30_days',
          auditLogging: false,
          multiTenant: false
        },
        features: {
          keyManagement: true,
          auditLogging: false,
          multiTenant: false,
          quantumSafe: false
        },
        downloadUrl: '/api/sdks/mobile-crypto-v2.3.1/download',
        isActive: true,
        createdAt: new Date(Date.now() - 86400000 * 21), // 21 days ago
        updatedAt: new Date(Date.now() - 86400000 * 7), // 7 days ago
      }
    ];

    await db.insert(sdks).values(testSDKs);
    console.log('✅ Seeded test SDK data');
  }

  // Seed encryption algorithms - COMPREHENSIVE MARKET COVERAGE
  private async seedEncryptionAlgorithms(): Promise<void> {
    const algorithms = [
      // === NIST APPROVED SYMMETRIC ENCRYPTION ===
      {
        name: 'AES-128-ECB',
        displayName: 'AES-128-ECB',
        description: 'Advanced Encryption Standard 128-bit with Electronic Codebook mode. Not recommended for most applications.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-128-CBC',
        displayName: 'AES-128-CBC',
        description: 'Advanced Encryption Standard 128-bit with Cipher Block Chaining mode. Widely supported standard.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-128-CFB',
        displayName: 'AES-128-CFB',
        description: 'Advanced Encryption Standard 128-bit with Cipher Feedback mode. Stream cipher mode.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-128-OFB',
        displayName: 'AES-128-OFB',
        description: 'Advanced Encryption Standard 128-bit with Output Feedback mode. Stream cipher mode.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-128-CTR',
        displayName: 'AES-128-CTR',
        description: 'Advanced Encryption Standard 128-bit with Counter mode. High-performance stream cipher mode.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-128-GCM',
        displayName: 'AES-128-GCM',
        description: 'Advanced Encryption Standard 128-bit with Galois Counter Mode. Authenticated encryption.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-192-ECB',
        displayName: 'AES-192-ECB',
        description: 'Advanced Encryption Standard 192-bit with Electronic Codebook mode.',
        type: 'symmetric' as const,
        keySize: 192,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-192-CBC',
        displayName: 'AES-192-CBC',
        description: 'Advanced Encryption Standard 192-bit with Cipher Block Chaining mode.',
        type: 'symmetric' as const,
        keySize: 192,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-192-GCM',
        displayName: 'AES-192-GCM',
        description: 'Advanced Encryption Standard 192-bit with Galois Counter Mode. High security authenticated encryption.',
        type: 'symmetric' as const,
        keySize: 192,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-ECB',
        displayName: 'AES-256-ECB',
        description: 'Advanced Encryption Standard 256-bit with Electronic Codebook mode.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-CBC',
        displayName: 'AES-256-CBC',
        description: 'Advanced Encryption Standard 256-bit with Cipher Block Chaining mode. High security standard.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-CFB',
        displayName: 'AES-256-CFB',
        description: 'Advanced Encryption Standard 256-bit with Cipher Feedback mode.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-OFB',
        displayName: 'AES-256-OFB',
        description: 'Advanced Encryption Standard 256-bit with Output Feedback mode.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-CTR',
        displayName: 'AES-256-CTR',
        description: 'Advanced Encryption Standard 256-bit with Counter mode. Maximum security stream cipher.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-GCM',
        displayName: 'AES-256-GCM',
        description: 'Advanced Encryption Standard 256-bit with Galois Counter Mode. Maximum security authenticated encryption.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-CBC',
        displayName: 'AES-256-CBC',
        description: 'Advanced Encryption Standard with 256-bit key and Cipher Block Chaining mode. Block cipher encryption.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-256-CTR',
        displayName: 'AES-256-CTR',
        description: 'Advanced Encryption Standard with 256-bit key and Counter mode. Stream cipher mode for AES.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'AES-128-GCM',
        displayName: 'AES-128-GCM',
        description: 'Advanced Encryption Standard with 128-bit key. Faster performance with good security for most use cases.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === STREAM CIPHERS ===
      {
        name: 'ChaCha20',
        displayName: 'ChaCha20',
        description: 'High-speed stream cipher by Daniel J. Bernstein. Alternative to AES for constrained environments.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ChaCha20-Poly1305',
        displayName: 'ChaCha20-Poly1305',
        description: 'ChaCha20 stream cipher with Poly1305 authenticator. IETF standard authenticated encryption.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Salsa20',
        displayName: 'Salsa20',
        description: 'Stream cipher by Daniel J. Bernstein. Predecessor to ChaCha20.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === LEGACY SYMMETRIC (STILL USED) ===
      {
        name: 'DES',
        displayName: 'DES',
        description: 'Data Encryption Standard. Legacy algorithm, weak security. Use only for legacy compatibility.',
        type: 'symmetric' as const,
        keySize: 56,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: '3DES',
        displayName: 'Triple DES',
        description: 'Triple Data Encryption Standard. Legacy NIST standard, being phased out.',
        type: 'symmetric' as const,
        keySize: 168,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Blowfish',
        displayName: 'Blowfish',
        description: 'Block cipher by Bruce Schneier. Fast, patent-free alternative to DES.',
        type: 'symmetric' as const,
        keySize: 448,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Twofish',
        displayName: 'Twofish',
        description: 'Block cipher by Bruce Schneier. AES finalist with strong security properties.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Serpent',
        displayName: 'Serpent',
        description: 'Block cipher and AES finalist. Conservative design with high security margin.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Camellia-128',
        displayName: 'Camellia-128',
        description: 'Japanese block cipher standard. ISO/IEC 18033-3 standard.',
        type: 'symmetric' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Camellia-256',
        displayName: 'Camellia-256',
        description: 'Japanese block cipher standard 256-bit. High security international standard.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === ASYMMETRIC ENCRYPTION & SIGNATURES ===
      {
        name: 'RSA-1024',
        displayName: 'RSA-1024',
        description: 'RSA with 1024-bit key. Legacy support only, not recommended for new applications.',
        type: 'asymmetric' as const,
        keySize: 1024,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: 'RSA-2048',
        displayName: 'RSA-2048',
        description: 'RSA with 2048-bit key. Current minimum standard for digital signatures and key exchange.',
        type: 'asymmetric' as const,
        keySize: 2048,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'RSA-3072',
        displayName: 'RSA-3072',
        description: 'RSA with 3072-bit key. Enhanced security level equivalent to AES-128.',
        type: 'asymmetric' as const,
        keySize: 3072,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'RSA-4096',
        displayName: 'RSA-4096',
        description: 'RSA with 4096-bit key. High security level equivalent to AES-128/192.',
        type: 'asymmetric' as const,
        keySize: 4096,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'RSA-8192',
        displayName: 'RSA-8192',
        description: 'RSA with 8192-bit key. Maximum classical security, very slow performance.',
        type: 'asymmetric' as const,
        keySize: 8192,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === DIGITAL SIGNATURE ALGORITHM ===
      {
        name: 'DSA-1024',
        displayName: 'DSA-1024',
        description: 'Digital Signature Algorithm 1024-bit. Legacy NIST standard.',
        type: 'asymmetric' as const,
        keySize: 1024,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: 'DSA-2048',
        displayName: 'DSA-2048',
        description: 'Digital Signature Algorithm 2048-bit. Current NIST FIPS 186-4 standard.',
        type: 'asymmetric' as const,
        keySize: 2048,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'DSA-3072',
        displayName: 'DSA-3072',
        description: 'Digital Signature Algorithm 3072-bit. High security NIST standard.',
        type: 'asymmetric' as const,
        keySize: 3072,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === ELLIPTIC CURVE CRYPTOGRAPHY ===
      {
        name: 'ECDSA-P192',
        displayName: 'ECDSA P-192',
        description: 'Elliptic Curve Digital Signature Algorithm with P-192 curve. NIST standard.',
        type: 'asymmetric' as const,
        keySize: 192,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ECDSA-P224',
        displayName: 'ECDSA P-224',
        description: 'Elliptic Curve Digital Signature Algorithm with P-224 curve. Medium security.',
        type: 'asymmetric' as const,
        keySize: 224,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ECDSA-P256',
        displayName: 'ECDSA P-256',
        description: 'Elliptic Curve Digital Signature Algorithm with P-256 curve. Smaller keys with equivalent security.',
        type: 'asymmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Ed25519',
        displayName: 'Ed25519',
        description: 'Edwards-curve Digital Signature Algorithm using Curve25519. High-performance signatures.',
        type: 'asymmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'X25519',
        displayName: 'X25519',
        description: 'Elliptic Curve Diffie-Hellman key agreement using Curve25519. Fast key exchange.',
        type: 'asymmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ECDSA-P384',
        displayName: 'ECDSA P-384',
        description: 'Elliptic Curve Digital Signature Algorithm with P-384 curve. Suite B standard.',
        type: 'asymmetric' as const,
        keySize: 384,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ECDSA-P521',
        displayName: 'ECDSA P-521',
        description: 'Elliptic Curve Digital Signature Algorithm with P-521 curve. Maximum classical security.',
        type: 'asymmetric' as const,
        keySize: 521,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ECDSA-secp256k1',
        displayName: 'ECDSA secp256k1',
        description: 'Elliptic Curve Digital Signature Algorithm with secp256k1 curve. Bitcoin standard.',
        type: 'asymmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === ELLIPTIC CURVE DIFFIE-HELLMAN ===
      {
        name: 'ECDH-P256',
        displayName: 'ECDH P-256',
        description: 'Elliptic Curve Diffie-Hellman with P-256 curve. Key agreement protocol.',
        type: 'asymmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ECDH-P384',
        displayName: 'ECDH P-384',
        description: 'Elliptic Curve Diffie-Hellman with P-384 curve. High security key agreement.',
        type: 'asymmetric' as const,
        keySize: 384,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'ECDH-P521',
        displayName: 'ECDH P-521',
        description: 'Elliptic Curve Diffie-Hellman with P-521 curve. Maximum security key agreement.',
        type: 'asymmetric' as const,
        keySize: 521,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // Key Derivation Functions - VERIFIED WORKING
      {
        name: 'PBKDF2',
        displayName: 'PBKDF2-SHA256',
        description: 'Password-Based Key Derivation Function 2. Standard for password-based encryption.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'HKDF',
        displayName: 'HKDF-SHA256',
        description: 'HMAC-based Key Derivation Function. Extracting cryptographic keys from source material.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Scrypt',
        displayName: 'Scrypt',
        description: 'Memory-hard key derivation function. Resistant to hardware attacks.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'HMAC-SHA256',
        displayName: 'HMAC-SHA256',
        description: 'Hash-based Message Authentication Code using SHA-256. Message integrity verification.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === MODERN CURVE ALGORITHMS ===
      {
        name: 'Ed25519',
        displayName: 'Ed25519',
        description: 'Edwards-curve Digital Signature Algorithm using Curve25519. RFC 8032 standard.',
        type: 'asymmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Ed448',
        displayName: 'Ed448',
        description: 'Edwards-curve Digital Signature Algorithm using Curve448. High security level.',
        type: 'asymmetric' as const,
        keySize: 448,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'X25519',
        displayName: 'X25519',
        description: 'Elliptic Curve Diffie-Hellman key agreement using Curve25519. RFC 7748 standard.',
        type: 'asymmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'X448',
        displayName: 'X448',
        description: 'Elliptic Curve Diffie-Hellman key agreement using Curve448. High security ECDH.',
        type: 'asymmetric' as const,
        keySize: 448,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === HASH FUNCTIONS (NIST APPROVED) ===
      {
        name: 'MD5',
        displayName: 'MD5',
        description: 'Message Digest Algorithm 5. Legacy hash, cryptographically broken.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: 'SHA-1',
        displayName: 'SHA-1',
        description: 'Secure Hash Algorithm 1. Legacy NIST standard, deprecated due to collisions.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: 'SHA-224',
        displayName: 'SHA-224',
        description: 'Secure Hash Algorithm 224-bit. NIST FIPS 180-4 standard.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA-256',
        displayName: 'SHA-256',
        description: 'Secure Hash Algorithm 256-bit. Most widely used NIST standard.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA-384',
        displayName: 'SHA-384',
        description: 'Secure Hash Algorithm 384-bit. High security NIST standard.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA-512',
        displayName: 'SHA-512',
        description: 'Secure Hash Algorithm 512-bit. Maximum security NIST standard.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA-512/224',
        displayName: 'SHA-512/224',
        description: 'SHA-512 truncated to 224 bits. NIST FIPS 180-4 variant.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA-512/256',
        displayName: 'SHA-512/256',
        description: 'SHA-512 truncated to 256 bits. Better performance than SHA-256.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === SHA-3 FAMILY (NIST FIPS 202) ===
      {
        name: 'SHA3-224',
        displayName: 'SHA3-224',
        description: 'SHA-3 with 224-bit output. NIST FIPS 202 standard.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA3-256',
        displayName: 'SHA3-256',
        description: 'SHA-3 with 256-bit output. Modern NIST Keccak standard.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA3-384',
        displayName: 'SHA3-384',
        description: 'SHA-3 with 384-bit output. High security Keccak hash.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA3-512',
        displayName: 'SHA3-512',
        description: 'SHA-3 with 512-bit output. Maximum security Keccak hash.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHAKE128',
        displayName: 'SHAKE128',
        description: 'Extendable-output function based on Keccak. Variable length output.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHAKE256',
        displayName: 'SHAKE256',
        description: 'Extendable-output function based on Keccak. High security variable output.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === MODERN HASH FUNCTIONS ===
      {
        name: 'BLAKE2b',
        displayName: 'BLAKE2b',
        description: 'High-speed cryptographic hash function. Faster than SHA-2 and SHA-3.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'BLAKE2s',
        displayName: 'BLAKE2s',
        description: 'BLAKE2 optimized for 8-32 bit platforms. Constrained environment hash.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'BLAKE3',
        displayName: 'BLAKE3',
        description: 'Latest BLAKE hash function. Extremely fast with strong security properties.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'RIPEMD160',
        displayName: 'RIPEMD160',
        description: 'RACE Integrity Primitives Evaluation Message Digest. European alternative to SHA-1.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Whirlpool',
        displayName: 'Whirlpool',
        description: 'Cryptographic hash function designed by Vincent Rijmen and Paulo Barreto.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === MESSAGE AUTHENTICATION CODES ===
      {
        name: 'HMAC-MD5',
        displayName: 'HMAC-MD5',
        description: 'Hash-based Message Authentication Code using MD5. Legacy MAC.',
        type: 'hash' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: 'HMAC-SHA1',
        displayName: 'HMAC-SHA1',
        description: 'Hash-based Message Authentication Code using SHA-1. Legacy MAC.',
        type: 'hash' as const,
        keySize: 160,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: 'HMAC-SHA256',
        displayName: 'HMAC-SHA256',
        description: 'Hash-based Message Authentication Code using SHA-256. Standard MAC.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'HMAC-SHA384',
        displayName: 'HMAC-SHA384',
        description: 'Hash-based Message Authentication Code using SHA-384. High security MAC.',
        type: 'hash' as const,
        keySize: 384,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'HMAC-SHA512',
        displayName: 'HMAC-SHA512',
        description: 'Hash-based Message Authentication Code using SHA-512. Maximum security MAC.',
        type: 'hash' as const,
        keySize: 512,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'CMAC-AES',
        displayName: 'CMAC-AES',
        description: 'Cipher-based Message Authentication Code using AES. NIST SP 800-38B standard.',
        type: 'hash' as const,
        keySize: 128,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Poly1305',
        displayName: 'Poly1305',
        description: 'Cryptographic message authentication code by Daniel J. Bernstein.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === KEY DERIVATION FUNCTIONS ===
      {
        name: 'PBKDF2-SHA1',
        displayName: 'PBKDF2-SHA1',
        description: 'Password-Based Key Derivation Function 2 with SHA-1. Legacy KDF.',
        type: 'hash' as const,
        keySize: 160,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: false,
      },
      {
        name: 'PBKDF2-SHA256',
        displayName: 'PBKDF2-SHA256',
        description: 'Password-Based Key Derivation Function 2 with SHA-256. Standard KDF.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'PBKDF2-SHA512',
        displayName: 'PBKDF2-SHA512',
        description: 'Password-Based Key Derivation Function 2 with SHA-512. High security KDF.',
        type: 'hash' as const,
        keySize: 512,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Scrypt',
        displayName: 'Scrypt',
        description: 'Memory-hard key derivation function. Resistant to custom hardware attacks.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Argon2i',
        displayName: 'Argon2i',
        description: 'Password Hashing Competition winner. Side-channel resistant variant.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Argon2d',
        displayName: 'Argon2d',
        description: 'Argon2 data-dependent variant. Maximum resistance to time-memory trade-off attacks.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'Argon2id',
        displayName: 'Argon2id',
        description: 'Argon2 hybrid variant. Balanced security against side-channel and time-memory attacks.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'bcrypt',
        displayName: 'bcrypt',
        description: 'Adaptive hash function for passwords. Based on Blowfish cipher.',
        type: 'hash' as const,
        keySize: 192,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'HKDF-SHA256',
        displayName: 'HKDF-SHA256',
        description: 'HMAC-based Key Derivation Function with SHA-256. RFC 5869 standard.',
        type: 'hash' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'HKDF-SHA384',
        displayName: 'HKDF-SHA384',
        description: 'HMAC-based Key Derivation Function with SHA-384. High security HKDF.',
        type: 'hash' as const,
        keySize: 384,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'HKDF-SHA512',
        displayName: 'HKDF-SHA512',
        description: 'HMAC-based Key Derivation Function with SHA-512. Maximum security HKDF.',
        type: 'hash' as const,
        keySize: 512,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // === POST-QUANTUM CRYPTOGRAPHY (NIST SELECTED 2024) ===
      {
        name: 'ML-KEM-512',
        displayName: 'ML-KEM-512 (Kyber-512)',
        description: 'NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism. AES-128 equivalent security.',
        type: 'post_quantum' as const,
        keySize: 512,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'ML-KEM-768',
        displayName: 'ML-KEM-768 (Kyber-768)',
        description: 'NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism. AES-192 equivalent security.',
        type: 'post_quantum' as const,
        keySize: 768,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'ML-KEM-1024',
        displayName: 'ML-KEM-1024 (Kyber-1024)',
        description: 'NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism. AES-256 equivalent security.',
        type: 'post_quantum' as const,
        keySize: 1024,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'ML-DSA-44',
        displayName: 'ML-DSA-44 (Dilithium-2)',
        description: 'NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm. Security Level 2.',
        type: 'post_quantum' as const,
        keySize: 44,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'ML-DSA-65',
        displayName: 'ML-DSA-65 (Dilithium-3)',
        description: 'NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm. Security Level 3.',
        type: 'post_quantum' as const,
        keySize: 65,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'ML-DSA-87',
        displayName: 'ML-DSA-87 (Dilithium-5)',
        description: 'NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm. Security Level 5.',
        type: 'post_quantum' as const,
        keySize: 87,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'SLH-DSA-SHAKE-128s',
        displayName: 'SLH-DSA-SHAKE-128s (SPHINCS+)',
        description: 'NIST FIPS 205 Stateless Hash-Based Digital Signature Algorithm. Conservative backup standard.',
        type: 'post_quantum' as const,
        keySize: 128,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'SLH-DSA-SHAKE-128f',
        displayName: 'SLH-DSA-SHAKE-128f (SPHINCS+)',
        description: 'NIST FIPS 205 Stateless Hash-Based Digital Signature Algorithm. Fast variant.',
        type: 'post_quantum' as const,
        keySize: 128,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'SLH-DSA-SHA2-128s',
        displayName: 'SLH-DSA-SHA2-128s (SPHINCS+)',
        description: 'NIST FIPS 205 Stateless Hash-Based Digital Signature Algorithm. SHA-2 variant.',
        type: 'post_quantum' as const,
        keySize: 128,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'FN-DSA-512',
        displayName: 'FN-DSA-512 (FALCON-512)',
        description: 'NIST FIPS 206 FFT over NTRU-Lattice Digital Signature Algorithm. Compact signatures.',
        type: 'post_quantum' as const,
        keySize: 512,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'FN-DSA-1024',
        displayName: 'FN-DSA-1024 (FALCON-1024)',
        description: 'NIST FIPS 206 FFT over NTRU-Lattice Digital Signature Algorithm. High security.',
        type: 'post_quantum' as const,
        keySize: 1024,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      
      // === POST-QUANTUM ALTERNATIVES (NIST ROUND 4) ===
      {
        name: 'HQC-128',
        displayName: 'HQC-128',
        description: 'Hamming Quasi-Cyclic code-based encryption. NIST selected backup algorithm.',
        type: 'post_quantum' as const,
        keySize: 128,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'HQC-192',
        displayName: 'HQC-192',
        description: 'Hamming Quasi-Cyclic code-based encryption. Medium security level.',
        type: 'post_quantum' as const,
        keySize: 192,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'HQC-256',
        displayName: 'HQC-256',
        description: 'Hamming Quasi-Cyclic code-based encryption. High security level.',
        type: 'post_quantum' as const,
        keySize: 256,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'Classic-McEliece-348864',
        displayName: 'Classic McEliece 348864',
        description: 'Code-based cryptosystem. Conservative post-quantum encryption.',
        type: 'post_quantum' as const,
        keySize: 348864,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'BIKE-L1',
        displayName: 'BIKE Level 1',
        description: 'Bit Flipping Key Encapsulation. Code-based post-quantum cryptography.',
        type: 'post_quantum' as const,
        keySize: 128,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'NTRU-HPS-2048-509',
        displayName: 'NTRU-HPS-2048-509',
        description: 'NTRU lattice-based encryption. Alternative post-quantum approach.',
        type: 'post_quantum' as const,
        keySize: 509,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'SABER-Lightsaber',
        displayName: 'SABER Lightsaber',
        description: 'Module Learning With Rounding encryption. Efficient post-quantum scheme.',
        type: 'post_quantum' as const,
        keySize: 512,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'FrodoKEM-640',
        displayName: 'FrodoKEM-640',
        description: 'Learning With Errors encryption. Conservative lattice-based approach.',
        type: 'post_quantum' as const,
        keySize: 640,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
    ];

    await db.insert(encryptionAlgorithms).values(algorithms);
  }

  async getRecommendedAlgorithms(applicationConfig: {
    applicationType?: string;
    securityLevel?: string;
    complianceRequirements?: string[];
    deploymentEnvironment?: string;
  }): Promise<EncryptionAlgorithm[]> {
    // Ensure algorithms are seeded
    await this.getEncryptionAlgorithms();
    
    const { applicationType, securityLevel, complianceRequirements = [], deploymentEnvironment } = applicationConfig;
    
    // Get all algorithms first
    const allAlgorithms = await db
      .select()
      .from(encryptionAlgorithms)
      .where(eq(encryptionAlgorithms.isActive, true));
    
    // Smart recommendation logic based on application requirements
    const recommended: EncryptionAlgorithm[] = [];
    
    // Post-quantum requirements (high priority)
    if (complianceRequirements.includes('quantum-safe') || 
        securityLevel === 'maximum' ||
        applicationType === 'government' ||
        applicationType === 'defense') {
      recommended.push(...allAlgorithms.filter(a => a.isPostQuantum));
    }
    
    // High-performance requirements
    if (applicationType === 'gaming' || 
        applicationType === 'streaming' ||
        deploymentEnvironment === 'mobile' ||
        deploymentEnvironment === 'iot') {
      recommended.push(...allAlgorithms.filter(a => 
        a.name === 'ChaCha20-Poly1305' || 
        a.name === 'AES-128-GCM' ||
        a.name === 'BLAKE3'
      ));
    }
    
    // Enterprise/Financial requirements
    if (applicationType === 'financial' || 
        applicationType === 'healthcare' ||
        complianceRequirements.includes('fips-140-2') ||
        complianceRequirements.includes('common-criteria') ||
        securityLevel === 'high') {
      recommended.push(...allAlgorithms.filter(a => 
        a.name === 'AES-256-GCM' || 
        a.name === 'RSA-4096' ||
        a.name === 'ECDSA-P384' ||
        a.name === 'SHA-3-256'
      ));
    }
    
    // Standard business applications
    if (applicationType === 'web-application' || 
        applicationType === 'e-commerce' ||
        applicationType === 'saas' ||
        securityLevel === 'standard') {
      recommended.push(...allAlgorithms.filter(a => 
        a.name === 'AES-256-GCM' || 
        a.name === 'RSA-2048' ||
        a.name === 'ECDSA-P256' ||
        a.name === 'SHA-256'
      ));
    }
    
    // Remove duplicates and ensure we have at least basic recommendations
    const uniqueRecommended = Array.from(
      new Map(recommended.map(alg => [alg.id, alg])).values()
    );
    
    // If no specific recommendations, provide balanced defaults
    if (uniqueRecommended.length === 0) {
      uniqueRecommended.push(
        ...allAlgorithms.filter(a => 
          a.name === 'AES-256-GCM' || 
          a.name === 'RSA-2048' ||
          a.name === 'SHA-256'
        )
      );
    }
    
    return uniqueRecommended.slice(0, 6); // Limit to top 6 recommendations
  }

  async getEncryptionAlgorithm(id: string): Promise<EncryptionAlgorithm | undefined> {
    const [algorithm] = await db
      .select()
      .from(encryptionAlgorithms)
      .where(eq(encryptionAlgorithms.id, id));
    return algorithm;
  }

  // Key management operations
  async getEncryptionKeys(tenantId: string): Promise<EncryptionKey[]> {
    return await db
      .select()
      .from(encryptionKeys)
      .where(eq(encryptionKeys.tenantId, tenantId))
      .orderBy(desc(encryptionKeys.createdAt));
  }

  async createEncryptionKey(keyData: InsertEncryptionKey): Promise<EncryptionKey> {
    const [key] = await db
      .insert(encryptionKeys)
      .values({
        ...keyData,
        keyId: `key_${randomUUID().replace(/-/g, '').substring(0, 12)}`,
      })
      .returning();
    return key;
  }

  async updateEncryptionKeyStatus(keyId: string, status: string): Promise<void> {
    await db
      .update(encryptionKeys)
      .set({ status: status as any, updatedAt: new Date() })
      .where(eq(encryptionKeys.id, keyId));
  }

  // Security monitoring operations
  async getSecurityEvents(tenantId: string, limit = 50): Promise<SecurityEvent[]> {
    return await db
      .select()
      .from(securityEvents)
      .where(eq(securityEvents.tenantId, tenantId))
      .orderBy(desc(securityEvents.createdAt))
      .limit(limit);
  }

  async createSecurityEvent(eventData: InsertSecurityEvent): Promise<SecurityEvent> {
    const [event] = await db.insert(securityEvents).values(eventData).returning();
    return event;
  }

  // API usage operations
  async getApiUsage(tenantId: string, days = 30): Promise<ApiUsage[]> {
    const since = new Date();
    since.setDate(since.getDate() - days);
    
    return await db
      .select()
      .from(apiUsage)
      .where(and(
        eq(apiUsage.tenantId, tenantId),
        eq(apiUsage.date, since)
      ))
      .orderBy(desc(apiUsage.date));
  }

  async recordApiUsage(usageData: InsertApiUsage): Promise<ApiUsage> {
    const [usage] = await db.insert(apiUsage).values(usageData).returning();
    return usage;
  }

  // Dashboard statistics
  async getDashboardStats(tenantId: string): Promise<{
    activeSDKs: number;
    encryptedRequests: number;
    keyRotations: number;
    threatBlocks: number;
  }> {
    // Get active SDKs count
    const [activeSDKsResult] = await db
      .select({ count: count() })
      .from(sdks)
      .where(and(eq(sdks.tenantId, tenantId), eq(sdks.isActive, true)));

    // Get recent usage stats (last 30 days)
    const [usageResult] = await db
      .select({
        encryptedRequests: sum(apiUsage.encryptionRequests),
        keyRotations: sum(apiUsage.keyRotations),
        threatBlocks: sum(apiUsage.threatsBlocked),
      })
      .from(apiUsage)
      .where(eq(apiUsage.tenantId, tenantId));

    return {
      activeSDKs: activeSDKsResult?.count || 0,
      encryptedRequests: Number(usageResult?.encryptedRequests) || 0,
      keyRotations: Number(usageResult?.keyRotations) || 0,
      threatBlocks: Number(usageResult?.threatBlocks) || 0,
    };
  }

  // User management
  async getTenantUsers(tenantId: string): Promise<User[]> {
    return await db
      .select()
      .from(users)
      .where(eq(users.tenantId, tenantId))
      .orderBy(desc(users.createdAt));
  }

  async updateUserRole(userId: string, role: string): Promise<void> {
    await db
      .update(users)
      .set({ role: role as any, updatedAt: new Date() })
      .where(eq(users.id, userId));
  }
}

export const storage = new DatabaseStorage();
