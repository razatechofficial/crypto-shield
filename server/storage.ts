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
  getSDKs(tenantId: string): Promise<Sdk[]>;
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
  async getSDKs(tenantId: string): Promise<Sdk[]> {
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

  // Seed encryption algorithms
  private async seedEncryptionAlgorithms(): Promise<void> {
    const algorithms = [
      // Symmetric algorithms
      {
        name: 'AES-256-GCM',
        displayName: 'AES-256-GCM',
        description: 'Advanced Encryption Standard with 256-bit key and Galois Counter Mode. Industry standard for symmetric encryption.',
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
      {
        name: 'ChaCha20-Poly1305',
        displayName: 'ChaCha20-Poly1305',
        description: 'High-speed stream cipher with authenticated encryption. Excellent for mobile and embedded devices.',
        type: 'symmetric' as const,
        keySize: 256,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // Asymmetric algorithms
      {
        name: 'RSA-2048',
        displayName: 'RSA-2048',
        description: 'RSA with 2048-bit key. Widely supported for digital signatures and key exchange.',
        type: 'asymmetric' as const,
        keySize: 2048,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'RSA-4096',
        displayName: 'RSA-4096',
        description: 'RSA with 4096-bit key. Higher security level for sensitive applications.',
        type: 'asymmetric' as const,
        keySize: 4096,
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
        name: 'ECDSA-P384',
        displayName: 'ECDSA P-384',
        description: 'Elliptic Curve Digital Signature Algorithm with P-384 curve. Higher security for enterprise use.',
        type: 'asymmetric' as const,
        keySize: 384,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // Hash algorithms
      {
        name: 'SHA-256',
        displayName: 'SHA-256',
        description: 'Secure Hash Algorithm 256-bit. Standard for data integrity verification.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'SHA-3-256',
        displayName: 'SHA-3-256',
        description: 'Third-generation Secure Hash Algorithm. Latest NIST standard with enhanced security.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      {
        name: 'BLAKE3',
        displayName: 'BLAKE3',
        description: 'High-performance cryptographic hash function. Faster than SHA-2 with better security properties.',
        type: 'hash' as const,
        keySize: null,
        isQuantumSafe: false,
        isPostQuantum: false,
        isActive: true,
      },
      
      // Post-quantum algorithms
      {
        name: 'Kyber-768',
        displayName: 'CRYSTALS-Kyber-768',
        description: 'Post-quantum key encapsulation mechanism. NIST-selected standard for quantum-resistant encryption.',
        type: 'post_quantum' as const,
        keySize: 768,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'Dilithium-3',
        displayName: 'CRYSTALS-Dilithium-3',
        description: 'Post-quantum digital signature scheme. NIST-selected standard for quantum-resistant signatures.',
        type: 'post_quantum' as const,
        keySize: null,
        isQuantumSafe: true,
        isPostQuantum: true,
        isActive: true,
      },
      {
        name: 'SPHINCS-SHA256-128s',
        displayName: 'SPHINCS+ SHA-256-128s',
        description: 'Stateless hash-based signature scheme. Conservative post-quantum option with proven security.',
        type: 'post_quantum' as const,
        keySize: 128,
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
      .where(eq(encryptionKeys.keyId, keyId));
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
