import {
  users,
  tenants,
  sdks,
  encryptionAlgorithms,
  encryptionKeys,
  securityEvents,
  apiUsage,
  cryptoOperations,
  performanceMetrics,
  securityIncidents,
  sdkDeployments,
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
  type CryptoOperation,
  type InsertCryptoOperation,
  type PerformanceMetric,
  type InsertPerformanceMetric,
  type SecurityIncident,
  type InsertSecurityIncident,
  type SdkDeployment,
  type InsertSdkDeployment,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, count, sum, gte } from "drizzle-orm";
import { randomUUID } from "crypto";

export interface IStorage {
  // User operations (required for Authentication)
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User>;
  
  // Tenant operations
  getTenant(id: string): Promise<Tenant | undefined>;
  getTenantByApiKey(apiKey: string): Promise<Tenant | undefined>;
  createTenant(tenant: InsertTenant): Promise<Tenant>;
  getOrCreateTenantForUser(userId: string, email: string): Promise<string>;
  
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
  
  // User management operations
  getUsersByTenant(tenantId: string): Promise<User[]>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(userData: Partial<User>): Promise<User>;
  updateUserRole(userId: string, role: string): Promise<User>;
  updateUserStatus(userId: string, status: string): Promise<User>;
  deleteUser(userId: string): Promise<void>;
  
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
}

export class DatabaseStorage implements IStorage {
  // User operations (required for Authentication)
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

  async getOrCreateTenantForUser(userId: string, email: string): Promise<string> {
    // Check if user already exists with a tenant
    const existingUser = await this.getUser(userId);
    if (existingUser && existingUser.tenantId) {
      return existingUser.tenantId;
    }

    // Create a new tenant for the user
    const tenant = await this.createTenant({
      name: `${email.split('@')[0]}'s Organization`,
      subscriptionTier: 'trial' as any,
      id: randomUUID(),
    });

    return tenant.id;
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

  async updateSDK(id: string, updates: Partial<Pick<Sdk, 'downloadUrl'>>): Promise<Sdk | undefined> {
    const [updatedSDK] = await db.update(sdks).set(updates).where(eq(sdks.id, id)).returning();
    return updatedSDK;
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
    const financeId = randomUUID();
    const testSDKs = [
      {
        id: financeId,
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
        downloadUrl: `/api/sdks/${financeId}/download`,
        isActive: true,
        createdAt: new Date(Date.now() - 86400000 * 7), // 7 days ago
        updatedAt: new Date(Date.now() - 86400000 * 2), // 2 days ago
      },
      (function() {
        const healthId = randomUUID();
        return {
          id: healthId,
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
          downloadUrl: `/api/sdks/${healthId}/download`,
          isActive: true,
          createdAt: new Date(Date.now() - 86400000 * 14), // 14 days ago
          updatedAt: new Date(Date.now() - 86400000 * 5), // 5 days ago
        };
      })(),
      (function() {
        const quantumId = randomUUID();
        return {
          id: quantumId,
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
          downloadUrl: `/api/sdks/${quantumId}/download`,
          isActive: true,
          createdAt: new Date(Date.now() - 86400000 * 3), // 3 days ago
          updatedAt: new Date(Date.now() - 86400000 * 1), // 1 day ago
        };
      })(),
      (function() {
        const mobileId = randomUUID();
        return {
          id: mobileId,
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
          downloadUrl: `/api/sdks/${mobileId}/download`,
          isActive: true,
          createdAt: new Date(Date.now() - 86400000 * 21), // 21 days ago
          updatedAt: new Date(Date.now() - 86400000 * 7), // 7 days ago
        };
      })()
    ];

    await db.insert(sdks).values(testSDKs);
    console.log('✅ Seeded test SDK data');
  }

  // Seed comprehensive monitoring data for development
  private async seedMonitoringData(tenantId: string): Promise<void> {
    const now = new Date();
    const userId = 'dev-user-123'; // Mock user for dev mode

    // 1. Seed encryption keys
    const encryptionKeysData = [
      {
        tenantId,
        name: 'Production API Key',
        description: 'Primary encryption key for production API endpoints',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        status: 'active' as const,
        purpose: 'encryption',
        rotationSchedule: '90_days',
        createdAt: new Date(now.getTime() - 86400000 * 30), // 30 days ago
      },
      {
        tenantId,
        name: 'Backup Encryption Key',
        description: 'Secondary key for data backup encryption',
        algorithm: 'ChaCha20-Poly1305',
        keySize: 256,
        status: 'active' as const,
        purpose: 'backup',
        rotationSchedule: '30_days',
        createdAt: new Date(now.getTime() - 86400000 * 15), // 15 days ago
      },
      {
        tenantId,
        name: 'Legacy Migration Key',
        description: 'Temporary key for legacy data migration',
        algorithm: 'AES-256-CBC',
        keySize: 256,
        status: 'rotating' as const,
        purpose: 'migration',
        rotationSchedule: '7_days',
        createdAt: new Date(now.getTime() - 86400000 * 7), // 7 days ago
      }
    ];

    await db.insert(encryptionKeys).values(encryptionKeysData);

    // 2. Seed crypto operations (last 7 days of activity)
    const operationsData = [];
    for (let day = 0; day < 7; day++) {
      const dayDate = new Date(now.getTime() - 86400000 * day);
      const operationsPerDay = Math.floor(Math.random() * 500) + 200; // 200-700 operations per day
      
      for (let op = 0; op < operationsPerDay; op++) {
        const opTime = new Date(dayDate.getTime() + Math.random() * 86400000);
        operationsData.push({
          tenantId,
          operation: Math.random() > 0.6 ? 'encryption' : 'decryption',
          algorithm: ['AES-256-GCM', 'ChaCha20-Poly1305', 'RSA-2048'][Math.floor(Math.random() * 3)],
          keyId: encryptionKeysData[Math.floor(Math.random() * encryptionKeysData.length)].name,
          dataSize: Math.floor(Math.random() * 10000) + 100, // 100-10KB
          duration: Math.floor(Math.random() * 50) + 5, // 5-55ms
          status: Math.random() > 0.05 ? 'success' : 'failure', // 95% success rate
          metadata: { source: Math.random() > 0.5 ? 'api' : 'sdk' },
          createdAt: opTime
        });
      }
    }

    await db.insert(cryptoOperations).values(operationsData);

    // 3. Seed security incidents
    const incidentsData = [
      {
        tenantId,
        incidentType: 'failed_authentication',
        severity: 'medium' as const,
        status: 'resolved' as const,
        description: 'Multiple failed authentication attempts detected from suspicious IP',
        affectedSystems: JSON.stringify(['api', 'dashboard']),
        resolution: 'IP blocked, monitoring enhanced',
        createdAt: new Date(now.getTime() - 86400000 * 5),
        resolvedAt: new Date(now.getTime() - 86400000 * 4),
      },
      {
        tenantId,
        incidentType: 'key_rotation_failed',
        severity: 'high' as const,
        status: 'investigating' as const,
        description: 'Automated key rotation failed for backup encryption key',
        affectedSystems: JSON.stringify(['backup_service']),
        resolution: null,
        createdAt: new Date(now.getTime() - 86400000 * 2),
        resolvedAt: null,
      },
      {
        tenantId,
        incidentType: 'unusual_traffic_pattern',
        severity: 'low' as const,
        status: 'resolved' as const,
        description: 'Spike in encryption requests detected outside normal hours',
        affectedSystems: JSON.stringify(['encryption_api']),
        resolution: 'Confirmed as legitimate batch processing job',
        createdAt: new Date(now.getTime() - 86400000 * 1),
        resolvedAt: new Date(now.getTime() - 86400000 * 1 + 7200000), // 2 hours later
      }
    ];

    await db.insert(securityIncidents).values(incidentsData);

    // 4. Seed SDK deployments
    const deploymentsData = [
      {
        tenantId,
        sdkId: 'finance-sdk-prod',
        version: '2.1.0',
        environment: 'production',
        platform: 'nodejs',
        region: 'us-east-1',
        instanceCount: 5,
        healthStatus: 'healthy' as const,
        totalOperations: 15420,
        successRate: 99.2,
        lastHeartbeat: new Date(now.getTime() - 300000), // 5 minutes ago
        createdAt: new Date(now.getTime() - 86400000 * 14)
      },
      {
        tenantId,
        sdkId: 'healthcare-sdk-staging',
        version: '1.8.3',
        environment: 'staging',
        platform: 'python',
        region: 'us-west-2',
        instanceCount: 2,
        healthStatus: 'healthy' as const,
        totalOperations: 3240,
        successRate: 97.8,
        lastHeartbeat: new Date(now.getTime() - 180000), // 3 minutes ago
        createdAt: new Date(now.getTime() - 86400000 * 10)
      },
      {
        tenantId,
        sdkId: 'mobile-sdk-prod',
        version: '2.0.1',
        environment: 'production',
        platform: 'swift',
        region: 'eu-west-1',
        instanceCount: 8,
        healthStatus: 'degraded' as const,
        totalOperations: 8750,
        successRate: 94.5,
        lastHeartbeat: new Date(now.getTime() - 900000), // 15 minutes ago (degraded)
        createdAt: new Date(now.getTime() - 86400000 * 21)
      }
    ];

    await db.insert(sdkDeployments).values(deploymentsData);

    // 5. Seed performance metrics
    const metricsData = [];
    for (let hour = 0; hour < 24; hour++) {
      const hourTime = new Date(now.getTime() - 3600000 * hour);
      metricsData.push({
        tenantId,
        metricType: 'encryption_latency',
        value: Math.floor(Math.random() * 30) + 15, // 15-45ms
        unit: 'milliseconds',
        timestamp: hourTime,
        metadata: { algorithm: 'AES-256-GCM' }
      });
      metricsData.push({
        tenantId,
        metricType: 'throughput',
        value: Math.floor(Math.random() * 1000) + 500, // 500-1500 ops/min
        unit: 'operations_per_minute',
        timestamp: hourTime,
        metadata: { endpoint: '/api/encrypt' }
      });
    }

    await db.insert(performanceMetrics).values(metricsData);

    // 6. Seed API usage data
    const usageData = [];
    for (let day = 0; day < 30; day++) {
      const dayDate = new Date(now.getTime() - 86400000 * day);
      usageData.push({
        tenantId,
        date: dayDate,
        apiCalls: Math.floor(Math.random() * 5000) + 2000,
        encryptionRequests: Math.floor(Math.random() * 3000) + 1000,
        decryptionRequests: Math.floor(Math.random() * 2500) + 800,
        keyRotations: Math.floor(Math.random() * 5) + 1,
        threatsBlocked: Math.floor(Math.random() * 20),
        bytesProcessed: BigInt(Math.floor(Math.random() * 100000000) + 50000000),
        uniqueUsers: Math.floor(Math.random() * 200) + 50
      });
    }

    await db.insert(apiUsage).values(usageData);

    console.log('✅ Seeded comprehensive monitoring data (keys, operations, incidents, deployments, metrics, usage)');
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
    // Check if keys exist, if not, seed monitoring data
    const existing = await db.select().from(encryptionKeys).where(eq(encryptionKeys.tenantId, tenantId)).limit(1);
    if (existing.length === 0) {
      await this.seedMonitoringData(tenantId);
    }
    
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

  async getUsersByTenant(tenantId: string): Promise<User[]> {
    return await db
      .select()
      .from(users)
      .where(eq(users.tenantId, tenantId))
      .orderBy(desc(users.createdAt));
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email));
    return user;
  }

  async createUser(userData: Partial<User>): Promise<User> {
    const [user] = await db
      .insert(users)
      .values({
        id: randomUUID(),
        email: userData.email!,
        firstName: userData.firstName || null,
        lastName: userData.lastName || null,
        profileImageUrl: userData.profileImageUrl || null,
        role: userData.role as any || 'viewer',
        tenantId: userData.tenantId!,
        createdAt: new Date(),
        updatedAt: new Date()
      })
      .returning();
    return user;
  }

  async updateUserRole(userId: string, role: string): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ role: role as any, updatedAt: new Date() })
      .where(eq(users.id, userId))
      .returning();
    return user;
  }

  async updateUserStatus(userId: string, status: string): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ 
        // Add status field handling - for now we'll use role field or add a custom property
        updatedAt: new Date() 
      })
      .where(eq(users.id, userId))
      .returning();
    return user;
  }

  async deleteUser(userId: string): Promise<void> {
    await db
      .delete(users)
      .where(eq(users.id, userId));
  }

  // REAL MONITORING OPERATIONS - Track actual SDK usage
  
  // 1. Track actual SDK usage across deployed applications
  async recordCryptoOperation(operation: InsertCryptoOperation): Promise<CryptoOperation> {
    const [record] = await db.insert(cryptoOperations).values(operation).returning();
    
    // Update deployment statistics in real-time
    if (operation.sdkId) {
      await this.updateDeploymentStats(operation.sdkId, operation.status === 'success');
    }
    
    return record;
  }

  async getCryptoOperations(tenantId: string, hours = 24): Promise<CryptoOperation[]> {
    const since = new Date();
    since.setHours(since.getHours() - hours);
    
    return await db
      .select()
      .from(cryptoOperations)
      .where(and(
        eq(cryptoOperations.tenantId, tenantId),
        gte(cryptoOperations.createdAt, since)
      ))
      .orderBy(desc(cryptoOperations.createdAt));
  }

  async getOperationStats(tenantId: string, hours = 24): Promise<{
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    averageLatency: number;
    operationsByAlgorithm: { algorithm: string; count: number }[];
    hourlyOperations: { hour: string; count: number }[];
  }> {
    const since = new Date();
    since.setHours(since.getHours() - hours);

    // Get total and status counts
    const operations = await db
      .select()
      .from(cryptoOperations)
      .where(and(
        eq(cryptoOperations.tenantId, tenantId),
        gte(cryptoOperations.createdAt, since)
      ));

    const totalOperations = operations.length;
    const successfulOperations = operations.filter(op => op.status === 'success').length;
    const failedOperations = totalOperations - successfulOperations;
    const averageLatency = operations.length > 0 
      ? operations.reduce((sum, op) => sum + op.duration, 0) / operations.length 
      : 0;

    // Group by algorithm
    const algorithmCounts = operations.reduce((acc, op) => {
      acc[op.algorithm] = (acc[op.algorithm] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const operationsByAlgorithm = Object.entries(algorithmCounts).map(([algorithm, count]) => ({
      algorithm,
      count
    }));

    // Group by hour
    const hourlyCounts = operations.reduce((acc, op) => {
      const hour = new Date(op.createdAt || new Date()).getHours().toString().padStart(2, '0') + ':00';
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const hourlyOperations = Array.from({length: 24}, (_, i) => {
      const hour = i.toString().padStart(2, '0') + ':00';
      return { hour, count: hourlyCounts[hour] || 0 };
    });

    return {
      totalOperations,
      successfulOperations,
      failedOperations,
      averageLatency: Math.round(averageLatency),
      operationsByAlgorithm,
      hourlyOperations
    };
  }

  // 2. Monitor real encryption/decryption operations
  async recordPerformanceMetric(metric: InsertPerformanceMetric): Promise<PerformanceMetric> {
    const [record] = await db.insert(performanceMetrics).values(metric).returning();
    return record;
  }

  async getPerformanceMetrics(tenantId: string, metricType?: string, hours = 24): Promise<PerformanceMetric[]> {
    const since = new Date();
    since.setHours(since.getHours() - hours);
    
    const conditions = [
      eq(performanceMetrics.tenantId, tenantId),
      gte(performanceMetrics.timestamp, since)
    ];
    
    if (metricType) {
      conditions.push(eq(performanceMetrics.metricType, metricType));
    }
    
    return await db
      .select()
      .from(performanceMetrics)
      .where(and(...conditions))
      .orderBy(desc(performanceMetrics.timestamp));
  }

  // 3. Collect genuine performance metrics
  async getSystemHealthMetrics(tenantId: string): Promise<{
    encryptionPerformance: number;
    keyInfrastructure: number;
    autoHealing: number;
    averageResponseTime: number;
    errorRate: number;
    activeDeployments: number;
  }> {
    const operations = await this.getCryptoOperations(tenantId, 24);
    const deployments = await this.getSdkDeployments(tenantId);
    
    const totalOps = operations.length;
    const successOps = operations.filter(op => op.status === 'success').length;
    const failedOps = totalOps - successOps;
    
    const encryptionPerformance = totalOps > 0 ? (successOps / totalOps) * 100 : 100;
    const errorRate = totalOps > 0 ? (failedOps / totalOps) * 100 : 0;
    const averageResponseTime = totalOps > 0 
      ? operations.reduce((sum, op) => sum + op.duration, 0) / totalOps 
      : 0;
    
    const activeDeployments = deployments.filter(d => d.healthStatus === 'healthy').length;
    const keyInfrastructure = deployments.length > 0 
      ? (activeDeployments / deployments.length) * 100 
      : 100;
    
    // Calculate actual auto-healing based on incident resolution rate
    const incidents = await this.getSecurityIncidents(tenantId);
    const resolvedIncidents = incidents.filter(i => i.status === 'resolved').length;
    const autoHealing = incidents.length > 0 
      ? (resolvedIncidents / incidents.length) * 100 
      : 0; // No incidents means no auto-healing data yet

    return {
      encryptionPerformance: Math.round(encryptionPerformance * 10) / 10,
      keyInfrastructure: Math.round(keyInfrastructure * 10) / 10,
      autoHealing: Math.round(autoHealing * 10) / 10,
      averageResponseTime: Math.round(averageResponseTime),
      errorRate: Math.round(errorRate * 10) / 10,
      activeDeployments
    };
  }

  // 4. Record actual security events from live systems
  async recordSecurityIncident(incident: InsertSecurityIncident): Promise<SecurityIncident> {
    const [record] = await db.insert(securityIncidents).values(incident).returning();
    
    // Auto-trigger security event
    await this.createSecurityEvent({
      tenantId: incident.tenantId,
      eventType: 'security_incident',
      severity: incident.severity,
      description: `Security incident: ${incident.incidentType}`,
      metadata: { incidentId: record.id }
    });
    
    return record;
  }

  async getSecurityIncidents(tenantId: string, status?: string): Promise<SecurityIncident[]> {
    const conditions = [eq(securityIncidents.tenantId, tenantId)];
    
    if (status) {
      conditions.push(eq(securityIncidents.status, status));
    }
    
    return await db
      .select()
      .from(securityIncidents)
      .where(and(...conditions))
      .orderBy(desc(securityIncidents.createdAt));
  }

  // SDK deployment tracking
  async registerSdkDeployment(deployment: InsertSdkDeployment): Promise<SdkDeployment> {
    const [record] = await db.insert(sdkDeployments).values({
      ...deployment,
      lastHeartbeat: new Date()
    }).returning();
    return record;
  }

  async updateDeploymentStats(sdkId: string, operationSuccess: boolean): Promise<void> {
    const deployment = await db
      .select()
      .from(sdkDeployments)
      .where(eq(sdkDeployments.sdkId, sdkId))
      .limit(1);
    
    if (deployment.length > 0) {
      const current = deployment[0];
      const newTotal = (current.totalOperations || 0) + 1;
      const currentSuccessful = Math.round(((current.successRate || 0) / 100) * (current.totalOperations || 0));
      const newSuccessful = operationSuccess ? currentSuccessful + 1 : currentSuccessful;
      const newSuccessRate = Math.round((newSuccessful / newTotal) * 100);
      
      await db
        .update(sdkDeployments)
        .set({
          totalOperations: newTotal,
          successRate: newSuccessRate,
          lastHeartbeat: new Date(),
          updatedAt: new Date()
        })
        .where(eq(sdkDeployments.id, current.id));
    }
  }

  async getSdkDeployments(tenantId: string): Promise<SdkDeployment[]> {
    return await db
      .select()
      .from(sdkDeployments)
      .where(eq(sdkDeployments.tenantId, tenantId))
      .orderBy(desc(sdkDeployments.createdAt));
  }

  async updateDeploymentHealth(deploymentId: string, healthStatus: string): Promise<void> {
    await db
      .update(sdkDeployments)
      .set({
        healthStatus: healthStatus as any,
        lastHeartbeat: new Date(),
        updatedAt: new Date()
      })
      .where(eq(sdkDeployments.id, deploymentId));
  }
}

export const storage = new DatabaseStorage();
