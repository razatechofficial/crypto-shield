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
  
  // Tenant operations
  getTenant(id: string): Promise<Tenant | undefined>;
  getTenantByApiKey(apiKey: string): Promise<Tenant | undefined>;
  createTenant(tenant: InsertTenant): Promise<Tenant>;
  
  // SDK operations
  getSDKs(tenantId: string): Promise<Sdk[]>;
  createSDK(sdk: InsertSdk): Promise<Sdk>;
  getSDK(id: string): Promise<Sdk | undefined>;
  
  // Algorithm operations
  getEncryptionAlgorithms(): Promise<EncryptionAlgorithm[]>;
  getEncryptionAlgorithm(id: string): Promise<EncryptionAlgorithm | undefined>;
  
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
    const [tenant] = await db
      .insert(tenants)
      .values({
        ...tenantData,
        apiKey: `ak_${randomUUID().replace(/-/g, '')}`,
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

  // Algorithm operations
  async getEncryptionAlgorithms(): Promise<EncryptionAlgorithm[]> {
    return await db
      .select()
      .from(encryptionAlgorithms)
      .where(eq(encryptionAlgorithms.isActive, true))
      .orderBy(encryptionAlgorithms.name);
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
