import { sql } from 'drizzle-orm';
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  integer,
  boolean,
  pgEnum,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from 'drizzle-orm';

// Session storage table for Replit Auth
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User roles enum
export const userRoleEnum = pgEnum('user_role', ['admin', 'developer', 'viewer']);

// Subscription tiers enum
export const subscriptionTierEnum = pgEnum('subscription_tier', ['starter', 'professional', 'enterprise']);

// Algorithm types enum
export const algorithmTypeEnum = pgEnum('algorithm_type', ['symmetric', 'asymmetric', 'hash', 'post_quantum', 'tee', 'homomorphic', 'mpc', 'zero_knowledge']);

// Key status enum
export const keyStatusEnum = pgEnum('key_status', ['active', 'rotating', 'revoked', 'expired']);

// SDK language enum
export const sdkLanguageEnum = pgEnum('sdk_language', ['javascript', 'python', 'java', 'csharp', 'go', 'rust', 'dart', 'swift', 'kotlin', 'php', 'ruby', 'cpp']);

// Security levels enum
export const securityLevelEnum = pgEnum('security_level', ['standard', 'enhanced', 'maximum', 'confidential', 'privacy_preserving']);

// Confidential computing features enum
export const confidentialFeatureEnum = pgEnum('confidential_feature', ['teeEncryption', 'homomorphicEncryption', 'multiPartyComputation', 'zeroKnowledgeProofs', 'differentialPrivacy', 'secureAggregation']);

// User storage table for Replit Auth
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  role: userRoleEnum("role").default('developer'),
  tenantId: varchar("tenant_id").references(() => tenants.id),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Tenants table for multi-tenancy
export const tenants = pgTable("tenants", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  domain: varchar("domain"),
  subscriptionTier: subscriptionTierEnum("subscription_tier").default('starter'),
  apiKey: varchar("api_key").unique().notNull(),
  settings: jsonb("settings").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Encryption algorithms table
export const encryptionAlgorithms = pgTable("encryption_algorithms", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull().unique(),
  displayName: varchar("display_name").notNull(),
  description: text("description"),
  type: algorithmTypeEnum("type").notNull(),
  keySize: integer("key_size"),
  isQuantumSafe: boolean("is_quantum_safe").default(false),
  isPostQuantum: boolean("is_post_quantum").default(false),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

// Generated SDKs table
export const sdks = pgTable("sdks", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  userId: varchar("user_id").references(() => users.id).notNull(),
  name: varchar("name").notNull(),
  languages: text("languages").notNull(), // JSON array of supported languages
  algorithms: text("algorithms").notNull(), // JSON array of algorithm IDs
  applicationType: varchar("application_type"),
  deploymentEnvironment: varchar("deployment_environment"),
  securityLevel: securityLevelEnum("security_level"),
  dataTypes: text("data_types"), // JSON array
  complianceRequirements: text("compliance_requirements"), // JSON array
  confidentialFeatures: text("confidential_features"), // JSON array of confidential computing features
  configuration: jsonb("configuration").notNull().default({}),
  features: jsonb("features").notNull().default({}),
  downloadUrl: varchar("download_url"),
  version: varchar("version").default('2.0.0'),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Encryption keys table
export const encryptionKeys = pgTable("encryption_keys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  keyId: varchar("key_id").notNull().unique(),
  keyType: varchar("key_type").notNull(), // 'primary', 'session', 'backup'
  algorithmId: varchar("algorithm_id").references(() => encryptionAlgorithms.id).notNull(),
  status: keyStatusEnum("status").default('active'),
  expiresAt: timestamp("expires_at"),
  rotationInterval: integer("rotation_interval").default(30), // days
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Security events table for monitoring
export const securityEvents = pgTable("security_events", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  eventType: varchar("event_type").notNull(), // 'threat_detected', 'key_rotated', 'unauthorized_access'
  severity: varchar("severity").notNull(), // 'low', 'medium', 'high', 'critical'
  source: varchar("source"), // IP address or service
  description: text("description"),
  metadata: jsonb("metadata").default({}),
  isResolved: boolean("is_resolved").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

// API usage statistics
export const apiUsage = pgTable("api_usage", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  date: timestamp("date").notNull(),
  encryptionRequests: integer("encryption_requests").default(0),
  decryptionRequests: integer("decryption_requests").default(0),
  keyRotations: integer("key_rotations").default(0),
  threatsBlocked: integer("threats_blocked").default(0),
  createdAt: timestamp("created_at").defaultNow(),
});

// Relations
export const tenantRelations = relations(tenants, ({ many }) => ({
  users: many(users),
  sdks: many(sdks),
  encryptionKeys: many(encryptionKeys),
  securityEvents: many(securityEvents),
  apiUsage: many(apiUsage),
}));

export const userRelations = relations(users, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [users.tenantId],
    references: [tenants.id],
  }),
  sdks: many(sdks),
}));

export const sdkRelations = relations(sdks, ({ one }) => ({
  tenant: one(tenants, {
    fields: [sdks.tenantId],
    references: [tenants.id],
  }),
  user: one(users, {
    fields: [sdks.userId],
    references: [users.id],
  }),
}));

export const encryptionKeyRelations = relations(encryptionKeys, ({ one }) => ({
  tenant: one(tenants, {
    fields: [encryptionKeys.tenantId],
    references: [tenants.id],
  }),
  algorithm: one(encryptionAlgorithms, {
    fields: [encryptionKeys.algorithmId],
    references: [encryptionAlgorithms.id],
  }),
}));

export const securityEventRelations = relations(securityEvents, ({ one }) => ({
  tenant: one(tenants, {
    fields: [securityEvents.tenantId],
    references: [tenants.id],
  }),
}));

export const apiUsageRelations = relations(apiUsage, ({ one }) => ({
  tenant: one(tenants, {
    fields: [apiUsage.tenantId],
    references: [tenants.id],
  }),
}));

// Insert schemas
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertTenantSchema = createInsertSchema(tenants).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertSdkSchema = createInsertSchema(sdks).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
}).extend({
  // Transform array fields to JSON strings for database storage
  languages: z.array(z.string()).transform((val) => JSON.stringify(val)),
  algorithms: z.array(z.string()).transform((val) => JSON.stringify(val)),
  dataTypes: z.array(z.string()).optional().transform((val) => val ? JSON.stringify(val) : null),
  complianceRequirements: z.array(z.string()).optional().transform((val) => val ? JSON.stringify(val) : null),
  confidentialFeatures: z.array(z.string()).optional().transform((val) => val ? JSON.stringify(val) : null),
});

export const insertEncryptionKeySchema = createInsertSchema(encryptionKeys).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertSecurityEventSchema = createInsertSchema(securityEvents).omit({
  id: true,
  createdAt: true,
});

export const insertApiUsageSchema = createInsertSchema(apiUsage).omit({
  id: true,
  createdAt: true,
});

// Types
export type UpsertUser = typeof users.$inferInsert;
export type User = typeof users.$inferSelect;
export type Tenant = typeof tenants.$inferSelect;
export type InsertTenant = z.infer<typeof insertTenantSchema>;
export type Sdk = typeof sdks.$inferSelect;
export type InsertSdk = z.infer<typeof insertSdkSchema>;
export type EncryptionAlgorithm = typeof encryptionAlgorithms.$inferSelect;
export type EncryptionKey = typeof encryptionKeys.$inferSelect;
export type InsertEncryptionKey = z.infer<typeof insertEncryptionKeySchema>;
export type SecurityEvent = typeof securityEvents.$inferSelect;
export type InsertSecurityEvent = z.infer<typeof insertSecurityEventSchema>;
export type ApiUsage = typeof apiUsage.$inferSelect;
export type InsertApiUsage = z.infer<typeof insertApiUsageSchema>;

// Real-time monitoring tables
export const cryptoOperations = pgTable("crypto_operations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  sdkId: varchar("sdk_id").references(() => sdks.id),
  operation: varchar("operation").notNull(), // encrypt, decrypt, sign, verify
  algorithm: varchar("algorithm").notNull(),
  keyId: varchar("key_id").references(() => encryptionKeys.id),
  status: varchar("status").notNull(), // success, failure, timeout
  duration: integer("duration").notNull(), // milliseconds
  dataSize: integer("data_size"), // bytes processed
  clientId: varchar("client_id"), // SDK instance identifier
  ipAddress: varchar("ip_address"),
  userAgent: varchar("user_agent"),
  errorCode: varchar("error_code"),
  errorMessage: text("error_message"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
});

export const performanceMetrics = pgTable("performance_metrics", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  sdkId: varchar("sdk_id").references(() => sdks.id),
  metricType: varchar("metric_type").notNull(), // throughput, latency, cpu_usage, memory_usage
  value: integer("value").notNull(),
  unit: varchar("unit").notNull(), // ops/sec, ms, %, mb
  timestamp: timestamp("timestamp").defaultNow(),
  metadata: jsonb("metadata").default({}),
});

export const securityIncidents = pgTable("security_incidents", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  incidentType: varchar("incident_type").notNull(), // brute_force, key_compromise, anomaly_detection
  severity: varchar("severity").notNull(), // critical, high, medium, low
  status: varchar("status").notNull(), // open, investigating, resolved, false_positive
  description: text("description").notNull(),
  source: varchar("source"), // system, user_report, automated_detection
  affectedSdks: text("affected_sdks").array(),
  affectedKeys: text("affected_keys").array(),
  detectionMethod: varchar("detection_method"),
  mitigationSteps: text("mitigation_steps").array(),
  assignedTo: varchar("assigned_to").references(() => users.id),
  resolvedAt: timestamp("resolved_at"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const sdkDeployments = pgTable("sdk_deployments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  sdkId: varchar("sdk_id").references(() => sdks.id).notNull(),
  environment: varchar("environment").notNull(), // production, staging, development
  version: varchar("version").notNull(),
  applicationName: varchar("application_name"),
  deploymentUrl: varchar("deployment_url"),
  healthStatus: varchar("health_status").notNull().default('healthy'), // healthy, degraded, critical, offline
  lastHeartbeat: timestamp("last_heartbeat"),
  instanceCount: integer("instance_count").default(1),
  totalOperations: integer("total_operations").default(0),
  successRate: integer("success_rate").default(100),
  averageLatency: integer("average_latency").default(0),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Insert schemas for new tables
export const insertCryptoOperationSchema = createInsertSchema(cryptoOperations).omit({
  id: true,
  createdAt: true,
});

export const insertPerformanceMetricSchema = createInsertSchema(performanceMetrics).omit({
  id: true,
  timestamp: true,
});

export const insertSecurityIncidentSchema = createInsertSchema(securityIncidents).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertSdkDeploymentSchema = createInsertSchema(sdkDeployments).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// Types for new tables
export type CryptoOperation = typeof cryptoOperations.$inferSelect;
export type InsertCryptoOperation = z.infer<typeof insertCryptoOperationSchema>;
export type PerformanceMetric = typeof performanceMetrics.$inferSelect;
export type InsertPerformanceMetric = z.infer<typeof insertPerformanceMetricSchema>;
export type SecurityIncident = typeof securityIncidents.$inferSelect;
export type InsertSecurityIncident = z.infer<typeof insertSecurityIncidentSchema>;
export type SdkDeployment = typeof sdkDeployments.$inferSelect;
export type InsertSdkDeployment = z.infer<typeof insertSdkDeploymentSchema>;

// Relations for new tables
export const cryptoOperationRelations = relations(cryptoOperations, ({ one }) => ({
  tenant: one(tenants, {
    fields: [cryptoOperations.tenantId],
    references: [tenants.id],
  }),
  sdk: one(sdks, {
    fields: [cryptoOperations.sdkId],
    references: [sdks.id],
  }),
  key: one(encryptionKeys, {
    fields: [cryptoOperations.keyId],
    references: [encryptionKeys.id],
  }),
}));

export const performanceMetricRelations = relations(performanceMetrics, ({ one }) => ({
  tenant: one(tenants, {
    fields: [performanceMetrics.tenantId],
    references: [tenants.id],
  }),
  sdk: one(sdks, {
    fields: [performanceMetrics.sdkId],
    references: [sdks.id],
  }),
}));

export const securityIncidentRelations = relations(securityIncidents, ({ one }) => ({
  tenant: one(tenants, {
    fields: [securityIncidents.tenantId],
    references: [tenants.id],
  }),
  assignedUser: one(users, {
    fields: [securityIncidents.assignedTo],
    references: [users.id],
  }),
}));

export const sdkDeploymentRelations = relations(sdkDeployments, ({ one }) => ({
  tenant: one(tenants, {
    fields: [sdkDeployments.tenantId],
    references: [tenants.id],
  }),
  sdk: one(sdks, {
    fields: [sdkDeployments.sdkId],
    references: [sdks.id],
  }),
}));
