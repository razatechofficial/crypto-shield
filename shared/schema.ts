import { sql } from 'drizzle-orm';
import {
  index,
  uniqueIndex,
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

// Session storage table for Averox authentication
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
export const keyStatusEnum = pgEnum('key_status', ['active', 'rotating', 'revoked', 'expired', 'pending_activation', 'scheduled_rotation', 'archived']);

// Key rotation trigger enum
export const rotationTriggerEnum = pgEnum('rotation_trigger', ['time_based', 'usage_based', 'manual', 'compromise_detected', 'policy_change']);

// Key rotation status enum  
export const rotationStatusEnum = pgEnum('rotation_status', ['in_progress', 'completed', 'failed', 'rolled_back', 'cancelled']);

// Key version status enum
export const keyVersionStatusEnum = pgEnum('key_version_status', ['current', 'previous', 'deprecated', 'compromised']);

// SDK language enum
export const sdkLanguageEnum = pgEnum('sdk_language', ['javascript', 'python', 'java', 'csharp', 'go', 'rust', 'dart', 'swift', 'kotlin', 'php', 'ruby', 'cpp']);

// Security levels enum
export const securityLevelEnum = pgEnum('security_level', ['standard', 'enhanced', 'maximum', 'confidential', 'privacy_preserving', 'quantum_ready', 'post_quantum']);

// Confidential computing features enum
export const confidentialFeatureEnum = pgEnum('confidential_feature', ['teeEncryption', 'homomorphicEncryption', 'multiPartyComputation', 'zeroKnowledgeProofs', 'differentialPrivacy', 'secureAggregation']);

// HSM provider enum
export const hsmProviderEnum = pgEnum('hsm_provider', ['safenet', 'thales', 'ncipher', 'aws_cloudhsm', 'azure_dedicated_hsm', 'utimaco', 'yubico', 'nitrokey', 'gemalto', 'securenet']);

// HSM connection type enum
export const hsmConnectionTypeEnum = pgEnum('hsm_connection_type', ['pkcs11', 'kmip', 'rest_api', 'proprietary']);

// HSM device status enum
export const hsmDeviceStatusEnum = pgEnum('hsm_device_status', ['online', 'offline', 'maintenance', 'error', 'initializing', 'tampered']);

// Smart token type enum
export const smartTokenTypeEnum = pgEnum('smart_token_type', ['yubikey_piv', 'yubikey_fido2', 'smartcard_piv', 'smartcard_cac', 'pkcs15_token', 'tpm2_token', 'mobile_secure_element']);

// HSM session status enum
export const hsmSessionStatusEnum = pgEnum('hsm_session_status', ['active', 'idle', 'expired', 'terminated', 'error']);

// FIPS validation level enum
export const fipsValidationLevelEnum = pgEnum('fips_validation_level', ['level_1', 'level_2', 'level_3', 'level_4']);

// Government compliance framework enum
export const complianceFrameworkEnum = pgEnum('compliance_framework', ['fips_140_2', 'fips_140_3', 'common_criteria', 'federal_pki', 'dod_pki', 'fisma', 'fedramp', 'itar', 'cnssi_1253']);

// HSM key usage policy enum
export const keyUsagePolicyEnum = pgEnum('key_usage_policy', ['unrestricted', 'sign_only', 'encrypt_only', 'time_limited', 'operation_limited', 'single_use', 'escrow_required']);

// HSM operation type enum
export const hsmOperationTypeEnum = pgEnum('hsm_operation_type', ['key_generate', 'key_import', 'key_export', 'key_delete', 'sign', 'encrypt', 'decrypt', 'verify', 'key_derive', 'certificate_generate', 'attestation']);

// HSM audit event type enum
export const hsmAuditEventTypeEnum = pgEnum('hsm_audit_event_type', ['login', 'logout', 'key_access', 'key_modification', 'configuration_change', 'security_violation', 'maintenance_access', 'backup_operation', 'recovery_operation']);

// User storage table for Averox authentication
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
  // FIPS 140-3 compliance mapping
  fipsValidated: boolean("fips_validated").default(false),
  fipsValidationNumber: varchar("fips_validation_number"),
  fipsSecurityLevel: integer("fips_security_level"), // 1-4
  nistApproved: boolean("nist_approved").default(false),
  nistStandard: varchar("nist_standard"), // e.g., "FIPS 197", "SP 800-38D"
  // Performance and capability metadata
  securityStrength: integer("security_strength"), // bits of security (128, 192, 256)
  capabilities: text("capabilities"), // JSON array of operations: ["encrypt", "decrypt", "kem", "sign", "verify"]
  limitations: text("limitations"), // JSON array of known limitations
  recommendedUse: text("recommended_use"), // description of recommended use cases
  migrationPath: varchar("migration_path"), // path for quantum migration
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

// Encryption keys table with versioning support
export const encryptionKeys = pgTable("encryption_keys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  keyId: varchar("key_id").notNull().unique(),
  keyType: varchar("key_type").notNull(), // 'primary', 'session', 'backup'
  algorithmId: varchar("algorithm_id").references(() => encryptionAlgorithms.id).notNull(),
  status: keyStatusEnum("status").default('active'),
  
  // Key Versioning & Lifecycle Management
  version: integer("version").default(1).notNull(),
  versionStatus: keyVersionStatusEnum("version_status").default('current'),
  parentKeyId: varchar("parent_key_id").references(() => encryptionKeys.id), // Self-reference to master key
  previousVersionId: varchar("previous_version_id").references(() => encryptionKeys.id), // Reference to previous version
  
  // Expiration & Rotation
  expiresAt: timestamp("expires_at"),
  rotationInterval: integer("rotation_interval").default(30), // days
  lastRotatedAt: timestamp("last_rotated_at"),
  nextRotationAt: timestamp("next_rotation_at"),
  rotationTrigger: rotationTriggerEnum("rotation_trigger"),
  
  // Usage Tracking for Rotation
  usageCount: integer("usage_count").default(0),
  maxUsageCount: integer("max_usage_count"), // Max operations before rotation
  
  // Key Lifecycle
  activatedAt: timestamp("activated_at"),
  deactivatedAt: timestamp("deactivated_at"),
  
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => {
  return {
    // Ensure only one current version per parent key
    uniqueCurrentVersion: uniqueIndex("unique_current_version_per_parent")
      .on(table.parentKeyId)
      .where(sql`version_status = 'current'`),
    
    // Index for efficient key rotation queries
    rotationScheduleIdx: index("idx_keys_rotation_schedule")
      .on(table.tenantId, table.nextRotationAt, table.status),
    
    // Index for version queries
    versioningIdx: index("idx_keys_versioning")
      .on(table.parentKeyId, table.version, table.versionStatus),
      
    // Index for usage-based rotation queries  
    usageTrackingIdx: index("idx_keys_usage_tracking")
      .on(table.tenantId, table.usageCount, table.maxUsageCount),
  };
});

// Key Rotation Policies table
export const keyRotationPolicies = pgTable("key_rotation_policies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  policyName: varchar("policy_name").notNull(),
  keyType: varchar("key_type").notNull(), // Apply to specific key types
  algorithmId: varchar("algorithm_id").references(() => encryptionAlgorithms.id),
  
  // Rotation Triggers
  timeBasedRotation: boolean("time_based_rotation").default(false),
  rotationIntervalDays: integer("rotation_interval_days").default(30),
  
  usageBasedRotation: boolean("usage_based_rotation").default(false),
  maxOperations: integer("max_operations").default(100000),
  
  // Policy Settings
  autoRotationEnabled: boolean("auto_rotation_enabled").default(true),
  notifyBeforeRotation: boolean("notify_before_rotation").default(true),
  notificationDays: integer("notification_days").default(7),
  
  // Compliance & Governance
  retainPreviousVersions: integer("retain_previous_versions").default(3),
  emergencyRotationEnabled: boolean("emergency_rotation_enabled").default(true),
  approvalRequired: boolean("approval_required").default(false),
  
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Key Rotation History table for audit trails
export const keyRotationHistory = pgTable("key_rotation_history", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  keyId: varchar("key_id").references(() => encryptionKeys.id).notNull(),
  fromVersion: integer("from_version"),
  toVersion: integer("to_version").notNull(),
  
  rotationTrigger: rotationTriggerEnum("rotation_trigger").notNull(),
  triggeredBy: varchar("triggered_by"), // user_id or 'system'
  policyId: varchar("policy_id").references(() => keyRotationPolicies.id),
  
  // Rotation Details
  rotationStarted: timestamp("rotation_started").notNull(),
  rotationCompleted: timestamp("rotation_completed"),
  rotationStatus: varchar("rotation_status").notNull().default('in_progress'), // TODO: Convert to enum after fixing transactions
  
  // Rollback capability
  canRollback: boolean("can_rollback").default(true),
  rolledBackAt: timestamp("rolled_back_at"),
  rolledBackBy: varchar("rolled_back_by"),
  
  errorMessage: text("error_message"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
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

// HSM Providers table
export const hsmProviders = pgTable("hsm_providers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  name: varchar("name").notNull(),
  provider: hsmProviderEnum("provider").notNull(),
  connectionType: hsmConnectionTypeEnum("connection_type").notNull(),
  configuration: jsonb("configuration").notNull().default({}), // PKCS#11 lib path, KMIP endpoint, credentials
  isActive: boolean("is_active").default(true),
  fipsValidationLevel: fipsValidationLevelEnum("fips_validation_level"),
  commonCriteriaLevel: varchar("common_criteria_level"), // EAL4+, EAL5+, EAL6+, EAL7
  certifications: text("certifications"), // JSON array of certifications
  maxSessions: integer("max_sessions").default(10),
  healthCheckUrl: varchar("health_check_url"),
  lastHealthCheck: timestamp("last_health_check"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// HSM Devices table
export const hsmDevices = pgTable("hsm_devices", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  providerId: varchar("provider_id").references(() => hsmProviders.id).notNull(),
  deviceId: varchar("device_id").notNull(), // HSM device identifier
  serialNumber: varchar("serial_number").unique(),
  model: varchar("model"),
  firmwareVersion: varchar("firmware_version"),
  status: hsmDeviceStatusEnum("status").default('offline'),
  capabilities: text("capabilities"), // JSON array of supported operations
  slotCount: integer("slot_count"),
  usedSlots: integer("used_slots").default(0),
  maxKeys: integer("max_keys"),
  usedKeys: integer("used_keys").default(0),
  batteryLevel: integer("battery_level"), // For portable HSMs
  temperature: integer("temperature"), // Celsius
  tamperStatus: varchar("tamper_status").default('secure'), // secure, warning, violated
  lastAttestation: timestamp("last_attestation"),
  attestationData: jsonb("attestation_data").default({}),
  location: varchar("location"), // Physical location
  responsible: varchar("responsible").references(() => users.id), // Responsible person
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// HSM Sessions table
export const hsmSessions = pgTable("hsm_sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  deviceId: varchar("device_id").references(() => hsmDevices.id).notNull(),
  sessionId: varchar("session_id").notNull(), // HSM session handle
  userId: varchar("user_id").references(() => users.id).notNull(),
  status: hsmSessionStatusEnum("status").default('active'),
  authMethod: varchar("auth_method").notNull(), // password, smart_card, biometric, multi_factor
  slotId: integer("slot_id"),
  loginTime: timestamp("login_time").defaultNow(),
  lastActivity: timestamp("last_activity").defaultNow(),
  expiresAt: timestamp("expires_at"),
  operationCount: integer("operation_count").default(0),
  ipAddress: varchar("ip_address"),
  userAgent: varchar("user_agent"),
  metadata: jsonb("metadata").default({}),
});

// Smart Tokens table
export const smartTokens = pgTable("smart_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  userId: varchar("user_id").references(() => users.id).notNull(),
  tokenType: smartTokenTypeEnum("token_type").notNull(),
  serialNumber: varchar("serial_number").unique().notNull(),
  manufacturer: varchar("manufacturer"),
  model: varchar("model"),
  firmwareVersion: varchar("firmware_version"),
  status: varchar("status").default('active'), // active, suspended, revoked, lost
  capabilities: text("capabilities"), // JSON array of supported operations
  certificates: jsonb("certificates").default({}), // Stored certificates metadata
  keySlots: integer("key_slots"),
  usedSlots: integer("used_slots").default(0),
  pivSupported: boolean("piv_supported").default(false),
  fido2Supported: boolean("fido2_supported").default(false),
  lastSeen: timestamp("last_seen"),
  enrollmentDate: timestamp("enrollment_date").defaultNow(),
  expirationDate: timestamp("expiration_date"),
  pinRetries: integer("pin_retries").default(3),
  pukRetries: integer("puk_retries").default(3),
  isBlocked: boolean("is_blocked").default(false),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// HSM Keys table (extends encryption_keys with HSM specifics)
export const hsmKeys = pgTable("hsm_keys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  deviceId: varchar("device_id").references(() => hsmDevices.id),
  tokenId: varchar("token_id").references(() => smartTokens.id),
  keyId: varchar("key_id").notNull().unique(), // HSM key handle/identifier
  keyLabel: varchar("key_label").notNull(),
  algorithmId: varchar("algorithm_id").references(() => encryptionAlgorithms.id).notNull(),
  keyType: varchar("key_type").notNull(), // 'master', 'signing', 'encryption', 'authentication'
  keyUsagePolicy: keyUsagePolicyEnum("key_usage_policy").default('unrestricted'),
  status: keyStatusEnum("status").default('active'),
  isExportable: boolean("is_exportable").default(false),
  isSensitive: boolean("is_sensitive").default(true),
  isExtractable: boolean("is_extractable").default(false),
  keySize: integer("key_size").notNull(),
  publicKey: text("public_key"), // PEM formatted public key
  keyFingerprint: varchar("key_fingerprint").unique(),
  createdInHsm: timestamp("created_in_hsm").notNull(),
  expiresAt: timestamp("expires_at"),
  rotationInterval: integer("rotation_interval").default(30), // days
  usageLimit: integer("usage_limit"), // Max operations before rotation
  usageCount: integer("usage_count").default(0),
  lastUsed: timestamp("last_used"),
  backupStatus: varchar("backup_status").default('none'), // none, backed_up, escrow
  escrowedBy: varchar("escrowed_by"), // Escrow authority
  attestationData: jsonb("attestation_data").default({}),
  complianceFlags: text("compliance_flags"), // JSON array of compliance requirements
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// HSM Operations Audit table
export const hsmAuditLog = pgTable("hsm_audit_log", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  deviceId: varchar("device_id").references(() => hsmDevices.id),
  sessionId: varchar("session_id").references(() => hsmSessions.id),
  keyId: varchar("key_id").references(() => hsmKeys.id),
  userId: varchar("user_id").references(() => users.id).notNull(),
  operationType: hsmOperationTypeEnum("operation_type").notNull(),
  eventType: hsmAuditEventTypeEnum("event_type").notNull(),
  status: varchar("status").notNull(), // success, failure, denied, error
  requestData: jsonb("request_data").default({}), // Sanitized request parameters
  responseData: jsonb("response_data").default({}), // Operation results (no sensitive data)
  errorCode: varchar("error_code"),
  errorMessage: text("error_message"),
  duration: integer("duration"), // milliseconds
  ipAddress: varchar("ip_address"),
  userAgent: varchar("user_agent"),
  complianceContext: jsonb("compliance_context").default({}), // FIPS, CC context
  riskScore: integer("risk_score"), // 1-100 risk assessment
  requiresApproval: boolean("requires_approval").default(false),
  approvedBy: varchar("approved_by").references(() => users.id),
  approvedAt: timestamp("approved_at"),
  eventTime: timestamp("event_time").defaultNow(),
});

// Government Compliance Assessments table
export const complianceAssessments = pgTable("compliance_assessments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  assessmentName: varchar("assessment_name").notNull(),
  framework: complianceFrameworkEnum("framework").notNull(),
  assessmentDate: timestamp("assessment_date").defaultNow(),
  assessor: varchar("assessor").references(() => users.id).notNull(),
  scope: text("scope"), // JSON array of systems/components assessed
  findings: jsonb("findings").default({}), // Assessment results
  recommendations: text("recommendations").array(),
  riskLevel: varchar("risk_level").notNull(), // low, medium, high, critical
  status: varchar("status").default('draft'), // draft, in_review, approved, rejected
  validUntil: timestamp("valid_until"),
  evidence: jsonb("evidence").default({}), // Supporting evidence metadata
  reportUrl: varchar("report_url"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Certificate Authority table for PKI integration
export const certificateAuthorities = pgTable("certificate_authorities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  name: varchar("name").notNull(),
  type: varchar("type").notNull(), // 'root', 'intermediate', 'issuing'
  keyId: varchar("key_id").references(() => hsmKeys.id).notNull(), // HSM-bound CA key
  certificate: text("certificate").notNull(), // PEM formatted certificate
  certificateChain: text("certificate_chain"), // Full certificate chain
  serialNumber: varchar("serial_number").unique().notNull(),
  issuer: varchar("issuer"),
  subject: varchar("subject").notNull(),
  validFrom: timestamp("valid_from").notNull(),
  validTo: timestamp("valid_to").notNull(),
  keyUsage: text("key_usage").array(),
  extendedKeyUsage: text("extended_key_usage").array(),
  isActive: boolean("is_active").default(true),
  revocationList: varchar("revocation_list_url"),
  ocspResponder: varchar("ocsp_responder_url"),
  issuedCertificates: integer("issued_certificates").default(0),
  revokedCertificates: integer("revoked_certificates").default(0),
  complianceLevel: varchar("compliance_level"), // FPKI, DoD PKI compliant
  auditTrail: jsonb("audit_trail").default({}),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Relations
export const tenantRelations = relations(tenants, ({ many }) => ({
  users: many(users),
  sdks: many(sdks),
  encryptionKeys: many(encryptionKeys),
  securityEvents: many(securityEvents),
  apiUsage: many(apiUsage),
  hsmProviders: many(hsmProviders),
  smartTokens: many(smartTokens),
  hsmKeys: many(hsmKeys),
  hsmAuditLog: many(hsmAuditLog),
  complianceAssessments: many(complianceAssessments),
  certificateAuthorities: many(certificateAuthorities),
}));

export const userRelations = relations(users, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [users.tenantId],
    references: [tenants.id],
  }),
  sdks: many(sdks),
  smartTokens: many(smartTokens),
  hsmSessions: many(hsmSessions),
  hsmAuditLog: many(hsmAuditLog),
  complianceAssessments: many(complianceAssessments),
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

export const encryptionKeyRelations = relations(encryptionKeys, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [encryptionKeys.tenantId],
    references: [tenants.id],
  }),
  algorithm: one(encryptionAlgorithms, {
    fields: [encryptionKeys.algorithmId],
    references: [encryptionAlgorithms.id],
  }),
  parentKey: one(encryptionKeys, {
    fields: [encryptionKeys.parentKeyId],
    references: [encryptionKeys.id],
    relationName: "keyVersions"
  }),
  previousVersion: one(encryptionKeys, {
    fields: [encryptionKeys.previousVersionId],
    references: [encryptionKeys.id],
    relationName: "versionChain"
  }),
  rotationHistory: many(keyRotationHistory),
}));

export const keyRotationPolicyRelations = relations(keyRotationPolicies, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [keyRotationPolicies.tenantId],
    references: [tenants.id],
  }),
  algorithm: one(encryptionAlgorithms, {
    fields: [keyRotationPolicies.algorithmId],
    references: [encryptionAlgorithms.id],
  }),
  rotationHistory: many(keyRotationHistory),
}));

export const keyRotationHistoryRelations = relations(keyRotationHistory, ({ one }) => ({
  tenant: one(tenants, {
    fields: [keyRotationHistory.tenantId],
    references: [tenants.id],
  }),
  key: one(encryptionKeys, {
    fields: [keyRotationHistory.keyId],
    references: [encryptionKeys.id],
  }),
  policy: one(keyRotationPolicies, {
    fields: [keyRotationHistory.policyId],
    references: [keyRotationPolicies.id],
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

export const insertKeyRotationPolicySchema = createInsertSchema(keyRotationPolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertKeyRotationHistorySchema = createInsertSchema(keyRotationHistory).omit({
  id: true,
  createdAt: true,
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
export type KeyRotationPolicy = typeof keyRotationPolicies.$inferSelect;
export type InsertKeyRotationPolicy = z.infer<typeof insertKeyRotationPolicySchema>;
export type KeyRotationHistory = typeof keyRotationHistory.$inferSelect;
export type InsertKeyRotationHistory = z.infer<typeof insertKeyRotationHistorySchema>;
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

// HSM Insert schemas
export const insertHsmProviderSchema = createInsertSchema(hsmProviders).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertHsmDeviceSchema = createInsertSchema(hsmDevices).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertHsmSessionSchema = createInsertSchema(hsmSessions).omit({
  id: true,
});

export const insertSmartTokenSchema = createInsertSchema(smartTokens).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertHsmKeySchema = createInsertSchema(hsmKeys).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertHsmAuditLogSchema = createInsertSchema(hsmAuditLog).omit({
  id: true,
  eventTime: true,
});

export const insertComplianceAssessmentSchema = createInsertSchema(complianceAssessments).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertCertificateAuthoritySchema = createInsertSchema(certificateAuthorities).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// Types for existing tables
export type CryptoOperation = typeof cryptoOperations.$inferSelect;
export type InsertCryptoOperation = z.infer<typeof insertCryptoOperationSchema>;
export type PerformanceMetric = typeof performanceMetrics.$inferSelect;
export type InsertPerformanceMetric = z.infer<typeof insertPerformanceMetricSchema>;
export type SecurityIncident = typeof securityIncidents.$inferSelect;
export type InsertSecurityIncident = z.infer<typeof insertSecurityIncidentSchema>;
export type SdkDeployment = typeof sdkDeployments.$inferSelect;
export type InsertSdkDeployment = z.infer<typeof insertSdkDeploymentSchema>;

// HSM Types
export type HsmProvider = typeof hsmProviders.$inferSelect;
export type InsertHsmProvider = z.infer<typeof insertHsmProviderSchema>;
export type HsmDevice = typeof hsmDevices.$inferSelect;
export type InsertHsmDevice = z.infer<typeof insertHsmDeviceSchema>;
export type HsmSession = typeof hsmSessions.$inferSelect;
export type InsertHsmSession = z.infer<typeof insertHsmSessionSchema>;
export type SmartToken = typeof smartTokens.$inferSelect;
export type InsertSmartToken = z.infer<typeof insertSmartTokenSchema>;
export type HsmKey = typeof hsmKeys.$inferSelect;
export type InsertHsmKey = z.infer<typeof insertHsmKeySchema>;
export type HsmAuditLog = typeof hsmAuditLog.$inferSelect;
export type InsertHsmAuditLog = z.infer<typeof insertHsmAuditLogSchema>;
export type ComplianceAssessment = typeof complianceAssessments.$inferSelect;
export type InsertComplianceAssessment = z.infer<typeof insertComplianceAssessmentSchema>;
export type CertificateAuthority = typeof certificateAuthorities.$inferSelect;
export type InsertCertificateAuthority = z.infer<typeof insertCertificateAuthoritySchema>;

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

// HSM Relations
export const hsmProviderRelations = relations(hsmProviders, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [hsmProviders.tenantId],
    references: [tenants.id],
  }),
  devices: many(hsmDevices),
}));

export const hsmDeviceRelations = relations(hsmDevices, ({ one, many }) => ({
  provider: one(hsmProviders, {
    fields: [hsmDevices.providerId],
    references: [hsmProviders.id],
  }),
  responsible: one(users, {
    fields: [hsmDevices.responsible],
    references: [users.id],
  }),
  sessions: many(hsmSessions),
  keys: many(hsmKeys),
}));

export const hsmSessionRelations = relations(hsmSessions, ({ one }) => ({
  device: one(hsmDevices, {
    fields: [hsmSessions.deviceId],
    references: [hsmDevices.id],
  }),
  user: one(users, {
    fields: [hsmSessions.userId],
    references: [users.id],
  }),
}));

export const smartTokenRelations = relations(smartTokens, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [smartTokens.tenantId],
    references: [tenants.id],
  }),
  user: one(users, {
    fields: [smartTokens.userId],
    references: [users.id],
  }),
  keys: many(hsmKeys),
}));

export const hsmKeyRelations = relations(hsmKeys, ({ one }) => ({
  tenant: one(tenants, {
    fields: [hsmKeys.tenantId],
    references: [tenants.id],
  }),
  device: one(hsmDevices, {
    fields: [hsmKeys.deviceId],
    references: [hsmDevices.id],
  }),
  token: one(smartTokens, {
    fields: [hsmKeys.tokenId],
    references: [smartTokens.id],
  }),
  algorithm: one(encryptionAlgorithms, {
    fields: [hsmKeys.algorithmId],
    references: [encryptionAlgorithms.id],
  }),
}));

export const hsmAuditLogRelations = relations(hsmAuditLog, ({ one }) => ({
  tenant: one(tenants, {
    fields: [hsmAuditLog.tenantId],
    references: [tenants.id],
  }),
  device: one(hsmDevices, {
    fields: [hsmAuditLog.deviceId],
    references: [hsmDevices.id],
  }),
  session: one(hsmSessions, {
    fields: [hsmAuditLog.sessionId],
    references: [hsmSessions.id],
  }),
  key: one(hsmKeys, {
    fields: [hsmAuditLog.keyId],
    references: [hsmKeys.id],
  }),
  user: one(users, {
    fields: [hsmAuditLog.userId],
    references: [users.id],
  }),
  approver: one(users, {
    fields: [hsmAuditLog.approvedBy],
    references: [users.id],
  }),
}));

export const complianceAssessmentRelations = relations(complianceAssessments, ({ one }) => ({
  tenant: one(tenants, {
    fields: [complianceAssessments.tenantId],
    references: [tenants.id],
  }),
  assessor: one(users, {
    fields: [complianceAssessments.assessor],
    references: [users.id],
  }),
}));

export const certificateAuthorityRelations = relations(certificateAuthorities, ({ one }) => ({
  tenant: one(tenants, {
    fields: [certificateAuthorities.tenantId],
    references: [tenants.id],
  }),
  key: one(hsmKeys, {
    fields: [certificateAuthorities.keyId],
    references: [hsmKeys.id],
  }),
}));

// ============================================================================
// MULTI-CLOUD KEY DISTRIBUTION SCHEMA - Enterprise KMS Integration
// ============================================================================

// Cloud provider types enum
export const cloudProviderEnum = pgEnum('cloud_provider', ['aws_kms', 'azure_key_vault', 'gcp_kms', 'hashicorp_vault', 'ibm_key_protect']);

// Key distribution status enum
export const distributionStatusEnum = pgEnum('distribution_status', ['pending', 'synced', 'drift_detected', 'sync_failed', 'disabled']);

// Replication status enum  
export const replicationStatusEnum = pgEnum('replication_status', ['in_progress', 'completed', 'failed', 'paused']);

// BYOK import status enum
export const byokImportStatusEnum = pgEnum('byok_import_status', ['pending_validation', 'imported', 'validation_failed', 'expired', 'revoked']);

// Cloud provider configurations
export const cloudProviderConfigs = pgTable("cloud_provider_configs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  provider: cloudProviderEnum("provider").notNull(),
  name: varchar("name").notNull(), // User-friendly name
  description: text("description"),
  
  // Provider-specific configuration (encrypted)
  region: varchar("region").notNull(),
  credentialsEncrypted: text("credentials_encrypted").notNull(), // Encrypted JSON
  
  // Connection settings
  endpoint: varchar("endpoint"), // Custom endpoint if needed
  isActive: boolean("is_active").default(true),
  healthStatus: varchar("health_status").default('unknown'), // healthy, unhealthy, unknown
  lastHealthCheck: timestamp("last_health_check"),
  
  // Metadata
  tags: jsonb("tags").default({}),
  createdBy: varchar("created_by").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Key distribution mappings - tracks which keys are distributed to which providers
export const keyDistributions = pgTable("key_distributions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  keyId: varchar("key_id").references(() => encryptionKeys.id).notNull(),
  providerConfigId: varchar("provider_config_id").references(() => cloudProviderConfigs.id).notNull(),
  
  // Provider-specific key identifiers
  providerKeyId: varchar("provider_key_id").notNull(), // ARN, ID, etc.
  providerKeyArn: varchar("provider_key_arn"), // Full ARN for AWS
  providerAlias: varchar("provider_alias"), // Key alias if supported
  
  // Distribution settings
  distributionStatus: distributionStatusEnum("distribution_status").default('pending'),
  autoSync: boolean("auto_sync").default(true),
  autoRotate: boolean("auto_rotate").default(true),
  
  // Sync tracking
  lastSyncAt: timestamp("last_sync_at"),
  lastSyncStatus: varchar("last_sync_status"),
  syncError: text("sync_error"),
  driftDetectedAt: timestamp("drift_detected_at"),
  
  // Metadata
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  uniqueIndex("unique_key_provider_distribution").on(table.keyId, table.providerConfigId),
]);

// Cross-region replication configurations
export const keyReplications = pgTable("key_replications", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  sourceDistributionId: varchar("source_distribution_id").references(() => keyDistributions.id).notNull(),
  targetProviderConfigId: varchar("target_provider_config_id").references(() => cloudProviderConfigs.id).notNull(),
  
  // Replication settings
  replicationStatus: replicationStatusEnum("replication_status").default('in_progress'),
  targetKeyId: varchar("target_key_id"), // Key ID in target region/provider
  targetKeyArn: varchar("target_key_arn"),
  
  // Replication policy
  isAutomatic: boolean("is_automatic").default(true),
  replicationPolicy: jsonb("replication_policy").default({}),
  
  // Status tracking
  startedAt: timestamp("started_at").defaultNow(),
  completedAt: timestamp("completed_at"),
  lastError: text("last_error"),
  retryCount: integer("retry_count").default(0),
  
  // Metadata
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// BYOK (Bring Your Own Key) import tracking
export const byokImports = pgTable("byok_imports", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  keyId: varchar("key_id").references(() => encryptionKeys.id).notNull(),
  
  // Import details
  importStatus: byokImportStatusEnum("import_status").default('pending_validation'),
  customerKeyId: varchar("customer_key_id").notNull(), // Customer's original key identifier
  wrappingMethod: varchar("wrapping_method").notNull(), // RSA-OAEP, AES-KW, etc.
  
  // Custody and compliance
  custodyPolicy: jsonb("custody_policy").default({}), // Escrow, exportability rules
  attestationData: jsonb("attestation_data").default({}), // Trust path validation
  
  // Import lifecycle
  importedAt: timestamp("imported_at"),
  expiresAt: timestamp("expires_at"),
  revokedAt: timestamp("revoked_at"),
  revocationReason: text("revocation_reason"),
  
  // Audit trail
  importedBy: varchar("imported_by").references(() => users.id).notNull(),
  validatedBy: varchar("validated_by").references(() => users.id),
  
  // Metadata
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Compliance policies and automated reporting
export const compliancePolicies = pgTable("compliance_policies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  tenantId: varchar("tenant_id").references(() => tenants.id).notNull(),
  
  // Policy identification
  name: varchar("name").notNull(),
  framework: complianceFrameworkEnum("framework").notNull(),
  version: varchar("version").notNull(),
  description: text("description"),
  
  // Policy rules (NIST controls, PCI requirements, etc.)
  controls: jsonb("controls").notNull(), // Mapped controls and requirements
  keyRequirements: jsonb("key_requirements").default({}), // Key-specific requirements
  auditRequirements: jsonb("audit_requirements").default({}), // Audit log requirements
  
  // Enforcement settings
  isEnforcing: boolean("is_enforcing").default(false),
  enforcementLevel: varchar("enforcement_level").default('warn'), // warn, block, audit
  
  // Reporting
  reportingSchedule: varchar("reporting_schedule"), // daily, weekly, monthly, quarterly
  nextReportDue: timestamp("next_report_due"),
  lastReportGenerated: timestamp("last_report_generated"),
  
  // Metadata
  tags: jsonb("tags").default({}),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// ============================================================================
// MULTI-CLOUD RELATIONS
// ============================================================================

export const cloudProviderConfigRelations = relations(cloudProviderConfigs, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [cloudProviderConfigs.tenantId],
    references: [tenants.id],
  }),
  creator: one(users, {
    fields: [cloudProviderConfigs.createdBy],
    references: [users.id],
  }),
  distributions: many(keyDistributions),
  replications: many(keyReplications),
}));

export const keyDistributionRelations = relations(keyDistributions, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [keyDistributions.tenantId],
    references: [tenants.id],
  }),
  key: one(encryptionKeys, {
    fields: [keyDistributions.keyId],
    references: [encryptionKeys.id],
  }),
  providerConfig: one(cloudProviderConfigs, {
    fields: [keyDistributions.providerConfigId],
    references: [cloudProviderConfigs.id],
  }),
  sourceReplications: many(keyReplications),
}));

export const keyReplicationRelations = relations(keyReplications, ({ one }) => ({
  tenant: one(tenants, {
    fields: [keyReplications.tenantId],
    references: [tenants.id],
  }),
  sourceDistribution: one(keyDistributions, {
    fields: [keyReplications.sourceDistributionId],
    references: [keyDistributions.id],
  }),
  targetProviderConfig: one(cloudProviderConfigs, {
    fields: [keyReplications.targetProviderConfigId],
    references: [cloudProviderConfigs.id],
  }),
}));

export const byokImportRelations = relations(byokImports, ({ one }) => ({
  tenant: one(tenants, {
    fields: [byokImports.tenantId],
    references: [tenants.id],
  }),
  key: one(encryptionKeys, {
    fields: [byokImports.keyId],
    references: [encryptionKeys.id],
  }),
  importer: one(users, {
    fields: [byokImports.importedBy],
    references: [users.id],
  }),
  validator: one(users, {
    fields: [byokImports.validatedBy],
    references: [users.id],
  }),
}));

export const compliancePolicyRelations = relations(compliancePolicies, ({ one }) => ({
  tenant: one(tenants, {
    fields: [compliancePolicies.tenantId],
    references: [tenants.id],
  }),
  creator: one(users, {
    fields: [compliancePolicies.createdBy],
    references: [users.id],
  }),
}));

// ============================================================================
// MULTI-CLOUD TYPES & SCHEMAS
// ============================================================================

// TypeScript types for multi-cloud entities
export type CloudProviderConfig = typeof cloudProviderConfigs.$inferSelect;
export type InsertCloudProviderConfig = typeof cloudProviderConfigs.$inferInsert;

export type KeyDistribution = typeof keyDistributions.$inferSelect;
export type InsertKeyDistribution = typeof keyDistributions.$inferInsert;

export type KeyReplication = typeof keyReplications.$inferSelect;
export type InsertKeyReplication = typeof keyReplications.$inferInsert;

export type ByokImport = typeof byokImports.$inferSelect;
export type InsertByokImport = typeof byokImports.$inferInsert;

export type CompliancePolicy = typeof compliancePolicies.$inferSelect;
export type InsertCompliancePolicy = typeof compliancePolicies.$inferInsert;

// Zod schemas for validation
export const insertCloudProviderConfigSchema = createInsertSchema(cloudProviderConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertKeyDistributionSchema = createInsertSchema(keyDistributions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertKeyReplicationSchema = createInsertSchema(keyReplications).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertByokImportSchema = createInsertSchema(byokImports).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertCompliancePolicySchema = createInsertSchema(compliancePolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// Provider-specific configuration types
export interface AwsKmsConfig {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  roleArn?: string;
}

export interface AzureKeyVaultConfig {
  clientId: string;
  clientSecret: string;
  tenantId: string;
  vaultUrl: string;
}

export interface GcpKmsConfig {
  projectId: string;
  keyRingId: string;
  locationId: string;
  serviceAccountKey: string;
}

// Provider operation result types
export interface ProviderKeyResult {
  success: boolean;
  keyId?: string;
  keyArn?: string;
  alias?: string;
  error?: string;
  metadata?: Record<string, any>;
}

export interface ProviderHealthResult {
  healthy: boolean;
  responseTime?: number;
  error?: string;
  lastChecked: Date;
}
