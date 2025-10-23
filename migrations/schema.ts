import { pgTable, foreignKey, unique, varchar, boolean, integer, text, jsonb, timestamp, index, pgEnum } from "drizzle-orm/pg-core"
import { sql } from "drizzle-orm"

export const algorithmType = pgEnum("algorithm_type", ['symmetric', 'asymmetric', 'hash', 'post_quantum', 'tee', 'homomorphic', 'mpc', 'zero_knowledge'])
export const approvalStatus = pgEnum("approval_status", ['pending', 'approved', 'rejected', 'cancelled', 'expired'])
export const auditAction = pgEnum("audit_action", ['user:created', 'user:updated', 'user:disabled', 'user:invited', 'user:role_changed', 'org:created', 'org:updated', 'org:deleted', 'org:settings_changed', 'key:created', 'key:updated', 'key:deleted', 'key:rotated', 'key:exported', 'key:imported', 'provider:created', 'provider:updated', 'provider:deleted', 'provider:configured', 'subscription:created', 'subscription:updated', 'subscription:cancelled', 'invoice:paid', 'login:success', 'login:failed', 'logout', 'permission:granted', 'permission:denied', 'policy:created', 'policy:updated', 'policy:enforced', 'approval:requested', 'approval:granted'])
export const byokImportStatus = pgEnum("byok_import_status", ['pending_validation', 'imported', 'validation_failed', 'expired', 'revoked'])
export const cloudProvider = pgEnum("cloud_provider", ['aws_kms', 'azure_key_vault', 'gcp_kms', 'hashicorp_vault', 'ibm_key_protect'])
export const complianceFramework = pgEnum("compliance_framework", ['fips_140_2', 'fips_140_3', 'common_criteria', 'federal_pki', 'dod_pki', 'fisma', 'fedramp', 'itar', 'cnssi_1253'])
export const confidentialFeature = pgEnum("confidential_feature", ['teeEncryption', 'homomorphicEncryption', 'multiPartyComputation', 'zeroKnowledgeProofs', 'differentialPrivacy', 'secureAggregation'])
export const distributionStatus = pgEnum("distribution_status", ['pending', 'synced', 'drift_detected', 'sync_failed', 'disabled'])
export const extendedUserRole = pgEnum("extended_user_role", ['admin', 'manager', 'developer', 'viewer'])
export const fipsValidationLevel = pgEnum("fips_validation_level", ['level_1', 'level_2', 'level_3', 'level_4'])
export const hsmAuditEventType = pgEnum("hsm_audit_event_type", ['login', 'logout', 'key_access', 'key_modification', 'configuration_change', 'security_violation', 'maintenance_access', 'backup_operation', 'recovery_operation'])
export const hsmConnectionType = pgEnum("hsm_connection_type", ['pkcs11', 'kmip', 'rest_api', 'proprietary'])
export const hsmDeviceStatus = pgEnum("hsm_device_status", ['online', 'offline', 'maintenance', 'error', 'initializing', 'tampered'])
export const hsmOperationType = pgEnum("hsm_operation_type", ['key_generate', 'key_import', 'key_export', 'key_delete', 'sign', 'encrypt', 'decrypt', 'verify', 'key_derive', 'certificate_generate', 'attestation'])
export const hsmProvider = pgEnum("hsm_provider", ['safenet', 'thales', 'ncipher', 'aws_cloudhsm', 'azure_dedicated_hsm', 'utimaco', 'yubico', 'nitrokey', 'gemalto', 'securenet'])
export const hsmSessionStatus = pgEnum("hsm_session_status", ['active', 'idle', 'expired', 'terminated', 'error'])
export const invoiceStatus = pgEnum("invoice_status", ['draft', 'open', 'paid', 'uncollectible', 'void', 'deleted'])
export const keyStatus = pgEnum("key_status", ['active', 'rotating', 'revoked', 'expired', 'pending_activation', 'scheduled_rotation', 'archived'])
export const keyUsagePolicy = pgEnum("key_usage_policy", ['unrestricted', 'sign_only', 'encrypt_only', 'time_limited', 'operation_limited', 'single_use', 'escrow_required'])
export const keyVersionStatus = pgEnum("key_version_status", ['current', 'previous', 'deprecated', 'compromised'])
export const notificationType = pgEnum("notification_type", ['security_alert', 'key_rotation', 'system_maintenance', 'sdk_update', 'compliance_reminder', 'billing_update', 'trial_expiry', 'general'])
export const paymentProvider = pgEnum("payment_provider", ['stripe', 'paypal'])
export const permission = pgEnum("permission", ['org:manage', 'org:view', 'org:billing', 'users:manage', 'users:view', 'users:invite', 'keys:manage', 'keys:rotate', 'keys:export', 'keys:delete', 'keys:view', 'providers:manage', 'providers:view', 'providers:configure', 'analytics:view', 'analytics:export', 'billing:manage', 'billing:view', 'alerts:manage', 'alerts:view', 'audit:view', 'audit:export', 'policies:manage', 'policies:view', 'hsm:manage', 'hsm:view', 'hsm:operate', 'compliance:manage', 'compliance:view', 'compliance:report'])
export const replicationStatus = pgEnum("replication_status", ['in_progress', 'completed', 'failed', 'paused'])
export const rotationStatus = pgEnum("rotation_status", ['in_progress', 'completed', 'failed', 'rolled_back', 'cancelled'])
export const rotationTrigger = pgEnum("rotation_trigger", ['time_based', 'usage_based', 'manual', 'compromise_detected', 'policy_change'])
export const sdkLanguage = pgEnum("sdk_language", ['javascript', 'python', 'java', 'csharp', 'go', 'rust', 'dart', 'swift', 'kotlin', 'php', 'ruby', 'cpp'])
export const securityLevel = pgEnum("security_level", ['standard', 'enhanced', 'maximum', 'confidential', 'privacy_preserving', 'quantum_ready', 'post_quantum'])
export const smartTokenType = pgEnum("smart_token_type", ['yubikey_piv', 'yubikey_fido2', 'smartcard_piv', 'smartcard_cac', 'pkcs15_token', 'tpm2_token', 'mobile_secure_element'])
export const subscriptionStatus = pgEnum("subscription_status", ['active', 'past_due', 'canceled', 'unpaid', 'incomplete', 'incomplete_expired', 'trialing'])
export const subscriptionTier = pgEnum("subscription_tier", ['starter', 'professional', 'enterprise'])
export const userRole = pgEnum("user_role", ['admin', 'developer', 'viewer'])
export const userStatus = pgEnum("user_status", ['active', 'invited', 'disabled', 'suspended'])
export const webhookStatus = pgEnum("webhook_status", ['pending', 'processed', 'failed', 'retry'])


export const accessPolicies = pgTable("access_policies", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	dualControlRequired: boolean("dual_control_required").default(false),
	exportApprovalRequired: boolean("export_approval_required").default(true),
	deleteApprovalRequired: boolean("delete_approval_required").default(true),
	minApprovers: integer("min_approvers").default(1),
	separationOfDuties: boolean("separation_of_duties").default(false),
	keyDeletionGracePeriod: integer("key_deletion_grace_period").default(24),
	maxKeyAge: integer("max_key_age").default(365),
	mandatoryRotation: boolean("mandatory_rotation").default(false),
	ipWhitelist: text("ip_whitelist"),
	timeRestrictions: jsonb("time_restrictions").default({}),
	locationRestrictions: jsonb("location_restrictions").default({}),
	auditLogRetention: integer("audit_log_retention").default(2555),
	complianceFrameworks: text("compliance_frameworks"),
	enforced: boolean().default(true),
	createdBy: varchar("created_by").notNull(),
	approvedBy: varchar("approved_by"),
	approvedAt: timestamp("approved_at", { mode: 'string' }),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "access_policies_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.createdBy],
			foreignColumns: [users.id],
			name: "access_policies_created_by_users_id_fk"
		}),
	foreignKey({
			columns: [table.approvedBy],
			foreignColumns: [users.id],
			name: "access_policies_approved_by_users_id_fk"
		}),
	unique("access_policies_tenant_id_unique").on(table.tenantId),
]);

export const approvalWorkflows = pgTable("approval_workflows", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	requestType: varchar("request_type").notNull(),
	targetType: varchar("target_type").notNull(),
	targetId: varchar("target_id").notNull(),
	requestedBy: varchar("requested_by").notNull(),
	status: approvalStatus().default('pending'),
	requiredApprovers: integer("required_approvers").default(1),
	currentApprovers: integer("current_approvers").default(0),
	requestData: jsonb("request_data").notNull(),
	justification: text(),
	requestedAt: timestamp("requested_at", { mode: 'string' }).defaultNow(),
	expiresAt: timestamp("expires_at", { mode: 'string' }),
	completedAt: timestamp("completed_at", { mode: 'string' }),
	executeAt: timestamp("execute_at", { mode: 'string' }),
	executedAt: timestamp("executed_at", { mode: 'string' }),
	executionResult: jsonb("execution_result").default({}),
	auditEventId: varchar("audit_event_id"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "approval_workflows_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.requestedBy],
			foreignColumns: [users.id],
			name: "approval_workflows_requested_by_users_id_fk"
		}),
	foreignKey({
			columns: [table.auditEventId],
			foreignColumns: [auditEvents.id],
			name: "approval_workflows_audit_event_id_audit_events_id_fk"
		}),
]);

export const auditEvents = pgTable("audit_events", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	userId: varchar("user_id"),
	action: auditAction().notNull(),
	targetType: varchar("target_type"),
	targetId: varchar("target_id"),
	ipAddress: varchar("ip_address"),
	userAgent: text("user_agent"),
	requestId: varchar("request_id"),
	oldValues: jsonb("old_values").default({}),
	newValues: jsonb("new_values").default({}),
	metadata: jsonb().default({}),
	success: boolean().default(true),
	errorMessage: text("error_message"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "audit_events_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.userId],
			foreignColumns: [users.id],
			name: "audit_events_user_id_users_id_fk"
		}),
]);

export const approvals = pgTable("approvals", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	workflowId: varchar("workflow_id").notNull(),
	approverId: varchar("approver_id").notNull(),
	status: approvalStatus().default('pending'),
	decision: varchar(),
	comments: text(),
	signatureData: jsonb("signature_data").default({}),
	requestedAt: timestamp("requested_at", { mode: 'string' }).defaultNow(),
	respondedAt: timestamp("responded_at", { mode: 'string' }),
	auditEventId: varchar("audit_event_id"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.workflowId],
			foreignColumns: [approvalWorkflows.id],
			name: "approvals_workflow_id_approval_workflows_id_fk"
		}),
	foreignKey({
			columns: [table.approverId],
			foreignColumns: [users.id],
			name: "approvals_approver_id_users_id_fk"
		}),
	foreignKey({
			columns: [table.auditEventId],
			foreignColumns: [auditEvents.id],
			name: "approvals_audit_event_id_audit_events_id_fk"
		}),
]);

export const certificateAuthorities = pgTable("certificate_authorities", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	name: varchar().notNull(),
	type: varchar().notNull(),
	keyId: varchar("key_id").notNull(),
	certificate: text().notNull(),
	certificateChain: text("certificate_chain"),
	serialNumber: varchar("serial_number").notNull(),
	issuer: varchar(),
	subject: varchar().notNull(),
	validFrom: timestamp("valid_from", { mode: 'string' }).notNull(),
	validTo: timestamp("valid_to", { mode: 'string' }).notNull(),
	keyUsage: text("key_usage").array(),
	extendedKeyUsage: text("extended_key_usage").array(),
	isActive: boolean("is_active").default(true),
	revocationListUrl: varchar("revocation_list_url"),
	ocspResponderUrl: varchar("ocsp_responder_url"),
	issuedCertificates: integer("issued_certificates").default(0),
	revokedCertificates: integer("revoked_certificates").default(0),
	complianceLevel: varchar("compliance_level"),
	auditTrail: jsonb("audit_trail").default({}),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "certificate_authorities_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.keyId],
			foreignColumns: [hsmKeys.id],
			name: "certificate_authorities_key_id_hsm_keys_id_fk"
		}),
	unique("certificate_authorities_serial_number_unique").on(table.serialNumber),
]);

export const byokImports = pgTable("byok_imports", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	keyId: varchar("key_id").notNull(),
	importStatus: byokImportStatus("import_status").default('pending_validation'),
	customerKeyId: varchar("customer_key_id").notNull(),
	wrappingMethod: varchar("wrapping_method").notNull(),
	custodyPolicy: jsonb("custody_policy").default({}),
	attestationData: jsonb("attestation_data").default({}),
	importedAt: timestamp("imported_at", { mode: 'string' }),
	expiresAt: timestamp("expires_at", { mode: 'string' }),
	revokedAt: timestamp("revoked_at", { mode: 'string' }),
	revocationReason: text("revocation_reason"),
	importedBy: varchar("imported_by").notNull(),
	validatedBy: varchar("validated_by"),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "byok_imports_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.keyId],
			foreignColumns: [encryptionKeys.id],
			name: "byok_imports_key_id_encryption_keys_id_fk"
		}),
	foreignKey({
			columns: [table.importedBy],
			foreignColumns: [users.id],
			name: "byok_imports_imported_by_users_id_fk"
		}),
	foreignKey({
			columns: [table.validatedBy],
			foreignColumns: [users.id],
			name: "byok_imports_validated_by_users_id_fk"
		}),
]);

export const cloudProviderConfigs = pgTable("cloud_provider_configs", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	provider: cloudProvider().notNull(),
	name: varchar().notNull(),
	description: text(),
	region: varchar().notNull(),
	credentialsEncrypted: text("credentials_encrypted").notNull(),
	endpoint: varchar(),
	isActive: boolean("is_active").default(true),
	healthStatus: varchar("health_status").default('unknown'),
	lastHealthCheck: timestamp("last_health_check", { mode: 'string' }),
	tags: jsonb().default({}),
	createdBy: varchar("created_by"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "cloud_provider_configs_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.createdBy],
			foreignColumns: [users.id],
			name: "cloud_provider_configs_created_by_users_id_fk"
		}),
]);

export const apiUsage = pgTable("api_usage", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	date: timestamp({ mode: 'string' }).notNull(),
	encryptionRequests: integer("encryption_requests").default(0),
	decryptionRequests: integer("decryption_requests").default(0),
	keyRotations: integer("key_rotations").default(0),
	threatsBlocked: integer("threats_blocked").default(0),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "api_usage_tenant_id_tenants_id_fk"
		}),
]);

export const cryptoOperations = pgTable("crypto_operations", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	sdkId: varchar("sdk_id"),
	operation: varchar().notNull(),
	algorithm: varchar().notNull(),
	keyId: varchar("key_id"),
	status: varchar().notNull(),
	duration: integer().notNull(),
	dataSize: integer("data_size"),
	clientId: varchar("client_id"),
	ipAddress: varchar("ip_address"),
	userAgent: varchar("user_agent"),
	errorCode: varchar("error_code"),
	errorMessage: text("error_message"),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "crypto_operations_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.sdkId],
			foreignColumns: [sdks.id],
			name: "crypto_operations_sdk_id_sdks_id_fk"
		}),
	foreignKey({
			columns: [table.keyId],
			foreignColumns: [encryptionKeys.id],
			name: "crypto_operations_key_id_encryption_keys_id_fk"
		}),
]);

export const encryptionAlgorithms = pgTable("encryption_algorithms", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	name: varchar().notNull(),
	displayName: varchar("display_name").notNull(),
	description: text(),
	type: algorithmType().notNull(),
	keySize: integer("key_size"),
	isQuantumSafe: boolean("is_quantum_safe").default(false),
	isPostQuantum: boolean("is_post_quantum").default(false),
	isActive: boolean("is_active").default(true),
	fipsValidated: boolean("fips_validated").default(false),
	fipsValidationNumber: varchar("fips_validation_number"),
	fipsSecurityLevel: integer("fips_security_level"),
	nistApproved: boolean("nist_approved").default(false),
	nistStandard: varchar("nist_standard"),
	securityStrength: integer("security_strength"),
	capabilities: text(),
	limitations: text(),
	recommendedUse: text("recommended_use"),
	migrationPath: varchar("migration_path"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("encryption_algorithms_name_unique").on(table.name),
]);

export const complianceAssessments = pgTable("compliance_assessments", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	assessmentName: varchar("assessment_name").notNull(),
	framework: complianceFramework().notNull(),
	assessmentDate: timestamp("assessment_date", { mode: 'string' }).defaultNow(),
	assessor: varchar().notNull(),
	scope: text(),
	findings: jsonb().default({}),
	recommendations: text().array(),
	riskLevel: varchar("risk_level").notNull(),
	status: varchar().default('draft'),
	validUntil: timestamp("valid_until", { mode: 'string' }),
	evidence: jsonb().default({}),
	reportUrl: varchar("report_url"),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "compliance_assessments_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.assessor],
			foreignColumns: [users.id],
			name: "compliance_assessments_assessor_users_id_fk"
		}),
]);

export const compliancePolicies = pgTable("compliance_policies", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	name: varchar().notNull(),
	framework: complianceFramework().notNull(),
	version: varchar().notNull(),
	description: text(),
	controls: jsonb().notNull(),
	keyRequirements: jsonb("key_requirements").default({}),
	auditRequirements: jsonb("audit_requirements").default({}),
	isEnforcing: boolean("is_enforcing").default(false),
	enforcementLevel: varchar("enforcement_level").default('warn'),
	reportingSchedule: varchar("reporting_schedule"),
	nextReportDue: timestamp("next_report_due", { mode: 'string' }),
	lastReportGenerated: timestamp("last_report_generated", { mode: 'string' }),
	tags: jsonb().default({}),
	createdBy: varchar("created_by").notNull(),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "compliance_policies_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.createdBy],
			foreignColumns: [users.id],
			name: "compliance_policies_created_by_users_id_fk"
		}),
]);

export const encryptionKeys = pgTable("encryption_keys", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	keyId: varchar("key_id").notNull(),
	keyType: varchar("key_type").notNull(),
	algorithmId: varchar("algorithm_id").notNull(),
	status: keyStatus().default('active'),
	version: integer().default(1).notNull(),
	versionStatus: keyVersionStatus("version_status").default('current'),
	parentKeyId: varchar("parent_key_id"),
	previousVersionId: varchar("previous_version_id"),
	expiresAt: timestamp("expires_at", { mode: 'string' }),
	rotationInterval: integer("rotation_interval").default(30),
	lastRotatedAt: timestamp("last_rotated_at", { mode: 'string' }),
	nextRotationAt: timestamp("next_rotation_at", { mode: 'string' }),
	rotationTrigger: rotationTrigger("rotation_trigger"),
	usageCount: integer("usage_count").default(0),
	maxUsageCount: integer("max_usage_count"),
	activatedAt: timestamp("activated_at", { mode: 'string' }),
	deactivatedAt: timestamp("deactivated_at", { mode: 'string' }),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	foreignKey({
			columns: [table.tenantId],
			foreignColumns: [tenants.id],
			name: "encryption_keys_tenant_id_tenants_id_fk"
		}),
	foreignKey({
			columns: [table.algorithmId],
			foreignColumns: [encryptionAlgorithms.id],
			name: "encryption_keys_algorithm_id_encryption_algorithms_id_fk"
		}),
	unique("encryption_keys_id_unique").on(table.id),
	unique("encryption_keys_key_id_unique").on(table.keyId),
]);

export const hsmAuditLog = pgTable("hsm_audit_log", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	deviceId: varchar("device_id"),
	sessionId: varchar("session_id"),
	keyId: varchar("key_id"),
	userId: varchar("user_id").notNull(),
	operationType: hsmOperationType("operation_type").notNull(),
	eventType: hsmAuditEventType("event_type").notNull(),
	status: varchar().notNull(),
	requestData: jsonb("request_data").default({}),
	responseData: jsonb("response_data").default({}),
	errorCode: varchar("error_code"),
	errorMessage: text("error_message"),
	duration: integer(),
	ipAddress: varchar("ip_address"),
	userAgent: varchar("user_agent"),
	complianceContext: jsonb("compliance_context").default({}),
	riskScore: integer("risk_score"),
	requiresApproval: boolean("requires_approval").default(false),
	approvedBy: varchar("approved_by"),
	approvedAt: timestamp("approved_at", { mode: 'string' }),
	eventTime: timestamp("event_time", { mode: 'string' }).defaultNow(),
});

export const hsmDevices = pgTable("hsm_devices", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	providerId: varchar("provider_id").notNull(),
	deviceId: varchar("device_id").notNull(),
	serialNumber: varchar("serial_number"),
	model: varchar(),
	firmwareVersion: varchar("firmware_version"),
	status: hsmDeviceStatus().default('offline'),
	capabilities: text(),
	slotCount: integer("slot_count"),
	usedSlots: integer("used_slots").default(0),
	maxKeys: integer("max_keys"),
	usedKeys: integer("used_keys").default(0),
	batteryLevel: integer("battery_level"),
	temperature: integer(),
	tamperStatus: varchar("tamper_status").default('secure'),
	lastAttestation: timestamp("last_attestation", { mode: 'string' }),
	attestationData: jsonb("attestation_data").default({}),
	location: varchar(),
	responsible: varchar(),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("hsm_devices_serial_number_unique").on(table.serialNumber),
]);

export const hsmProviders = pgTable("hsm_providers", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	name: varchar().notNull(),
	provider: hsmProvider().notNull(),
	connectionType: hsmConnectionType("connection_type").notNull(),
	configuration: jsonb().default({}).notNull(),
	isActive: boolean("is_active").default(true),
	fipsValidationLevel: fipsValidationLevel("fips_validation_level"),
	commonCriteriaLevel: varchar("common_criteria_level"),
	certifications: text(),
	maxSessions: integer("max_sessions").default(10),
	healthCheckUrl: varchar("health_check_url"),
	lastHealthCheck: timestamp("last_health_check", { mode: 'string' }),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const hsmSessions = pgTable("hsm_sessions", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	deviceId: varchar("device_id").notNull(),
	sessionId: varchar("session_id").notNull(),
	userId: varchar("user_id").notNull(),
	status: hsmSessionStatus().default('active'),
	authMethod: varchar("auth_method").notNull(),
	slotId: integer("slot_id"),
	loginTime: timestamp("login_time", { mode: 'string' }).defaultNow(),
	lastActivity: timestamp("last_activity", { mode: 'string' }).defaultNow(),
	expiresAt: timestamp("expires_at", { mode: 'string' }),
	operationCount: integer("operation_count").default(0),
	ipAddress: varchar("ip_address"),
	userAgent: varchar("user_agent"),
	metadata: jsonb().default({}),
});

export const invoices = pgTable("invoices", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	subscriptionId: varchar("subscription_id").notNull(),
	provider: paymentProvider().notNull(),
	providerInvoiceId: varchar("provider_invoice_id").notNull(),
	status: invoiceStatus().default('open'),
	amountCents: integer("amount_cents").notNull(),
	currency: varchar().default('USD'),
	taxCents: integer("tax_cents").default(0),
	invoiceDate: timestamp("invoice_date", { mode: 'string' }).notNull(),
	dueDate: timestamp("due_date", { mode: 'string' }),
	paidAt: timestamp("paid_at", { mode: 'string' }),
	hostedUrl: varchar("hosted_url"),
	downloadUrl: varchar("download_url"),
	lineItems: jsonb("line_items").default({}),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("invoices_provider_invoice_id_unique").on(table.providerInvoiceId),
]);

export const keyDistributions = pgTable("key_distributions", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	keyId: varchar("key_id").notNull(),
	providerConfigId: varchar("provider_config_id").notNull(),
	providerKeyId: varchar("provider_key_id").notNull(),
	providerKeyArn: varchar("provider_key_arn"),
	providerAlias: varchar("provider_alias"),
	distributionStatus: distributionStatus("distribution_status").default('pending'),
	autoSync: boolean("auto_sync").default(true),
	autoRotate: boolean("auto_rotate").default(true),
	lastSyncAt: timestamp("last_sync_at", { mode: 'string' }),
	lastSyncStatus: varchar("last_sync_status"),
	syncError: text("sync_error"),
	driftDetectedAt: timestamp("drift_detected_at", { mode: 'string' }),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const hsmKeys = pgTable("hsm_keys", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	deviceId: varchar("device_id"),
	tokenId: varchar("token_id"),
	keyId: varchar("key_id").notNull(),
	keyLabel: varchar("key_label").notNull(),
	algorithmId: varchar("algorithm_id").notNull(),
	keyType: varchar("key_type").notNull(),
	keyUsagePolicy: keyUsagePolicy("key_usage_policy").default('unrestricted'),
	status: keyStatus().default('active'),
	isExportable: boolean("is_exportable").default(false),
	isSensitive: boolean("is_sensitive").default(true),
	isExtractable: boolean("is_extractable").default(false),
	keySize: integer("key_size").notNull(),
	publicKey: text("public_key"),
	keyFingerprint: varchar("key_fingerprint"),
	createdInHsm: timestamp("created_in_hsm", { mode: 'string' }).notNull(),
	expiresAt: timestamp("expires_at", { mode: 'string' }),
	rotationInterval: integer("rotation_interval").default(30),
	usageLimit: integer("usage_limit"),
	usageCount: integer("usage_count").default(0),
	lastUsed: timestamp("last_used", { mode: 'string' }),
	backupStatus: varchar("backup_status").default('none'),
	escrowedBy: varchar("escrowed_by"),
	attestationData: jsonb("attestation_data").default({}),
	complianceFlags: text("compliance_flags"),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("hsm_keys_key_id_unique").on(table.keyId),
	unique("hsm_keys_key_fingerprint_unique").on(table.keyFingerprint),
]);

export const keyReplications = pgTable("key_replications", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	sourceDistributionId: varchar("source_distribution_id").notNull(),
	targetProviderConfigId: varchar("target_provider_config_id").notNull(),
	replicationStatus: replicationStatus("replication_status").default('in_progress'),
	targetKeyId: varchar("target_key_id"),
	targetKeyArn: varchar("target_key_arn"),
	isAutomatic: boolean("is_automatic").default(true),
	replicationPolicy: jsonb("replication_policy").default({}),
	startedAt: timestamp("started_at", { mode: 'string' }).defaultNow(),
	completedAt: timestamp("completed_at", { mode: 'string' }),
	lastError: text("last_error"),
	retryCount: integer("retry_count").default(0),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const keyRotationHistory = pgTable("key_rotation_history", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	keyId: varchar("key_id").notNull(),
	fromVersion: integer("from_version"),
	toVersion: integer("to_version").notNull(),
	rotationTrigger: rotationTrigger("rotation_trigger").notNull(),
	triggeredBy: varchar("triggered_by"),
	policyId: varchar("policy_id"),
	rotationStarted: timestamp("rotation_started", { mode: 'string' }).notNull(),
	rotationCompleted: timestamp("rotation_completed", { mode: 'string' }),
	rotationStatus: varchar("rotation_status").default('in_progress').notNull(),
	canRollback: boolean("can_rollback").default(true),
	rolledBackAt: timestamp("rolled_back_at", { mode: 'string' }),
	rolledBackBy: varchar("rolled_back_by"),
	errorMessage: text("error_message"),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
});

export const keyRotationPolicies = pgTable("key_rotation_policies", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	policyName: varchar("policy_name").notNull(),
	keyType: varchar("key_type").notNull(),
	algorithmId: varchar("algorithm_id"),
	timeBasedRotation: boolean("time_based_rotation").default(false),
	rotationIntervalDays: integer("rotation_interval_days").default(30),
	usageBasedRotation: boolean("usage_based_rotation").default(false),
	maxOperations: integer("max_operations").default(100000),
	autoRotationEnabled: boolean("auto_rotation_enabled").default(true),
	notifyBeforeRotation: boolean("notify_before_rotation").default(true),
	notificationDays: integer("notification_days").default(7),
	retainPreviousVersions: integer("retain_previous_versions").default(3),
	emergencyRotationEnabled: boolean("emergency_rotation_enabled").default(true),
	approvalRequired: boolean("approval_required").default(false),
	isActive: boolean("is_active").default(true),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const notifications = pgTable("notifications", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	userId: varchar("user_id"),
	type: notificationType().notNull(),
	title: varchar().notNull(),
	message: text().notNull(),
	actionUrl: varchar("action_url"),
	isRead: boolean("is_read").default(false),
	priority: varchar().default('medium').notNull(),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	readAt: timestamp("read_at", { mode: 'string' }),
});

export const packages = pgTable("packages", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	userId: varchar("user_id").notNull(),
	name: varchar().notNull(),
	description: text(),
	version: varchar().default('1.0.0').notNull(),
	isVisible: boolean("is_visible").default(true),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const performanceMetrics = pgTable("performance_metrics", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	sdkId: varchar("sdk_id"),
	metricType: varchar("metric_type").notNull(),
	value: integer().notNull(),
	unit: varchar().notNull(),
	timestamp: timestamp({ mode: 'string' }).defaultNow(),
	metadata: jsonb().default({}),
});

export const rolePermissions = pgTable("role_permissions", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	role: extendedUserRole().notNull(),
	permission: permission().notNull(),
	isGranted: boolean("is_granted").default(true),
	tenantId: varchar("tenant_id"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
});

export const sdkDeployments = pgTable("sdk_deployments", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	sdkId: varchar("sdk_id").notNull(),
	environment: varchar().notNull(),
	version: varchar().notNull(),
	applicationName: varchar("application_name"),
	deploymentUrl: varchar("deployment_url"),
	healthStatus: varchar("health_status").default('healthy').notNull(),
	lastHeartbeat: timestamp("last_heartbeat", { mode: 'string' }),
	instanceCount: integer("instance_count").default(1),
	totalOperations: integer("total_operations").default(0),
	successRate: integer("success_rate").default(100),
	averageLatency: integer("average_latency").default(0),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const securityEvents = pgTable("security_events", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	eventType: varchar("event_type").notNull(),
	severity: varchar().notNull(),
	source: varchar(),
	description: text(),
	metadata: jsonb().default({}),
	isResolved: boolean("is_resolved").default(false),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
});

export const securityIncidents = pgTable("security_incidents", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	incidentType: varchar("incident_type").notNull(),
	severity: varchar().notNull(),
	status: varchar().notNull(),
	description: text().notNull(),
	source: varchar(),
	affectedSdks: text("affected_sdks").array(),
	affectedKeys: text("affected_keys").array(),
	detectionMethod: varchar("detection_method"),
	mitigationSteps: text("mitigation_steps").array(),
	assignedTo: varchar("assigned_to"),
	resolvedAt: timestamp("resolved_at", { mode: 'string' }),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const smartTokens = pgTable("smart_tokens", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	userId: varchar("user_id").notNull(),
	tokenType: smartTokenType("token_type").notNull(),
	serialNumber: varchar("serial_number").notNull(),
	manufacturer: varchar(),
	model: varchar(),
	firmwareVersion: varchar("firmware_version"),
	status: varchar().default('active'),
	capabilities: text(),
	certificates: jsonb().default({}),
	keySlots: integer("key_slots"),
	usedSlots: integer("used_slots").default(0),
	pivSupported: boolean("piv_supported").default(false),
	fido2Supported: boolean("fido2_supported").default(false),
	lastSeen: timestamp("last_seen", { mode: 'string' }),
	enrollmentDate: timestamp("enrollment_date", { mode: 'string' }).defaultNow(),
	expirationDate: timestamp("expiration_date", { mode: 'string' }),
	pinRetries: integer("pin_retries").default(3),
	pukRetries: integer("puk_retries").default(3),
	isBlocked: boolean("is_blocked").default(false),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("smart_tokens_serial_number_unique").on(table.serialNumber),
]);

export const subscriptionPlans = pgTable("subscription_plans", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	code: varchar().notNull(),
	name: varchar().notNull(),
	description: text(),
	priceCents: integer("price_cents").notNull(),
	currency: varchar().default('USD'),
	interval: varchar().default('month'),
	features: jsonb().default({}).notNull(),
	limits: jsonb().default({}).notNull(),
	isActive: boolean("is_active").default(true),
	sortOrder: integer("sort_order").default(0),
	stripeProductId: varchar("stripe_product_id"),
	stripePriceId: varchar("stripe_price_id"),
	paypalProductId: varchar("paypal_product_id"),
	paypalPlanId: varchar("paypal_plan_id"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("subscription_plans_code_unique").on(table.code),
]);

export const tenantFeatureOverrides = pgTable("tenant_feature_overrides", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	featureCode: varchar("feature_code").notNull(),
	enabled: boolean().notNull(),
	notes: text(),
	overriddenBy: varchar("overridden_by"),
	expiresAt: timestamp("expires_at", { mode: 'string' }),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const tenantSubscriptions = pgTable("tenant_subscriptions", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	planId: varchar("plan_id").notNull(),
	provider: paymentProvider().notNull(),
	customerId: varchar("customer_id").notNull(),
	subscriptionId: varchar("subscription_id").notNull(),
	status: subscriptionStatus().default('active'),
	currentPeriodStart: timestamp("current_period_start", { mode: 'string' }),
	currentPeriodEnd: timestamp("current_period_end", { mode: 'string' }),
	trialEnd: timestamp("trial_end", { mode: 'string' }),
	cancelAtPeriodEnd: boolean("cancel_at_period_end").default(false),
	canceledAt: timestamp("canceled_at", { mode: 'string' }),
	seats: integer().default(1),
	priceCents: integer("price_cents"),
	currency: varchar().default('USD'),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const tenantUsers = pgTable("tenant_users", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	userId: varchar("user_id").notNull(),
	role: extendedUserRole().default('viewer'),
	status: userStatus().default('active'),
	invitedAt: timestamp("invited_at", { mode: 'string' }),
	invitedBy: varchar("invited_by"),
	joinedAt: timestamp("joined_at", { mode: 'string' }),
	lastActiveAt: timestamp("last_active_at", { mode: 'string' }),
	permissions: text(),
	metadata: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});

export const webhooksLog = pgTable("webhooks_log", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	provider: paymentProvider().notNull(),
	eventId: varchar("event_id").notNull(),
	eventType: varchar("event_type").notNull(),
	payload: jsonb().notNull(),
	signature: varchar(),
	status: webhookStatus().default('pending'),
	processedAt: timestamp("processed_at", { mode: 'string' }),
	retryCount: integer("retry_count").default(0),
	errorMessage: text("error_message"),
	tenantId: varchar("tenant_id"),
	subscriptionId: varchar("subscription_id"),
	receivedAt: timestamp("received_at", { mode: 'string' }).defaultNow(),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("webhooks_log_event_id_unique").on(table.eventId),
]);

export const tenants = pgTable("tenants", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	name: varchar().notNull(),
	domain: varchar(),
	subscriptionTier: subscriptionTier("subscription_tier").default('starter'),
	apiKey: varchar("api_key").notNull(),
	settings: jsonb().default({}),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("tenants_api_key_unique").on(table.apiKey),
]);

export const sessions = pgTable("sessions", {
	sid: varchar().primaryKey().notNull(),
	sess: jsonb().notNull(),
	expire: timestamp({ mode: 'string' }).notNull(),
}, (table) => [
	index("IDX_session_expire").using("btree", table.expire.asc().nullsLast().op("timestamp_ops")),
]);

export const users = pgTable("users", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	email: varchar(),
	firstName: varchar("first_name"),
	lastName: varchar("last_name"),
	profileImageUrl: varchar("profile_image_url"),
	passwordHash: varchar("password_hash"),
	isEmailVerified: boolean("is_email_verified").default(false),
	emailVerificationTokenHash: varchar("email_verification_token_hash"),
	emailVerificationExpires: timestamp("email_verification_expires", { mode: 'string' }),
	passwordResetTokenHash: varchar("password_reset_token_hash"),
	passwordResetExpires: timestamp("password_reset_expires", { mode: 'string' }),
	companyName: varchar("company_name"),
	website: varchar(),
	phoneNumber: varchar("phone_number"),
	stripeCustomerId: varchar("stripe_customer_id"),
	stripeSubscriptionId: varchar("stripe_subscription_id"),
	subscriptionStatus: subscriptionStatus("subscription_status").default('trialing'),
	subscriptionPlan: subscriptionTier("subscription_plan").default('starter'),
	trialStartDate: timestamp("trial_start_date", { mode: 'string' }),
	trialEndDate: timestamp("trial_end_date", { mode: 'string' }),
	role: userRole().default('developer'),
	tenantId: varchar("tenant_id"),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
}, (table) => [
	unique("users_email_unique").on(table.email),
]);

export const sdks = pgTable("sdks", {
	id: varchar().default(gen_random_uuid()).primaryKey().notNull(),
	tenantId: varchar("tenant_id").notNull(),
	userId: varchar("user_id").notNull(),
	name: varchar().notNull(),
	languages: text().notNull(),
	algorithms: text().notNull(),
	applicationType: varchar("application_type"),
	deploymentEnvironment: varchar("deployment_environment"),
	securityLevel: securityLevel("security_level"),
	dataTypes: text("data_types"),
	complianceRequirements: text("compliance_requirements"),
	confidentialFeatures: text("confidential_features"),
	configuration: jsonb().default({}).notNull(),
	features: jsonb().default({}).notNull(),
	downloadUrl: varchar("download_url"),
	version: varchar().default('2.0.0'),
	isActive: boolean("is_active").default(true),
	vaultKekName: varchar("vault_kek_name"),
	vaultKekAlgorithm: varchar("vault_kek_algorithm"),
	vaultKekVersion: integer("vault_kek_version"),
	envelopeEncryptionEnabled: boolean("envelope_encryption_enabled").default(true),
	createdAt: timestamp("created_at", { mode: 'string' }).defaultNow(),
	updatedAt: timestamp("updated_at", { mode: 'string' }).defaultNow(),
});
