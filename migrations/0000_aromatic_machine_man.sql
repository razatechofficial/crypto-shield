CREATE TYPE "public"."algorithm_type" AS ENUM('symmetric', 'asymmetric', 'hash', 'post_quantum', 'tee', 'homomorphic', 'mpc', 'zero_knowledge');--> statement-breakpoint
CREATE TYPE "public"."approval_status" AS ENUM('pending', 'approved', 'rejected', 'cancelled', 'expired');--> statement-breakpoint
CREATE TYPE "public"."audit_action" AS ENUM('user:created', 'user:updated', 'user:disabled', 'user:invited', 'user:role_changed', 'org:created', 'org:updated', 'org:deleted', 'org:settings_changed', 'key:created', 'key:updated', 'key:deleted', 'key:rotated', 'key:exported', 'key:imported', 'provider:created', 'provider:updated', 'provider:deleted', 'provider:configured', 'subscription:created', 'subscription:updated', 'subscription:cancelled', 'invoice:paid', 'login:success', 'login:failed', 'logout', 'permission:granted', 'permission:denied', 'policy:created', 'policy:updated', 'policy:enforced', 'approval:requested', 'approval:granted');--> statement-breakpoint
CREATE TYPE "public"."byok_import_status" AS ENUM('pending_validation', 'imported', 'validation_failed', 'expired', 'revoked');--> statement-breakpoint
CREATE TYPE "public"."cloud_provider" AS ENUM('aws_kms', 'azure_key_vault', 'gcp_kms', 'hashicorp_vault', 'ibm_key_protect');--> statement-breakpoint
CREATE TYPE "public"."compliance_framework" AS ENUM('fips_140_2', 'fips_140_3', 'common_criteria', 'federal_pki', 'dod_pki', 'fisma', 'fedramp', 'itar', 'cnssi_1253');--> statement-breakpoint
CREATE TYPE "public"."confidential_feature" AS ENUM('teeEncryption', 'homomorphicEncryption', 'multiPartyComputation', 'zeroKnowledgeProofs', 'differentialPrivacy', 'secureAggregation');--> statement-breakpoint
CREATE TYPE "public"."distribution_status" AS ENUM('pending', 'synced', 'drift_detected', 'sync_failed', 'disabled');--> statement-breakpoint
CREATE TYPE "public"."extended_user_role" AS ENUM('admin', 'manager', 'developer', 'viewer');--> statement-breakpoint
CREATE TYPE "public"."fips_validation_level" AS ENUM('level_1', 'level_2', 'level_3', 'level_4');--> statement-breakpoint
CREATE TYPE "public"."hsm_audit_event_type" AS ENUM('login', 'logout', 'key_access', 'key_modification', 'configuration_change', 'security_violation', 'maintenance_access', 'backup_operation', 'recovery_operation');--> statement-breakpoint
CREATE TYPE "public"."hsm_connection_type" AS ENUM('pkcs11', 'kmip', 'rest_api', 'proprietary');--> statement-breakpoint
CREATE TYPE "public"."hsm_device_status" AS ENUM('online', 'offline', 'maintenance', 'error', 'initializing', 'tampered');--> statement-breakpoint
CREATE TYPE "public"."hsm_operation_type" AS ENUM('key_generate', 'key_import', 'key_export', 'key_delete', 'sign', 'encrypt', 'decrypt', 'verify', 'key_derive', 'certificate_generate', 'attestation');--> statement-breakpoint
CREATE TYPE "public"."hsm_provider" AS ENUM('safenet', 'thales', 'ncipher', 'aws_cloudhsm', 'azure_dedicated_hsm', 'utimaco', 'yubico', 'nitrokey', 'gemalto', 'securenet');--> statement-breakpoint
CREATE TYPE "public"."hsm_session_status" AS ENUM('active', 'idle', 'expired', 'terminated', 'error');--> statement-breakpoint
CREATE TYPE "public"."invoice_status" AS ENUM('draft', 'open', 'paid', 'uncollectible', 'void', 'deleted');--> statement-breakpoint
CREATE TYPE "public"."key_status" AS ENUM('active', 'rotating', 'revoked', 'expired', 'pending_activation', 'scheduled_rotation', 'archived');--> statement-breakpoint
CREATE TYPE "public"."key_usage_policy" AS ENUM('unrestricted', 'sign_only', 'encrypt_only', 'time_limited', 'operation_limited', 'single_use', 'escrow_required');--> statement-breakpoint
CREATE TYPE "public"."key_version_status" AS ENUM('current', 'previous', 'deprecated', 'compromised');--> statement-breakpoint
CREATE TYPE "public"."notification_type" AS ENUM('security_alert', 'key_rotation', 'system_maintenance', 'sdk_update', 'compliance_reminder', 'billing_update', 'trial_expiry', 'general');--> statement-breakpoint
CREATE TYPE "public"."payment_provider" AS ENUM('stripe', 'paypal');--> statement-breakpoint
CREATE TYPE "public"."permission" AS ENUM('org:manage', 'org:view', 'org:billing', 'users:manage', 'users:view', 'users:invite', 'keys:manage', 'keys:rotate', 'keys:export', 'keys:delete', 'keys:view', 'providers:manage', 'providers:view', 'providers:configure', 'analytics:view', 'analytics:export', 'billing:manage', 'billing:view', 'alerts:manage', 'alerts:view', 'audit:view', 'audit:export', 'policies:manage', 'policies:view', 'hsm:manage', 'hsm:view', 'hsm:operate', 'compliance:manage', 'compliance:view', 'compliance:report');--> statement-breakpoint
CREATE TYPE "public"."replication_status" AS ENUM('in_progress', 'completed', 'failed', 'paused');--> statement-breakpoint
CREATE TYPE "public"."rotation_status" AS ENUM('in_progress', 'completed', 'failed', 'rolled_back', 'cancelled');--> statement-breakpoint
CREATE TYPE "public"."rotation_trigger" AS ENUM('time_based', 'usage_based', 'manual', 'compromise_detected', 'policy_change');--> statement-breakpoint
CREATE TYPE "public"."sdk_language" AS ENUM('javascript', 'python', 'java', 'csharp', 'go', 'rust', 'dart', 'swift', 'kotlin', 'php', 'ruby', 'cpp');--> statement-breakpoint
CREATE TYPE "public"."security_level" AS ENUM('standard', 'enhanced', 'maximum', 'confidential', 'privacy_preserving', 'quantum_ready', 'post_quantum');--> statement-breakpoint
CREATE TYPE "public"."smart_token_type" AS ENUM('yubikey_piv', 'yubikey_fido2', 'smartcard_piv', 'smartcard_cac', 'pkcs15_token', 'tpm2_token', 'mobile_secure_element');--> statement-breakpoint
CREATE TYPE "public"."subscription_status" AS ENUM('active', 'past_due', 'canceled', 'unpaid', 'incomplete', 'incomplete_expired', 'trialing');--> statement-breakpoint
CREATE TYPE "public"."subscription_tier" AS ENUM('starter', 'professional', 'enterprise');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('admin', 'developer', 'viewer');--> statement-breakpoint
CREATE TYPE "public"."user_status" AS ENUM('active', 'invited', 'disabled', 'suspended');--> statement-breakpoint
CREATE TYPE "public"."webhook_status" AS ENUM('pending', 'processed', 'failed', 'retry');--> statement-breakpoint
CREATE TABLE "access_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"dual_control_required" boolean DEFAULT false,
	"export_approval_required" boolean DEFAULT true,
	"delete_approval_required" boolean DEFAULT true,
	"min_approvers" integer DEFAULT 1,
	"separation_of_duties" boolean DEFAULT false,
	"key_deletion_grace_period" integer DEFAULT 24,
	"max_key_age" integer DEFAULT 365,
	"mandatory_rotation" boolean DEFAULT false,
	"ip_whitelist" text,
	"time_restrictions" jsonb DEFAULT '{}'::jsonb,
	"location_restrictions" jsonb DEFAULT '{}'::jsonb,
	"audit_log_retention" integer DEFAULT 2555,
	"compliance_frameworks" text,
	"enforced" boolean DEFAULT true,
	"created_by" varchar NOT NULL,
	"approved_by" varchar,
	"approved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "access_policies_tenant_id_unique" UNIQUE("tenant_id")
);
--> statement-breakpoint
CREATE TABLE "api_usage" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"date" timestamp NOT NULL,
	"encryption_requests" integer DEFAULT 0,
	"decryption_requests" integer DEFAULT 0,
	"key_rotations" integer DEFAULT 0,
	"threats_blocked" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "approval_workflows" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"request_type" varchar NOT NULL,
	"target_type" varchar NOT NULL,
	"target_id" varchar NOT NULL,
	"requested_by" varchar NOT NULL,
	"status" "approval_status" DEFAULT 'pending',
	"required_approvers" integer DEFAULT 1,
	"current_approvers" integer DEFAULT 0,
	"request_data" jsonb NOT NULL,
	"justification" text,
	"requested_at" timestamp DEFAULT now(),
	"expires_at" timestamp,
	"completed_at" timestamp,
	"execute_at" timestamp,
	"executed_at" timestamp,
	"execution_result" jsonb DEFAULT '{}'::jsonb,
	"audit_event_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "approvals" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workflow_id" varchar NOT NULL,
	"approver_id" varchar NOT NULL,
	"status" "approval_status" DEFAULT 'pending',
	"decision" varchar,
	"comments" text,
	"signature_data" jsonb DEFAULT '{}'::jsonb,
	"requested_at" timestamp DEFAULT now(),
	"responded_at" timestamp,
	"audit_event_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "audit_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"user_id" varchar,
	"action" "audit_action" NOT NULL,
	"target_type" varchar,
	"target_id" varchar,
	"ip_address" varchar,
	"user_agent" text,
	"request_id" varchar,
	"old_values" jsonb DEFAULT '{}'::jsonb,
	"new_values" jsonb DEFAULT '{}'::jsonb,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"success" boolean DEFAULT true,
	"error_message" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "byok_imports" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"key_id" varchar NOT NULL,
	"import_status" "byok_import_status" DEFAULT 'pending_validation',
	"customer_key_id" varchar NOT NULL,
	"wrapping_method" varchar NOT NULL,
	"custody_policy" jsonb DEFAULT '{}'::jsonb,
	"attestation_data" jsonb DEFAULT '{}'::jsonb,
	"imported_at" timestamp,
	"expires_at" timestamp,
	"revoked_at" timestamp,
	"revocation_reason" text,
	"imported_by" varchar NOT NULL,
	"validated_by" varchar,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "certificate_authorities" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"name" varchar NOT NULL,
	"type" varchar NOT NULL,
	"key_id" varchar NOT NULL,
	"certificate" text NOT NULL,
	"certificate_chain" text,
	"serial_number" varchar NOT NULL,
	"issuer" varchar,
	"subject" varchar NOT NULL,
	"valid_from" timestamp NOT NULL,
	"valid_to" timestamp NOT NULL,
	"key_usage" text[],
	"extended_key_usage" text[],
	"is_active" boolean DEFAULT true,
	"revocation_list_url" varchar,
	"ocsp_responder_url" varchar,
	"issued_certificates" integer DEFAULT 0,
	"revoked_certificates" integer DEFAULT 0,
	"compliance_level" varchar,
	"audit_trail" jsonb DEFAULT '{}'::jsonb,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "certificate_authorities_serial_number_unique" UNIQUE("serial_number")
);
--> statement-breakpoint
CREATE TABLE "cloud_provider_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"provider" "cloud_provider" NOT NULL,
	"name" varchar NOT NULL,
	"description" text,
	"region" varchar NOT NULL,
	"credentials_encrypted" text NOT NULL,
	"endpoint" varchar,
	"is_active" boolean DEFAULT true,
	"health_status" varchar DEFAULT 'unknown',
	"last_health_check" timestamp,
	"tags" jsonb DEFAULT '{}'::jsonb,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "compliance_assessments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"assessment_name" varchar NOT NULL,
	"framework" "compliance_framework" NOT NULL,
	"assessment_date" timestamp DEFAULT now(),
	"assessor" varchar NOT NULL,
	"scope" text,
	"findings" jsonb DEFAULT '{}'::jsonb,
	"recommendations" text[],
	"risk_level" varchar NOT NULL,
	"status" varchar DEFAULT 'draft',
	"valid_until" timestamp,
	"evidence" jsonb DEFAULT '{}'::jsonb,
	"report_url" varchar,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "compliance_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"name" varchar NOT NULL,
	"framework" "compliance_framework" NOT NULL,
	"version" varchar NOT NULL,
	"description" text,
	"controls" jsonb NOT NULL,
	"key_requirements" jsonb DEFAULT '{}'::jsonb,
	"audit_requirements" jsonb DEFAULT '{}'::jsonb,
	"is_enforcing" boolean DEFAULT false,
	"enforcement_level" varchar DEFAULT 'warn',
	"reporting_schedule" varchar,
	"next_report_due" timestamp,
	"last_report_generated" timestamp,
	"tags" jsonb DEFAULT '{}'::jsonb,
	"created_by" varchar NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "crypto_operations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"sdk_id" varchar,
	"operation" varchar NOT NULL,
	"algorithm" varchar NOT NULL,
	"key_id" varchar,
	"status" varchar NOT NULL,
	"duration" integer NOT NULL,
	"data_size" integer,
	"client_id" varchar,
	"ip_address" varchar,
	"user_agent" varchar,
	"error_code" varchar,
	"error_message" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "encryption_algorithms" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar NOT NULL,
	"display_name" varchar NOT NULL,
	"description" text,
	"type" "algorithm_type" NOT NULL,
	"key_size" integer,
	"is_quantum_safe" boolean DEFAULT false,
	"is_post_quantum" boolean DEFAULT false,
	"is_active" boolean DEFAULT true,
	"fips_validated" boolean DEFAULT false,
	"fips_validation_number" varchar,
	"fips_security_level" integer,
	"nist_approved" boolean DEFAULT false,
	"nist_standard" varchar,
	"security_strength" integer,
	"capabilities" text,
	"limitations" text,
	"recommended_use" text,
	"migration_path" varchar,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "encryption_algorithms_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "encryption_keys" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"key_id" varchar NOT NULL,
	"key_type" varchar NOT NULL,
	"algorithm_id" varchar NOT NULL,
	"status" "key_status" DEFAULT 'active',
	"version" integer DEFAULT 1 NOT NULL,
	"version_status" "key_version_status" DEFAULT 'current',
	"parent_key_id" varchar,
	"previous_version_id" varchar,
	"expires_at" timestamp,
	"rotation_interval" integer DEFAULT 30,
	"last_rotated_at" timestamp,
	"next_rotation_at" timestamp,
	"rotation_trigger" "rotation_trigger",
	"usage_count" integer DEFAULT 0,
	"max_usage_count" integer,
	"activated_at" timestamp,
	"deactivated_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "encryption_keys_key_id_unique" UNIQUE("key_id")
);
--> statement-breakpoint
CREATE TABLE "hsm_audit_log" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"device_id" varchar,
	"session_id" varchar,
	"key_id" varchar,
	"user_id" varchar NOT NULL,
	"operation_type" "hsm_operation_type" NOT NULL,
	"event_type" "hsm_audit_event_type" NOT NULL,
	"status" varchar NOT NULL,
	"request_data" jsonb DEFAULT '{}'::jsonb,
	"response_data" jsonb DEFAULT '{}'::jsonb,
	"error_code" varchar,
	"error_message" text,
	"duration" integer,
	"ip_address" varchar,
	"user_agent" varchar,
	"compliance_context" jsonb DEFAULT '{}'::jsonb,
	"risk_score" integer,
	"requires_approval" boolean DEFAULT false,
	"approved_by" varchar,
	"approved_at" timestamp,
	"event_time" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "hsm_devices" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" varchar NOT NULL,
	"device_id" varchar NOT NULL,
	"serial_number" varchar,
	"model" varchar,
	"firmware_version" varchar,
	"status" "hsm_device_status" DEFAULT 'offline',
	"capabilities" text,
	"slot_count" integer,
	"used_slots" integer DEFAULT 0,
	"max_keys" integer,
	"used_keys" integer DEFAULT 0,
	"battery_level" integer,
	"temperature" integer,
	"tamper_status" varchar DEFAULT 'secure',
	"last_attestation" timestamp,
	"attestation_data" jsonb DEFAULT '{}'::jsonb,
	"location" varchar,
	"responsible" varchar,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "hsm_devices_serial_number_unique" UNIQUE("serial_number")
);
--> statement-breakpoint
CREATE TABLE "hsm_keys" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"device_id" varchar,
	"token_id" varchar,
	"key_id" varchar NOT NULL,
	"key_label" varchar NOT NULL,
	"algorithm_id" varchar NOT NULL,
	"key_type" varchar NOT NULL,
	"key_usage_policy" "key_usage_policy" DEFAULT 'unrestricted',
	"status" "key_status" DEFAULT 'active',
	"is_exportable" boolean DEFAULT false,
	"is_sensitive" boolean DEFAULT true,
	"is_extractable" boolean DEFAULT false,
	"key_size" integer NOT NULL,
	"public_key" text,
	"key_fingerprint" varchar,
	"created_in_hsm" timestamp NOT NULL,
	"expires_at" timestamp,
	"rotation_interval" integer DEFAULT 30,
	"usage_limit" integer,
	"usage_count" integer DEFAULT 0,
	"last_used" timestamp,
	"backup_status" varchar DEFAULT 'none',
	"escrowed_by" varchar,
	"attestation_data" jsonb DEFAULT '{}'::jsonb,
	"compliance_flags" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "hsm_keys_key_id_unique" UNIQUE("key_id"),
	CONSTRAINT "hsm_keys_key_fingerprint_unique" UNIQUE("key_fingerprint")
);
--> statement-breakpoint
CREATE TABLE "hsm_providers" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"name" varchar NOT NULL,
	"provider" "hsm_provider" NOT NULL,
	"connection_type" "hsm_connection_type" NOT NULL,
	"configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"is_active" boolean DEFAULT true,
	"fips_validation_level" "fips_validation_level",
	"common_criteria_level" varchar,
	"certifications" text,
	"max_sessions" integer DEFAULT 10,
	"health_check_url" varchar,
	"last_health_check" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "hsm_sessions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"device_id" varchar NOT NULL,
	"session_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"status" "hsm_session_status" DEFAULT 'active',
	"auth_method" varchar NOT NULL,
	"slot_id" integer,
	"login_time" timestamp DEFAULT now(),
	"last_activity" timestamp DEFAULT now(),
	"expires_at" timestamp,
	"operation_count" integer DEFAULT 0,
	"ip_address" varchar,
	"user_agent" varchar,
	"metadata" jsonb DEFAULT '{}'::jsonb
);
--> statement-breakpoint
CREATE TABLE "invoices" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"subscription_id" varchar NOT NULL,
	"provider" "payment_provider" NOT NULL,
	"provider_invoice_id" varchar NOT NULL,
	"status" "invoice_status" DEFAULT 'open',
	"amount_cents" integer NOT NULL,
	"currency" varchar DEFAULT 'USD',
	"tax_cents" integer DEFAULT 0,
	"invoice_date" timestamp NOT NULL,
	"due_date" timestamp,
	"paid_at" timestamp,
	"hosted_url" varchar,
	"download_url" varchar,
	"line_items" jsonb DEFAULT '{}'::jsonb,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "invoices_provider_invoice_id_unique" UNIQUE("provider_invoice_id")
);
--> statement-breakpoint
CREATE TABLE "key_distributions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"key_id" varchar NOT NULL,
	"provider_config_id" varchar NOT NULL,
	"provider_key_id" varchar NOT NULL,
	"provider_key_arn" varchar,
	"provider_alias" varchar,
	"distribution_status" "distribution_status" DEFAULT 'pending',
	"auto_sync" boolean DEFAULT true,
	"auto_rotate" boolean DEFAULT true,
	"last_sync_at" timestamp,
	"last_sync_status" varchar,
	"sync_error" text,
	"drift_detected_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "key_replications" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"source_distribution_id" varchar NOT NULL,
	"target_provider_config_id" varchar NOT NULL,
	"replication_status" "replication_status" DEFAULT 'in_progress',
	"target_key_id" varchar,
	"target_key_arn" varchar,
	"is_automatic" boolean DEFAULT true,
	"replication_policy" jsonb DEFAULT '{}'::jsonb,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp,
	"last_error" text,
	"retry_count" integer DEFAULT 0,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "key_rotation_history" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"key_id" varchar NOT NULL,
	"from_version" integer,
	"to_version" integer NOT NULL,
	"rotation_trigger" "rotation_trigger" NOT NULL,
	"triggered_by" varchar,
	"policy_id" varchar,
	"rotation_started" timestamp NOT NULL,
	"rotation_completed" timestamp,
	"rotation_status" varchar DEFAULT 'in_progress' NOT NULL,
	"can_rollback" boolean DEFAULT true,
	"rolled_back_at" timestamp,
	"rolled_back_by" varchar,
	"error_message" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "key_rotation_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"policy_name" varchar NOT NULL,
	"key_type" varchar NOT NULL,
	"algorithm_id" varchar,
	"time_based_rotation" boolean DEFAULT false,
	"rotation_interval_days" integer DEFAULT 30,
	"usage_based_rotation" boolean DEFAULT false,
	"max_operations" integer DEFAULT 100000,
	"auto_rotation_enabled" boolean DEFAULT true,
	"notify_before_rotation" boolean DEFAULT true,
	"notification_days" integer DEFAULT 7,
	"retain_previous_versions" integer DEFAULT 3,
	"emergency_rotation_enabled" boolean DEFAULT true,
	"approval_required" boolean DEFAULT false,
	"is_active" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "notifications" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"user_id" varchar,
	"type" "notification_type" NOT NULL,
	"title" varchar NOT NULL,
	"message" text NOT NULL,
	"action_url" varchar,
	"is_read" boolean DEFAULT false,
	"priority" varchar DEFAULT 'medium' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"read_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "packages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"name" varchar NOT NULL,
	"description" text,
	"version" varchar DEFAULT '1.0.0' NOT NULL,
	"is_visible" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "performance_metrics" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"sdk_id" varchar,
	"metric_type" varchar NOT NULL,
	"value" integer NOT NULL,
	"unit" varchar NOT NULL,
	"timestamp" timestamp DEFAULT now(),
	"metadata" jsonb DEFAULT '{}'::jsonb
);
--> statement-breakpoint
CREATE TABLE "role_permissions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"role" "extended_user_role" NOT NULL,
	"permission" "permission" NOT NULL,
	"is_granted" boolean DEFAULT true,
	"tenant_id" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sdk_deployments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"sdk_id" varchar NOT NULL,
	"environment" varchar NOT NULL,
	"version" varchar NOT NULL,
	"application_name" varchar,
	"deployment_url" varchar,
	"health_status" varchar DEFAULT 'healthy' NOT NULL,
	"last_heartbeat" timestamp,
	"instance_count" integer DEFAULT 1,
	"total_operations" integer DEFAULT 0,
	"success_rate" integer DEFAULT 100,
	"average_latency" integer DEFAULT 0,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sdks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"name" varchar NOT NULL,
	"languages" text NOT NULL,
	"algorithms" text NOT NULL,
	"application_type" varchar,
	"deployment_environment" varchar,
	"security_level" "security_level",
	"data_types" text,
	"compliance_requirements" text,
	"confidential_features" text,
	"configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"features" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"download_url" varchar,
	"version" varchar DEFAULT '2.0.0',
	"is_active" boolean DEFAULT true,
	"vault_kek_name" varchar,
	"vault_kek_algorithm" varchar,
	"vault_kek_version" integer,
	"envelope_encryption_enabled" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"event_type" varchar NOT NULL,
	"severity" varchar NOT NULL,
	"source" varchar,
	"description" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"is_resolved" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_incidents" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"incident_type" varchar NOT NULL,
	"severity" varchar NOT NULL,
	"status" varchar NOT NULL,
	"description" text NOT NULL,
	"source" varchar,
	"affected_sdks" text[],
	"affected_keys" text[],
	"detection_method" varchar,
	"mitigation_steps" text[],
	"assigned_to" varchar,
	"resolved_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"sid" varchar PRIMARY KEY NOT NULL,
	"sess" jsonb NOT NULL,
	"expire" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "smart_tokens" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"token_type" "smart_token_type" NOT NULL,
	"serial_number" varchar NOT NULL,
	"manufacturer" varchar,
	"model" varchar,
	"firmware_version" varchar,
	"status" varchar DEFAULT 'active',
	"capabilities" text,
	"certificates" jsonb DEFAULT '{}'::jsonb,
	"key_slots" integer,
	"used_slots" integer DEFAULT 0,
	"piv_supported" boolean DEFAULT false,
	"fido2_supported" boolean DEFAULT false,
	"last_seen" timestamp,
	"enrollment_date" timestamp DEFAULT now(),
	"expiration_date" timestamp,
	"pin_retries" integer DEFAULT 3,
	"puk_retries" integer DEFAULT 3,
	"is_blocked" boolean DEFAULT false,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "smart_tokens_serial_number_unique" UNIQUE("serial_number")
);
--> statement-breakpoint
CREATE TABLE "subscription_plans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"code" varchar NOT NULL,
	"name" varchar NOT NULL,
	"description" text,
	"price_cents" integer NOT NULL,
	"currency" varchar DEFAULT 'USD',
	"interval" varchar DEFAULT 'month',
	"features" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"limits" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"is_active" boolean DEFAULT true,
	"sort_order" integer DEFAULT 0,
	"stripe_product_id" varchar,
	"stripe_price_id" varchar,
	"paypal_product_id" varchar,
	"paypal_plan_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "subscription_plans_code_unique" UNIQUE("code")
);
--> statement-breakpoint
CREATE TABLE "tenant_feature_overrides" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"feature_code" varchar NOT NULL,
	"enabled" boolean NOT NULL,
	"notes" text,
	"overridden_by" varchar,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "tenant_subscriptions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"plan_id" varchar NOT NULL,
	"provider" "payment_provider" NOT NULL,
	"customer_id" varchar NOT NULL,
	"subscription_id" varchar NOT NULL,
	"status" "subscription_status" DEFAULT 'active',
	"current_period_start" timestamp,
	"current_period_end" timestamp,
	"trial_end" timestamp,
	"cancel_at_period_end" boolean DEFAULT false,
	"canceled_at" timestamp,
	"seats" integer DEFAULT 1,
	"price_cents" integer,
	"currency" varchar DEFAULT 'USD',
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "tenant_users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"role" "extended_user_role" DEFAULT 'viewer',
	"status" "user_status" DEFAULT 'active',
	"invited_at" timestamp,
	"invited_by" varchar,
	"joined_at" timestamp,
	"last_active_at" timestamp,
	"permissions" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "tenants" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar NOT NULL,
	"domain" varchar,
	"subscription_tier" "subscription_tier" DEFAULT 'starter',
	"api_key" varchar NOT NULL,
	"settings" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "tenants_api_key_unique" UNIQUE("api_key")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar,
	"first_name" varchar,
	"last_name" varchar,
	"profile_image_url" varchar,
	"password_hash" varchar,
	"is_email_verified" boolean DEFAULT false,
	"email_verification_token_hash" varchar,
	"email_verification_expires" timestamp,
	"password_reset_token_hash" varchar,
	"password_reset_expires" timestamp,
	"company_name" varchar,
	"website" varchar,
	"phone_number" varchar,
	"stripe_customer_id" varchar,
	"stripe_subscription_id" varchar,
	"subscription_status" "subscription_status" DEFAULT 'trialing',
	"subscription_plan" "subscription_tier" DEFAULT 'starter',
	"trial_start_date" timestamp,
	"trial_end_date" timestamp,
	"role" "user_role" DEFAULT 'developer',
	"tenant_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "webhooks_log" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider" "payment_provider" NOT NULL,
	"event_id" varchar NOT NULL,
	"event_type" varchar NOT NULL,
	"payload" jsonb NOT NULL,
	"signature" varchar,
	"status" "webhook_status" DEFAULT 'pending',
	"processed_at" timestamp,
	"retry_count" integer DEFAULT 0,
	"error_message" text,
	"tenant_id" varchar,
	"subscription_id" varchar,
	"received_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "webhooks_log_event_id_unique" UNIQUE("event_id")
);
--> statement-breakpoint
ALTER TABLE "access_policies" ADD CONSTRAINT "access_policies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_policies" ADD CONSTRAINT "access_policies_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_policies" ADD CONSTRAINT "access_policies_approved_by_users_id_fk" FOREIGN KEY ("approved_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_usage" ADD CONSTRAINT "api_usage_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_workflows" ADD CONSTRAINT "approval_workflows_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_workflows" ADD CONSTRAINT "approval_workflows_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_workflows" ADD CONSTRAINT "approval_workflows_audit_event_id_audit_events_id_fk" FOREIGN KEY ("audit_event_id") REFERENCES "public"."audit_events"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approvals" ADD CONSTRAINT "approvals_workflow_id_approval_workflows_id_fk" FOREIGN KEY ("workflow_id") REFERENCES "public"."approval_workflows"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approvals" ADD CONSTRAINT "approvals_approver_id_users_id_fk" FOREIGN KEY ("approver_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approvals" ADD CONSTRAINT "approvals_audit_event_id_audit_events_id_fk" FOREIGN KEY ("audit_event_id") REFERENCES "public"."audit_events"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "byok_imports" ADD CONSTRAINT "byok_imports_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "byok_imports" ADD CONSTRAINT "byok_imports_key_id_encryption_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."encryption_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "byok_imports" ADD CONSTRAINT "byok_imports_imported_by_users_id_fk" FOREIGN KEY ("imported_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "byok_imports" ADD CONSTRAINT "byok_imports_validated_by_users_id_fk" FOREIGN KEY ("validated_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_authorities" ADD CONSTRAINT "certificate_authorities_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_authorities" ADD CONSTRAINT "certificate_authorities_key_id_hsm_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."hsm_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_provider_configs" ADD CONSTRAINT "cloud_provider_configs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_provider_configs" ADD CONSTRAINT "cloud_provider_configs_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_assessments" ADD CONSTRAINT "compliance_assessments_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_assessments" ADD CONSTRAINT "compliance_assessments_assessor_users_id_fk" FOREIGN KEY ("assessor") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_policies" ADD CONSTRAINT "compliance_policies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_policies" ADD CONSTRAINT "compliance_policies_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crypto_operations" ADD CONSTRAINT "crypto_operations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crypto_operations" ADD CONSTRAINT "crypto_operations_sdk_id_sdks_id_fk" FOREIGN KEY ("sdk_id") REFERENCES "public"."sdks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crypto_operations" ADD CONSTRAINT "crypto_operations_key_id_encryption_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."encryption_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "encryption_keys" ADD CONSTRAINT "encryption_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "encryption_keys" ADD CONSTRAINT "encryption_keys_algorithm_id_encryption_algorithms_id_fk" FOREIGN KEY ("algorithm_id") REFERENCES "public"."encryption_algorithms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
-- Temporarily disabled problematic foreign key constraints
-- ALTER TABLE "encryption_keys" ADD CONSTRAINT "fk_encryption_keys_parent_tenant_scoped" FOREIGN KEY ("tenant_id","parent_key_id") REFERENCES "public"."encryption_keys"("tenant_id","id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
-- ALTER TABLE "encryption_keys" ADD CONSTRAINT "fk_encryption_keys_previous_version_tenant_scoped" FOREIGN KEY ("tenant_id","previous_version_id") REFERENCES "public"."encryption_keys"("tenant_id","id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_audit_log" ADD CONSTRAINT "hsm_audit_log_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_audit_log" ADD CONSTRAINT "hsm_audit_log_device_id_hsm_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."hsm_devices"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_audit_log" ADD CONSTRAINT "hsm_audit_log_session_id_hsm_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."hsm_sessions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_audit_log" ADD CONSTRAINT "hsm_audit_log_key_id_hsm_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."hsm_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_audit_log" ADD CONSTRAINT "hsm_audit_log_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_audit_log" ADD CONSTRAINT "hsm_audit_log_approved_by_users_id_fk" FOREIGN KEY ("approved_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_devices" ADD CONSTRAINT "hsm_devices_provider_id_hsm_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."hsm_providers"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_devices" ADD CONSTRAINT "hsm_devices_responsible_users_id_fk" FOREIGN KEY ("responsible") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_keys" ADD CONSTRAINT "hsm_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_keys" ADD CONSTRAINT "hsm_keys_device_id_hsm_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."hsm_devices"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_keys" ADD CONSTRAINT "hsm_keys_token_id_smart_tokens_id_fk" FOREIGN KEY ("token_id") REFERENCES "public"."smart_tokens"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_keys" ADD CONSTRAINT "hsm_keys_algorithm_id_encryption_algorithms_id_fk" FOREIGN KEY ("algorithm_id") REFERENCES "public"."encryption_algorithms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_providers" ADD CONSTRAINT "hsm_providers_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_sessions" ADD CONSTRAINT "hsm_sessions_device_id_hsm_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."hsm_devices"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsm_sessions" ADD CONSTRAINT "hsm_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_subscription_id_tenant_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."tenant_subscriptions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_distributions" ADD CONSTRAINT "key_distributions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_distributions" ADD CONSTRAINT "key_distributions_key_id_encryption_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."encryption_keys"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_distributions" ADD CONSTRAINT "key_distributions_provider_config_id_cloud_provider_configs_id_fk" FOREIGN KEY ("provider_config_id") REFERENCES "public"."cloud_provider_configs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_replications" ADD CONSTRAINT "key_replications_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_replications" ADD CONSTRAINT "key_replications_source_distribution_id_key_distributions_id_fk" FOREIGN KEY ("source_distribution_id") REFERENCES "public"."key_distributions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_replications" ADD CONSTRAINT "key_replications_target_provider_config_id_cloud_provider_configs_id_fk" FOREIGN KEY ("target_provider_config_id") REFERENCES "public"."cloud_provider_configs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_rotation_history" ADD CONSTRAINT "key_rotation_history_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_rotation_history" ADD CONSTRAINT "key_rotation_history_policy_id_key_rotation_policies_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."key_rotation_policies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
-- Temporarily disabled problematic foreign key constraint
-- ALTER TABLE "key_rotation_history" ADD CONSTRAINT "fk_key_rotation_history_tenant_scoped" FOREIGN KEY ("tenant_id","key_id") REFERENCES "public"."encryption_keys"("tenant_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_rotation_policies" ADD CONSTRAINT "key_rotation_policies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "key_rotation_policies" ADD CONSTRAINT "key_rotation_policies_algorithm_id_encryption_algorithms_id_fk" FOREIGN KEY ("algorithm_id") REFERENCES "public"."encryption_algorithms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "packages" ADD CONSTRAINT "packages_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "packages" ADD CONSTRAINT "packages_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "performance_metrics" ADD CONSTRAINT "performance_metrics_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "performance_metrics" ADD CONSTRAINT "performance_metrics_sdk_id_sdks_id_fk" FOREIGN KEY ("sdk_id") REFERENCES "public"."sdks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sdk_deployments" ADD CONSTRAINT "sdk_deployments_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sdk_deployments" ADD CONSTRAINT "sdk_deployments_sdk_id_sdks_id_fk" FOREIGN KEY ("sdk_id") REFERENCES "public"."sdks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sdks" ADD CONSTRAINT "sdks_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sdks" ADD CONSTRAINT "sdks_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_incidents" ADD CONSTRAINT "security_incidents_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_incidents" ADD CONSTRAINT "security_incidents_assigned_to_users_id_fk" FOREIGN KEY ("assigned_to") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "smart_tokens" ADD CONSTRAINT "smart_tokens_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "smart_tokens" ADD CONSTRAINT "smart_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_feature_overrides" ADD CONSTRAINT "tenant_feature_overrides_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_feature_overrides" ADD CONSTRAINT "tenant_feature_overrides_overridden_by_users_id_fk" FOREIGN KEY ("overridden_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_subscriptions" ADD CONSTRAINT "tenant_subscriptions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_subscriptions" ADD CONSTRAINT "tenant_subscriptions_plan_id_subscription_plans_id_fk" FOREIGN KEY ("plan_id") REFERENCES "public"."subscription_plans"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_users" ADD CONSTRAINT "tenant_users_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_users" ADD CONSTRAINT "tenant_users_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_users" ADD CONSTRAINT "tenant_users_invited_by_users_id_fk" FOREIGN KEY ("invited_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhooks_log" ADD CONSTRAINT "webhooks_log_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhooks_log" ADD CONSTRAINT "webhooks_log_subscription_id_tenant_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."tenant_subscriptions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_approval_tenant_status" ON "approval_workflows" USING btree ("tenant_id","status");--> statement-breakpoint
CREATE INDEX "idx_approval_expires" ON "approval_workflows" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_workflow_approver" ON "approvals" USING btree ("workflow_id","approver_id");--> statement-breakpoint
CREATE INDEX "idx_approval_audit_link" ON "approvals" USING btree ("audit_event_id");--> statement-breakpoint
CREATE INDEX "idx_audit_tenant_action" ON "audit_events" USING btree ("tenant_id","action");--> statement-breakpoint
CREATE INDEX "idx_audit_user_time" ON "audit_events" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_target" ON "audit_events" USING btree ("target_type","target_id");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_tenant_key" ON "encryption_keys" USING btree ("tenant_id","id");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_current_version_per_family" ON "encryption_keys" USING btree (COALESCE(parent_key_id, id)) WHERE version_status = 'current';--> statement-breakpoint
CREATE INDEX "idx_keys_rotation_schedule" ON "encryption_keys" USING btree ("tenant_id","next_rotation_at","status");--> statement-breakpoint
CREATE INDEX "idx_keys_versioning" ON "encryption_keys" USING btree ("parent_key_id","version","version_status");--> statement-breakpoint
CREATE INDEX "idx_keys_usage_tracking" ON "encryption_keys" USING btree ("tenant_id","usage_count","max_usage_count");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_key_provider_distribution" ON "key_distributions" USING btree ("key_id","provider_config_id");--> statement-breakpoint
CREATE INDEX "idx_rotation_history_tenant_key" ON "key_rotation_history" USING btree ("tenant_id","key_id");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_role_permission" ON "role_permissions" USING btree ("role","permission","tenant_id");--> statement-breakpoint
CREATE INDEX "idx_role_permission_granted" ON "role_permissions" USING btree ("role","is_granted");--> statement-breakpoint
CREATE INDEX "IDX_session_expire" ON "sessions" USING btree ("expire");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_stripe_product" ON "subscription_plans" USING btree ("stripe_product_id") WHERE stripe_product_id IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "unique_stripe_price" ON "subscription_plans" USING btree ("stripe_price_id") WHERE stripe_price_id IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "unique_paypal_product" ON "subscription_plans" USING btree ("paypal_product_id") WHERE paypal_product_id IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "unique_paypal_plan" ON "subscription_plans" USING btree ("paypal_plan_id") WHERE paypal_plan_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_plan_active_sort" ON "subscription_plans" USING btree ("is_active","sort_order");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_tenant_feature" ON "tenant_feature_overrides" USING btree ("tenant_id","feature_code");--> statement-breakpoint
CREATE INDEX "idx_tenant_feature_enabled" ON "tenant_feature_overrides" USING btree ("tenant_id","enabled");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_active_tenant_subscription" ON "tenant_subscriptions" USING btree ("tenant_id") WHERE status IN ('active', 'trialing');--> statement-breakpoint
CREATE INDEX "idx_tenant_subscription_status" ON "tenant_subscriptions" USING btree ("tenant_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_user_tenant_membership" ON "tenant_users" USING btree ("tenant_id","user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "unique_webhook_event" ON "webhooks_log" USING btree ("provider","event_id");--> statement-breakpoint
CREATE INDEX "idx_webhook_provider_type" ON "webhooks_log" USING btree ("provider","event_type");--> statement-breakpoint
CREATE INDEX "idx_webhook_status" ON "webhooks_log" USING btree ("status","received_at");