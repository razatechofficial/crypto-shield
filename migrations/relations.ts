import { relations } from "drizzle-orm/relations";
import { tenants, accessPolicies, users, approvalWorkflows, auditEvents, approvals, certificateAuthorities, hsmKeys, byokImports, encryptionKeys, cloudProviderConfigs, apiUsage, cryptoOperations, sdks, complianceAssessments, compliancePolicies, encryptionAlgorithms } from "./schema";

export const accessPoliciesRelations = relations(accessPolicies, ({one}) => ({
	tenant: one(tenants, {
		fields: [accessPolicies.tenantId],
		references: [tenants.id]
	}),
	user_createdBy: one(users, {
		fields: [accessPolicies.createdBy],
		references: [users.id],
		relationName: "accessPolicies_createdBy_users_id"
	}),
	user_approvedBy: one(users, {
		fields: [accessPolicies.approvedBy],
		references: [users.id],
		relationName: "accessPolicies_approvedBy_users_id"
	}),
}));

export const tenantsRelations = relations(tenants, ({many}) => ({
	accessPolicies: many(accessPolicies),
	approvalWorkflows: many(approvalWorkflows),
	auditEvents: many(auditEvents),
	certificateAuthorities: many(certificateAuthorities),
	byokImports: many(byokImports),
	cloudProviderConfigs: many(cloudProviderConfigs),
	apiUsages: many(apiUsage),
	cryptoOperations: many(cryptoOperations),
	complianceAssessments: many(complianceAssessments),
	compliancePolicies: many(compliancePolicies),
	encryptionKeys: many(encryptionKeys),
}));

export const usersRelations = relations(users, ({many}) => ({
	accessPolicies_createdBy: many(accessPolicies, {
		relationName: "accessPolicies_createdBy_users_id"
	}),
	accessPolicies_approvedBy: many(accessPolicies, {
		relationName: "accessPolicies_approvedBy_users_id"
	}),
	approvalWorkflows: many(approvalWorkflows),
	auditEvents: many(auditEvents),
	approvals: many(approvals),
	byokImports_importedBy: many(byokImports, {
		relationName: "byokImports_importedBy_users_id"
	}),
	byokImports_validatedBy: many(byokImports, {
		relationName: "byokImports_validatedBy_users_id"
	}),
	cloudProviderConfigs: many(cloudProviderConfigs),
	complianceAssessments: many(complianceAssessments),
	compliancePolicies: many(compliancePolicies),
}));

export const approvalWorkflowsRelations = relations(approvalWorkflows, ({one, many}) => ({
	tenant: one(tenants, {
		fields: [approvalWorkflows.tenantId],
		references: [tenants.id]
	}),
	user: one(users, {
		fields: [approvalWorkflows.requestedBy],
		references: [users.id]
	}),
	auditEvent: one(auditEvents, {
		fields: [approvalWorkflows.auditEventId],
		references: [auditEvents.id]
	}),
	approvals: many(approvals),
}));

export const auditEventsRelations = relations(auditEvents, ({one, many}) => ({
	approvalWorkflows: many(approvalWorkflows),
	tenant: one(tenants, {
		fields: [auditEvents.tenantId],
		references: [tenants.id]
	}),
	user: one(users, {
		fields: [auditEvents.userId],
		references: [users.id]
	}),
	approvals: many(approvals),
}));

export const approvalsRelations = relations(approvals, ({one}) => ({
	approvalWorkflow: one(approvalWorkflows, {
		fields: [approvals.workflowId],
		references: [approvalWorkflows.id]
	}),
	user: one(users, {
		fields: [approvals.approverId],
		references: [users.id]
	}),
	auditEvent: one(auditEvents, {
		fields: [approvals.auditEventId],
		references: [auditEvents.id]
	}),
}));

export const certificateAuthoritiesRelations = relations(certificateAuthorities, ({one}) => ({
	tenant: one(tenants, {
		fields: [certificateAuthorities.tenantId],
		references: [tenants.id]
	}),
	hsmKey: one(hsmKeys, {
		fields: [certificateAuthorities.keyId],
		references: [hsmKeys.id]
	}),
}));

export const hsmKeysRelations = relations(hsmKeys, ({many}) => ({
	certificateAuthorities: many(certificateAuthorities),
}));

export const byokImportsRelations = relations(byokImports, ({one}) => ({
	tenant: one(tenants, {
		fields: [byokImports.tenantId],
		references: [tenants.id]
	}),
	encryptionKey: one(encryptionKeys, {
		fields: [byokImports.keyId],
		references: [encryptionKeys.id]
	}),
	user_importedBy: one(users, {
		fields: [byokImports.importedBy],
		references: [users.id],
		relationName: "byokImports_importedBy_users_id"
	}),
	user_validatedBy: one(users, {
		fields: [byokImports.validatedBy],
		references: [users.id],
		relationName: "byokImports_validatedBy_users_id"
	}),
}));

export const encryptionKeysRelations = relations(encryptionKeys, ({one, many}) => ({
	byokImports: many(byokImports),
	cryptoOperations: many(cryptoOperations),
	tenant: one(tenants, {
		fields: [encryptionKeys.tenantId],
		references: [tenants.id]
	}),
	encryptionAlgorithm: one(encryptionAlgorithms, {
		fields: [encryptionKeys.algorithmId],
		references: [encryptionAlgorithms.id]
	}),
}));

export const cloudProviderConfigsRelations = relations(cloudProviderConfigs, ({one}) => ({
	tenant: one(tenants, {
		fields: [cloudProviderConfigs.tenantId],
		references: [tenants.id]
	}),
	user: one(users, {
		fields: [cloudProviderConfigs.createdBy],
		references: [users.id]
	}),
}));

export const apiUsageRelations = relations(apiUsage, ({one}) => ({
	tenant: one(tenants, {
		fields: [apiUsage.tenantId],
		references: [tenants.id]
	}),
}));

export const cryptoOperationsRelations = relations(cryptoOperations, ({one}) => ({
	tenant: one(tenants, {
		fields: [cryptoOperations.tenantId],
		references: [tenants.id]
	}),
	sdk: one(sdks, {
		fields: [cryptoOperations.sdkId],
		references: [sdks.id]
	}),
	encryptionKey: one(encryptionKeys, {
		fields: [cryptoOperations.keyId],
		references: [encryptionKeys.id]
	}),
}));

export const sdksRelations = relations(sdks, ({many}) => ({
	cryptoOperations: many(cryptoOperations),
}));

export const complianceAssessmentsRelations = relations(complianceAssessments, ({one}) => ({
	tenant: one(tenants, {
		fields: [complianceAssessments.tenantId],
		references: [tenants.id]
	}),
	user: one(users, {
		fields: [complianceAssessments.assessor],
		references: [users.id]
	}),
}));

export const compliancePoliciesRelations = relations(compliancePolicies, ({one}) => ({
	tenant: one(tenants, {
		fields: [compliancePolicies.tenantId],
		references: [tenants.id]
	}),
	user: one(users, {
		fields: [compliancePolicies.createdBy],
		references: [users.id]
	}),
}));

export const encryptionAlgorithmsRelations = relations(encryptionAlgorithms, ({many}) => ({
	encryptionKeys: many(encryptionKeys),
}));