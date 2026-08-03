package auth

import "net/http"

// Permission is a fine-grained capability, decoupled from role. The Verification
// Store (SP2) authorizes on permissions rather than raw roles so a large SOC can
// separate the analyst who verifies from the reviewer who approves, and so
// evidence deletion (accountability-sensitive) is restricted independently.
type Permission string

const (
	CanVerify         Permission = "verification:verify"          // create/update an attestation
	CanUploadEvidence Permission = "verification:evidence:upload" // attach evidence to a verification
	CanDeleteEvidence Permission = "verification:evidence:delete" // soft-delete evidence
	CanReview         Permission = "verification:review"          // approve/reject in the review pipeline
	CanExport         Permission = "verification:export"          // export verification data

	// CVE↔ATT&CK Relationship Store permissions.
	CanCurateThreatIntel Permission = "threatintel:curate" // create/edit relationships + evidence
	CanReviewThreatIntel Permission = "threatintel:review" // promote/demote effective confidence, change lifecycle status

	// Attack Path — Analyst+Admin can dispatch fleet-wide graph collection
	// and manage collection jobs.
	CanTriggerScan         Permission = "scan:trigger"
	CanCollectAttackPath   Permission = "attackpath:collect"
	CanCreateAttackPathJob Permission = "attackpath:jobs:create"
	CanCancelAttackPathJob Permission = "attackpath:jobs:cancel"
	CanRetryAttackPathJob  Permission = "attackpath:jobs:retry"
	CanSetAttackPathAsset  Permission = "attackpath:assets:set"

	// Scenario/campaign execution — Analyst+Admin can run and cancel.
	CanRunScenario          Permission = "scenarios:run"
	CanRunCalderaAdversary  Permission = "caldera:adversaries:run"
	CanRunAdversaryTemplate Permission = "adversary-templates:run"
	CanCancelScenarioRun    Permission = "scenarios:runs:cancel"

	// SIEM correlation + detection verification — Analyst+Admin can trigger.
	CanCorrelateSIEM            Permission = "siem:correlate"
	CanViewSIEMCorrelations     Permission = "siem:correlations:view"
	CanRunDetectionVerification Permission = "detectverify:run"
	CanLookupIOC                Permission = "ioc:lookup"

	// Campaigns, findings, ITSM push — Analyst+Admin.
	CanCreateCampaign   Permission = "campaigns:create"
	CanStopCampaign     Permission = "campaigns:stop"
	CanSetFindingStatus Permission = "findings:set-status"
	CanPushToITSM       Permission = "ticketing:push"
	CanBulkPushToITSM   Permission = "ticketing:push-bulk"

	// Custom scenario authoring — Analyst+Admin.
	CanCreateScenario Permission = "scenarios:create"
	CanUploadScenario Permission = "scenarios:upload"
	CanCloneScenario  Permission = "scenarios:clone"
	CanUpdateScenario Permission = "scenarios:update"
	CanDeleteScenario Permission = "scenarios:delete"

	// Variant executor — Analyst+Admin.
	CanGenerateVariants    Permission = "variants:generate"
	CanRunVariants         Permission = "variants:run"
	CanViewVariantRun      Permission = "variants:run:view"
	CanViewVariantCoverage Permission = "variants:coverage:view"
	CanViewVariantStats    Permission = "variants:stats:view"

	// Payload families — read is Analyst+Admin (write is Admin only, below).
	CanListPayloadFamilies Permission = "payload-families:list"
	CanViewPayloadFamily   Permission = "payload-families:view"

	// Exercise Engine executions — Analyst+Admin can run and observe.
	CanLaunchExerciseExecution Permission = "exercises:executions:launch"
	CanAbortExerciseExecution  Permission = "exercises:executions:abort"
	CanApproveExerciseStep     Permission = "exercises:executions:approve-step"
	CanInjectExerciseEvidence  Permission = "exercises:executions:inject-evidence"

	// Admin-only: agent state, license, connection config.
	CanSetAgentState        Permission = "agents:set-state"
	CanStopAgent            Permission = "agents:stop"
	CanViewLicense          Permission = "license:view"
	CanViewConnectionConfig Permission = "config:view-connection"

	// Admin-only: user management.
	CanListUsers         Permission = "users:list"
	CanCreateUser        Permission = "users:create"
	CanUpdateUser        Permission = "users:update"
	CanDeleteUser        Permission = "users:delete"
	CanResetUserPassword Permission = "users:reset-password"

	// Admin-only: Caldera engine status, threat-intel connector.
	CanViewCalderaStatus       Permission = "caldera:status:view"
	CanViewConnectorStatus     Permission = "connector:status:view"
	CanSyncConnector           Permission = "connector:sync"
	CanDeleteConnectorScenario Permission = "connector:scenarios:delete"

	// Admin-only: attack-path schedule, ART content management.
	CanSetAttackPathSchedule Permission = "attackpath:schedule:set"
	CanViewARTContentStatus  Permission = "art-content:status:view"
	CanReseedARTContent      Permission = "art-content:reseed"

	// Admin-only: global search reindex trigger.
	CanReindexSearch Permission = "search:reindex"

	// Admin-only: IOC registry management (suppress/unsuppress, customer import).
	CanManageIOCs Permission = "iocs:manage"

	// Admin-only: filesystem integrity tamper events, audit log.
	CanViewTamperEvents           Permission = "tamper:events:view"
	CanAcknowledgeTamperEvent     Permission = "tamper:events:acknowledge"
	CanAcknowledgeAllTamperEvents Permission = "tamper:events:acknowledge-all"
	CanViewAuditLogs              Permission = "audit-logs:view"

	// Admin-only: ITSM connector config.
	CanListTicketingConfigs   Permission = "ticketing:configs:list"
	CanCreateTicketingConfig  Permission = "ticketing:configs:create"
	CanUpdateTicketingConfig  Permission = "ticketing:configs:update"
	CanDeleteTicketingConfig  Permission = "ticketing:configs:delete"
	CanTestTicketingConfig    Permission = "ticketing:configs:test"
	CanProbeTicketingConfig   Permission = "ticketing:probe"
	CanProbeTicketingProjects Permission = "ticketing:probe-projects"
	CanSyncTicketing          Permission = "ticketing:sync"

	// Admin-only: payload family write/delete.
	CanCreatePayloadFamily Permission = "payload-families:create"
	CanDeletePayloadFamily Permission = "payload-families:delete"

	// Admin-only: SIEM correlation connector config.
	CanListSIEMConfigs  Permission = "siem:configs:list"
	CanCreateSIEMConfig Permission = "siem:configs:create"
	CanUpdateSIEMConfig Permission = "siem:configs:update"
	CanDeleteSIEMConfig Permission = "siem:configs:delete"
	CanTestSIEMConfig   Permission = "siem:configs:test"

	// Admin-only: Detection Verification connector config.
	CanListDetectionConnectors  Permission = "detectverify:configs:list"
	CanCreateDetectionConnector Permission = "detectverify:configs:create"
	CanUpdateDetectionConnector Permission = "detectverify:configs:update"
	CanDeleteDetectionConnector Permission = "detectverify:configs:delete"
	CanTestDetectionConnector   Permission = "detectverify:configs:test"

	// EPP Response Actions — CanExecuteResponseAction is Admin-only,
	// deliberately stricter than every other "run" permission in this file
	// (all of which are Analyst+Admin): unlike detectverify (read-only),
	// executing a response action can isolate a live host, kill a process,
	// or delete/quarantine a file. CanViewResponseActions (the audit trail)
	// is Analyst+Admin like other "view" permissions; connector config is
	// Admin-only like every other connector config in this file.
	CanExecuteResponseAction   Permission = "actions:execute"
	CanViewResponseActions     Permission = "actions:view"
	CanListResponseConnectors  Permission = "actions:connectors:list"
	CanCreateResponseConnector Permission = "actions:connectors:create"
	CanUpdateResponseConnector Permission = "actions:connectors:update"
	CanDeleteResponseConnector Permission = "actions:connectors:delete"
	CanTestResponseConnector   Permission = "actions:connectors:test"

	// Admin-only: OpenAEV Connector config + sync + air-gapped import.
	CanViewOpenAEVConfig             Permission = "openaev:config:view"
	CanUpdateOpenAEVConfig           Permission = "openaev:config:update"
	CanTestOpenAEVConfig             Permission = "openaev:config:test"
	CanSyncOpenAEV                   Permission = "openaev:sync"
	CanImportOpenAEVBundle           Permission = "openaev:import"
	CanCreateExercisePlanFromOpenAEV Permission = "openaev:scenarios:create-plan"

	// Admin-only: exercise plan/template authoring.
	CanCreateExercisePlan          Permission = "exercises:plans:create"
	CanValidateExercisePlan        Permission = "exercises:plans:validate"
	CanUpdateExercisePlan          Permission = "exercises:plans:update"
	CanDeleteExercisePlan          Permission = "exercises:plans:delete"
	CanCreateExerciseTemplate      Permission = "exercises:templates:create"
	CanInstantiateExerciseTemplate Permission = "exercises:templates:instantiate"

	// SSO (OIDC) config — Admin only. New capability, not a route that
	// existed before this slice, so it doesn't inherit a Group A/B grant
	// from the RBAC-expansion migration.
	CanViewSSOConfig   Permission = "sso:config:view"
	CanManageSSOConfig Permission = "sso:config:manage"

	// SCIM provisioning — Admin only. Separate from SSO's permissions:
	// different protocol, different admin action (rotate a token vs.
	// configure an IdP issuer).
	CanViewSCIMConfig   Permission = "scim:config:view"
	CanManageSCIMConfig Permission = "scim:config:manage"

	// Endpoint Remediation Execution — CanExecuteRemediation is Analyst+Admin
	// (Tier 1 fixes); CanApproveRemediation is Admin-only, deliberately
	// stricter (Tier 2 fixes and every rollback -- reversing a security
	// control is inherently risk-increasing, mirroring how
	// CanExecuteResponseAction is stricter than every other "run"
	// permission in this file).
	CanExecuteRemediation Permission = "remediation:execute"
	CanApproveRemediation Permission = "remediation:approve"
)

// rolePermissions maps each role to the permissions it holds. Viewer is
// read-only and holds none of the verification permissions.
var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin: {
		CanVerify:            true,
		CanUploadEvidence:    true,
		CanDeleteEvidence:    true,
		CanReview:            true,
		CanExport:            true,
		CanCurateThreatIntel: true,
		CanReviewThreatIntel: true,

		// Phase 7 RBAC expansion — Group A (34, also granted to Analyst below)
		// and Group B (51, admin-only) from the 2026-07-18 migration.
		CanTriggerScan: true, CanCollectAttackPath: true, CanCreateAttackPathJob: true,
		CanCancelAttackPathJob: true, CanRetryAttackPathJob: true, CanSetAttackPathAsset: true,
		CanRunScenario: true, CanRunCalderaAdversary: true, CanRunAdversaryTemplate: true,
		CanCancelScenarioRun: true, CanCorrelateSIEM: true, CanViewSIEMCorrelations: true,
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,
		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,

		CanSetAgentState: true, CanStopAgent: true, CanViewLicense: true, CanViewConnectionConfig: true,
		CanListUsers: true, CanCreateUser: true, CanUpdateUser: true, CanDeleteUser: true,
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanReindexSearch: true, CanManageIOCs: true, CanViewTamperEvents: true,
		CanAcknowledgeTamperEvent: true, CanAcknowledgeAllTamperEvents: true, CanViewAuditLogs: true,
		CanListTicketingConfigs: true, CanCreateTicketingConfig: true, CanUpdateTicketingConfig: true,
		CanDeleteTicketingConfig: true, CanTestTicketingConfig: true, CanProbeTicketingConfig: true,
		CanProbeTicketingProjects: true, CanSyncTicketing: true, CanCreatePayloadFamily: true,
		CanDeletePayloadFamily: true, CanListSIEMConfigs: true, CanCreateSIEMConfig: true,
		CanUpdateSIEMConfig: true, CanDeleteSIEMConfig: true, CanTestSIEMConfig: true,
		CanListDetectionConnectors: true, CanCreateDetectionConnector: true,
		CanUpdateDetectionConnector: true, CanDeleteDetectionConnector: true,
		CanTestDetectionConnector: true, CanExecuteResponseAction: true, CanViewResponseActions: true,
		CanListResponseConnectors: true, CanCreateResponseConnector: true, CanUpdateResponseConnector: true,
		CanDeleteResponseConnector: true, CanTestResponseConnector: true,
		CanViewOpenAEVConfig: true, CanUpdateOpenAEVConfig: true,
		CanTestOpenAEVConfig: true, CanSyncOpenAEV: true, CanImportOpenAEVBundle: true,
		CanCreateExercisePlanFromOpenAEV: true, CanCreateExercisePlan: true,
		CanValidateExercisePlan: true, CanUpdateExercisePlan: true, CanDeleteExercisePlan: true,
		CanCreateExerciseTemplate: true, CanInstantiateExerciseTemplate: true,
		CanViewSSOConfig: true, CanManageSSOConfig: true,
		CanViewSCIMConfig: true, CanManageSCIMConfig: true,
		CanExecuteRemediation: true, CanApproveRemediation: true,
	},
	RoleAnalyst: {
		CanVerify:            true,
		CanUploadEvidence:    true,
		CanReview:            true,
		CanExport:            true,
		CanCurateThreatIntel: true,
		// CanDeleteEvidence and CanReviewThreatIntel intentionally withheld —
		// deletion and confidence review are admin-only so a single analyst
		// cannot quietly remove audit material or self-approve their own claim.

		// Phase 7 RBAC expansion — Group A only (34); Group B is admin-only.
		CanTriggerScan: true, CanCollectAttackPath: true, CanCreateAttackPathJob: true,
		CanCancelAttackPathJob: true, CanRetryAttackPathJob: true, CanSetAttackPathAsset: true,
		CanRunScenario: true, CanRunCalderaAdversary: true, CanRunAdversaryTemplate: true,
		CanCancelScenarioRun: true, CanCorrelateSIEM: true, CanViewSIEMCorrelations: true,
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,
		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
		CanViewResponseActions: true,
		CanExecuteRemediation:  true,
	},
	RoleViewer: {},
}

// HasPermission reports whether a role holds a permission.
func HasPermission(role Role, perm Permission) bool {
	return rolePermissions[role][perm]
}

// Permissions returns the full permission set granted to a role, for the client
// to enable/disable controls in the UI.
func Permissions(role Role) []Permission {
	set := rolePermissions[role]
	out := make([]Permission, 0, len(set))
	for _, p := range []Permission{
		CanVerify, CanUploadEvidence, CanDeleteEvidence, CanReview, CanExport,
		CanCurateThreatIntel, CanReviewThreatIntel,

		CanTriggerScan, CanCollectAttackPath, CanCreateAttackPathJob, CanCancelAttackPathJob,
		CanRetryAttackPathJob, CanSetAttackPathAsset, CanRunScenario, CanRunCalderaAdversary,
		CanRunAdversaryTemplate, CanCancelScenarioRun, CanCorrelateSIEM, CanViewSIEMCorrelations,
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanSetFindingStatus,
		CanPushToITSM, CanBulkPushToITSM, CanCreateScenario, CanUploadScenario, CanCloneScenario,
		CanUpdateScenario, CanDeleteScenario, CanGenerateVariants, CanRunVariants, CanViewVariantRun,
		CanViewVariantCoverage, CanViewVariantStats, CanListPayloadFamilies, CanViewPayloadFamily,
		CanLaunchExerciseExecution, CanAbortExerciseExecution, CanApproveExerciseStep,
		CanInjectExerciseEvidence, CanLookupIOC,

		CanSetAgentState, CanStopAgent, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
		CanReseedARTContent, CanReindexSearch, CanManageIOCs, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,
		CanViewAuditLogs, CanListTicketingConfigs, CanCreateTicketingConfig, CanUpdateTicketingConfig,
		CanDeleteTicketingConfig, CanTestTicketingConfig, CanProbeTicketingConfig, CanProbeTicketingProjects,
		CanSyncTicketing, CanCreatePayloadFamily, CanDeletePayloadFamily, CanListSIEMConfigs,
		CanCreateSIEMConfig, CanUpdateSIEMConfig, CanDeleteSIEMConfig, CanTestSIEMConfig,
		CanListDetectionConnectors, CanCreateDetectionConnector, CanUpdateDetectionConnector,
		CanDeleteDetectionConnector, CanTestDetectionConnector,
		CanExecuteResponseAction, CanViewResponseActions, CanListResponseConnectors,
		CanCreateResponseConnector, CanUpdateResponseConnector, CanDeleteResponseConnector, CanTestResponseConnector,
		CanViewOpenAEVConfig, CanUpdateOpenAEVConfig,
		CanTestOpenAEVConfig, CanSyncOpenAEV, CanImportOpenAEVBundle, CanCreateExercisePlanFromOpenAEV,
		CanCreateExercisePlan, CanValidateExercisePlan, CanUpdateExercisePlan, CanDeleteExercisePlan,
		CanCreateExerciseTemplate, CanInstantiateExerciseTemplate,

		CanViewSSOConfig, CanManageSSOConfig,

		CanViewSCIMConfig, CanManageSCIMConfig,

		CanExecuteRemediation, CanApproveRemediation,
	} {
		if set[p] {
			out = append(out, p)
		}
	}
	return out
}

// RequirePermission rejects requests whose role lacks the given permission.
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok || !HasPermission(claims.Role, perm) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	}
}
