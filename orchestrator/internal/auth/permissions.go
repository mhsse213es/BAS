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
	CanCreateCampaign Permission = "campaigns:create"
	CanStopCampaign   Permission = "campaigns:stop"
	// CanTargetAllAgents is Admin-only, unlike every other campaign
	// permission in this block -- targeting the entire fleet in one launch
	// is a materially bigger blast radius than targeting a group or an
	// explicit list, so it gets its own stricter gate rather than riding
	// on CanCreateCampaign.
	CanTargetAllAgents  Permission = "campaigns:target-all-agents"
	CanSetFindingStatus Permission = "findings:set-status"
	CanPushToITSM       Permission = "ticketing:push"
	CanBulkPushToITSM   Permission = "ticketing:push-bulk"

	// Custom scenario authoring — Analyst+Admin.
	CanCreateScenario Permission = "scenarios:create"
	CanUploadScenario Permission = "scenarios:upload"
	CanCloneScenario  Permission = "scenarios:clone"
	CanUpdateScenario Permission = "scenarios:update"
	CanDeleteScenario Permission = "scenarios:delete"

	// Content registry (TCF Phase 1) — artifact view is Analyst+Admin;
	// lifecycle transitions and the migration report are Admin only.
	CanViewContentArtifact        Permission = "content:artifact:view"
	CanTransitionContent          Permission = "content:transition"
	CanViewContentMigrationReport Permission = "content:migration:view"
	// CanManageComponents (TCF Phase 4) gates component promotion/reference
	// registration and composition -- a distinct capability from lifecycle
	// transition, though both are Admin-tier.
	CanManageComponents Permission = "content:manage-components"

	// Variant executor — Analyst+Admin.
	CanGenerateVariants    Permission = "variants:generate"
	CanRunVariants         Permission = "variants:run"
	CanViewVariantRun      Permission = "variants:run:view"
	CanViewVariantCoverage Permission = "variants:coverage:view"
	CanViewVariantStats    Permission = "variants:stats:view"
	CanViewAPIBASRuns      Permission = "apibas:runs:view"

	// Aleef API discovery (separate licence add-on). View reads runs, findings and regressions; run creates
	// engagements, starts and stops runs and records prior-knowledge reviews. Viewer holds neither.
	CanViewAleef Permission = "aleef:view"
	CanRunAleef  Permission = "aleef:run"
	// CanAuthorizeAleef creates engagements: the approval that lets runs touch a target. Admin only, and the
	// approver recorded is always the authenticated user, so an operator cannot approve their own scope.
	CanAuthorizeAleef Permission = "aleef:authorize"

	// Payload families — read is Analyst+Admin (write is Admin only, below).
	CanListPayloadFamilies Permission = "payload-families:list"
	CanViewPayloadFamily   Permission = "payload-families:view"

	// Exercise Engine executions — Analyst+Admin can run and observe.
	CanLaunchExerciseExecution Permission = "exercises:executions:launch"
	CanAbortExerciseExecution  Permission = "exercises:executions:abort"
	CanApproveExerciseStep     Permission = "exercises:executions:approve-step"
	// Kubernetes state-changing scenarios: request plans a run, approve authorises one run (a different operator
	// from the requester), execute runs an approved run as its requester.
	CanRequestK8sScenario Permission = "k8s-scenarios:request"
	CanApproveK8sScenario Permission = "k8s-scenarios:approve"
	CanExecuteK8sScenario Permission = "k8s-scenarios:execute"
	CanInjectExerciseEvidence  Permission = "exercises:executions:inject-evidence"

	// Admin-only: agent state, license, connection config.
	CanSetAgentState        Permission = "agents:set-state"
	CanStopAgent            Permission = "agents:stop"
	CanRemoveAgent          Permission = "agents:remove"
	CanViewLicense          Permission = "license:view"
	CanViewConnectionConfig Permission = "config:view-connection"
	CanManageAgentGroups    Permission = "agent-groups:manage"
	// CanViewAgentGroups is read-only and, unlike every other permission in
	// this block, is granted to Analyst as well as Admin -- reading the
	// group hierarchy is not a management action.
	CanViewAgentGroups Permission = "agent-groups:view"

	// Admin-only: user management.
	CanListUsers         Permission = "users:list"
	CanCreateUser        Permission = "users:create"
	CanUpdateUser        Permission = "users:update"
	CanDeleteUser        Permission = "users:delete"
	CanResetUserPassword Permission = "users:reset-password"

	// Admin-only: Caldera engine status, threat-intel connector.
	CanViewCalderaStatus   Permission = "caldera:status:view"
	CanViewConnectorStatus Permission = "connector:status:view"
	CanSyncConnector       Permission = "connector:sync"
	// CanUpdateConnectorConfig is Admin-only, matching CanViewConnectorStatus
	// and CanSyncConnector's existing tier -- it gates writing MISP/OpenCTI/
	// OTX connection settings (URL, API key), not just viewing or triggering
	// a sync of whatever's already configured.
	CanUpdateConnectorConfig Permission = "connector:config:update"
	// CanManageExecutionPolicy sets the installation-wide default for execution
	// policies that have no safe built-in value, such as the in-process host
	// language-mode requirement. Admin only: the default changes what every
	// later run is judged against.
	CanManageExecutionPolicy   Permission = "execution-policy:manage"
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
	// Pipeline injection and cleanup approvals. Admin-only. Self-approval is governed by
	// the deployment classification, not by this permission.
	CanApprovePipelineInjection Permission = "pipeline:injection:approve"
	CanApprovePipelineCleanup   Permission = "pipeline:cleanup:approve"

	// Backup & Recovery — Admin-only. The console never performs the backup
	// itself (see docs/superpowers/specs/2026-08-17-backup-recovery-design.md);
	// this permission gates only the ability to request one and to flag a
	// backup for restore intent (an audit marker, not an execution trigger).
	CanManageBackups Permission = "backups:manage"

	// TCF Phase 2A: link/new/dismiss unresolved actor identities (Admin only).
	CanResolveActorIdentity Permission = "intel:resolve-actor"

	// TCF Phase 2B: change a source instance's trust state (Admin only).
	CanManageSourceTrust Permission = "intel:manage-source-trust"

	// TCF Phase 2C: link a custom content version to a canonical threat
	// (Admin only).
	CanLinkContentThreat Permission = "content:link-threat"

	// network-policy:import gates importing a normalized firewall/
	// segmentation policy document (Network BAS Phase 2A) -- granted
	// alongside CanRunScenario, not admin-only, since this is an
	// analyst-usable, evidence-producing action.
	CanImportNetworkPolicy Permission = "network-policy:import"

	// network-topology:import gates importing a declared L3
	// zone-adjacency topology (Network BAS Phase 3) -- same placement
	// as CanImportNetworkPolicy, for the same reason.
	CanImportNetworkTopology Permission = "network-topology:import"

	// network-control-expectation:import gates importing a declared set
	// of expected firewall/IDS-IPS control outcomes (Network BAS Phase
	// 4) -- same placement as CanImportNetworkTopology, for the same
	// reason.
	CanImportNetworkControlExpectation Permission = "network-control-expectation:import"

	// cloud-topology:import gates importing a normalized cloud
	// network topology (VPCs, subnets, security groups, route tables,
	// peering -- Network BAS Phase 6A) -- same placement as
	// CanImportNetworkTopology, for the same reason.
	CanImportCloudTopology Permission = "cloud-topology:import"

	// remote-access:import gates importing on-premises VPN-tunnel and
	// mandatory-transit (bastion) boundary data (Network BAS Phase 6B)
	// -- same placement as CanImportCloudTopology, for the same reason.
	CanImportRemoteAccessTopology Permission = "remote-access:import"

	// ot-safety:import gates importing OT/ICS sensitive-zone and
	// required-transit declarations (Network BAS Phase 7A) -- same
	// placement as CanImportRemoteAccessTopology, for the same reason.
	CanImportOTSafetyConfig Permission = "ot-safety:import"

	// zone-isolation:import gates importing declared zone-pair
	// isolation expectations (Network BAS Phase 7B) -- same placement
	// as CanImportOTSafetyConfig, for the same reason.
	CanImportZoneIsolationConfig Permission = "zone-isolation:import"

	// regulatory-obligation:manage gates creating/listing regulatory
	// obligations and their evidence snapshots (Network BAS Phase 7C)
	// -- same placement as CanImportZoneIsolationConfig, for the same
	// reason.
	CanManageRegulatoryObligations Permission = "regulatory-obligation:manage"

	// target-scope:import gates importing a declared authorized
	// target-scope allowlist for active network probing -- same
	// placement as CanImportOTSafetyConfig, for the same reason.
	CanImportTargetScope Permission = "target-scope:import"
)

// rolePermissions maps each role to the permissions it holds. Viewer is
// read-only and holds none of the verification permissions.
var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin: {
		CanManageExecutionPolicy: true,

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
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true, CanTargetAllAgents: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,

		CanViewContentArtifact: true, CanTransitionContent: true, CanViewContentMigrationReport: true, CanManageComponents: true,

		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true, CanViewAPIBASRuns: true, CanViewAleef: true, CanRunAleef: true, CanAuthorizeAleef: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
		CanRequestK8sScenario: true, CanApproveK8sScenario: true, CanExecuteK8sScenario: true,

		CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true, CanManageAgentGroups: true, CanViewAgentGroups: true,
		CanListUsers: true, CanCreateUser: true, CanUpdateUser: true, CanDeleteUser: true,
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanUpdateConnectorConfig: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
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
		CanApprovePipelineInjection: true, CanApprovePipelineCleanup: true,
		CanManageBackups:                   true,
		CanResolveActorIdentity:            true,
		CanManageSourceTrust:               true,
		CanLinkContentThreat:               true,
		CanImportNetworkPolicy:             true,
		CanImportNetworkTopology:           true,
		CanImportNetworkControlExpectation: true,
		CanImportCloudTopology:             true,
		CanImportRemoteAccessTopology:      true,
		CanImportOTSafetyConfig:            true,
		CanImportZoneIsolationConfig:       true,
		CanManageRegulatoryObligations:     true,
		CanImportTargetScope:               true,
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
		CanImportNetworkPolicy: true, CanImportNetworkTopology: true, CanImportNetworkControlExpectation: true, CanImportCloudTopology: true, CanImportRemoteAccessTopology: true, CanImportOTSafetyConfig: true, CanImportZoneIsolationConfig: true, CanManageRegulatoryObligations: true, CanImportTargetScope: true,
		CanCancelScenarioRun: true, CanCorrelateSIEM: true, CanViewSIEMCorrelations: true,
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,

		CanViewContentArtifact: true,

		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true, CanViewAPIBASRuns: true, CanViewAleef: true, CanRunAleef: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
		CanRequestK8sScenario: true, CanExecuteK8sScenario: true,
		CanViewResponseActions: true,
		// Read-only counterpart to the admin-only CanManageAgentGroups --
		// analysts can see and target agent groups, not create/rename/
		// move/delete them.
		CanViewAgentGroups:    true,
		CanExecuteRemediation: true,
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
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanTargetAllAgents, CanSetFindingStatus,
		CanPushToITSM, CanBulkPushToITSM, CanCreateScenario, CanUploadScenario, CanCloneScenario,
		CanUpdateScenario, CanDeleteScenario, CanGenerateVariants, CanRunVariants, CanViewVariantRun,
		CanViewVariantCoverage, CanViewVariantStats, CanListPayloadFamilies, CanViewPayloadFamily,
		CanLaunchExerciseExecution, CanAbortExerciseExecution, CanApproveExerciseStep,
		CanInjectExerciseEvidence, CanLookupIOC,

		CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanManageAgentGroups, CanViewAgentGroups, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanUpdateConnectorConfig, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
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
		CanManageBackups,
		CanResolveActorIdentity,
		CanManageSourceTrust,
		CanLinkContentThreat,
		CanImportNetworkPolicy, CanImportNetworkTopology, CanImportNetworkControlExpectation, CanImportCloudTopology,
		CanViewContentArtifact, CanTransitionContent, CanViewContentMigrationReport, CanManageComponents,
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

// RequireAnyPermission admits a caller holding at least one of the permissions. A route that serves
// several approval kinds uses it at the door; the handler then checks the exact permission for the
// kind it is acting on.
func RequireAnyPermission(perms ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			for _, p := range perms {
				if HasPermission(claims.Role, p) {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
	}
}
