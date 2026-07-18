# Phase 7, Sub-project 2 (Identity & Access) — Part 1: RBAC Permission Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every one of the 85 routes currently gated by `auth.RequireRole` its own named `auth.Permission`, with default grants that reproduce today's exact role behavior — zero behavior change, but every sensitive action becomes independently permission-gated.

**Architecture:** Mechanical migration across 4 files. `internal/auth/permissions.go` gains 85 new `Permission` constants and grant-map entries. `internal/api/routes.go`'s two `RequireRole` route groups are dissolved into per-route `RequirePermission` calls. `internal/api/rbac_matrix_test.go`'s drift-detection table is retagged to match. `internal/auth/middleware.go`'s now-dead `RequireRole` is deleted.

**Tech Stack:** Go, chi router, existing `internal/auth` package conventions (`Permission` string type, `rolePermissions` grant map, `RequirePermission` middleware — all pre-existing, unchanged).

## Global Constraints

- **Zero behavior change.** Every route must return the exact same status codes for the exact same roles after this migration as before it. This is proven by `TestRBACMatrix_AuthorizationBoundary`, which must pass unmodified in its assertions (only route *tags* change, not its pass/fail logic).
- **Naming convention:** `<domain>:<action>`, matching the existing `verification:verify` / `threatintel:curate` pattern. Exact names are specified per-route in this plan — do not invent alternate names.
- **No new roles, no per-tenant grants, no UI changes** — see the spec's "Out of scope" section. This plan only touches `internal/auth` and `internal/api` Go files.
- **`auth.RequireRole` is deleted once dead** (Task 4) — this project's standing rule against leaving unused code in place.

---

### Task 1: Add 85 `Permission` constants and grant-map entries

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go`
- Modify: `orchestrator/internal/auth/permissions_test.go`

**Interfaces:**
- Produces: 85 new `Permission` constants (exact names below), each granted to `RoleAdmin`; the 34 "Group A" ones additionally granted to `RoleAnalyst`. `Permissions(RoleAdmin)` returns 92 entries after this task (7 existing + 85 new), `Permissions(RoleAnalyst)` returns 39 (5 existing + 34 new), `Permissions(RoleViewer)` stays empty. These constants are consumed by Task 2 (Group A, 34 of them) and Task 3 (Group B, 51 of them).

- [ ] **Step 1: Add the 34 Group-A constants to `permissions.go`**

In `orchestrator/internal/auth/permissions.go`, inside the existing `const ( ... )` block, immediately after the `CanReviewThreatIntel` line (before the closing `)`), add:

```go

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
	CanApproveExerciseStep    Permission = "exercises:executions:approve-step"
	CanInjectExerciseEvidence Permission = "exercises:executions:inject-evidence"
```

- [ ] **Step 2: Add the 51 Group-B constants to `permissions.go`**

Immediately after the Group-A block from Step 1 (still inside the same `const ( ... )`), add:

```go

	// Admin-only: agent state, license, connection config.
	CanSetAgentState        Permission = "agents:set-state"
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
```

- [ ] **Step 3: Extend the `rolePermissions` grant map**

In the same file, the `rolePermissions` map currently reads:

```go
var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin: {
		CanVerify:            true,
		CanUploadEvidence:    true,
		CanDeleteEvidence:    true,
		CanReview:            true,
		CanExport:            true,
		CanCurateThreatIntel: true,
		CanReviewThreatIntel: true,
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
	},
	RoleViewer: {},
}
```

Replace it with:

```go
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
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true,

		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
		CanListUsers: true, CanCreateUser: true, CanUpdateUser: true, CanDeleteUser: true,
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanViewTamperEvents: true,
		CanAcknowledgeTamperEvent: true, CanAcknowledgeAllTamperEvents: true, CanViewAuditLogs: true,
		CanListTicketingConfigs: true, CanCreateTicketingConfig: true, CanUpdateTicketingConfig: true,
		CanDeleteTicketingConfig: true, CanTestTicketingConfig: true, CanProbeTicketingConfig: true,
		CanProbeTicketingProjects: true, CanSyncTicketing: true, CanCreatePayloadFamily: true,
		CanDeletePayloadFamily: true, CanListSIEMConfigs: true, CanCreateSIEMConfig: true,
		CanUpdateSIEMConfig: true, CanDeleteSIEMConfig: true, CanTestSIEMConfig: true,
		CanListDetectionConnectors: true, CanCreateDetectionConnector: true,
		CanUpdateDetectionConnector: true, CanDeleteDetectionConnector: true,
		CanTestDetectionConnector: true, CanViewOpenAEVConfig: true, CanUpdateOpenAEVConfig: true,
		CanTestOpenAEVConfig: true, CanSyncOpenAEV: true, CanImportOpenAEVBundle: true,
		CanCreateExercisePlanFromOpenAEV: true, CanCreateExercisePlan: true,
		CanValidateExercisePlan: true, CanUpdateExercisePlan: true, CanDeleteExercisePlan: true,
		CanCreateExerciseTemplate: true, CanInstantiateExerciseTemplate: true,
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
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true,
	},
	RoleViewer: {},
}
```

- [ ] **Step 4: Extend the `Permissions()` ordered slice**

In the same file, `Permissions()` currently reads:

```go
func Permissions(role Role) []Permission {
	set := rolePermissions[role]
	out := make([]Permission, 0, len(set))
	for _, p := range []Permission{CanVerify, CanUploadEvidence, CanDeleteEvidence, CanReview, CanExport,
		CanCurateThreatIntel, CanReviewThreatIntel} {
		if set[p] {
			out = append(out, p)
		}
	}
	return out
}
```

Replace the loop's slice literal with the full 92-entry ordered list (existing 7, then Group A's 34, then Group B's 51):

```go
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
		CanInjectExerciseEvidence,

		CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
		CanReseedARTContent, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,
		CanViewAuditLogs, CanListTicketingConfigs, CanCreateTicketingConfig, CanUpdateTicketingConfig,
		CanDeleteTicketingConfig, CanTestTicketingConfig, CanProbeTicketingConfig, CanProbeTicketingProjects,
		CanSyncTicketing, CanCreatePayloadFamily, CanDeletePayloadFamily, CanListSIEMConfigs,
		CanCreateSIEMConfig, CanUpdateSIEMConfig, CanDeleteSIEMConfig, CanTestSIEMConfig,
		CanListDetectionConnectors, CanCreateDetectionConnector, CanUpdateDetectionConnector,
		CanDeleteDetectionConnector, CanTestDetectionConnector, CanViewOpenAEVConfig, CanUpdateOpenAEVConfig,
		CanTestOpenAEVConfig, CanSyncOpenAEV, CanImportOpenAEVBundle, CanCreateExercisePlanFromOpenAEV,
		CanCreateExercisePlan, CanValidateExercisePlan, CanUpdateExercisePlan, CanDeleteExercisePlan,
		CanCreateExerciseTemplate, CanInstantiateExerciseTemplate,
	} {
		if set[p] {
			out = append(out, p)
		}
	}
	return out
}
```

- [ ] **Step 5: Update the two pre-existing tests that hard-code the old 7-permission set**

`permissions_test.go`'s `TestHasPermission_MatrixIsComplete` and `TestPermissions_Ordering` both hard-code the exact set/order of permissions Admin holds. Both will fail once Step 3/4 land unless updated — this is expected, not a regression.

In `orchestrator/internal/auth/permissions_test.go`, replace `TestHasPermission_MatrixIsComplete`'s body:

```go
func TestHasPermission_MatrixIsComplete(t *testing.T) {
	tested := map[Permission]bool{
		CanVerify: true, CanUploadEvidence: true, CanDeleteEvidence: true,
		CanReview: true, CanExport: true, CanCurateThreatIntel: true, CanReviewThreatIntel: true,

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
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true,

		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
		CanListUsers: true, CanCreateUser: true, CanUpdateUser: true, CanDeleteUser: true,
		CanResetUserPassword: true, CanViewCalderaStatus: true, CanViewConnectorStatus: true,
		CanSyncConnector: true, CanDeleteConnectorScenario: true, CanSetAttackPathSchedule: true,
		CanViewARTContentStatus: true, CanReseedARTContent: true, CanViewTamperEvents: true,
		CanAcknowledgeTamperEvent: true, CanAcknowledgeAllTamperEvents: true, CanViewAuditLogs: true,
		CanListTicketingConfigs: true, CanCreateTicketingConfig: true, CanUpdateTicketingConfig: true,
		CanDeleteTicketingConfig: true, CanTestTicketingConfig: true, CanProbeTicketingConfig: true,
		CanProbeTicketingProjects: true, CanSyncTicketing: true, CanCreatePayloadFamily: true,
		CanDeletePayloadFamily: true, CanListSIEMConfigs: true, CanCreateSIEMConfig: true,
		CanUpdateSIEMConfig: true, CanDeleteSIEMConfig: true, CanTestSIEMConfig: true,
		CanListDetectionConnectors: true, CanCreateDetectionConnector: true,
		CanUpdateDetectionConnector: true, CanDeleteDetectionConnector: true,
		CanTestDetectionConnector: true, CanViewOpenAEVConfig: true, CanUpdateOpenAEVConfig: true,
		CanTestOpenAEVConfig: true, CanSyncOpenAEV: true, CanImportOpenAEVBundle: true,
		CanCreateExercisePlanFromOpenAEV: true, CanCreateExercisePlan: true,
		CanValidateExercisePlan: true, CanUpdateExercisePlan: true, CanDeleteExercisePlan: true,
		CanCreateExerciseTemplate: true, CanInstantiateExerciseTemplate: true,
	}
	for _, p := range Permissions(RoleAdmin) {
		if !tested[p] {
			t.Errorf("permission %q is granted to admin but has no row in TestHasPermission_FullMatrix", p)
		}
	}
	if len(tested) != len(Permissions(RoleAdmin)) {
		t.Errorf("tested %d permissions, admin holds %d — counts diverged", len(tested), len(Permissions(RoleAdmin)))
	}
}
```

Replace `TestPermissions_Ordering`'s body:

```go
func TestPermissions_Ordering(t *testing.T) {
	got := Permissions(RoleAdmin)
	want := []Permission{
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
		CanInjectExerciseEvidence,

		CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
		CanReseedARTContent, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,
		CanViewAuditLogs, CanListTicketingConfigs, CanCreateTicketingConfig, CanUpdateTicketingConfig,
		CanDeleteTicketingConfig, CanTestTicketingConfig, CanProbeTicketingConfig, CanProbeTicketingProjects,
		CanSyncTicketing, CanCreatePayloadFamily, CanDeletePayloadFamily, CanListSIEMConfigs,
		CanCreateSIEMConfig, CanUpdateSIEMConfig, CanDeleteSIEMConfig, CanTestSIEMConfig,
		CanListDetectionConnectors, CanCreateDetectionConnector, CanUpdateDetectionConnector,
		CanDeleteDetectionConnector, CanTestDetectionConnector, CanViewOpenAEVConfig, CanUpdateOpenAEVConfig,
		CanTestOpenAEVConfig, CanSyncOpenAEV, CanImportOpenAEVBundle, CanCreateExercisePlanFromOpenAEV,
		CanCreateExercisePlan, CanValidateExercisePlan, CanUpdateExercisePlan, CanDeleteExercisePlan,
		CanCreateExerciseTemplate, CanInstantiateExerciseTemplate,
	}
	if len(got) != len(want) {
		t.Fatalf("Permissions(RoleAdmin) len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Permissions(RoleAdmin)[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if got := Permissions(RoleViewer); len(got) != 0 {
		t.Fatalf("Permissions(RoleViewer) = %v, want empty", got)
	}
}
```

- [ ] **Step 6: Add the new migration-inventory consistency test**

Append to `orchestrator/internal/auth/permissions_test.go`:

```go
// TestPermissionGrants_MatchMigrationInventory is the regression guard for
// the 2026-07-18 RBAC permission expansion: it proves the grant map matches
// the migration's own inventory (34 Group-A permissions granted to both
// Admin and Analyst; 51 Group-B permissions granted to Admin only), so a
// future edit to routes.go or permissions.go can't silently drift the two
// apart. See docs/superpowers/specs/2026-07-18-phase7-rbac-permission-expansion-design.md.
func TestPermissionGrants_MatchMigrationInventory(t *testing.T) {
	groupA := []Permission{
		CanTriggerScan, CanCollectAttackPath, CanCreateAttackPathJob, CanCancelAttackPathJob,
		CanRetryAttackPathJob, CanSetAttackPathAsset, CanRunScenario, CanRunCalderaAdversary,
		CanRunAdversaryTemplate, CanCancelScenarioRun, CanCorrelateSIEM, CanViewSIEMCorrelations,
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanSetFindingStatus,
		CanPushToITSM, CanBulkPushToITSM, CanCreateScenario, CanUploadScenario, CanCloneScenario,
		CanUpdateScenario, CanDeleteScenario, CanGenerateVariants, CanRunVariants, CanViewVariantRun,
		CanViewVariantCoverage, CanViewVariantStats, CanListPayloadFamilies, CanViewPayloadFamily,
		CanLaunchExerciseExecution, CanAbortExerciseExecution, CanApproveExerciseStep,
		CanInjectExerciseEvidence,
	}
	if len(groupA) != 34 {
		t.Fatalf("groupA has %d entries, want 34", len(groupA))
	}

	groupB := []Permission{
		CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
		CanSyncConnector, CanDeleteConnectorScenario, CanSetAttackPathSchedule, CanViewARTContentStatus,
		CanReseedARTContent, CanViewTamperEvents, CanAcknowledgeTamperEvent, CanAcknowledgeAllTamperEvents,
		CanViewAuditLogs, CanListTicketingConfigs, CanCreateTicketingConfig, CanUpdateTicketingConfig,
		CanDeleteTicketingConfig, CanTestTicketingConfig, CanProbeTicketingConfig, CanProbeTicketingProjects,
		CanSyncTicketing, CanCreatePayloadFamily, CanDeletePayloadFamily, CanListSIEMConfigs,
		CanCreateSIEMConfig, CanUpdateSIEMConfig, CanDeleteSIEMConfig, CanTestSIEMConfig,
		CanListDetectionConnectors, CanCreateDetectionConnector, CanUpdateDetectionConnector,
		CanDeleteDetectionConnector, CanTestDetectionConnector, CanViewOpenAEVConfig, CanUpdateOpenAEVConfig,
		CanTestOpenAEVConfig, CanSyncOpenAEV, CanImportOpenAEVBundle, CanCreateExercisePlanFromOpenAEV,
		CanCreateExercisePlan, CanValidateExercisePlan, CanUpdateExercisePlan, CanDeleteExercisePlan,
		CanCreateExerciseTemplate, CanInstantiateExerciseTemplate,
	}
	if len(groupB) != 51 {
		t.Fatalf("groupB has %d entries, want 51", len(groupB))
	}

	for _, p := range groupA {
		if !HasPermission(RoleAdmin, p) {
			t.Errorf("RoleAdmin missing group-A permission %q", p)
		}
		if !HasPermission(RoleAnalyst, p) {
			t.Errorf("RoleAnalyst missing group-A permission %q", p)
		}
		if HasPermission(RoleViewer, p) {
			t.Errorf("RoleViewer unexpectedly holds group-A permission %q", p)
		}
	}
	for _, p := range groupB {
		if !HasPermission(RoleAdmin, p) {
			t.Errorf("RoleAdmin missing group-B permission %q", p)
		}
		if HasPermission(RoleAnalyst, p) {
			t.Errorf("RoleAnalyst unexpectedly holds admin-only group-B permission %q", p)
		}
		if HasPermission(RoleViewer, p) {
			t.Errorf("RoleViewer unexpectedly holds group-B permission %q", p)
		}
	}
}
```

- [ ] **Step 7: Build and test**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/auth/... -v`
Expected: clean build; all tests pass, including `TestHasPermission_MatrixIsComplete`, `TestPermissions_Ordering`, and the new `TestPermissionGrants_MatchMigrationInventory`.

- [ ] **Step 8: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/auth/permissions.go internal/auth/permissions_test.go
git commit -m "feat(rbac): add 85 permission constants for the Group A/B route migration

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: Convert Group A (34 routes, Analyst+Admin) to per-route permissions

**Files:**
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: the 34 Group-A `Permission` constants from Task 1 (`CanTriggerScan` through `CanInjectExerciseEvidence`, exact list in Task 1 Step 1).
- Produces: no new interfaces — this task only changes how existing routes are gated.

- [ ] **Step 1: Ground the current file state**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && sed -n '200,249p' internal/api/routes.go`
Confirm the output still matches the block described below (route order, handler names) before editing — if it has drifted, adjust the edits in this task to match the real file rather than applying them blindly.

- [ ] **Step 2: Convert each of the 34 routes**

Using Edit, apply each of the following old→new replacements in `orchestrator/internal/api/routes.go` (each `old_string` is a unique route-registration line; only the line itself changes, so surrounding indentation is preserved automatically):

| Old | New |
|---|---|
| `r.Post("/api/scan/{agentId}", h.TriggerScan)` | `r.With(auth.RequirePermission(auth.CanTriggerScan)).Post("/api/scan/{agentId}", h.TriggerScan)` |
| `r.Post("/api/attackpath/collect/{agentId}", h.DispatchAttackPathCollect)` | `r.With(auth.RequirePermission(auth.CanCollectAttackPath)).Post("/api/attackpath/collect/{agentId}", h.DispatchAttackPathCollect)` |
| `r.Post("/api/attackpath/jobs", h.CreateAttackPathJob)` | `r.With(auth.RequirePermission(auth.CanCreateAttackPathJob)).Post("/api/attackpath/jobs", h.CreateAttackPathJob)` |
| `r.Post("/api/attackpath/jobs/{id}/cancel", h.CancelAttackPathJob)` | `r.With(auth.RequirePermission(auth.CanCancelAttackPathJob)).Post("/api/attackpath/jobs/{id}/cancel", h.CancelAttackPathJob)` |
| `r.Post("/api/attackpath/jobs/{id}/retry", h.RetryAttackPathJob)` | `r.With(auth.RequirePermission(auth.CanRetryAttackPathJob)).Post("/api/attackpath/jobs/{id}/retry", h.RetryAttackPathJob)` |
| `r.Post("/api/attackpath/assets", h.SetAttackPathAsset)` | `r.With(auth.RequirePermission(auth.CanSetAttackPathAsset)).Post("/api/attackpath/assets", h.SetAttackPathAsset)` |
| `r.Post("/api/scenarios/{id}/run", h.RunScenario)` | `r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/scenarios/{id}/run", h.RunScenario)` |
| `r.Post("/api/caldera/adversaries/{adversaryId}/run", h.RunCalderaAdversary)` | `r.With(auth.RequirePermission(auth.CanRunCalderaAdversary)).Post("/api/caldera/adversaries/{adversaryId}/run", h.RunCalderaAdversary)` |
| `r.Post("/api/adversary-templates/{id}/run", h.RunAdversaryTemplate)` | `r.With(auth.RequirePermission(auth.CanRunAdversaryTemplate)).Post("/api/adversary-templates/{id}/run", h.RunAdversaryTemplate)` |
| `r.Post("/api/scenarios/runs/{runId}/cancel", h.CancelRun)` | `r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/scenarios/runs/{runId}/cancel", h.CancelRun)` |
| `r.Post("/api/siem/correlate/{runId}", h.TriggerSIEMCorrelation)` | `r.With(auth.RequirePermission(auth.CanCorrelateSIEM)).Post("/api/siem/correlate/{runId}", h.TriggerSIEMCorrelation)` |
| `r.Get("/api/siem/correlations/{runId}", h.GetSIEMCorrelations)` | `r.With(auth.RequirePermission(auth.CanViewSIEMCorrelations)).Get("/api/siem/correlations/{runId}", h.GetSIEMCorrelations)` |
| `r.Post("/api/detectverify/run/{runId}", h.TriggerDetectionVerification)` | `r.With(auth.RequirePermission(auth.CanRunDetectionVerification)).Post("/api/detectverify/run/{runId}", h.TriggerDetectionVerification)` |
| `r.Post("/api/campaigns", h.CreateCampaign)` | `r.With(auth.RequirePermission(auth.CanCreateCampaign)).Post("/api/campaigns", h.CreateCampaign)` |
| `r.Post("/api/campaigns/{id}/stop", h.StopCampaign)` | `r.With(auth.RequirePermission(auth.CanStopCampaign)).Post("/api/campaigns/{id}/stop", h.StopCampaign)` |
| `r.Post("/api/findings/{id}/status", h.SetFindingStatus)` | `r.With(auth.RequirePermission(auth.CanSetFindingStatus)).Post("/api/findings/{id}/status", h.SetFindingStatus)` |
| `r.Post("/api/ticketing/push", h.PushFindingToITSM)` | `r.With(auth.RequirePermission(auth.CanPushToITSM)).Post("/api/ticketing/push", h.PushFindingToITSM)` |
| `r.Post("/api/ticketing/push/bulk", h.BulkPushToITSM)` | `r.With(auth.RequirePermission(auth.CanBulkPushToITSM)).Post("/api/ticketing/push/bulk", h.BulkPushToITSM)` |
| `r.Post("/api/scenarios", h.CreateScenario)` | `r.With(auth.RequirePermission(auth.CanCreateScenario)).Post("/api/scenarios", h.CreateScenario)` |
| `r.Post("/api/scenarios/upload", h.UploadScenario)` | `r.With(auth.RequirePermission(auth.CanUploadScenario)).Post("/api/scenarios/upload", h.UploadScenario)` |
| `r.Post("/api/scenarios/{id}/clone", h.CloneScenario)` | `r.With(auth.RequirePermission(auth.CanCloneScenario)).Post("/api/scenarios/{id}/clone", h.CloneScenario)` |
| `r.Put("/api/scenarios/{id}", h.UpdateScenario)` | `r.With(auth.RequirePermission(auth.CanUpdateScenario)).Put("/api/scenarios/{id}", h.UpdateScenario)` |
| `r.Delete("/api/scenarios/{id}", h.DeleteScenario)` | `r.With(auth.RequirePermission(auth.CanDeleteScenario)).Delete("/api/scenarios/{id}", h.DeleteScenario)` |
| `r.Post("/api/variants/generate", h.GenerateVariants)` | `r.With(auth.RequirePermission(auth.CanGenerateVariants)).Post("/api/variants/generate", h.GenerateVariants)` |
| `r.Post("/api/variants/run", h.RunVariants)` | `r.With(auth.RequirePermission(auth.CanRunVariants)).Post("/api/variants/run", h.RunVariants)` |
| `r.Get("/api/variants/run/{id}", h.GetVariantRun)` | `r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/variants/run/{id}", h.GetVariantRun)` |
| `r.Get("/api/variants/coverage", h.GetVariantCoverage)` | `r.With(auth.RequirePermission(auth.CanViewVariantCoverage)).Get("/api/variants/coverage", h.GetVariantCoverage)` |
| `r.Get("/api/variants/stats", h.GetVariantStats)` | `r.With(auth.RequirePermission(auth.CanViewVariantStats)).Get("/api/variants/stats", h.GetVariantStats)` |
| `r.Get("/api/payload-families", h.GetPayloadFamilies)` | `r.With(auth.RequirePermission(auth.CanListPayloadFamilies)).Get("/api/payload-families", h.GetPayloadFamilies)` |
| `r.Get("/api/payload-families/{techniqueId}", h.GetTechniqueFamilies)` | `r.With(auth.RequirePermission(auth.CanViewPayloadFamily)).Get("/api/payload-families/{techniqueId}", h.GetTechniqueFamilies)` |
| `r.Post("/api/exercises/executions/{id}/launch", h.LaunchExerciseExecution)` | `r.With(auth.RequirePermission(auth.CanLaunchExerciseExecution)).Post("/api/exercises/executions/{id}/launch", h.LaunchExerciseExecution)` |
| `r.Post("/api/exercises/executions/{id}/abort", h.AbortExerciseExecution)` | `r.With(auth.RequirePermission(auth.CanAbortExerciseExecution)).Post("/api/exercises/executions/{id}/abort", h.AbortExerciseExecution)` |
| `r.Post("/api/exercises/executions/{id}/steps/{stepId}/approve", h.ApproveExerciseStep)` | `r.With(auth.RequirePermission(auth.CanApproveExerciseStep)).Post("/api/exercises/executions/{id}/steps/{stepId}/approve", h.ApproveExerciseStep)` |
| `r.Post("/api/exercises/executions/{id}/evidence", h.InjectEvidence)` | `r.With(auth.RequirePermission(auth.CanInjectExerciseEvidence)).Post("/api/exercises/executions/{id}/evidence", h.InjectEvidence)` |

- [ ] **Step 3: Remove the now-empty `RequireRole` group wrapper**

The group opens with (2 leading tabs, then 3 leading tabs for the `r.Use` line):

```
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin, auth.RoleAnalyst))
```

Using Edit with `old_string` exactly matching those two lines (confirm exact tabs via the Step 1 grounding read) and `new_string` = empty, remove them.

The group closes with (2 leading tabs) `})` immediately after the last converted route. Using Edit, replace:

```
			r.With(auth.RequirePermission(auth.CanInjectExerciseEvidence)).Post("/api/exercises/executions/{id}/evidence", h.InjectEvidence)
		})
```

with:

```
			r.With(auth.RequirePermission(auth.CanInjectExerciseEvidence)).Post("/api/exercises/executions/{id}/evidence", h.InjectEvidence)
```

(This removes only the closing `})` line; the route line itself is unchanged from Step 2.)

- [ ] **Step 4: Reformat and build**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -w internal/api/routes.go && go build ./...`
Expected: clean build. `gofmt -w` fixes the indentation of the 34 routes now that they're no longer nested inside the removed `r.Group`.

- [ ] **Step 5: Retag the 34 matching entries in `rbac_matrix_test.go`**

In `orchestrator/internal/api/rbac_matrix_test.go`, the `// ── analyst + admin ──` section (currently lines 142-175) has 34 entries of the form `{http.MethodX, "/path", tierAnalystAdmin, ""}`. Using Edit, replace each `tierAnalystAdmin, ""` with `tierPermission, auth.CanXxx` per this mapping (same order as the table in Step 2):

```go
	{http.MethodPost, "/api/scan/{agentId}", tierPermission, auth.CanTriggerScan},
	{http.MethodPost, "/api/attackpath/collect/{agentId}", tierPermission, auth.CanCollectAttackPath},
	{http.MethodPost, "/api/attackpath/jobs", tierPermission, auth.CanCreateAttackPathJob},
	{http.MethodPost, "/api/attackpath/jobs/{id}/cancel", tierPermission, auth.CanCancelAttackPathJob},
	{http.MethodPost, "/api/attackpath/jobs/{id}/retry", tierPermission, auth.CanRetryAttackPathJob},
	{http.MethodPost, "/api/attackpath/assets", tierPermission, auth.CanSetAttackPathAsset},
	{http.MethodPost, "/api/scenarios/{id}/run", tierPermission, auth.CanRunScenario},
	{http.MethodPost, "/api/caldera/adversaries/{adversaryId}/run", tierPermission, auth.CanRunCalderaAdversary},
	{http.MethodPost, "/api/adversary-templates/{id}/run", tierPermission, auth.CanRunAdversaryTemplate},
	{http.MethodPost, "/api/scenarios/runs/{runId}/cancel", tierPermission, auth.CanCancelScenarioRun},
	{http.MethodPost, "/api/siem/correlate/{runId}", tierPermission, auth.CanCorrelateSIEM},
	{http.MethodPost, "/api/detectverify/run/{runId}", tierPermission, auth.CanRunDetectionVerification},
	{http.MethodGet, "/api/siem/correlations/{runId}", tierPermission, auth.CanViewSIEMCorrelations},
	{http.MethodPost, "/api/campaigns", tierPermission, auth.CanCreateCampaign},
	{http.MethodPost, "/api/campaigns/{id}/stop", tierPermission, auth.CanStopCampaign},
	{http.MethodPost, "/api/findings/{id}/status", tierPermission, auth.CanSetFindingStatus},
	{http.MethodPost, "/api/ticketing/push", tierPermission, auth.CanPushToITSM},
	{http.MethodPost, "/api/ticketing/push/bulk", tierPermission, auth.CanBulkPushToITSM},
	{http.MethodPost, "/api/scenarios", tierPermission, auth.CanCreateScenario},
	{http.MethodPost, "/api/scenarios/upload", tierPermission, auth.CanUploadScenario},
	{http.MethodPost, "/api/scenarios/{id}/clone", tierPermission, auth.CanCloneScenario},
	{http.MethodPut, "/api/scenarios/{id}", tierPermission, auth.CanUpdateScenario},
	{http.MethodDelete, "/api/scenarios/{id}", tierPermission, auth.CanDeleteScenario},
	{http.MethodPost, "/api/variants/generate", tierPermission, auth.CanGenerateVariants},
	{http.MethodPost, "/api/variants/run", tierPermission, auth.CanRunVariants},
	{http.MethodGet, "/api/variants/run/{id}", tierPermission, auth.CanViewVariantRun},
	{http.MethodGet, "/api/variants/coverage", tierPermission, auth.CanViewVariantCoverage},
	{http.MethodGet, "/api/variants/stats", tierPermission, auth.CanViewVariantStats},
	{http.MethodGet, "/api/payload-families", tierPermission, auth.CanListPayloadFamilies},
	{http.MethodGet, "/api/payload-families/{techniqueId}", tierPermission, auth.CanViewPayloadFamily},
	{http.MethodPost, "/api/exercises/executions/{id}/launch", tierPermission, auth.CanLaunchExerciseExecution},
	{http.MethodPost, "/api/exercises/executions/{id}/abort", tierPermission, auth.CanAbortExerciseExecution},
	{http.MethodPost, "/api/exercises/executions/{id}/steps/{stepId}/approve", tierPermission, auth.CanApproveExerciseStep},
	{http.MethodPost, "/api/exercises/executions/{id}/evidence", tierPermission, auth.CanInjectExerciseEvidence},
```

The easiest reliable way to do this: since each `routeCase` line is already unique by its path+method, apply 34 individual Edit calls, each changing just `tierAnalystAdmin, ""` → `tierPermission, auth.CanXxx` on that one line (use enough of the line, e.g. the full old line text, as `old_string` to keep the match unique).

- [ ] **Step 6: Run the RBAC matrix tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run 'TestRBACMatrix' -v`
Expected: `TestRBACMatrix_AuthorizationBoundary`, `TestRBACMatrix_NoDrift`, `TestRBACMatrix_MethodConfusion`, and `TestPlatformAdminRoutes_Gating` all PASS — this proves the 34 converted routes behave identically to before (Admin and Analyst still pass, Viewer still gets 403, anonymous still gets 401).

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(rbac): convert Group A (Analyst+Admin, 34 routes) to per-route permissions

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: Convert Group B (51 routes, Admin-only) to per-route permissions

**Files:**
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: the 51 Group-B `Permission` constants from Task 1 (`CanSetAgentState` through `CanInstantiateExerciseTemplate`, exact list in Task 1 Step 2).

- [ ] **Step 1: Ground the current file state**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && sed -n '303,387p' internal/api/routes.go`
Confirm the output matches the block described below before editing.

- [ ] **Step 2: Convert each of the 51 routes**

Using Edit, apply each of the following old→new replacements in `orchestrator/internal/api/routes.go`:

| Old | New |
|---|---|
| `r.Put("/api/agents/{agentId}/state", h.SetAgentState)` | `r.With(auth.RequirePermission(auth.CanSetAgentState)).Put("/api/agents/{agentId}/state", h.SetAgentState)` |
| `r.Get("/api/license", h.GetLicenseInfo)` | `r.With(auth.RequirePermission(auth.CanViewLicense)).Get("/api/license", h.GetLicenseInfo)` |
| `r.Get("/api/config/connection", h.GetConnectionConfig)` | `r.With(auth.RequirePermission(auth.CanViewConnectionConfig)).Get("/api/config/connection", h.GetConnectionConfig)` |
| `r.Get("/api/users", h.ListUsers)` | `r.With(auth.RequirePermission(auth.CanListUsers)).Get("/api/users", h.ListUsers)` |
| `r.Post("/api/users", h.CreateUser)` | `r.With(auth.RequirePermission(auth.CanCreateUser)).Post("/api/users", h.CreateUser)` |
| `r.Put("/api/users/{id}", h.UpdateUser)` | `r.With(auth.RequirePermission(auth.CanUpdateUser)).Put("/api/users/{id}", h.UpdateUser)` |
| `r.Delete("/api/users/{id}", h.DeleteUser)` | `r.With(auth.RequirePermission(auth.CanDeleteUser)).Delete("/api/users/{id}", h.DeleteUser)` |
| `r.Post("/api/users/{id}/reset-password", h.ResetPassword)` | `r.With(auth.RequirePermission(auth.CanResetUserPassword)).Post("/api/users/{id}/reset-password", h.ResetPassword)` |
| `r.Get("/api/caldera/status", h.GetCalderaStatus)` | `r.With(auth.RequirePermission(auth.CanViewCalderaStatus)).Get("/api/caldera/status", h.GetCalderaStatus)` |
| `r.Get("/api/connector/status", h.GetConnectorStatus)` | `r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/connector/status", h.GetConnectorStatus)` |
| `r.Post("/api/connector/sync", h.TriggerConnectorSync)` | `r.With(auth.RequirePermission(auth.CanSyncConnector)).Post("/api/connector/sync", h.TriggerConnectorSync)` |
| `r.Delete("/api/connector/scenarios/{id}", h.DeleteIntelScenario)` | `r.With(auth.RequirePermission(auth.CanDeleteConnectorScenario)).Delete("/api/connector/scenarios/{id}", h.DeleteIntelScenario)` |
| `r.Post("/api/attackpath/schedule", h.SetAttackPathSchedule)` | `r.With(auth.RequirePermission(auth.CanSetAttackPathSchedule)).Post("/api/attackpath/schedule", h.SetAttackPathSchedule)` |
| `r.Get("/api/art/content/status", h.GetARTContentStatus)` | `r.With(auth.RequirePermission(auth.CanViewARTContentStatus)).Get("/api/art/content/status", h.GetARTContentStatus)` |
| `r.Post("/api/art/content/reseed", h.ReseedART)` | `r.With(auth.RequirePermission(auth.CanReseedARTContent)).Post("/api/art/content/reseed", h.ReseedART)` |
| `r.Get("/api/tamper-events", h.GetTamperEvents)` | `r.With(auth.RequirePermission(auth.CanViewTamperEvents)).Get("/api/tamper-events", h.GetTamperEvents)` |
| `r.Post("/api/tamper-events/{id}/acknowledge", h.AcknowledgeTamperEvent)` | `r.With(auth.RequirePermission(auth.CanAcknowledgeTamperEvent)).Post("/api/tamper-events/{id}/acknowledge", h.AcknowledgeTamperEvent)` |
| `r.Post("/api/tamper-events/acknowledge-all", h.AcknowledgeAllTamperEvents)` | `r.With(auth.RequirePermission(auth.CanAcknowledgeAllTamperEvents)).Post("/api/tamper-events/acknowledge-all", h.AcknowledgeAllTamperEvents)` |
| `r.Get("/api/audit-logs", h.GetAuditLogs)` | `r.With(auth.RequirePermission(auth.CanViewAuditLogs)).Get("/api/audit-logs", h.GetAuditLogs)` |
| `r.Get("/api/ticketing/configs", h.ListTicketingConfigs)` | `r.With(auth.RequirePermission(auth.CanListTicketingConfigs)).Get("/api/ticketing/configs", h.ListTicketingConfigs)` |
| `r.Post("/api/ticketing/configs", h.CreateTicketingConfig)` | `r.With(auth.RequirePermission(auth.CanCreateTicketingConfig)).Post("/api/ticketing/configs", h.CreateTicketingConfig)` |
| `r.Put("/api/ticketing/configs/{id}", h.UpdateTicketingConfig)` | `r.With(auth.RequirePermission(auth.CanUpdateTicketingConfig)).Put("/api/ticketing/configs/{id}", h.UpdateTicketingConfig)` |
| `r.Delete("/api/ticketing/configs/{id}", h.DeleteTicketingConfig)` | `r.With(auth.RequirePermission(auth.CanDeleteTicketingConfig)).Delete("/api/ticketing/configs/{id}", h.DeleteTicketingConfig)` |
| `r.Post("/api/ticketing/configs/{id}/test", h.TestTicketingConfig)` | `r.With(auth.RequirePermission(auth.CanTestTicketingConfig)).Post("/api/ticketing/configs/{id}/test", h.TestTicketingConfig)` |
| `r.Post("/api/ticketing/probe", h.ProbeTicketingConfig)` | `r.With(auth.RequirePermission(auth.CanProbeTicketingConfig)).Post("/api/ticketing/probe", h.ProbeTicketingConfig)` |
| `r.Post("/api/ticketing/probe/projects", h.ProbeListProjects)` | `r.With(auth.RequirePermission(auth.CanProbeTicketingProjects)).Post("/api/ticketing/probe/projects", h.ProbeListProjects)` |
| `r.Post("/api/ticketing/sync", h.TriggerTicketingSync)` | `r.With(auth.RequirePermission(auth.CanSyncTicketing)).Post("/api/ticketing/sync", h.TriggerTicketingSync)` |
| `r.Post("/api/payload-families", h.CreatePayloadFamily)` | `r.With(auth.RequirePermission(auth.CanCreatePayloadFamily)).Post("/api/payload-families", h.CreatePayloadFamily)` |
| `r.Delete("/api/payload-families/{id}", h.DeletePayloadFamily)` | `r.With(auth.RequirePermission(auth.CanDeletePayloadFamily)).Delete("/api/payload-families/{id}", h.DeletePayloadFamily)` |
| `r.Get("/api/siem/configs", h.ListSIEMConfigs)` | `r.With(auth.RequirePermission(auth.CanListSIEMConfigs)).Get("/api/siem/configs", h.ListSIEMConfigs)` |
| `r.Post("/api/siem/configs", h.CreateSIEMConfig)` | `r.With(auth.RequirePermission(auth.CanCreateSIEMConfig)).Post("/api/siem/configs", h.CreateSIEMConfig)` |
| `r.Put("/api/siem/configs/{id}", h.UpdateSIEMConfig)` | `r.With(auth.RequirePermission(auth.CanUpdateSIEMConfig)).Put("/api/siem/configs/{id}", h.UpdateSIEMConfig)` |
| `r.Delete("/api/siem/configs/{id}", h.DeleteSIEMConfig)` | `r.With(auth.RequirePermission(auth.CanDeleteSIEMConfig)).Delete("/api/siem/configs/{id}", h.DeleteSIEMConfig)` |
| `r.Post("/api/siem/configs/{id}/test", h.TestSIEMConfig)` | `r.With(auth.RequirePermission(auth.CanTestSIEMConfig)).Post("/api/siem/configs/{id}/test", h.TestSIEMConfig)` |
| `r.Get("/api/detectverify/configs", h.ListDetectionConnectors)` | `r.With(auth.RequirePermission(auth.CanListDetectionConnectors)).Get("/api/detectverify/configs", h.ListDetectionConnectors)` |
| `r.Post("/api/detectverify/configs", h.CreateDetectionConnector)` | `r.With(auth.RequirePermission(auth.CanCreateDetectionConnector)).Post("/api/detectverify/configs", h.CreateDetectionConnector)` |
| `r.Put("/api/detectverify/configs/{id}", h.UpdateDetectionConnector)` | `r.With(auth.RequirePermission(auth.CanUpdateDetectionConnector)).Put("/api/detectverify/configs/{id}", h.UpdateDetectionConnector)` |
| `r.Delete("/api/detectverify/configs/{id}", h.DeleteDetectionConnector)` | `r.With(auth.RequirePermission(auth.CanDeleteDetectionConnector)).Delete("/api/detectverify/configs/{id}", h.DeleteDetectionConnector)` |
| `r.Post("/api/detectverify/configs/{id}/test", h.TestDetectionConnector)` | `r.With(auth.RequirePermission(auth.CanTestDetectionConnector)).Post("/api/detectverify/configs/{id}/test", h.TestDetectionConnector)` |
| `r.Get("/api/openaev/config", h.GetOpenAEVConfig)` | `r.With(auth.RequirePermission(auth.CanViewOpenAEVConfig)).Get("/api/openaev/config", h.GetOpenAEVConfig)` |
| `r.Put("/api/openaev/config", h.PutOpenAEVConfig)` | `r.With(auth.RequirePermission(auth.CanUpdateOpenAEVConfig)).Put("/api/openaev/config", h.PutOpenAEVConfig)` |
| `r.Post("/api/openaev/config/test", h.TestOpenAEVConfig)` | `r.With(auth.RequirePermission(auth.CanTestOpenAEVConfig)).Post("/api/openaev/config/test", h.TestOpenAEVConfig)` |
| `r.Post("/api/openaev/sync", h.SyncOpenAEV)` | `r.With(auth.RequirePermission(auth.CanSyncOpenAEV)).Post("/api/openaev/sync", h.SyncOpenAEV)` |
| `r.Post("/api/openaev/import", h.ImportOpenAEVBundle)` | `r.With(auth.RequirePermission(auth.CanImportOpenAEVBundle)).Post("/api/openaev/import", h.ImportOpenAEVBundle)` |
| `r.Post("/api/openaev/scenarios/{id}/create-plan", h.CreateExercisePlanFromOpenAEV)` | `r.With(auth.RequirePermission(auth.CanCreateExercisePlanFromOpenAEV)).Post("/api/openaev/scenarios/{id}/create-plan", h.CreateExercisePlanFromOpenAEV)` |
| `r.Post("/api/exercises/plans", h.CreateExercisePlan)` | `r.With(auth.RequirePermission(auth.CanCreateExercisePlan)).Post("/api/exercises/plans", h.CreateExercisePlan)` |
| `r.Post("/api/exercises/plans/validate", h.ValidateExercisePlan)` | `r.With(auth.RequirePermission(auth.CanValidateExercisePlan)).Post("/api/exercises/plans/validate", h.ValidateExercisePlan)` |
| `r.Put("/api/exercises/plans/{id}", h.UpdateExercisePlan)` | `r.With(auth.RequirePermission(auth.CanUpdateExercisePlan)).Put("/api/exercises/plans/{id}", h.UpdateExercisePlan)` |
| `r.Delete("/api/exercises/plans/{id}", h.DeleteExercisePlan)` | `r.With(auth.RequirePermission(auth.CanDeleteExercisePlan)).Delete("/api/exercises/plans/{id}", h.DeleteExercisePlan)` |
| `r.Post("/api/exercises/templates", h.CreateExerciseTemplate)` | `r.With(auth.RequirePermission(auth.CanCreateExerciseTemplate)).Post("/api/exercises/templates", h.CreateExerciseTemplate)` |
| `r.Post("/api/exercises/templates/{id}/instantiate", h.InstantiateExerciseTemplate)` | `r.With(auth.RequirePermission(auth.CanInstantiateExerciseTemplate)).Post("/api/exercises/templates/{id}/instantiate", h.InstantiateExerciseTemplate)` |

- [ ] **Step 3: Remove the now-empty `RequireRole` group wrapper**

The group opens with:

```
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin))
```

Using Edit with `old_string` exactly matching those two lines (confirm exact tabs via the Step 1 grounding read) and `new_string` = empty, remove them.

The group closes with (2 leading tabs) `})` immediately after the last converted route. Using Edit, replace:

```
			r.With(auth.RequirePermission(auth.CanInstantiateExerciseTemplate)).Post("/api/exercises/templates/{id}/instantiate", h.InstantiateExerciseTemplate)
		})
```

with:

```
			r.With(auth.RequirePermission(auth.CanInstantiateExerciseTemplate)).Post("/api/exercises/templates/{id}/instantiate", h.InstantiateExerciseTemplate)
```

- [ ] **Step 4: Reformat and build**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -w internal/api/routes.go && go build ./...`
Expected: clean build.

- [ ] **Step 5: Retag the 51 matching entries in `rbac_matrix_test.go`**

In `orchestrator/internal/api/rbac_matrix_test.go`, the `// ── admin only ──` section (currently lines 178-228) has 51 entries of the form `{http.MethodX, "/path", tierAdminOnly, ""}`. Using Edit, replace each with `tierPermission, auth.CanXxx` per this mapping:

```go
	{http.MethodPut, "/api/agents/{agentId}/state", tierPermission, auth.CanSetAgentState},
	{http.MethodGet, "/api/license", tierPermission, auth.CanViewLicense},
	{http.MethodGet, "/api/config/connection", tierPermission, auth.CanViewConnectionConfig},
	{http.MethodGet, "/api/users", tierPermission, auth.CanListUsers},
	{http.MethodPost, "/api/users", tierPermission, auth.CanCreateUser},
	{http.MethodPut, "/api/users/{id}", tierPermission, auth.CanUpdateUser},
	{http.MethodDelete, "/api/users/{id}", tierPermission, auth.CanDeleteUser},
	{http.MethodPost, "/api/users/{id}/reset-password", tierPermission, auth.CanResetUserPassword},
	{http.MethodGet, "/api/caldera/status", tierPermission, auth.CanViewCalderaStatus},
	{http.MethodGet, "/api/connector/status", tierPermission, auth.CanViewConnectorStatus},
	{http.MethodPost, "/api/connector/sync", tierPermission, auth.CanSyncConnector},
	{http.MethodDelete, "/api/connector/scenarios/{id}", tierPermission, auth.CanDeleteConnectorScenario},
	{http.MethodPost, "/api/attackpath/schedule", tierPermission, auth.CanSetAttackPathSchedule},
	{http.MethodGet, "/api/art/content/status", tierPermission, auth.CanViewARTContentStatus},
	{http.MethodPost, "/api/art/content/reseed", tierPermission, auth.CanReseedARTContent},
	{http.MethodGet, "/api/tamper-events", tierPermission, auth.CanViewTamperEvents},
	{http.MethodPost, "/api/tamper-events/{id}/acknowledge", tierPermission, auth.CanAcknowledgeTamperEvent},
	{http.MethodPost, "/api/tamper-events/acknowledge-all", tierPermission, auth.CanAcknowledgeAllTamperEvents},
	{http.MethodGet, "/api/audit-logs", tierPermission, auth.CanViewAuditLogs},
	{http.MethodGet, "/api/ticketing/configs", tierPermission, auth.CanListTicketingConfigs},
	{http.MethodPost, "/api/ticketing/configs", tierPermission, auth.CanCreateTicketingConfig},
	{http.MethodPut, "/api/ticketing/configs/{id}", tierPermission, auth.CanUpdateTicketingConfig},
	{http.MethodDelete, "/api/ticketing/configs/{id}", tierPermission, auth.CanDeleteTicketingConfig},
	{http.MethodPost, "/api/ticketing/configs/{id}/test", tierPermission, auth.CanTestTicketingConfig},
	{http.MethodPost, "/api/ticketing/probe", tierPermission, auth.CanProbeTicketingConfig},
	{http.MethodPost, "/api/ticketing/probe/projects", tierPermission, auth.CanProbeTicketingProjects},
	{http.MethodPost, "/api/ticketing/sync", tierPermission, auth.CanSyncTicketing},
	{http.MethodPost, "/api/payload-families", tierPermission, auth.CanCreatePayloadFamily},
	{http.MethodDelete, "/api/payload-families/{id}", tierPermission, auth.CanDeletePayloadFamily},
	{http.MethodGet, "/api/siem/configs", tierPermission, auth.CanListSIEMConfigs},
	{http.MethodPost, "/api/siem/configs", tierPermission, auth.CanCreateSIEMConfig},
	{http.MethodPut, "/api/siem/configs/{id}", tierPermission, auth.CanUpdateSIEMConfig},
	{http.MethodDelete, "/api/siem/configs/{id}", tierPermission, auth.CanDeleteSIEMConfig},
	{http.MethodPost, "/api/siem/configs/{id}/test", tierPermission, auth.CanTestSIEMConfig},
	{http.MethodGet, "/api/detectverify/configs", tierPermission, auth.CanListDetectionConnectors},
	{http.MethodPost, "/api/detectverify/configs", tierPermission, auth.CanCreateDetectionConnector},
	{http.MethodPut, "/api/detectverify/configs/{id}", tierPermission, auth.CanUpdateDetectionConnector},
	{http.MethodDelete, "/api/detectverify/configs/{id}", tierPermission, auth.CanDeleteDetectionConnector},
	{http.MethodPost, "/api/detectverify/configs/{id}/test", tierPermission, auth.CanTestDetectionConnector},
	{http.MethodGet, "/api/openaev/config", tierPermission, auth.CanViewOpenAEVConfig},
	{http.MethodPut, "/api/openaev/config", tierPermission, auth.CanUpdateOpenAEVConfig},
	{http.MethodPost, "/api/openaev/config/test", tierPermission, auth.CanTestOpenAEVConfig},
	{http.MethodPost, "/api/openaev/sync", tierPermission, auth.CanSyncOpenAEV},
	{http.MethodPost, "/api/openaev/import", tierPermission, auth.CanImportOpenAEVBundle},
	{http.MethodPost, "/api/openaev/scenarios/{id}/create-plan", tierPermission, auth.CanCreateExercisePlanFromOpenAEV},
	{http.MethodPost, "/api/exercises/plans", tierPermission, auth.CanCreateExercisePlan},
	{http.MethodPost, "/api/exercises/plans/validate", tierPermission, auth.CanValidateExercisePlan},
	{http.MethodPut, "/api/exercises/plans/{id}", tierPermission, auth.CanUpdateExercisePlan},
	{http.MethodDelete, "/api/exercises/plans/{id}", tierPermission, auth.CanDeleteExercisePlan},
	{http.MethodPost, "/api/exercises/templates", tierPermission, auth.CanCreateExerciseTemplate},
	{http.MethodPost, "/api/exercises/templates/{id}/instantiate", tierPermission, auth.CanInstantiateExerciseTemplate},
```

Apply as 51 individual Edit calls, each changing `tierAdminOnly, ""` → `tierPermission, auth.CanXxx` on that one line, same approach as Task 2 Step 5.

- [ ] **Step 6: Run the RBAC matrix tests**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run 'TestRBACMatrix' -v`
Expected: all pass, same as Task 2 Step 6, now covering all 85 migrated routes.

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(rbac): convert Group B (Admin-only, 51 routes) to per-route permissions

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Delete dead `auth.RequireRole` and rebase `TestAuthorizationPrecedence` onto `RequirePermission`

**Files:**
- Modify: `orchestrator/internal/auth/middleware.go`
- Modify: `orchestrator/internal/auth/middleware_test.go`

**Interfaces:**
- Consumes: `auth.RequirePermission` (pre-existing), `auth.CanDeleteEvidence` (pre-existing) — reused here rather than one of Task 1's new constants, to keep this authn/authz-precedence test decoupled from the RBAC migration's specific inventory.

- [ ] **Step 1: Confirm `RequireRole` has zero remaining callers**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -rn "RequireRole" --include="*.go" . | grep -v "_test.go"`
Expected: only the function definition itself in `internal/auth/middleware.go` — no callers in `routes.go` (Tasks 2 and 3 removed them both).

- [ ] **Step 2: Delete `RequireRole` from `middleware.go`**

In `orchestrator/internal/auth/middleware.go`, remove this function entirely:

```go
// RequireRole rejects requests from users whose role is not in the allowed list.
func RequireRole(roles ...Role) func(http.Handler) http.Handler {
	allowed := make(map[Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok || !allowed[claims.Role] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

```

Also update `RequirePlatformAdmin`'s doc comment, which references the now-deleted function. Replace:

```go
// RequirePlatformAdmin rejects requests from users who are not
// platform-admins. Distinct from RequireRole: platform-admin is an
// orthogonal flag (which tenant, or none), not a fourth RBAC tier (what
// permission level).
```

with:

```go
// RequirePlatformAdmin rejects requests from users who are not
// platform-admins. Platform-admin is an orthogonal flag (which tenant, or
// none) checked independently of role/permission — not a fourth RBAC tier.
```

- [ ] **Step 3: Delete the 3 `RequireRole`-specific tests from `middleware_test.go`**

In `orchestrator/internal/auth/middleware_test.go`, delete these three test functions entirely (they test `RequireRole` directly, which no longer exists):
- `TestRequireRole_AllowedRolePasses`
- `TestRequireRole_DisallowedRoleForbidden`
- `TestRequireRole_NoClaimsInContext_DenyByDefault`

- [ ] **Step 4: Rebase `TestAuthorizationPrecedence` onto `RequirePermission`**

This test pins a real invariant (authentication failures return 401 before any authorization check runs; authorization failures return 403) that has nothing to do with `RequireRole` specifically — it just needs *some* authz middleware under test. Replace its body's use of `RequireRole(RoleAdmin)` with `RequirePermission(CanDeleteEvidence)` (Admin holds it, Viewer doesn't — same pass/fail shape as before):

Replace:

```go
			handler := Middleware("secret")(RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))
```

with:

```go
			handler := Middleware("secret")(RequirePermission(CanDeleteEvidence)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))
```

- [ ] **Step 5: Build and test**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/auth/... -v`
Expected: clean build (confirms zero remaining `RequireRole` references anywhere), all tests pass including the rebased `TestAuthorizationPrecedence`.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/auth/middleware.go internal/auth/middleware_test.go
git commit -m "refactor(rbac): delete dead RequireRole, rebase precedence test onto RequirePermission

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: Full regression + capture

**Files:** none (verification + vault/memory).

- [ ] **Step 1: Full `internal/api` + `internal/auth` regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... ./internal/auth/... -v`
Expected: PASS across both packages — this is the definitive proof that all 85 route conversions preserve identical authorization behavior end-to-end through the real mounted router.

- [ ] **Step 2: Full repo test suite + build + vet**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./... && go build ./... && go vet ./...`
Expected: PASS/clean across every package — no other package references `auth.RequireRole` or any of the old grant-map shape.

- [ ] **Step 3: gofmt check**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/auth/permissions.go internal/auth/permissions_test.go internal/auth/middleware.go internal/auth/middleware_test.go internal/api/routes.go internal/api/rbac_matrix_test.go`
Expected: no output (all files already gofmt-clean from Task 2/3's `gofmt -w` and Go's own formatting habits — if anything is listed, run `gofmt -w` on it and commit as a dedicated `style:` commit, same pattern as the Multi-Tenancy slice's `f2e9818`).

- [ ] **Step 4: Update the vault (outside the git repo)**

The vault at `C:\Users\Administrator\Audspect-Vault` is NOT in the repo — update it directly, do not `git add` it.
- Create `04 Features/RBAC Permission Expansion.md` (feature note: the 85-permission inventory summary, the 1:1-mirror-first design call, the two pre-existing tests that needed updating and why, the `TestAuthorizationPrecedence` rebase decision).
- Edit `11 Roadmaps/Roadmap.md`: mark Phase 7 Sub-project 2's RBAC-expansion piece done; note SSO and SCIM (the other two Identity & Access pieces) remain not started.
- Append to the current daily note: this session's work, the route-count correction caught during spec-writing (73→85), and the `rolePermissions` map being unexported (so the consistency test had to live in `internal/auth`, not `internal/api` as the spec's mechanism section first said).

- [ ] **Step 5: Update Claude memory**

Edit `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_platform_roadmap_2026h2.md`: mark Phase 7 Sub-project 2's RBAC-expansion piece done under the Identity & Access entry; flag SSO/SCIM as the remaining two pieces, each needing its own brainstorm. Update the `MEMORY.md` index line.

- [ ] **Step 6: Report completion**

Announce the feature is done, list the commits, and state plainly: this closes the RBAC-expansion piece of Identity & Access only. SSO (SAML/OIDC) and SCIM provisioning — the other two pieces of Phase 7 Sub-project 2 — are still fully unstarted and each needs its own brainstorm cycle.

---

## Self-Review

**Spec coverage:**
- 85 permission constants, 1:1 mirror of current role behavior → Task 1. ✓
- Naming convention `<domain>:<action>` → applied throughout Task 1. ✓
- Route migration (Group A 34, Group B 51) → Tasks 2-3. ✓
- `RequireRole` deletion → Task 4. ✓
- `rbac_matrix_test.go` retagging via existing `tierPermission` mechanism → Tasks 2-3 Step 5. ✓
- New consistency test → Task 1 Step 6 (corrected from the spec's stated location — see below). ✓
- No new roles / no per-tenant grants / no UI changes / no new restrictions on open routes → none of these are touched by any task. ✓
- Testing strategy (boundary test, no-drift test, full regression) → Tasks 2 Step 6, 3 Step 6, 5 Steps 1-2. ✓

**Grounding correction made while writing this plan (same discipline as every prior slice this session):** the spec's Mechanism section said the new `TestPermissionGrants_MatchMigrationInventory` test would live in `internal/api/rbac_matrix_test.go` and assert directly against `rolePermissions`. That's wrong — `rolePermissions` is an unexported `internal/auth` package variable; `internal/api` cannot reference it. Task 1 Step 6 places the test in `internal/auth/permissions_test.go` instead, asserting the equivalent facts through the exported `HasPermission` function. Also corrected: the spec's initial route-count estimate (~73) was superseded by the grounded count (85 = 34 + 51) before the spec was finalized — this plan uses the corrected, verified numbers throughout, cross-checked against the live `rbac_matrix_test.go` route table during plan-writing.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; every command has an expected result. The two large `Edit`-table steps (Task 2 Step 2, Task 3 Step 2) list all 34/51 old→new pairs explicitly rather than describing them abstractly.

**Type consistency:** every `Permission` constant name and its exact `<domain>:<action>` string value is defined once in Task 1 and reused identically (same spelling) in Tasks 2, 3, and 4 — cross-checked against the spec's two inventory tables during plan-writing.
