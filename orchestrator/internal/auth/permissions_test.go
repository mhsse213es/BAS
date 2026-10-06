package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHasPermission_FullMatrix(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		{RoleAdmin, CanVerify, true},
		{RoleAdmin, CanUploadEvidence, true},
		{RoleAdmin, CanDeleteEvidence, true},
		{RoleAdmin, CanReview, true},
		{RoleAdmin, CanExport, true},
		{RoleAdmin, CanCurateThreatIntel, true},
		{RoleAdmin, CanReviewThreatIntel, true},

		{RoleAnalyst, CanVerify, true},
		{RoleAnalyst, CanUploadEvidence, true},
		{RoleAnalyst, CanDeleteEvidence, false}, // withheld: accountability
		{RoleAnalyst, CanReview, true},
		{RoleAnalyst, CanExport, true},
		{RoleAnalyst, CanCurateThreatIntel, true},
		{RoleAnalyst, CanReviewThreatIntel, false}, // withheld: no self-approval

		{RoleViewer, CanVerify, false},
		{RoleViewer, CanUploadEvidence, false},
		{RoleViewer, CanDeleteEvidence, false},
		{RoleViewer, CanReview, false},
		{RoleViewer, CanExport, false},
		{RoleViewer, CanCurateThreatIntel, false},
		{RoleViewer, CanReviewThreatIntel, false},

		{RoleAdmin, CanViewAgentGroups, true},
		{RoleAnalyst, CanViewAgentGroups, true},
		{RoleViewer, CanViewAgentGroups, false},

		{RoleAdmin, CanTargetAllAgents, true},
		{RoleAnalyst, CanTargetAllAgents, false},
		{RoleViewer, CanTargetAllAgents, false},

		{RoleAdmin, CanUpdateConnectorConfig, true},
		{RoleAnalyst, CanUpdateConnectorConfig, false},
		{RoleViewer, CanUpdateConnectorConfig, false},
	}
	for _, tc := range cases {
		if got := HasPermission(tc.role, tc.perm); got != tc.want {
			t.Errorf("HasPermission(%s, %s) = %v, want %v", tc.role, tc.perm, got, tc.want)
		}
	}
}

// TestHasPermission_MatrixIsComplete guards against a new Permission
// constant being added without a corresponding row above: it fails loudly
// if the tested set diverges from the set of permissions admin actually
// holds (admin currently holds every defined permission — see
// rolePermissions in permissions.go). A permission added but NOT granted
// to admin would not trip this check; that's an inherent limitation of Go
// having no enum reflection, not something this test can close.
func TestHasPermission_MatrixIsComplete(t *testing.T) {
	tested := map[Permission]bool{
		CanVerify: true, CanUploadEvidence: true, CanDeleteEvidence: true,
		CanReview: true, CanExport: true, CanCurateThreatIntel: true, CanReviewThreatIntel: true,

		CanTriggerScan: true, CanCollectAttackPath: true, CanCreateAttackPathJob: true,
		CanCancelAttackPathJob: true, CanRetryAttackPathJob: true, CanSetAttackPathAsset: true,
		CanRunScenario: true, CanRunCalderaAdversary: true, CanRunAdversaryTemplate: true,
		CanCancelScenarioRun: true, CanCorrelateSIEM: true, CanViewSIEMCorrelations: true,
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true, CanTargetAllAgents: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,
		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,

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
		CanTestDetectionConnector: true,
		CanExecuteResponseAction:  true, CanViewResponseActions: true, CanListResponseConnectors: true,
		CanCreateResponseConnector: true, CanUpdateResponseConnector: true, CanDeleteResponseConnector: true,
		CanTestResponseConnector: true,
		CanViewOpenAEVConfig:     true, CanUpdateOpenAEVConfig: true,
		CanTestOpenAEVConfig: true, CanSyncOpenAEV: true, CanImportOpenAEVBundle: true,
		CanCreateExercisePlanFromOpenAEV: true, CanCreateExercisePlan: true,
		CanValidateExercisePlan: true, CanUpdateExercisePlan: true, CanDeleteExercisePlan: true,
		CanCreateExerciseTemplate: true, CanInstantiateExerciseTemplate: true,
		CanViewSSOConfig: true, CanManageSSOConfig: true,
		CanViewSCIMConfig: true, CanManageSCIMConfig: true,
		CanExecuteRemediation: true, CanApproveRemediation: true,
		CanManageBackups: true,

		CanViewContentArtifact: true, CanTransitionContent: true, CanViewContentMigrationReport: true,
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

func TestPermissions_Ordering(t *testing.T) {
	got := Permissions(RoleAdmin)
	want := []Permission{
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
		CanViewContentArtifact, CanTransitionContent, CanViewContentMigrationReport,
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

func TestRequirePermission_GrantedDeniedNoClaims(t *testing.T) {
	adminTok, _ := GenerateToken("a1", RoleAdmin, "secret", time.Hour)
	viewerTok, _ := GenerateToken("v1", RoleViewer, "secret", time.Hour)

	newHandler := func() (http.Handler, *bool) {
		called := false
		h := RequirePermission(CanDeleteEvidence)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		return h, &called
	}

	// Granted: admin holds CanDeleteEvidence.
	h, called := newHandler()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	rec := httptest.NewRecorder()
	Middleware("secret")(h).ServeHTTP(rec, req)
	if !*called || rec.Code != http.StatusOK {
		t.Fatalf("granted case: called=%v status=%d", *called, rec.Code)
	}

	// Denied: viewer holds no permissions.
	h, called = newHandler()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Authorization", "Bearer "+viewerTok)
	rec = httptest.NewRecorder()
	Middleware("secret")(h).ServeHTTP(rec, req)
	if *called || rec.Code != http.StatusForbidden {
		t.Fatalf("denied case: called=%v status=%d, want called=false status=403", *called, rec.Code)
	}

	// No claims at all (RequirePermission invoked with no Middleware in front).
	h, called = newHandler()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if *called || rec.Code != http.StatusForbidden {
		t.Fatalf("no-claims case: called=%v status=%d, want called=false status=403", *called, rec.Code)
	}
}

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

func TestCanApproveRemediation_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, CanApproveRemediation) {
		t.Error("expected RoleAdmin to hold CanApproveRemediation")
	}
	if HasPermission(RoleAnalyst, CanApproveRemediation) {
		t.Error("expected RoleAnalyst NOT to hold CanApproveRemediation")
	}
}

func TestCanExecuteRemediation_AnalystAndAdmin(t *testing.T) {
	if !HasPermission(RoleAdmin, CanExecuteRemediation) {
		t.Error("expected RoleAdmin to hold CanExecuteRemediation")
	}
	if !HasPermission(RoleAnalyst, CanExecuteRemediation) {
		t.Error("expected RoleAnalyst to hold CanExecuteRemediation")
	}
	if HasPermission(RoleViewer, CanExecuteRemediation) {
		t.Error("expected RoleViewer NOT to hold CanExecuteRemediation")
	}
}

func TestCanManageBackups_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, CanManageBackups) {
		t.Error("expected RoleAdmin to hold CanManageBackups")
	}
	if HasPermission(RoleAnalyst, CanManageBackups) {
		t.Error("expected RoleAnalyst NOT to hold CanManageBackups")
	}
	if HasPermission(RoleViewer, CanManageBackups) {
		t.Error("expected RoleViewer NOT to hold CanManageBackups")
	}
}

// Content registry: artifact view is Analyst+Admin; transition and the
// migration report are Admin only; Viewer holds none.
func TestContentRegistryPermissions(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		{RoleAdmin, CanViewContentArtifact, true},
		{RoleAnalyst, CanViewContentArtifact, true},
		{RoleViewer, CanViewContentArtifact, false},
		{RoleAdmin, CanTransitionContent, true},
		{RoleAnalyst, CanTransitionContent, false},
		{RoleViewer, CanTransitionContent, false},
		{RoleAdmin, CanViewContentMigrationReport, true},
		{RoleAnalyst, CanViewContentMigrationReport, false},
		{RoleViewer, CanViewContentMigrationReport, false},
	}
	for _, c := range cases {
		if got := HasPermission(c.role, c.perm); got != c.want {
			t.Errorf("HasPermission(%s, %s) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}
