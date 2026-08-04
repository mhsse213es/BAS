package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type authTier int

const (
	tierAny authTier = iota // any authenticated role (viewer, analyst, admin)
	tierAnalystAdmin
	tierAdminOnly
	tierPermission
	tierPlatformAdmin // orthogonal to role — see auth.RequirePlatformAdmin
)

type routeCase struct {
	method string
	path   string // chi path template, exactly as registered in routes.go
	tier   authTier
	perm   auth.Permission // only set when tier == tierPermission
}

// routeMatrix enumerates every route mounted inside the JWT-authenticated
// group in routes.go, paired with the role tier routes.go actually applies.
// This table is the single hand-maintained source of truth for 3a; the
// TestRBACMatrix_NoDrift test below keeps it honest against the live router.
var routeMatrix = []routeCase{
	// ── any authenticated role ──────────────────────────────────────────
	{http.MethodGet, "/api/agents", tierAny, ""},
	{http.MethodGet, "/api/agents/download/{platform}", tierAny, ""},
	{http.MethodGet, "/api/scenarios", tierAny, ""},
	{http.MethodGet, "/api/scenarios/{id}", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/report", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/report.json", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/attackflow", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/variant-coverage", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/variant-coverage/{techniqueId}", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/export", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/events", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/pdf", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/forensic.csv", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/iocs", tierAny, ""},
	{http.MethodGet, "/api/campaigns", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/summary", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/report", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/pdf", tierAny, ""},
	{http.MethodGet, "/api/campaigns/{id}/forensic.csv", tierAny, ""},
	{http.MethodGet, "/api/findings", tierAny, ""},
	{http.MethodGet, "/api/findings/{id}", tierAny, ""},
	{http.MethodGet, "/api/findings/{id}/tickets", tierAny, ""},
	{http.MethodGet, "/api/remediations", tierAny, ""},
	{http.MethodGet, "/api/ticketing/candidates", tierAny, ""},
	{http.MethodGet, "/api/ticketing/revalidation", tierAny, ""},
	{http.MethodGet, "/api/ticketing/summary", tierAny, ""},
	{http.MethodGet, "/api/reports", tierAny, ""},
	{http.MethodPost, "/api/reports", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/logs/operational", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/logs/security", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/telemetry", tierAny, ""},
	{http.MethodGet, "/api/rules", tierAny, ""},
	{http.MethodGet, "/api/rules/{id}", tierAny, ""},
	{http.MethodGet, "/api/rules/search", tierAny, ""},
	{http.MethodGet, "/api/rules/technique/{id}", tierAny, ""},
	{http.MethodGet, "/api/rules/export", tierAny, ""},
	{http.MethodPost, "/api/scan/safe/{agentId}", tierAny, ""},
	{http.MethodGet, "/api/art/techniques", tierAny, ""},
	{http.MethodGet, "/api/caldera/abilities", tierAny, ""},
	{http.MethodGet, "/api/techniques/unified", tierAny, ""},
	{http.MethodGet, "/api/crypto/info", tierAny, ""},
	{http.MethodGet, "/api/coverage/analytics", tierAny, ""},
	{http.MethodGet, "/api/coverage/matrix", tierAny, ""},
	{http.MethodGet, "/api/coverage/actors", tierAny, ""},
	{http.MethodGet, "/api/threat-priority/actors", tierAny, ""},
	{http.MethodGet, "/api/threat-priority/actors/{name}", tierAny, ""},
	{http.MethodGet, "/api/analytics/threat-intel-summary", tierAny, ""},
	{http.MethodGet, "/api/analytics/endpoint-posture", tierAny, ""},
	{http.MethodGet, "/api/iocs", tierAny, ""},
	{http.MethodGet, "/api/analytics/iocs", tierAny, ""},
	{http.MethodPost, "/api/iocs/{id}/suppress", tierPermission, auth.CanManageIOCs},
	{http.MethodPost, "/api/iocs/import", tierPermission, auth.CanManageIOCs},
	{http.MethodGet, "/api/intelligence/campaigns", tierAny, ""},
	{http.MethodGet, "/api/intelligence/malware", tierAny, ""},
	{http.MethodGet, "/api/intelligence/tools", tierAny, ""},
	{http.MethodGet, "/api/knowledge-graph/{type}/{id}", tierAny, ""},
	{http.MethodGet, "/api/search", tierAny, ""},
	{http.MethodPost, "/api/search/reindex", tierPermission, auth.CanReindexSearch},
	{http.MethodPost, "/api/search/select", tierAny, ""},
	{http.MethodPost, "/api/search/favorite", tierAny, ""},
	{http.MethodGet, "/api/search/recents", tierAny, ""},
	{http.MethodGet, "/api/search/operators", tierAny, ""},
	{http.MethodGet, "/api/ti/readiness", tierAny, ""},
	{http.MethodGet, "/api/ti/readiness/history", tierAny, ""},
	{http.MethodGet, "/api/ti/suggest-pack", tierAny, ""},
	{http.MethodGet, "/api/ti/priority", tierAny, ""},
	{http.MethodGet, "/api/adversary-templates", tierAny, ""},
	{http.MethodGet, "/api/caldera/adversaries", tierAny, ""},
	{http.MethodGet, "/api/caldera/adversaries/{adversaryId}", tierAny, ""},
	{http.MethodGet, "/api/posture/catalog", tierAny, ""},
	{http.MethodGet, "/api/attack/matrix", tierAny, ""},
	{http.MethodGet, "/api/attack/technique/{id}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/summary", tierAny, ""},
	{http.MethodGet, "/api/attackpath/history", tierAny, ""},
	{http.MethodGet, "/api/attackpath/assets", tierAny, ""},
	{http.MethodGet, "/api/attackpath/schedule", tierAny, ""},
	{http.MethodGet, "/api/attackpath/subnet/{agentId}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/jobs", tierAny, ""},
	{http.MethodGet, "/api/attackpath/jobs/{id}", tierAny, ""},
	{http.MethodGet, "/api/attackpath/correlation", tierAny, ""},
	{http.MethodGet, "/api/controlhealth/summary", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/risk", tierAny, ""},
	{http.MethodGet, "/api/agents/risk-summary", tierAny, ""},
	{http.MethodGet, "/api/exposure/assets", tierAny, ""},
	{http.MethodGet, "/api/exposure/assets/{hostKey}", tierAny, ""},
	{http.MethodGet, "/api/dashboard/current", tierAny, ""},
	{http.MethodGet, "/api/dashboard/trends", tierAny, ""},
	{http.MethodGet, "/api/recommend/simulations", tierAny, ""},
	{http.MethodGet, "/api/predict/risk", tierAny, ""},
	{http.MethodGet, "/api/openaev/status", tierAny, ""},
	{http.MethodGet, "/api/openaev/scenarios", tierAny, ""},
	{http.MethodGet, "/api/openaev/scenarios/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/plans", tierAny, ""},
	{http.MethodGet, "/api/exercises/plans/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/templates", tierAny, ""},
	{http.MethodGet, "/api/exercises/templates/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/evidence", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/evidence/verify", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/events", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.json", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.html", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.pdf", tierAny, ""},
	{http.MethodGet, "/api/exercises/executions/{id}/report.csv", tierAny, ""},
	{http.MethodPost, "/api/exercises/executions", tierAny, ""},
	{http.MethodPost, "/api/auth/change-password", tierAny, ""},
	{http.MethodGet, "/api/report/full/html", tierAny, ""},
	{http.MethodGet, "/api/report/full/pdf", tierAny, ""},
	{http.MethodGet, "/api/report/full/csv", tierAny, ""},
	{http.MethodGet, "/api/report/audit-pack", tierAny, ""},
	{http.MethodGet, "/api/compliance/frameworks", tierAny, ""},
	{http.MethodGet, "/api/compliance/report", tierAny, ""},
	{http.MethodGet, "/api/compliance/scores", tierAny, ""},
	{http.MethodGet, "/api/me/permissions", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/verifications", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/verifications/{expectationId}/history", tierAny, ""},
	{http.MethodGet, "/api/verifications/{id}/evidence", tierAny, ""},
	{http.MethodGet, "/api/evidence/{id}/download", tierAny, ""},
	{http.MethodGet, "/api/techniques/{id}/relationships", tierAny, ""},
	{http.MethodGet, "/api/relationships/{id}", tierAny, ""},
	{http.MethodGet, "/api/relationships/{id}/evidence", tierAny, ""},

	// ── analyst + admin (per-permission since the 2026-07-18 RBAC expansion) ──
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
	{http.MethodGet, "/api/threatintel/lookup", tierPermission, auth.CanLookupIOC},
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
	{http.MethodPost, "/api/vex/sweeps", tierPermission, auth.CanRunVariants},
	{http.MethodGet, "/api/vex/sweeps/active", tierPermission, auth.CanViewVariantRun},
	{http.MethodGet, "/api/vex/sweeps/{id}", tierPermission, auth.CanViewVariantRun},
	{http.MethodGet, "/api/vex/sweeps", tierPermission, auth.CanViewVariantRun},
	{http.MethodPost, "/api/vex/sweeps/{id}/cancel", tierPermission, auth.CanCancelScenarioRun},
	{http.MethodGet, "/api/payload-families", tierPermission, auth.CanListPayloadFamilies},
	{http.MethodGet, "/api/payload-families/{techniqueId}", tierPermission, auth.CanViewPayloadFamily},
	{http.MethodPost, "/api/exercises/executions/{id}/launch", tierPermission, auth.CanLaunchExerciseExecution},
	{http.MethodPost, "/api/exercises/executions/{id}/abort", tierPermission, auth.CanAbortExerciseExecution},
	{http.MethodPost, "/api/exercises/executions/{id}/steps/{stepId}/approve", tierPermission, auth.CanApproveExerciseStep},
	{http.MethodPost, "/api/exercises/executions/{id}/evidence", tierPermission, auth.CanInjectExerciseEvidence},

	// ── admin only (per-permission since the 2026-07-18 RBAC expansion) ────
	{http.MethodPut, "/api/agents/{agentId}/state", tierPermission, auth.CanSetAgentState},
	{http.MethodPost, "/api/agents/{agentId}/stop", tierPermission, auth.CanStopAgent},
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
	{http.MethodGet, "/api/actions/configs", tierPermission, auth.CanListResponseConnectors},
	{http.MethodPost, "/api/actions/configs", tierPermission, auth.CanCreateResponseConnector},
	{http.MethodPut, "/api/actions/configs/{id}", tierPermission, auth.CanUpdateResponseConnector},
	{http.MethodDelete, "/api/actions/configs/{id}", tierPermission, auth.CanDeleteResponseConnector},
	{http.MethodPost, "/api/actions/configs/{id}/test", tierPermission, auth.CanTestResponseConnector},
	{http.MethodPost, "/api/actions/run", tierPermission, auth.CanExecuteResponseAction},
	{http.MethodGet, "/api/actions", tierPermission, auth.CanViewResponseActions},
	{http.MethodPost, "/api/agents/{agentId}/remediations", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/agents/{agentId}/remediations", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/remediation-requests/{requestId}", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/remediation-requests/{requestId}/revalidations", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/agents/{agentId}/checks/{checkId}/drift", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/agents/{agentId}/drift-summary", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/drift-reports/summary", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/remediation-requests/{requestId}/cancel", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/remediation-requests/{requestId}/rollback", tierPermission, auth.CanApproveRemediation},
	{http.MethodPost, "/api/remediation-requests/{requestId}/verify-technique", tierPermission, auth.CanRunScenario},
	{http.MethodGet, "/api/technique-verification-runs/{id}", tierPermission, auth.CanRunScenario},
	{http.MethodGet, "/api/remediation-reports/summary", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/jobs/batch-remediation", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/jobs/{jobId}", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/jobs/{jobId}/cancel", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/job-schedules", tierPermission, auth.CanExecuteRemediation},
	{http.MethodGet, "/api/job-schedules", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/job-schedules/{scheduleId}/cancel", tierPermission, auth.CanExecuteRemediation},
	{http.MethodPost, "/api/agents/{agentId}/maintenance-freezes", tierPermission, auth.CanApproveRemediation},
	{http.MethodGet, "/api/agents/{agentId}/maintenance-freezes", tierPermission, auth.CanExecuteRemediation},
	{http.MethodDelete, "/api/maintenance-freezes/{freezeId}", tierPermission, auth.CanApproveRemediation},
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

	// ── fine-grained permission gates ───────────────────────────────────
	{http.MethodPost, "/api/verifications", tierPermission, auth.CanVerify},
	{http.MethodPost, "/api/verifications/{id}/evidence", tierPermission, auth.CanUploadEvidence},
	{http.MethodDelete, "/api/evidence/{id}", tierPermission, auth.CanDeleteEvidence},
	{http.MethodPost, "/api/relationships", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPut, "/api/relationships/{id}", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/evidence", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodDelete, "/api/relationship-evidence/{id}", tierPermission, auth.CanCurateThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/review", tierPermission, auth.CanReviewThreatIntel},
	{http.MethodPost, "/api/relationships/{id}/status", tierPermission, auth.CanReviewThreatIntel},
	{http.MethodGet, "/api/sso/config", tierPermission, auth.CanViewSSOConfig},
	{http.MethodPost, "/api/sso/config", tierPermission, auth.CanManageSSOConfig},
	{http.MethodPut, "/api/sso/config/{id}", tierPermission, auth.CanManageSSOConfig},
	{http.MethodDelete, "/api/sso/config/{id}", tierPermission, auth.CanManageSSOConfig},
	{http.MethodPost, "/api/sso/config/{id}/test", tierPermission, auth.CanManageSSOConfig},
	{http.MethodGet, "/api/scim/config", tierPermission, auth.CanViewSCIMConfig},
	{http.MethodPost, "/api/scim/config", tierPermission, auth.CanManageSCIMConfig},
	{http.MethodPut, "/api/scim/config/{id}", tierPermission, auth.CanManageSCIMConfig},
	{http.MethodPost, "/api/scim/config/{id}/rotate", tierPermission, auth.CanManageSCIMConfig},
	{http.MethodDelete, "/api/scim/config/{id}", tierPermission, auth.CanManageSCIMConfig},

	// ── platform-admin only (Phase 7 Multi-Tenancy) ─────────────────────
	{http.MethodPost, "/api/tenants", tierPlatformAdmin, ""},
	{http.MethodGet, "/api/tenants", tierPlatformAdmin, ""},
	{http.MethodPatch, "/api/tenants/{id}", tierPlatformAdmin, ""},
}

// publicRoutes lists every routes.go registration OUTSIDE the JWT-authenticated
// group — these are intentionally excluded from routeMatrix and from the
// drift guard's "must have a matrix entry" requirement.
var publicRoutes = map[string]bool{
	"POST /api/auth/login":                        true,
	"POST /api/auth/logout":                       true,
	"POST /api/auth/setup":                        true,
	"GET /login/{tenantSlug}/sso":                 true,
	"GET /api/auth/sso/callback":                  true,
	"GET /scim/v2/ServiceProviderConfig":          true,
	"GET /scim/v2/ResourceTypes":                  true,
	"GET /scim/v2/Schemas":                        true,
	"POST /scim/v2/Users":                         true,
	"GET /scim/v2/Users":                          true,
	"GET /scim/v2/Users/{id}":                     true,
	"PUT /scim/v2/Users/{id}":                     true,
	"PATCH /scim/v2/Users/{id}":                   true,
	"DELETE /scim/v2/Users/{id}":                  true,
	"GET /api/agents/ping":                        true,
	"POST /api/agents/enroll":                     true,
	"POST /api/agents/unenroll":                   true,
	"POST /api/agents/events":                     true,
	"POST /api/heartbeat":                         true,
	"POST /api/scenarios/result":                  true,
	"POST /api/scenarios/events":                  true,
	"POST /api/scenarios/runs/{runId}/detections": true,
	"POST /api/attackpath/collect":                true,
	"POST /api/attackpath/sharphound":             true,
	"POST /api/attackpath/jobs/{id}/ack":          true,
	"GET /ws/agent":                               true,
	"GET /ws/browser":                             true,
	"POST /api/ticketing/webhook/{configId}":      true,
	"GET /health":                                 true,
}

func tierAllows(tier authTier, perm auth.Permission, role auth.Role) bool {
	switch tier {
	case tierAny:
		return true
	case tierAnalystAdmin:
		return role == auth.RoleAdmin || role == auth.RoleAnalyst
	case tierAdminOnly:
		return role == auth.RoleAdmin
	case tierPermission:
		return auth.HasPermission(role, perm)
	case tierPlatformAdmin:
		// No Role alone ever grants platform-admin — the boundary test's
		// role-based identities must all be forbidden. The positive case
		// (a real platform-admin token passes) is TestPlatformAdminRoutes_Gating.
		return false
	default:
		return false
	}
}

var paramPattern = regexp.MustCompile(`\{[^}]+\}`)

func concretePath(tpl string) string {
	return paramPattern.ReplaceAllString(tpl, "x")
}

func mountTestRouter(t *testing.T) http.Handler {
	t.Helper()
	h := New(sharedDB.Pool, ws.NewHub(), nil, testJWTSecret)
	return Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)
}

func TestRBACMatrix_AuthorizationBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		identities := []struct {
			name string
			role auth.Role
			anon bool
		}{
			{"anonymous", "", true},
			{"viewer", auth.RoleViewer, false},
			{"analyst", auth.RoleAnalyst, false},
			{"admin", auth.RoleAdmin, false},
		}

		for _, rc := range routeMatrix {
			for _, id := range identities {
				t.Run(rc.method+" "+rc.path+"/"+id.name, func(t *testing.T) {
					req := httptest.NewRequest(rc.method, concretePath(rc.path), nil)
					if !id.anon {
						tenantID := "default"
						tok, err := auth.GenerateTenantToken("matrix-"+id.name, id.role, &tenantID, false, testJWTSecret, time.Hour)
						if err != nil {
							t.Fatalf("mint token: %v", err)
						}
						req.Header.Set("Authorization", "Bearer "+tok)
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)

					if id.anon {
						if rec.Code != http.StatusUnauthorized {
							t.Fatalf("anonymous: status = %d, want 401", rec.Code)
						}
						return
					}
					if tierAllows(rc.tier, rc.perm, id.role) {
						if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
							t.Fatalf("role %s should clear the authz gate for %s %s, got %d", id.role, rc.method, rc.path, rec.Code)
						}
						return
					}
					if rec.Code != http.StatusForbidden {
						t.Fatalf("role %s should be forbidden from %s %s, got %d", id.role, rc.method, rc.path, rec.Code)
					}
				})
			}
		}
	})
}

// TestPlatformAdminRoutes_Gating proves the positive case tierAllows can't
// express: a genuine platform-admin token (IsPlatformAdmin claim, no tenant)
// clears the gate, while a tenant-scoped RoleAdmin token does not.
func TestPlatformAdminRoutes_Gating(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		platformAdminTok, _ := auth.GenerateTenantToken("pa-1", auth.RoleAdmin, nil, true, testJWTSecret, time.Hour)
		tenantID := "default"
		tenantAdminTok, _ := auth.GenerateTenantToken("ta-1", auth.RoleAdmin, &tenantID, false, testJWTSecret, time.Hour)

		req := httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
		req.Header.Set("Authorization", "Bearer "+platformAdminTok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("platform-admin GET /api/tenants status = %d, want 200", rec.Code)
		}

		req = httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
		req.Header.Set("Authorization", "Bearer "+tenantAdminTok)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("tenant-admin (RoleAdmin, not platform-admin) GET /api/tenants status = %d, want 403", rec.Code)
		}
	})
}

// TestRBACMatrix_NoDrift keeps routeMatrix honest against the live router in
// both directions: every authenticated route chi actually registered must
// have a matrix entry (positive drift — a new route added without a role
// decision), and every matrix entry must correspond to a route chi actually
// registered (negative drift — a stale entry for a renamed/removed route).
func TestRBACMatrix_NoDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		mux, ok := router.(chi.Routes)
		if !ok {
			t.Fatalf("Mount() returned %T, not a chi.Routes", router)
		}

		walked := map[string]bool{}
		err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if route == "/*" {
				return nil
			}
			key := method + " " + route
			if publicRoutes[key] {
				return nil
			}
			walked[key] = true
			return nil
		})
		if err != nil {
			t.Fatalf("chi.Walk: %v", err)
		}

		matrixed := map[string]bool{}
		for _, rc := range routeMatrix {
			matrixed[rc.method+" "+rc.path] = true
		}

		for k := range walked {
			if !matrixed[k] {
				t.Errorf("registered route %q has no routeMatrix entry", k)
			}
		}
		for k := range matrixed {
			if !walked[k] {
				t.Errorf("routeMatrix entry %q does not correspond to a route chi.Walk found", k)
			}
		}
	})
}

// TestRBACMatrix_MethodConfusion samples one route per tier and drives every
// HTTP method chi supports against its exact path, pinning whichever
// precedence chi's routing actually exhibits between "unregistered method on
// a known path" (405) and the auth middleware (401/403) — not presupposing
// either order.
func TestRBACMatrix_MethodConfusion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		// Each sample path is single-method in routeMatrix (verified: grepping
		// the matrix for each literal path yields exactly one entry) so the
		// method sweep below can safely treat every other method as
		// unregistered without colliding with a genuinely-registered method
		// on the same path under a different tier.
		samples := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/crypto/info"},        // tierAny
			{http.MethodPost, "/api/variants/generate"}, // tierAnalystAdmin
			{http.MethodGet, "/api/license"},            // tierAdminOnly
			{http.MethodPost, "/api/verifications"},     // tierPermission
		}
		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions}

		for _, s := range samples {
			for _, m := range methods {
				t.Run(m+" "+s.path, func(t *testing.T) {
					req := httptest.NewRequest(m, s.path, nil)
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if m == s.method {
						// The registered method — must not be a routing-level 404/405.
						if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
							t.Fatalf("registered method %s %s got routing status %d", m, s.path, rec.Code)
						}
						return
					}
					// Empirically observed (not presumed): with the "/*" catch-all
					// static handler mounted at the router root, chi falls through
					// to that wildcard route for a path+method combination with no
					// matching handler, rather than emitting a 405. It never reaches
					// the auth middleware — auth state has no bearing on this status.
					if rec.Code != http.StatusNotFound {
						t.Fatalf("unregistered method %s %s: status = %d, want 404 (falls through to the static catch-all)", m, s.path, rec.Code)
					}
				})
			}
		}
	})
}

func TestUserHandlers_MalformedPathParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		adminID := seedUser(t, pool, "peggy", "password123", "admin", true)

		// Empty id segment. DELETE ... WHERE id='' affects 0 rows, no SQL error —
		// DeleteUser reports that as 404 "user not found", not a silent 204.
		req := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/", nil, auth.RoleAdmin, adminID), "id", "")
		rec := callAuthed(h.DeleteUser, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("empty id: status = %d, want 404 (DELETE ... WHERE id='' affects 0 rows, reported as not-found)", rec.Code)
		}

		// SQL-metacharacter id — must be treated as inert parameterized data,
		// affecting 0 rows (404), never executed as SQL.
		req2 := withURLParam(authedRequest(t, http.MethodDelete, "/api/users/x", nil, auth.RoleAdmin, adminID), "id", "' OR 1=1--")
		rec2 := callAuthed(h.DeleteUser, req2)
		if rec2.Code != http.StatusNotFound {
			t.Fatalf("SQL-metacharacter id: status = %d, want 404", rec2.Code)
		}
		var remaining int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&remaining); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if remaining != 1 {
			t.Fatalf("user count after SQL-metacharacter delete attempt = %d, want 1 (only the untouched admin row)", remaining)
		}
	})
}
