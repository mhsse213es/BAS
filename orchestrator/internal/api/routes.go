package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/audspect/bas/internal/auth"
	exercisetracker "github.com/audspect/bas/internal/exercise/tracker"
	"github.com/audspect/bas/internal/ws"
)

// Mount builds the full HTTP router and returns it.
// staticHandler serves the dashboard SPA — pass StaticHandler() in production
// (embedded FS) or http.FileServer(http.Dir("./wwwroot")) in tests/dev.
// rateLimitPerMin <= 0 disables rate limiting entirely (the default —
// existing installs are never surprise-limited on upgrade).
func Mount(h *Handler, hub *ws.Hub, jwtSecret, agentSecret string, staticHandler http.Handler, rateLimitPerMin, rateLimitBurst int, tracker ...*exercisetracker.Tracker) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)

	// API rate limiting (opt-in) — a single global token-bucket limit shared
	// by the SCIM and JWT-authenticated groups below, protecting against a
	// runaway client on this single-tenant-per-database product. Not a
	// per-tenant commercial quota system (that's Audspect Cloud's concern).
	var rateLimit func(http.Handler) http.Handler
	if rateLimitPerMin > 0 {
		rateLimit = RateLimitMiddleware(rateLimitPerMin, rateLimitBurst)
	}

	// ── Public endpoints (no auth) ────────────────────────────────────────
	r.Post("/api/auth/login", h.Login)
	r.Post("/api/auth/logout", h.Logout)
	r.Post("/api/auth/setup", h.Setup) // first-run admin provisioning (installer)
	r.Get("/login/{tenantSlug}/sso", h.InitiateSSOLogin)
	r.Get("/api/auth/sso/callback", h.SSOCallback)

	// Agent endpoints — protected by optional AGENT_SECRET shared token.
	// When agentSecret is empty these remain open (backward compat).
	r.Get("/api/agents/ping", h.PingAgent)
	r.Post("/api/agents/enroll", h.EnrollAgent)
	r.Post("/api/agents/unenroll", h.UnenrollAgent)
	r.Post("/api/agents/events", h.ReceiveEvents)
	r.Post("/api/heartbeat", h.Heartbeat)
	r.Post("/api/scenarios/result", h.SubmitScenarioResult)
	r.Post("/api/scenarios/events", h.SubmitRunEvents)
	r.Post("/api/scenarios/runs/{runId}/detections", h.SubmitRunDetections)
	r.Post("/api/attackpath/collect", h.SubmitAttackPathCollection)
	r.Post("/api/attackpath/sharphound", h.SubmitAttackPathSharpHound)
	r.Post("/api/attackpath/jobs/{id}/ack", h.AckAttackPathJob)

	// WebSocket — agents connect here.
	// Validates agentSecret query param / X-Agent-Token header when configured.
	r.Get("/ws/agent", func(w http.ResponseWriter, req *http.Request) {
		if agentSecret != "" {
			provided := req.URL.Query().Get("agentSecret")
			if provided == "" {
				provided = req.Header.Get("X-Agent-Token")
			}
			if provided != agentSecret {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		hub.ServeAgentWS(w, req)
	})

	// WebSocket — browser dashboard.
	// Requires a valid JWT from the bas_token cookie or Authorization header.
	r.Get("/ws/browser", func(w http.ResponseWriter, req *http.Request) {
		tokenStr := auth.TokenFromRequest(req)
		if tokenStr == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := auth.ValidateToken(tokenStr, jwtSecret); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		hub.ServeBrowserWS(w, req)
	})

	// ITSM inbound webhook — no JWT auth; connector validates via HMAC or IP allowlist
	r.Post("/api/ticketing/webhook/{configId}", h.ReceiveTicketingWebhook)

	// SCIM (RFC 7644) — own per-tenant bearer-token auth, not JWT. See
	// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
	r.Group(func(r chi.Router) {
		r.Use(h.scimAuth)
		if rateLimit != nil {
			r.Use(rateLimit)
		}
		r.Get("/scim/v2/ServiceProviderConfig", h.SCIMServiceProviderConfig)
		r.Get("/scim/v2/ResourceTypes", h.SCIMResourceTypes)
		r.Get("/scim/v2/Schemas", h.SCIMSchemas)
		r.Post("/scim/v2/Users", h.SCIMCreateUser)
		r.Get("/scim/v2/Users", h.SCIMListUsers)
		r.Get("/scim/v2/Users/{id}", h.SCIMGetUser)
		r.Put("/scim/v2/Users/{id}", h.SCIMReplaceUser)
		r.Patch("/scim/v2/Users/{id}", h.SCIMPatchUser)
		r.Delete("/scim/v2/Users/{id}", h.SCIMDeleteUser)
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Exercise tracking — no auth; single-use tokens gate access.
	if len(tracker) > 0 && tracker[0] != nil {
		tr := tracker[0]
		r.Get("/x/open/{token}", tr.HandleOpen)
		r.Get("/x/click/{token}", tr.HandleClick)
		r.Post("/x/cred/{token}", tr.HandleCredSubmit)
		r.Post("/x/report/{token}", tr.HandleReport)
		r.Post("/x/hook/{token}", tr.HandleWebhook) // inbound webhook from external systems
	}

	// ── Authenticated endpoints (JWT required) ────────────────────────────
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(jwtSecret))
		if rateLimit != nil {
			r.Use(rateLimit)
		}

		// Viewer + Analyst + Admin
		r.Get("/api/agents", h.GetAgents)
		r.Get("/api/agents/download/{platform}", h.DownloadAgent)
		r.Get("/api/scenarios", h.ListScenarios)
		r.Get("/api/scenarios/{id}", h.GetScenario)
		r.Get("/api/scenarios/runs", h.ListScenarioRuns)
		r.Get("/api/scenarios/runs/{runId}/report", h.GetRunReport)
		r.Get("/api/scenarios/runs/{runId}/report.json", h.GetRunReportData)
		r.Get("/api/scenarios/runs/{runId}/attackflow", h.GetRunAttackFlow)
		r.Get("/api/scenarios/runs/{runId}/variant-coverage", h.GetVariantCoverageReport)
		r.Get("/api/scenarios/runs/{runId}/variant-coverage/{techniqueId}", h.GetVariantMatrix)
		r.Get("/api/scenarios/runs/{runId}/export", h.ExportRunJSON)
		r.Get("/api/scenarios/runs/{runId}/events", h.ListRunEvents)
		r.Get("/api/scenarios/runs/{runId}/pdf", h.GetRunPDF)
		r.Get("/api/scenarios/runs/{runId}/forensic.csv", h.GetRunForensicCSV)
		r.Get("/api/scenarios/runs/{runId}/iocs", h.GetRunIOCs)
		r.Get("/api/campaigns", h.ListCampaigns)
		r.Get("/api/campaigns/{id}", h.GetCampaign)
		r.Get("/api/campaigns/{id}/summary", h.CampaignSummary)
		r.Get("/api/campaigns/{id}/report", h.GetCampaignReport)
		r.Get("/api/campaigns/{id}/pdf", h.GetCampaignPDF)
		r.Get("/api/campaigns/{id}/forensic.csv", h.GetCampaignCSV)
		r.Get("/api/findings", h.ListFindings)
		r.Get("/api/findings/{id}", h.GetFinding)
		r.Get("/api/findings/{id}/tickets", h.GetFindingTickets)
		r.Get("/api/remediations", h.ListRemediations)
		r.Get("/api/ticketing/candidates", h.ListTicketCandidates)
		r.Get("/api/ticketing/revalidation", h.RevalidationStatus)
		r.Get("/api/ticketing/summary", h.TicketingSummary)
		r.Get("/api/reports", h.ListReports)
		r.Post("/api/reports", h.CreateReport)
		r.Get("/api/agents/{agentId}/logs/operational", h.GetOpLogs)
		r.Get("/api/agents/{agentId}/logs/security", h.GetSecLogs)
		r.Get("/api/agents/{agentId}/telemetry", h.GetTelemetry)

		// Detection Rule Library — read-only, Viewer+.
		r.Get("/api/rules", h.ListRules)
		r.Get("/api/rules/{id}", h.GetRule)
		r.Get("/api/rules/search", h.SearchRules)
		r.Get("/api/rules/technique/{id}", h.RulesByTechnique)
		r.Get("/api/rules/export", h.ExportRule)

		// Viewer+ — safe read-only simulation makes no changes to the endpoint
		r.Post("/api/scan/safe/{agentId}", h.SafeScan)

		// Live framework catalogs — drive the real-time sweep counts and the
		// selectable technique/ability picker. Read-only, Viewer+.
		r.Get("/api/art/techniques", h.GetARTTechniques)
		r.Get("/api/caldera/abilities", h.GetCalderaAbilities)
		r.Get("/api/techniques/unified", h.GetUnifiedTechniques)

		// Crypto profile — read-only; useful for customer security reviews.
		r.Get("/api/crypto/info", h.GetCryptoInfo)

		// Coverage Analytics — aggregate prevention/detection breakdown across runs.
		r.Get("/api/coverage/analytics", h.GetCoverageAnalytics)

		// Technique Coverage -- content-existence matrix (simulation/detection
		// profile/purple exercise/compliance mapping), distinct from
		// /api/coverage/analytics above (run-result aggregation).
		r.Get("/api/coverage/matrix", h.CoverageMatrix)
		r.Get("/api/coverage/actors", h.CoverageActors)

		// Threat Prioritization -- standing, fleet-wide, per-actor composite
		// score (distinct from /api/coverage/matrix's technique-level view
		// and /api/recommend/simulations' technique-level ranking).
		r.Get("/api/threat-priority/actors", h.ThreatPriorityActors)
		r.Get("/api/threat-priority/actors/{name}", h.ThreatPriorityActorDetail)

		// Threat Intel Summary -- fleet-wide posture combining the above
		// per-actor scoring with KEV exposure, for dashboard consumption.
		r.Get("/api/analytics/threat-intel-summary", h.GetThreatIntelSummary)

		// Endpoint Posture -- fleet-wide agent health + derived EPP isolation
		// state, for dashboard consumption. Last of the 7 analytics categories.
		r.Get("/api/analytics/endpoint-posture", h.GetEndpointPosture)

		// IOC Registry -- flat search over the canonical IOC model
		// (Phase 0+A of the IOC handling initiative).
		r.Get("/api/iocs", h.GetIOCs)
		r.Get("/api/analytics/iocs", h.GetIOCAnalytics)
		r.With(auth.RequirePermission(auth.CanManageIOCs)).Post("/api/iocs/{id}/suppress", h.SetIOCSuppressed)
		r.With(auth.RequirePermission(auth.CanManageIOCs)).Post("/api/iocs/import", h.ImportIOCs)

		// Intelligence Expansion -- MISP/OpenCTI-sourced Campaigns/Malware/Tools
		// (distinct from /api/threat-priority's actor-level scoring).
		r.Get("/api/intelligence/campaigns", h.IntelligenceCampaigns)
		r.Get("/api/intelligence/malware", h.IntelligenceMalware)
		r.Get("/api/intelligence/tools", h.IntelligenceTools)
		r.Get("/api/knowledge-graph/{type}/{id}", h.KnowledgeGraphNeighborhood)
		r.Get("/api/search", h.Search)
		r.With(auth.RequirePermission(auth.CanReindexSearch)).Post("/api/search/reindex", h.SearchReindex)
		r.Post("/api/search/select", h.SearchSelect)
		r.Post("/api/search/favorite", h.SearchFavorite)
		r.Get("/api/search/recents", h.SearchRecents)
		r.Get("/api/search/operators", h.SearchOperators)

		// Threat Intelligence — readiness, KEV pack suggestions, EPSS priority scoring, and trends.
		r.Get("/api/ti/readiness", h.GetTIReadiness)
		r.Get("/api/ti/readiness/history", h.GetTIReadinessHistory)
		r.Get("/api/ti/suggest-pack", h.GetSuggestPack)
		r.Get("/api/ti/priority", h.GetTIPriority)

		// Adversary template catalog — curated playbooks mixing BAS + ART + Caldera.
		r.Get("/api/adversary-templates", h.GetAdversaryTemplates)
		r.Get("/api/caldera/adversaries", h.GetCalderaAdversaries)
		r.Get("/api/caldera/adversaries/{adversaryId}", h.GetCalderaAdversary)
		r.Get("/api/posture/catalog", h.GetPostureCatalog)

		// ATT&CK Coverage matrix — authoritative enterprise structure + per-technique
		// enrichment; coverage status is overlaid client-side from run data.
		r.Get("/api/attack/matrix", h.AttackMatrix)
		r.Get("/api/attack/technique/{id}", h.AttackTechnique)

		// Attack Path Validation — fleet lateral-movement graph summary.
		r.Get("/api/attackpath/summary", h.GetAttackPathSummary)
		r.Get("/api/attackpath/history", h.GetAttackPathHistory)
		r.Get("/api/attackpath/assets", h.GetAttackPathAssets)
		r.Get("/api/attackpath/schedule", h.GetAttackPathSchedule)
		r.Get("/api/attackpath/subnet/{agentId}", h.GetAttackPathSubnet)
		r.Get("/api/attackpath/jobs", h.ListAttackPathJobs)
		r.Get("/api/attackpath/jobs/{id}", h.GetAttackPathJob)
		r.Get("/api/attackpath/correlation", h.GetAttackPathCorrelation)
		r.Get("/api/controlhealth/summary", h.GetControlHealthSummary)
		r.Get("/api/agents/{agentId}/risk", h.GetAgentRisk)
		r.Get("/api/agents/risk-summary", h.GetAgentRiskSummary)
		r.Get("/api/exposure/assets", h.GetExposureAssets)
		r.Get("/api/exposure/assets/{hostKey}", h.GetExposureAsset)

		// Executive Dashboard — Phase 6. Fleet-wide risk/exposure/detection
		// trends, read-only (Viewer+).
		r.Get("/api/dashboard/current", h.GetDashboardCurrent)
		r.Get("/api/dashboard/trends", h.GetDashboardTrends)

		// Recommendation Engine — Phase 6. Best-next-simulation ranking,
		// read-only (Viewer+).
		r.Get("/api/recommend/simulations", h.GetRecommendedSimulations)

		// Predictive Risk — Phase 6. Risk-score forecast + exposure windows,
		// read-only (Viewer+).
		r.Get("/api/predict/risk", h.GetPredictRisk)

		// OpenAEV Connector — read-only, Viewer+.
		r.Get("/api/openaev/status", h.GetOpenAEVStatus)
		r.Get("/api/openaev/scenarios", h.ListOpenAEVScenarios)
		r.Get("/api/openaev/scenarios/{id}", h.GetOpenAEVScenario)

		// Analyst + Admin only — can trigger scans, run scenarios, and
		// author custom scenarios from the dashboard. Gated per-route since
		// the 2026-07-18 RBAC permission expansion (see
		// docs/superpowers/specs/2026-07-18-phase7-rbac-permission-expansion-design.md).
		r.With(auth.RequirePermission(auth.CanTriggerScan)).Post("/api/scan/{agentId}", h.TriggerScan)
		r.With(auth.RequirePermission(auth.CanCollectAttackPath)).Post("/api/attackpath/collect/{agentId}", h.DispatchAttackPathCollect)
		r.With(auth.RequirePermission(auth.CanCreateAttackPathJob)).Post("/api/attackpath/jobs", h.CreateAttackPathJob)
		r.With(auth.RequirePermission(auth.CanCancelAttackPathJob)).Post("/api/attackpath/jobs/{id}/cancel", h.CancelAttackPathJob)
		r.With(auth.RequirePermission(auth.CanRetryAttackPathJob)).Post("/api/attackpath/jobs/{id}/retry", h.RetryAttackPathJob)
		r.With(auth.RequirePermission(auth.CanSetAttackPathAsset)).Post("/api/attackpath/assets", h.SetAttackPathAsset)
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/scenarios/{id}/run", h.RunScenario)
		r.With(auth.RequirePermission(auth.CanRunCalderaAdversary)).Post("/api/caldera/adversaries/{adversaryId}/run", h.RunCalderaAdversary)
		r.With(auth.RequirePermission(auth.CanRunAdversaryTemplate)).Post("/api/adversary-templates/{id}/run", h.RunAdversaryTemplate)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/scenarios/runs/{runId}/cancel", h.CancelRun)
		// SIEM Correlation — trigger and results (Analyst+)
		r.With(auth.RequirePermission(auth.CanCorrelateSIEM)).Post("/api/siem/correlate/{runId}", h.TriggerSIEMCorrelation)
		r.With(auth.RequirePermission(auth.CanViewSIEMCorrelations)).Get("/api/siem/correlations/{runId}", h.GetSIEMCorrelations)
		// Detection Verification — manual trigger (Analyst+)
		r.With(auth.RequirePermission(auth.CanRunDetectionVerification)).Post("/api/detectverify/run/{runId}", h.TriggerDetectionVerification)
		r.With(auth.RequirePermission(auth.CanLookupIOC)).Get("/api/threatintel/lookup", h.LookupIOC)
		r.With(auth.RequirePermission(auth.CanCreateCampaign)).Post("/api/campaigns", h.CreateCampaign)
		r.With(auth.RequirePermission(auth.CanStopCampaign)).Post("/api/campaigns/{id}/stop", h.StopCampaign)
		r.With(auth.RequirePermission(auth.CanSetFindingStatus)).Post("/api/findings/{id}/status", h.SetFindingStatus)
		r.With(auth.RequirePermission(auth.CanPushToITSM)).Post("/api/ticketing/push", h.PushFindingToITSM)
		r.With(auth.RequirePermission(auth.CanBulkPushToITSM)).Post("/api/ticketing/push/bulk", h.BulkPushToITSM)

		// Custom scenario builder
		r.With(auth.RequirePermission(auth.CanCreateScenario)).Post("/api/scenarios", h.CreateScenario)
		r.With(auth.RequirePermission(auth.CanUploadScenario)).Post("/api/scenarios/upload", h.UploadScenario)
		r.With(auth.RequirePermission(auth.CanCloneScenario)).Post("/api/scenarios/{id}/clone", h.CloneScenario)
		r.With(auth.RequirePermission(auth.CanUpdateScenario)).Put("/api/scenarios/{id}", h.UpdateScenario)
		r.With(auth.RequirePermission(auth.CanDeleteScenario)).Delete("/api/scenarios/{id}", h.DeleteScenario)

		// Variant executor — multi-variant technique execution
		r.With(auth.RequirePermission(auth.CanGenerateVariants)).Post("/api/variants/generate", h.GenerateVariants)
		r.With(auth.RequirePermission(auth.CanRunVariants)).Post("/api/variants/run", h.RunVariants)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/variants/run/{id}", h.GetVariantRun)
		r.With(auth.RequirePermission(auth.CanViewVariantCoverage)).Get("/api/variants/coverage", h.GetVariantCoverage)
		r.With(auth.RequirePermission(auth.CanViewVariantStats)).Get("/api/variants/stats", h.GetVariantStats)

		// Full Variant Sweep — server-owned orchestration
		r.With(auth.RequirePermission(auth.CanRunVariants)).Post("/api/vex/sweeps", h.CreateVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/active", h.GetActiveVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}", h.GetVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps", h.ListVexSweeps)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/vex/sweeps/{id}/cancel", h.CancelVexSweep)

		// Payload families (Phase 3) — mutation/delete is Admin only (see below)
		r.With(auth.RequirePermission(auth.CanListPayloadFamilies)).Get("/api/payload-families", h.GetPayloadFamilies)
		r.With(auth.RequirePermission(auth.CanViewPayloadFamily)).Get("/api/payload-families/{techniqueId}", h.GetTechniqueFamilies)

		// Exercise Engine — Analyst+ can run and observe exercises.
		r.With(auth.RequirePermission(auth.CanLaunchExerciseExecution)).Post("/api/exercises/executions/{id}/launch", h.LaunchExerciseExecution)
		r.With(auth.RequirePermission(auth.CanAbortExerciseExecution)).Post("/api/exercises/executions/{id}/abort", h.AbortExerciseExecution)
		r.With(auth.RequirePermission(auth.CanApproveExerciseStep)).Post("/api/exercises/executions/{id}/steps/{stepId}/approve", h.ApproveExerciseStep)
		r.With(auth.RequirePermission(auth.CanInjectExerciseEvidence)).Post("/api/exercises/executions/{id}/evidence", h.InjectEvidence)

		// Exercise — read access for all authenticated roles.
		r.Get("/api/exercises/plans", h.ListExercisePlans)
		r.Get("/api/exercises/plans/{id}", h.GetExercisePlan)
		r.Get("/api/exercises/templates", h.ListExerciseTemplates)
		r.Get("/api/exercises/templates/{id}", h.GetExerciseTemplate)
		r.Get("/api/exercises/executions", h.ListExerciseExecutions)
		r.Get("/api/exercises/executions/{id}", h.GetExerciseExecution)
		r.Get("/api/exercises/executions/{id}/evidence", h.GetExerciseEvidence)
		r.Get("/api/exercises/executions/{id}/evidence/verify", h.VerifyExerciseChain)
		r.Get("/api/exercises/executions/{id}/events", h.GetExerciseEvents)
		r.Get("/api/exercises/executions/{id}/report.json", h.GetExerciseReportJSON)
		r.Get("/api/exercises/executions/{id}/report.html", h.GetExerciseReportHTML)
		r.Get("/api/exercises/executions/{id}/report.pdf", h.GetExerciseReportPDF)
		r.Get("/api/exercises/executions/{id}/report.csv", h.GetExerciseReportCSV)
		r.Post("/api/exercises/executions", h.CreateExerciseExecution)

		// Any authenticated user — self-service password change
		r.Post("/api/auth/change-password", h.ChangePassword)

		// Full report + audit pack — Viewer+ role
		r.Get("/api/report/full/html", h.GetFullReportHTML)
		r.Get("/api/report/full/pdf", h.GetFullReportPDF)
		r.Get("/api/report/full/csv", h.GetFullReportCSV)
		r.Get("/api/report/audit-pack", h.GetAuditPack)

		// Compliance — Viewer+ role
		r.Get("/api/compliance/frameworks", h.ListComplianceFrameworks)
		r.Get("/api/compliance/report", h.GetComplianceReport)
		r.Get("/api/compliance/scores", h.GetComplianceDashboardScores)

		// Detection Validation SP2 — manual verification queue + evidence store.
		// Reads are Viewer+; writes are gated on fine-grained permissions so a
		// large SOC can separate verifier, reviewer and evidence-deletion rights.
		r.Get("/api/me/permissions", h.GetMyPermissions)
		r.Get("/api/scenarios/runs/{runId}/verifications", h.ListRunVerifications)
		r.Get("/api/scenarios/runs/{runId}/verifications/{expectationId}/history", h.GetVerificationHistory)
		r.Get("/api/verifications/{id}/evidence", h.ListVerificationEvidence)
		r.Get("/api/evidence/{id}/download", h.DownloadEvidence)
		r.With(auth.RequirePermission(auth.CanVerify)).Post("/api/verifications", h.CreateVerification)
		r.With(auth.RequirePermission(auth.CanUploadEvidence)).Post("/api/verifications/{id}/evidence", h.UploadVerificationEvidence)
		r.With(auth.RequirePermission(auth.CanDeleteEvidence)).Delete("/api/evidence/{id}", h.DeleteEvidence)

		// CVE↔ATT&CK Relationship Store — evidence-backed, confidence-scored
		// technique-CVE relationships. Reads are Viewer+; curation and review are
		// gated on separate permissions so confidence promotion/demotion isn't
		// self-service for the same analyst who proposed it.
		r.Get("/api/techniques/{id}/relationships", h.ListTechniqueRelationships)
		r.Get("/api/relationships/{id}", h.GetRelationship)
		r.Get("/api/relationships/{id}/evidence", h.ListRelationshipEvidence)
		r.With(auth.RequirePermission(auth.CanCurateThreatIntel)).Post("/api/relationships", h.CreateRelationship)
		r.With(auth.RequirePermission(auth.CanCurateThreatIntel)).Put("/api/relationships/{id}", h.UpdateRelationship)
		r.With(auth.RequirePermission(auth.CanCurateThreatIntel)).Post("/api/relationships/{id}/evidence", h.AddRelationshipEvidence)
		r.With(auth.RequirePermission(auth.CanCurateThreatIntel)).Delete("/api/relationship-evidence/{id}", h.DeleteRelationshipEvidence)
		r.With(auth.RequirePermission(auth.CanReviewThreatIntel)).Post("/api/relationships/{id}/review", h.ReviewRelationship)
		r.With(auth.RequirePermission(auth.CanReviewThreatIntel)).Post("/api/relationships/{id}/status", h.SetRelationshipStatus)

		// SSO (OIDC) config — tenant-scoped CRUD. See
		// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
		r.With(auth.RequirePermission(auth.CanViewSSOConfig)).Get("/api/sso/config", h.GetSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Post("/api/sso/config", h.CreateSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Put("/api/sso/config/{id}", h.UpdateSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Delete("/api/sso/config/{id}", h.DeleteSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Post("/api/sso/config/{id}/test", h.TestSSOConfig)

		// SCIM provisioning config — tenant-scoped CRUD. See
		// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
		r.With(auth.RequirePermission(auth.CanViewSCIMConfig)).Get("/api/scim/config", h.GetSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Post("/api/scim/config", h.CreateSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Put("/api/scim/config/{id}", h.UpdateSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Post("/api/scim/config/{id}/rotate", h.RotateSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Delete("/api/scim/config/{id}", h.DeleteSCIMConfig)

		// Admin only — config + user management + connector. Gated per-route
		// since the 2026-07-18 RBAC permission expansion (see
		// docs/superpowers/specs/2026-07-18-phase7-rbac-permission-expansion-design.md).
		r.With(auth.RequirePermission(auth.CanSetAgentState)).Put("/api/agents/{agentId}/state", h.SetAgentState)
		r.With(auth.RequirePermission(auth.CanStopAgent)).Post("/api/agents/{agentId}/stop", h.StopAgent)
		r.With(auth.RequirePermission(auth.CanViewLicense)).Get("/api/license", h.GetLicenseInfo)
		r.With(auth.RequirePermission(auth.CanViewConnectionConfig)).Get("/api/config/connection", h.GetConnectionConfig)
		r.With(auth.RequirePermission(auth.CanListUsers)).Get("/api/users", h.ListUsers)
		r.With(auth.RequirePermission(auth.CanCreateUser)).Post("/api/users", h.CreateUser)
		r.With(auth.RequirePermission(auth.CanUpdateUser)).Put("/api/users/{id}", h.UpdateUser)
		r.With(auth.RequirePermission(auth.CanDeleteUser)).Delete("/api/users/{id}", h.DeleteUser)
		r.With(auth.RequirePermission(auth.CanResetUserPassword)).Post("/api/users/{id}/reset-password", h.ResetPassword)

		// Caldera engine status
		r.With(auth.RequirePermission(auth.CanViewCalderaStatus)).Get("/api/caldera/status", h.GetCalderaStatus)

		// Threat-intel connector
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/connector/status", h.GetConnectorStatus)
		r.With(auth.RequirePermission(auth.CanSyncConnector)).Post("/api/connector/sync", h.TriggerConnectorSync)
		r.With(auth.RequirePermission(auth.CanDeleteConnectorScenario)).Delete("/api/connector/scenarios/{id}", h.DeleteIntelScenario)

		// Attack-path schedule config — enables periodic fleet collection.
		r.With(auth.RequirePermission(auth.CanSetAttackPathSchedule)).Post("/api/attackpath/schedule", h.SetAttackPathSchedule)

		// ART content: status + content-pack reseed (no image rebuild)
		r.With(auth.RequirePermission(auth.CanViewARTContentStatus)).Get("/api/art/content/status", h.GetARTContentStatus)
		r.With(auth.RequirePermission(auth.CanReseedARTContent)).Post("/api/art/content/reseed", h.ReseedART)

		// Filesystem integrity — tamper event log + acknowledgement
		r.With(auth.RequirePermission(auth.CanViewTamperEvents)).Get("/api/tamper-events", h.GetTamperEvents)
		r.With(auth.RequirePermission(auth.CanAcknowledgeTamperEvent)).Post("/api/tamper-events/{id}/acknowledge", h.AcknowledgeTamperEvent)
		r.With(auth.RequirePermission(auth.CanAcknowledgeAllTamperEvents)).Post("/api/tamper-events/acknowledge-all", h.AcknowledgeAllTamperEvents)

		// Audit log — append-only record of all operator actions
		r.With(auth.RequirePermission(auth.CanViewAuditLogs)).Get("/api/audit-logs", h.GetAuditLogs)

		// Ticketing — ITSM connector management (admin only)
		r.With(auth.RequirePermission(auth.CanListTicketingConfigs)).Get("/api/ticketing/configs", h.ListTicketingConfigs)
		r.With(auth.RequirePermission(auth.CanCreateTicketingConfig)).Post("/api/ticketing/configs", h.CreateTicketingConfig)
		r.With(auth.RequirePermission(auth.CanUpdateTicketingConfig)).Put("/api/ticketing/configs/{id}", h.UpdateTicketingConfig)
		r.With(auth.RequirePermission(auth.CanDeleteTicketingConfig)).Delete("/api/ticketing/configs/{id}", h.DeleteTicketingConfig)
		r.With(auth.RequirePermission(auth.CanTestTicketingConfig)).Post("/api/ticketing/configs/{id}/test", h.TestTicketingConfig)
		r.With(auth.RequirePermission(auth.CanProbeTicketingConfig)).Post("/api/ticketing/probe", h.ProbeTicketingConfig)
		r.With(auth.RequirePermission(auth.CanProbeTicketingProjects)).Post("/api/ticketing/probe/projects", h.ProbeListProjects)
		r.With(auth.RequirePermission(auth.CanSyncTicketing)).Post("/api/ticketing/sync", h.TriggerTicketingSync)

		// Payload family management — write/delete restricted to Admin
		r.With(auth.RequirePermission(auth.CanCreatePayloadFamily)).Post("/api/payload-families", h.CreatePayloadFamily)
		r.With(auth.RequirePermission(auth.CanDeletePayloadFamily)).Delete("/api/payload-families/{id}", h.DeletePayloadFamily)

		// SIEM Correlation — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListSIEMConfigs)).Get("/api/siem/configs", h.ListSIEMConfigs)
		r.With(auth.RequirePermission(auth.CanCreateSIEMConfig)).Post("/api/siem/configs", h.CreateSIEMConfig)
		r.With(auth.RequirePermission(auth.CanUpdateSIEMConfig)).Put("/api/siem/configs/{id}", h.UpdateSIEMConfig)
		r.With(auth.RequirePermission(auth.CanDeleteSIEMConfig)).Delete("/api/siem/configs/{id}", h.DeleteSIEMConfig)
		r.With(auth.RequirePermission(auth.CanTestSIEMConfig)).Post("/api/siem/configs/{id}/test", h.TestSIEMConfig)

		// Detection Verification — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListDetectionConnectors)).Get("/api/detectverify/configs", h.ListDetectionConnectors)
		r.With(auth.RequirePermission(auth.CanCreateDetectionConnector)).Post("/api/detectverify/configs", h.CreateDetectionConnector)
		r.With(auth.RequirePermission(auth.CanUpdateDetectionConnector)).Put("/api/detectverify/configs/{id}", h.UpdateDetectionConnector)
		r.With(auth.RequirePermission(auth.CanDeleteDetectionConnector)).Delete("/api/detectverify/configs/{id}", h.DeleteDetectionConnector)
		r.With(auth.RequirePermission(auth.CanTestDetectionConnector)).Post("/api/detectverify/configs/{id}/test", h.TestDetectionConnector)

		// EPP Response Actions — connector management (Admin only)
		r.With(auth.RequirePermission(auth.CanListResponseConnectors)).Get("/api/actions/configs", h.ListResponseConnectors)
		r.With(auth.RequirePermission(auth.CanCreateResponseConnector)).Post("/api/actions/configs", h.CreateResponseConnector)
		r.With(auth.RequirePermission(auth.CanUpdateResponseConnector)).Put("/api/actions/configs/{id}", h.UpdateResponseConnector)
		r.With(auth.RequirePermission(auth.CanDeleteResponseConnector)).Delete("/api/actions/configs/{id}", h.DeleteResponseConnector)
		r.With(auth.RequirePermission(auth.CanTestResponseConnector)).Post("/api/actions/configs/{id}/test", h.TestResponseConnector)

		// EPP Response Actions — execute + audit trail
		r.With(auth.RequirePermission(auth.CanExecuteResponseAction)).Post("/api/actions/run", h.ExecuteResponseAction)
		r.With(auth.RequirePermission(auth.CanViewResponseActions)).Get("/api/actions", h.ListResponseActions)

		// Endpoint Remediation Execution — execute is Analyst+Admin (Tier 2's
		// stricter Admin-only gate is checked dynamically inside the handler,
		// since it depends on the requested remediation's own tier).
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/agents/{agentId}/remediations", h.ExecuteRemediation)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/remediations", h.ListAgentRemediations)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-requests/{requestId}", h.GetRemediation)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-requests/{requestId}/revalidations", h.GetRemediationRevalidations)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/checks/{checkId}/drift", h.GetControlDrift)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/drift-summary", h.GetAgentDriftSummary)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/drift-reports/summary", h.GetFleetDriftReport)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/remediation-requests/{requestId}/cancel", h.CancelRemediation)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Post("/api/remediation-requests/{requestId}/rollback", h.RollbackRemediation)
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/remediation-requests/{requestId}/verify-technique", h.VerifyTechnique)
		r.With(auth.RequirePermission(auth.CanRunScenario)).Get("/api/technique-verification-runs/{id}", h.GetTechniqueVerification)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/remediation-reports/summary", h.RemediationReportSummary)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/jobs/batch-remediation", h.CreateBatchRemediationJob)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/jobs/{jobId}", h.GetJob)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/jobs/{jobId}/cancel", h.CancelJob)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/job-schedules", h.CreateJobSchedule)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/job-schedules", h.ListJobSchedules)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Post("/api/job-schedules/{scheduleId}/cancel", h.CancelJobSchedule)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Post("/api/agents/{agentId}/maintenance-freezes", h.CreateAgentFreeze)
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/agents/{agentId}/maintenance-freezes", h.ListAgentFreezes)
		r.With(auth.RequirePermission(auth.CanApproveRemediation)).Delete("/api/maintenance-freezes/{freezeId}", h.DeleteAgentFreeze)

		// OpenAEV Connector — config + sync + air-gapped import (Admin only)
		r.With(auth.RequirePermission(auth.CanViewOpenAEVConfig)).Get("/api/openaev/config", h.GetOpenAEVConfig)
		r.With(auth.RequirePermission(auth.CanUpdateOpenAEVConfig)).Put("/api/openaev/config", h.PutOpenAEVConfig)
		r.With(auth.RequirePermission(auth.CanTestOpenAEVConfig)).Post("/api/openaev/config/test", h.TestOpenAEVConfig)
		r.With(auth.RequirePermission(auth.CanSyncOpenAEV)).Post("/api/openaev/sync", h.SyncOpenAEV)
		r.With(auth.RequirePermission(auth.CanImportOpenAEVBundle)).Post("/api/openaev/import", h.ImportOpenAEVBundle)
		r.With(auth.RequirePermission(auth.CanCreateExercisePlanFromOpenAEV)).Post("/api/openaev/scenarios/{id}/create-plan", h.CreateExercisePlanFromOpenAEV)

		// Exercise plan authoring — Admin only
		r.With(auth.RequirePermission(auth.CanCreateExercisePlan)).Post("/api/exercises/plans", h.CreateExercisePlan)
		r.With(auth.RequirePermission(auth.CanValidateExercisePlan)).Post("/api/exercises/plans/validate", h.ValidateExercisePlan)
		r.With(auth.RequirePermission(auth.CanUpdateExercisePlan)).Put("/api/exercises/plans/{id}", h.UpdateExercisePlan)
		r.With(auth.RequirePermission(auth.CanDeleteExercisePlan)).Delete("/api/exercises/plans/{id}", h.DeleteExercisePlan)

		// Exercise templates — Admin only for write, all authenticated for read
		r.With(auth.RequirePermission(auth.CanCreateExerciseTemplate)).Post("/api/exercises/templates", h.CreateExerciseTemplate)
		r.With(auth.RequirePermission(auth.CanInstantiateExerciseTemplate)).Post("/api/exercises/templates/{id}/instantiate", h.InstantiateExerciseTemplate)

		// Platform-admin only — Phase 7 Multi-Tenancy. Orthogonal to the role
		// tiers above: platform-admin is "which tenant, or none," not "what
		// permission level."
		r.Group(func(r chi.Router) {
			r.Use(auth.RequirePlatformAdmin())
			r.Post("/api/tenants", h.CreateTenant)
			r.Get("/api/tenants", h.ListTenants)
			r.Patch("/api/tenants/{id}", h.UpdateTenant)
		})
	})

	// Static files — serve the dashboard SPA from the embedded FS (tamper-proof).
	r.Handle("/*", staticHandler)

	return r
}
