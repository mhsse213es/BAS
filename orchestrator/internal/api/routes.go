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
func Mount(h *Handler, hub *ws.Hub, jwtSecret, agentSecret string, staticHandler http.Handler, tracker ...*exercisetracker.Tracker) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)

	// ── Public endpoints (no auth) ────────────────────────────────────────
	r.Post("/api/auth/login", h.Login)
	r.Post("/api/auth/logout", h.Logout)
	r.Post("/api/auth/setup", h.Setup) // first-run admin provisioning (installer)

	// Agent endpoints — protected by optional AGENT_SECRET shared token.
	// When agentSecret is empty these remain open (backward compat).
	r.Get("/api/agents/ping", h.PingAgent)
	r.Post("/api/agents/enroll", h.EnrollAgent)
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

		// Analyst + Admin only — can trigger scans, run scenarios, and
		// author custom scenarios from the dashboard.
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin, auth.RoleAnalyst))
			r.Post("/api/scan/{agentId}", h.TriggerScan)
			r.Post("/api/attackpath/collect/{agentId}", h.DispatchAttackPathCollect)
			r.Post("/api/attackpath/jobs", h.CreateAttackPathJob)
			r.Post("/api/attackpath/jobs/{id}/cancel", h.CancelAttackPathJob)
			r.Post("/api/attackpath/jobs/{id}/retry", h.RetryAttackPathJob)
			r.Post("/api/attackpath/assets", h.SetAttackPathAsset)
			r.Post("/api/scenarios/{id}/run", h.RunScenario)
			r.Post("/api/caldera/adversaries/{adversaryId}/run", h.RunCalderaAdversary)
			r.Post("/api/adversary-templates/{id}/run", h.RunAdversaryTemplate)
			r.Post("/api/scenarios/runs/{runId}/cancel", h.CancelRun)
			// SIEM Correlation — trigger and results (Analyst+)
			r.Post("/api/siem/correlate/{runId}", h.TriggerSIEMCorrelation)
			r.Get("/api/siem/correlations/{runId}", h.GetSIEMCorrelations)
			// Detection Verification — manual trigger (Analyst+)
			r.Post("/api/detectverify/run/{runId}", h.TriggerDetectionVerification)
			r.Post("/api/campaigns", h.CreateCampaign)
			r.Post("/api/campaigns/{id}/stop", h.StopCampaign)
			r.Post("/api/findings/{id}/status", h.SetFindingStatus)
			r.Post("/api/ticketing/push", h.PushFindingToITSM)
			r.Post("/api/ticketing/push/bulk", h.BulkPushToITSM)

			// Custom scenario builder
			r.Post("/api/scenarios", h.CreateScenario)
			r.Post("/api/scenarios/upload", h.UploadScenario)
			r.Post("/api/scenarios/{id}/clone", h.CloneScenario)
			r.Put("/api/scenarios/{id}", h.UpdateScenario)
			r.Delete("/api/scenarios/{id}", h.DeleteScenario)

			// Variant executor — multi-variant technique execution
			r.Post("/api/variants/generate", h.GenerateVariants)
			r.Post("/api/variants/run", h.RunVariants)
			r.Get("/api/variants/run/{id}", h.GetVariantRun)
			r.Get("/api/variants/coverage", h.GetVariantCoverage)
			r.Get("/api/variants/stats", h.GetVariantStats)

			// Payload families (Phase 3) — mutation/delete is Admin only (see below)
			r.Get("/api/payload-families", h.GetPayloadFamilies)
			r.Get("/api/payload-families/{techniqueId}", h.GetTechniqueFamilies)

			// Exercise Engine — Analyst+ can run and observe exercises.
			r.Post("/api/exercises/executions/{id}/launch", h.LaunchExerciseExecution)
			r.Post("/api/exercises/executions/{id}/abort", h.AbortExerciseExecution)
			r.Post("/api/exercises/executions/{id}/steps/{stepId}/approve", h.ApproveExerciseStep)
			r.Post("/api/exercises/executions/{id}/evidence", h.InjectEvidence)
		})

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

		// Admin only — config + user management + connector
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin))
			r.Put("/api/agents/{agentId}/state", h.SetAgentState)
			r.Get("/api/license", h.GetLicenseInfo)
			r.Get("/api/config/connection", h.GetConnectionConfig)
			r.Get("/api/users", h.ListUsers)
			r.Post("/api/users", h.CreateUser)
			r.Put("/api/users/{id}", h.UpdateUser)
			r.Delete("/api/users/{id}", h.DeleteUser)
			r.Post("/api/users/{id}/reset-password", h.ResetPassword)

			// Caldera engine status
			r.Get("/api/caldera/status", h.GetCalderaStatus)

			// Threat-intel connector
			r.Get("/api/connector/status", h.GetConnectorStatus)
			r.Post("/api/connector/sync", h.TriggerConnectorSync)
			r.Delete("/api/connector/scenarios/{id}", h.DeleteIntelScenario)

			// Attack-path schedule config — enables periodic fleet collection.
			r.Post("/api/attackpath/schedule", h.SetAttackPathSchedule)

			// ART content: status + content-pack reseed (no image rebuild)
			r.Get("/api/art/content/status", h.GetARTContentStatus)
			r.Post("/api/art/content/reseed", h.ReseedART)

			// Filesystem integrity — tamper event log + acknowledgement
			r.Get("/api/tamper-events", h.GetTamperEvents)
			r.Post("/api/tamper-events/{id}/acknowledge", h.AcknowledgeTamperEvent)
			r.Post("/api/tamper-events/acknowledge-all", h.AcknowledgeAllTamperEvents)

			// Audit log — append-only record of all operator actions
			r.Get("/api/audit-logs", h.GetAuditLogs)

			// Ticketing — ITSM connector management (admin only)
			r.Get("/api/ticketing/configs", h.ListTicketingConfigs)
			r.Post("/api/ticketing/configs", h.CreateTicketingConfig)
			r.Put("/api/ticketing/configs/{id}", h.UpdateTicketingConfig)
			r.Delete("/api/ticketing/configs/{id}", h.DeleteTicketingConfig)
			r.Post("/api/ticketing/configs/{id}/test", h.TestTicketingConfig)
			r.Post("/api/ticketing/probe", h.ProbeTicketingConfig)
			r.Post("/api/ticketing/probe/projects", h.ProbeListProjects)
			r.Post("/api/ticketing/sync", h.TriggerTicketingSync)

			// Payload family management — write/delete restricted to Admin
			r.Post("/api/payload-families", h.CreatePayloadFamily)
			r.Delete("/api/payload-families/{id}", h.DeletePayloadFamily)

			// SIEM Correlation — connector management (Admin only)
			r.Get("/api/siem/configs", h.ListSIEMConfigs)
			r.Post("/api/siem/configs", h.CreateSIEMConfig)
			r.Put("/api/siem/configs/{id}", h.UpdateSIEMConfig)
			r.Delete("/api/siem/configs/{id}", h.DeleteSIEMConfig)
			r.Post("/api/siem/configs/{id}/test", h.TestSIEMConfig)

			// Detection Verification — connector management (Admin only)
			r.Get("/api/detectverify/configs", h.ListDetectionConnectors)
			r.Post("/api/detectverify/configs", h.CreateDetectionConnector)
			r.Put("/api/detectverify/configs/{id}", h.UpdateDetectionConnector)
			r.Delete("/api/detectverify/configs/{id}", h.DeleteDetectionConnector)
			r.Post("/api/detectverify/configs/{id}/test", h.TestDetectionConnector)

			// Exercise plan authoring — Admin only
			r.Post("/api/exercises/plans", h.CreateExercisePlan)
			r.Post("/api/exercises/plans/validate", h.ValidateExercisePlan)
			r.Put("/api/exercises/plans/{id}", h.UpdateExercisePlan)
			r.Delete("/api/exercises/plans/{id}", h.DeleteExercisePlan)

			// Exercise templates — Admin only for write, all authenticated for read
			r.Post("/api/exercises/templates", h.CreateExerciseTemplate)
			r.Post("/api/exercises/templates/{id}/instantiate", h.InstantiateExerciseTemplate)
		})
	})

	// Static files — serve the dashboard SPA from the embedded FS (tamper-proof).
	r.Handle("/*", staticHandler)

	return r
}
