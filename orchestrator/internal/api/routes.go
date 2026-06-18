package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
)

// Mount builds the full HTTP router and returns it.
func Mount(h *Handler, hub *ws.Hub, jwtSecret, agentSecret string) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)

	// ── Public endpoints (no auth) ────────────────────────────────────────
	r.Post("/api/auth/login", h.Login)
	r.Post("/api/auth/logout", h.Logout)

	// Agent endpoints — protected by optional AGENT_SECRET shared token.
	// When agentSecret is empty these remain open (backward compat).
	r.Get("/api/agents/ping", h.PingAgent)
	r.Post("/api/agents/enroll", h.EnrollAgent)
	r.Post("/api/agents/events", h.ReceiveEvents)
	r.Post("/api/heartbeat", h.Heartbeat)
	r.Post("/api/scenarios/result", h.SubmitScenarioResult)
	r.Post("/api/scenarios/events", h.SubmitRunEvents)
	r.Post("/api/scenarios/runs/{runId}/detections", h.SubmitRunDetections)

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

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

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
		r.Get("/api/remediations", h.ListRemediations)
		r.Get("/api/reports", h.ListReports)
		r.Post("/api/reports", h.CreateReport)
		r.Get("/api/agents/{agentId}/logs/operational", h.GetOpLogs)
		r.Get("/api/agents/{agentId}/logs/security", h.GetSecLogs)
		r.Get("/api/agents/{agentId}/telemetry", h.GetTelemetry)

		// Viewer+ — safe read-only simulation makes no changes to the endpoint
		r.Post("/api/scan/safe/{agentId}", h.SafeScan)

		// Live framework catalogs — drive the real-time sweep counts and the
		// selectable technique/ability picker. Read-only, Viewer+.
		r.Get("/api/art/techniques", h.GetARTTechniques)
		r.Get("/api/caldera/abilities", h.GetCalderaAbilities)
		r.Get("/api/posture/catalog", h.GetPostureCatalog)

		// ATT&CK Coverage matrix — authoritative enterprise structure + per-technique
		// enrichment; coverage status is overlaid client-side from run data.
		r.Get("/api/attack/matrix", h.AttackMatrix)
		r.Get("/api/attack/technique/{id}", h.AttackTechnique)

		// Analyst + Admin only — can trigger scans, run scenarios, and
		// author custom scenarios from the dashboard.
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin, auth.RoleAnalyst))
			r.Post("/api/scan/{agentId}", h.TriggerScan)
			r.Post("/api/scenarios/{id}/run", h.RunScenario)
			r.Post("/api/scenarios/runs/{runId}/cancel", h.CancelRun)
			r.Post("/api/campaigns", h.CreateCampaign)
			r.Post("/api/campaigns/{id}/stop", h.StopCampaign)
			r.Post("/api/findings/{id}/status", h.SetFindingStatus)

			// Custom scenario builder
			r.Post("/api/scenarios", h.CreateScenario)
			r.Post("/api/scenarios/upload", h.UploadScenario)
			r.Post("/api/scenarios/{id}/clone", h.CloneScenario)
			r.Put("/api/scenarios/{id}", h.UpdateScenario)
			r.Delete("/api/scenarios/{id}", h.DeleteScenario)
		})

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

		// Admin only — config + user management + connector
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin))
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

			// ART content: status + content-pack reseed (no image rebuild)
			r.Get("/api/art/content/status", h.GetARTContentStatus)
			r.Post("/api/art/content/reseed", h.ReseedART)
		})
	})

	// Static files — serve the dashboard SPA
	r.Handle("/*", http.FileServer(http.Dir("./wwwroot")))

	return r
}
