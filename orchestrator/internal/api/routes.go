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
	r.Post("/api/heartbeat", h.Heartbeat)
	r.Post("/api/report", h.SubmitReport)
	r.Post("/api/scenarios/result", h.SubmitScenarioResult)

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
		r.Get("/api/report/{agentId}", h.GetReport)

		// Analyst + Admin only — can trigger scans and run scenarios
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin, auth.RoleAnalyst))
			r.Post("/api/scan/{agentId}", h.TriggerScan)
			r.Post("/api/scenarios/{id}/run", h.RunScenario)
		})

		// Any authenticated user — self-service password change
		r.Post("/api/auth/change-password", h.ChangePassword)

		// Full report + audit pack — Viewer+ role
		r.Get("/api/report/full/html", h.GetFullReportHTML)
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

			// Threat-intel connector
			r.Get("/api/connector/status", h.GetConnectorStatus)
			r.Post("/api/connector/sync", h.TriggerConnectorSync)
			r.Delete("/api/connector/scenarios/{id}", h.DeleteIntelScenario)
		})
	})

	// Static files — serve the dashboard SPA
	r.Handle("/*", http.FileServer(http.Dir("./wwwroot")))

	return r
}
