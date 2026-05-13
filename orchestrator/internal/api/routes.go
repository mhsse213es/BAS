package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
)

// Mount builds the full HTTP router and returns it.
func Mount(h *Handler, hub *ws.Hub, jwtSecret string) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)

	// CORS — allow dashboard origin in development
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			if req.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	// ── Public endpoints (no auth) ────────────────────────────────────────
	r.Post("/api/auth/login", h.Login)

	// Agent endpoints — no browser auth; agents identify via agentId field
	r.Post("/api/heartbeat", h.Heartbeat)
	r.Post("/api/report", h.SubmitReport)
	r.Post("/api/scenarios/result", h.SubmitScenarioResult)

	// WebSocket — agents connect here
	r.Get("/ws/agent", hub.ServeAgentWS)
	// WebSocket — browser dashboard connects here
	r.Get("/ws/browser", hub.ServeBrowserWS)

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

		// Admin only — user management (Phase 2)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleAdmin))
			// TODO: POST /api/users, GET /api/users, DELETE /api/users/{id}
		})
	})

	// Static files — serve the dashboard SPA
	r.Handle("/*", http.FileServer(http.Dir("./wwwroot")))

	return r
}
