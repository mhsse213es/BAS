package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// Handler holds shared dependencies for all API handlers.
type Handler struct {
	db          *pgxpool.Pool
	hub         *ws.Hub
	engine      *scenario.Engine
	secret      string
	agentSecret string // optional shared secret for agent-facing endpoints
	calderaURL  string
	calderaKey  string
	artStore    *scenario.ARTStore
}

// New creates a Handler.
func New(db *pgxpool.Pool, hub *ws.Hub, engine *scenario.Engine, secret string) *Handler {
	return &Handler{db: db, hub: hub, engine: engine, secret: secret}
}

// WithAgentSecret configures the optional agent shared secret.
func (h *Handler) WithAgentSecret(s string) *Handler {
	h.agentSecret = s
	return h
}

// validateAgentAuth checks the X-Agent-Token header when an agent secret is configured.
// Returns true if the request is authorized (secret matches, or no secret is configured).
func (h *Handler) validateAgentAuth(r *http.Request) bool {
	if h.agentSecret == "" {
		return true
	}
	provided := r.Header.Get("X-Agent-Token")
	if provided == "" {
		provided = r.URL.Query().Get("agentSecret")
	}
	return provided == h.agentSecret
}

// WithCaldera configures the optional Caldera integration.
func (h *Handler) WithCaldera(url, key string) *Handler {
	h.calderaURL = url
	h.calderaKey = key
	return h
}

// WithART attaches the pre-loaded ART store (may be nil if ART_DIR is unavailable).
func (h *Handler) WithART(store *scenario.ARTStore) *Handler {
	h.artStore = store
	return h
}

// ── Auth ─────────────────────────────────────────────────────────────────────

// POST /api/auth/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var id, hash, role string
	var isActive, mustChangePw bool
	err := h.db.QueryRow(r.Context(),
		`SELECT id, password_hash, role, is_active, must_change_pw FROM users WHERE username = $1`, req.Username,
	).Scan(&id, &hash, &role, &isActive, &mustChangePw)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if !isActive {
		jsonError(w, "account is disabled — contact your administrator", http.StatusForbidden)
		return
	}

	token, err := auth.GenerateToken(id, auth.Role(role), h.secret, 24*time.Hour)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	_, _ = h.db.Exec(r.Context(), `UPDATE users SET last_login = NOW() WHERE id = $1`, id)

	// Set HttpOnly cookie so the token is not accessible via JavaScript.
	http.SetCookie(w, &http.Cookie{
		Name:     "bas_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	respond(w, map[string]interface{}{
		"token":        token, // kept for backward compat with CLI/API clients
		"role":         role,
		"userId":       id,
		"mustChangePw": mustChangePw,
	})
}

// POST /api/auth/logout — clears the session cookie.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "bas_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// ── Agents ────────────────────────────────────────────────────────────────────

// GET /api/agents
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT agent_id, hostname, ip_address, os_version, username, status, env_label, has_report, last_update
		 FROM agents ORDER BY last_update DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
			&a.Username, &a.Status, &a.EnvLabel, &a.HasReport, &a.LastUpdate); err != nil {
			continue
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []models.Agent{}
	}
	respond(w, agents)
}

// POST /api/heartbeat — called by agents.
// Requires X-Agent-Token header when AGENT_SECRET is configured.
func (h *Handler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var hb models.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil || hb.AgentID == "" {
		jsonError(w, "invalid heartbeat payload", http.StatusBadRequest)
		return
	}

	_, err := h.db.Exec(r.Context(), `
		INSERT INTO agents (agent_id, hostname, ip_address, os_version, username, status, env_label, last_update)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			hostname    = EXCLUDED.hostname,
			ip_address  = EXCLUDED.ip_address,
			os_version  = EXCLUDED.os_version,
			username    = EXCLUDED.username,
			status      = EXCLUDED.status,
			env_label   = EXCLUDED.env_label,
			last_update = NOW()`,
		hb.AgentID, hb.Hostname, hb.IPAddr, hb.OSVer, hb.Username, hb.Status, hb.EnvLabel,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: hb.AgentID, Data: hb})
	w.WriteHeader(http.StatusOK)
}

// POST /api/scan/{agentId} — triggers a full-scan scenario on the agent.
// The "full-scan" scenario YAML must be present in the scenarios directory.
// The server builds all commands before sending — the agent only executes.
func (h *Handler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")

	sc, ok := h.engine.Get("full-scan")
	if !ok {
		jsonError(w, "full-scan scenario not found — add scenarios/full-scan.yaml to the scenarios directory", http.StatusNotFound)
		return
	}

	steps, err := scenario.BuildSteps(sc, h.calderaURL, h.calderaKey, h.artStore)
	if err != nil {
		jsonError(w, "build steps: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	runID := newID()
	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}
	_, err = h.db.Exec(r.Context(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW())`,
		runID, "full-scan", agentID, sc.Name, initiatedBy,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cmd := scenario.ScenarioCommand{
		RunID:      runID,
		ScenarioID: "full-scan",
		Name:       sc.Name,
		Steps:      steps,
	}
	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandScenario,
		AgentID: agentID,
		Data:    cmd,
	})
	if !sent {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}
	log.Printf("[scan] dispatched full-scan → agent %s (run %s)", agentID, runID)
	respond(w, map[string]string{"runId": runID, "status": "dispatched"})
}

// ── Scenarios ─────────────────────────────────────────────────────────────────

// GET /api/scenarios
func (h *Handler) ListScenarios(w http.ResponseWriter, r *http.Request) {
	respond(w, h.engine.List())
}

// GET /api/scenarios/{id}
func (h *Handler) GetScenario(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.engine.Get(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	respond(w, sc)
}

// POST /api/scenarios/{id}/run — dispatches scenario to a connected agent
func (h *Handler) RunScenario(w http.ResponseWriter, r *http.Request) {
	scenarioID := chi.URLParam(r, "id")
	var req struct {
		AgentID string `json:"agentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}

	sc, ok := h.engine.Get(scenarioID)
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}

	// Create a run record in RUNNING state, stamped with the requesting user
	runID := newID()
	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW())`,
		runID, scenarioID, req.AgentID, sc.Name, initiatedBy,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// local_check scenarios use built-in agent checks — no ART/Caldera required
	if sc.LocalCheck {
		sent := h.hub.SendToAgent(req.AgentID, models.WSMessage{
			Type:    models.MsgCommandSimulate,
			AgentID: req.AgentID,
			Data:    map[string]string{"scenarioId": scenarioID, "runId": runID},
		})
		if !sent {
			_, _ = h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
			jsonError(w, "agent not connected", http.StatusServiceUnavailable)
			return
		}
		log.Printf("[scenario] dispatched local-check %s → agent %s (run %s)", scenarioID, req.AgentID, runID)
		respond(w, map[string]string{"runId": runID, "status": "dispatched"})
		return
	}

	// Build concrete commands — all framework logic resolved server-side
	steps, err := scenario.BuildSteps(sc, h.calderaURL, h.calderaKey, h.artStore)
	if err != nil {
		jsonError(w, "build steps: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	cmd := scenario.ScenarioCommand{
		RunID:      runID,
		ScenarioID: scenarioID,
		Name:       sc.Name,
		Steps:      steps,
	}
	sent := h.hub.SendToAgent(req.AgentID, models.WSMessage{
		Type:    models.MsgCommandScenario,
		AgentID: req.AgentID,
		Data:    cmd,
	})
	if !sent {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}

	log.Printf("[scenario] dispatched %s → agent %s (run %s)", scenarioID, req.AgentID, runID)
	respond(w, map[string]string{"runId": runID, "status": "dispatched"})
}

// POST /api/scenarios/result — agents post raw execution results here.
// The server interprets exit codes and output, then saves SimulationResult records.
// All framework intelligence (ART, Caldera, custom) lives in the interpreter — not the agent.
func (h *Handler) SubmitScenarioResult(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var raw scenario.RawRunResult
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil || raw.RunID == "" {
		jsonError(w, "invalid payload — expected {runId, scenarioId, agentId, results}", http.StatusBadRequest)
		return
	}

	// Look up the scenario to get framework context for interpretation
	sc, _ := h.engine.Get(raw.ScenarioID)

	// Build a taskId→Step map for O(1) lookup
	stepMap := make(map[string]scenario.Step)
	if sc != nil {
		for _, s := range sc.Steps {
			stepMap[scenario.TaskID(s.TechniqueID, s.Name)] = s
		}
	}

	// Interpret each raw ExecResult into a SimulationResult
	simResults := make([]models.SimulationResult, 0, len(raw.Results))
	for _, execResult := range raw.Results {
		step, found := stepMap[execResult.TaskID]
		if !found {
			// Unknown step — treat as custom
			step = scenario.Step{Framework: "custom"}
		}
		simResults = append(simResults, scenario.Interpret(step, execResult))
	}

	status := "completed"
	if raw.Partial {
		status = "partial"
	}

	resultsJSON, _ := json.Marshal(simResults)
	// Append new results to whatever already exists (handles partial submissions).
	_, err := h.db.Exec(r.Context(),
		`UPDATE scenario_runs
		 SET status = $1, results = results || $2::jsonb, completed_at = NOW()
		 WHERE id = $3`,
		status, resultsJSON, raw.RunID,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Compute score from all accumulated results (including prior partial submissions).
	var allResultsJSON []byte
	h.db.QueryRow(r.Context(),
		`SELECT results FROM scenario_runs WHERE id = $1`, raw.RunID,
	).Scan(&allResultsJSON)
	var allResults []models.SimulationResult
	if len(allResultsJSON) > 0 {
		json.Unmarshal(allResultsJSON, &allResults)
	}
	if len(allResults) > 0 {
		// Fetch previous completed run for the same scenario+agent to compute Trend.
		var prevScoreJSON []byte
		h.db.QueryRow(r.Context(),
			`SELECT score FROM scenario_runs
			 WHERE scenario_id = $1 AND agent_id = $2 AND id != $3
			   AND status IN ('completed','partial') AND score IS NOT NULL
			 ORDER BY completed_at DESC LIMIT 1`,
			raw.ScenarioID, raw.AgentID, raw.RunID,
		).Scan(&prevScoreJSON)
		var prevScore *models.Score
		if len(prevScoreJSON) > 0 {
			var ps models.Score
			if json.Unmarshal(prevScoreJSON, &ps) == nil {
				prevScore = &ps
			}
		}
		score := models.ComputeScore(allResults, prevScore)
		scoreJSON, _ := json.Marshal(score)
		h.db.Exec(r.Context(),
			`UPDATE scenario_runs SET score = $1 WHERE id = $2`, scoreJSON, raw.RunID)
	}

	// Notify connected dashboards in real time
	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    models.MsgScenarioResult,
		AgentID: raw.AgentID,
		Data: map[string]interface{}{
			"runId":      raw.RunID,
			"scenarioId": raw.ScenarioID,
			"agentId":    raw.AgentID,
			"status":     status,
			"results":    simResults,
		},
	})
	w.WriteHeader(http.StatusOK)
}

// GET /api/scenarios/runs?agentId=&scenarioId=
func (h *Handler) ListScenarioRuns(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	scenarioID := r.URL.Query().Get("scenarioId")

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, name, status, results, score, initiated_by, started_at, completed_at
		 FROM scenario_runs
		 WHERE ($1 = '' OR agent_id = $1)
		   AND ($2 = '' OR scenario_id = $2)
		 ORDER BY started_at DESC LIMIT 100`,
		agentID, scenarioID,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type runRow struct {
		models.ScenarioRun
		InitiatedBy *string `json:"initiatedBy"`
	}
	var runs []runRow
	for rows.Next() {
		var run runRow
		var resultsJSON, scoreRaw []byte
		if err := rows.Scan(&run.ID, &run.ScenarioID, &run.AgentID, &run.Name,
			&run.Status, &resultsJSON, &scoreRaw, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt); err != nil {
			log.Printf("[api] list runs scan: %v", err)
			continue
		}
		json.Unmarshal(resultsJSON, &run.Results)
		if len(scoreRaw) > 0 {
			json.Unmarshal(scoreRaw, &run.Score)
		}
		runs = append(runs, run)
	}
	if runs == nil {
		runs = []runRow{}
	}
	respond(w, runs)
}

// ── Reports ───────────────────────────────────────────────────────────────────

// POST /api/report — agents upload full simulation reports here.
// Requires X-Agent-Token header when AGENT_SECRET is configured.
func (h *Handler) SubmitReport(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var report struct {
		AgentID       string          `json:"agentId"`
		Hostname      string          `json:"hostname"`
		IPAddress     string          `json:"ipAddress"`
		OSVersion     string          `json:"osVersion"`
		Username      string          `json:"username"`
		Status        string          `json:"status"`
		EnvLabel      string          `json:"envLabel"`
		SecurityTools json.RawMessage `json:"securityTools"`
		Categories    json.RawMessage `json:"categories"`
		Score         json.RawMessage `json:"score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil || report.AgentID == "" {
		jsonError(w, "invalid report payload", http.StatusBadRequest)
		return
	}

	tools := report.SecurityTools
	if tools == nil {
		tools = []byte("[]")
	}
	cats := report.Categories
	if cats == nil {
		cats = []byte("[]")
	}

	_, err := h.db.Exec(r.Context(), `
		INSERT INTO reports
			(agent_id, hostname, ip_address, os_version, username, status, env_label, security_tools, categories, score, last_update)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			hostname=EXCLUDED.hostname, ip_address=EXCLUDED.ip_address,
			os_version=EXCLUDED.os_version, username=EXCLUDED.username,
			status=EXCLUDED.status, env_label=EXCLUDED.env_label,
			security_tools=EXCLUDED.security_tools, categories=EXCLUDED.categories,
			score=EXCLUDED.score, last_update=NOW()`,
		report.AgentID, report.Hostname, report.IPAddress, report.OSVersion,
		report.Username, report.Status, report.EnvLabel, tools, cats, report.Score,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = h.db.Exec(r.Context(),
		`UPDATE agents SET has_report = true WHERE agent_id = $1`, report.AgentID)

	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    models.MsgReportReady,
		AgentID: report.AgentID,
		Data:    map[string]string{"agentId": report.AgentID, "status": report.Status},
	})
	w.WriteHeader(http.StatusOK)
}

// GET /api/report/{agentId}
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	row := h.db.QueryRow(r.Context(),
		`SELECT agent_id, hostname, ip_address, os_version, username, status, env_label,
		        security_tools, categories, score, started_at, last_update
		 FROM reports WHERE agent_id = $1`, agentID)

	var (
		rep        map[string]interface{}
		tools      json.RawMessage
		categories json.RawMessage
		score      json.RawMessage
	)
	var agID, host, ip, osv, user, status, env string
	var startedAt, lastUpdate time.Time
	if err := row.Scan(&agID, &host, &ip, &osv, &user, &status, &env,
		&tools, &categories, &score, &startedAt, &lastUpdate); err != nil {
		jsonError(w, "report not found", http.StatusNotFound)
		return
	}
	rep = map[string]interface{}{
		"agentId": agID, "hostname": host, "ipAddress": ip,
		"osVersion": osv, "username": user, "status": status, "envLabel": env,
		"securityTools": tools, "categories": categories, "score": score,
		"startedAt": startedAt, "lastUpdate": lastUpdate,
	}
	respond(w, rep)
}

// ── User Management (admin only) ─────────────────────────────────────────────

// GET /api/users
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, username, role, is_active, must_change_pw, created_at, last_login
		 FROM users ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type UserRow struct {
		ID           string     `json:"id"`
		Username     string     `json:"username"`
		Role         string     `json:"role"`
		IsActive     bool       `json:"isActive"`
		MustChangePw bool       `json:"mustChangePw"`
		CreatedAt    time.Time  `json:"createdAt"`
		LastLogin    *time.Time `json:"lastLogin"`
	}
	var users []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.IsActive, &u.MustChangePw, &u.CreatedAt, &u.LastLogin); err != nil {
			continue
		}
		users = append(users, u)
	}
	if users == nil {
		users = []UserRow{}
	}
	respond(w, users)
}

// POST /api/users
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		jsonError(w, "username and password are required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "analyst"
	}
	if req.Role != "admin" && req.Role != "analyst" && req.Role != "viewer" {
		jsonError(w, "role must be admin, analyst, or viewer", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}

	var id string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO users (username, password_hash, role, must_change_pw)
		 VALUES ($1, $2, $3, true)
		 RETURNING id`,
		req.Username, string(hash), req.Role,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "username already exists", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	respond(w, map[string]string{"id": id, "username": req.Username, "role": req.Role})
}

// PUT /api/users/{id}  — update role and/or active status (admin only)
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	claims, _ := auth.ClaimsFrom(r.Context())

	var req struct {
		Role     *string `json:"role"`
		IsActive *bool   `json:"isActive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Role == nil && req.IsActive == nil {
		jsonError(w, "provide role or isActive to update", http.StatusBadRequest)
		return
	}
	if req.Role != nil {
		if *req.Role != "admin" && *req.Role != "analyst" && *req.Role != "viewer" {
			jsonError(w, "role must be admin, analyst, or viewer", http.StatusBadRequest)
			return
		}
	}
	// Prevent admin from deactivating their own account
	if req.IsActive != nil && !*req.IsActive && claims != nil && claims.UserID == targetID {
		jsonError(w, "cannot deactivate your own account", http.StatusBadRequest)
		return
	}

	if req.Role != nil {
		h.db.Exec(r.Context(), `UPDATE users SET role = $1 WHERE id = $2`, *req.Role, targetID)
	}
	if req.IsActive != nil {
		h.db.Exec(r.Context(), `UPDATE users SET is_active = $1 WHERE id = $2`, *req.IsActive, targetID)
	}
	w.WriteHeader(http.StatusOK)
	respond(w, map[string]string{"status": "updated"})
}

// DELETE /api/users/{id}  — hard delete (admin only, cannot delete self)
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	claims, _ := auth.ClaimsFrom(r.Context())
	if claims != nil && claims.UserID == targetID {
		jsonError(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(), `DELETE FROM users WHERE id = $1`, targetID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/auth/change-password  — any authenticated user
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok || claims == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CurrentPassword == "" || req.NewPassword == "" {
		jsonError(w, "currentPassword and newPassword are required", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 {
		jsonError(w, "new password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	var hash string
	if err := h.db.QueryRow(r.Context(),
		`SELECT password_hash FROM users WHERE id = $1`, claims.UserID,
	).Scan(&hash); err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.CurrentPassword)) != nil {
		jsonError(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE users SET password_hash = $1, must_change_pw = false WHERE id = $2`,
		string(newHash), claims.UserID)

	respond(w, map[string]string{"status": "password updated"})
}

// POST /api/auth/reset-password  — admin resets another user's password
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	var req struct {
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewPassword == "" {
		jsonError(w, "newPassword is required", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 {
		jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE users SET password_hash = $1, must_change_pw = true WHERE id = $2`,
		string(hash), targetID)
	respond(w, map[string]string{"status": "password reset — user must change on next login"})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func respond(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[api] encode error: %v", err)
	}
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

func newID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
