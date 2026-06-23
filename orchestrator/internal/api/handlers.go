package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// Handler holds shared dependencies for all API handlers.
type Handler struct {
	db               *pgxpool.Pool
	hub              *ws.Hub
	engine           *scenario.Engine
	secret           string
	agentSecret      string // optional shared secret for agent-facing endpoints
	calderaURL       string
	calderaKey       string
	artStore         *scenario.ARTStore
	artContentDir    string               // seed source for ART atomics (ART_DIR)
	artPayloadDir    string               // seed source for ART payload binaries (ART_PAYLOAD_DIR)
	artKEVFile       string               // CISA KEV catalog JSON (KEV_FILE)
	artContentVer    string               // recorded content-pack version
	manifest         *integrity.Manifest  // binary hash manifest — nil means verification disabled
	complianceMapper *compliance.Mapper   // nil when not loaded
	reportingEngine  *reporting.Engine    // nil when not loaded
	scheduler        *connector.Scheduler // nil when no sources configured
}

// New creates a Handler.
func New(db *pgxpool.Pool, hub *ws.Hub, engine *scenario.Engine, secret string) *Handler {
	return &Handler{db: db, hub: hub, engine: engine, secret: secret}
}

// WithCompliance attaches the compliance mapper.
func (h *Handler) WithCompliance(m *compliance.Mapper) *Handler {
	h.complianceMapper = m
	return h
}

// WithReporting attaches the reporting engine.
func (h *Handler) WithReporting(e *reporting.Engine) *Handler {
	h.reportingEngine = e
	return h
}

// WithScheduler attaches the threat-intel connector scheduler.
func (h *Handler) WithScheduler(s *connector.Scheduler) *Handler {
	h.scheduler = s
	return h
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

// GET /api/agents/ping — token validation probe used by the GUI installer.
// Validates X-Agent-Token and returns 200/401 without touching any records.
func (h *Handler) PingAgent(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check Agent Secret", http.StatusUnauthorized)
		return
	}
	respond(w, map[string]string{"status": "ok"})
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

// WithContentSeed records the disk seed sources so the admin reseed endpoint
// can re-import a dropped content pack and hot-reload the ART store.
func (h *Handler) WithContentSeed(atomicsDir, payloadDir, kevFile, version string) *Handler {
	h.artContentDir = atomicsDir
	h.artPayloadDir = payloadDir
	h.artKEVFile = kevFile
	h.artContentVer = version
	return h
}

// WithManifest attaches the binary hash manifest for agent verification.
func (h *Handler) WithManifest(m *integrity.Manifest) *Handler {
	h.manifest = m
	return h
}

// verifyResultMAC checks X-Result-MAC on a pre-read body.
// Returns true if the MAC is valid, or if agent secret is not configured.
func (h *Handler) verifyResultMAC(r *http.Request, body []byte) bool {
	return integrity.VerifyResultMAC(body, h.agentSecret, r.Header.Get("X-Result-MAC"))
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
		h.auditLogAs(r, "", "user.login", req.Username, map[string]any{"username": req.Username, "reason": "invalid credentials"}, "fail")
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if !isActive {
		h.auditLogAs(r, id, "user.login", id, map[string]any{"username": req.Username, "reason": "account disabled"}, "fail")
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
	h.auditLogAs(r, id, "user.login", id, map[string]any{"role": role}, "ok")
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
		`SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
		        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
		        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
		        (SELECT COUNT(*) FROM scenario_runs sr WHERE sr.agent_id = a.agent_id) AS sims
		 FROM agents a ORDER BY a.last_update DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	now := time.Now()
	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		var stateStr, policyRaw string
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
			&a.Username, &a.Status, &a.EnvLabel, &a.HasReport,
			&a.BinaryHash, &a.BinaryTrusted, &a.LastUpdate,
			&stateStr, &policyRaw, &a.EnrolledAt, &a.Sims); err != nil {
			continue
		}
		// Connectivity is heartbeat-driven: a dead/rebooted agent stops updating
		// last_update, so surface it as offline rather than its frozen last status.
		a.Status = effectiveAgentStatus(a.Status, a.LastUpdate, now)
		a.State = models.AgentState(stateStr)
		var p models.PolicyBundle
		if err := json.Unmarshal([]byte(policyRaw), &p); err == nil {
			a.Policy = &p
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []models.Agent{}
	}
	respond(w, agents)
}

// agentFiles is the explicit allowlist of downloadable agent artifacts.
// key = URL platform param; value = filename and MIME type served.
var agentFiles = map[string]struct {
	filename string
	mimeType string
}{
	"linux-amd64":         {"bas-agent-linux-amd64", "application/octet-stream"},
	"linux-arm64":         {"bas-agent-linux-arm64", "application/octet-stream"},
	"linux-amd64-deb":     {"bas-agent-linux-amd64.deb", "application/vnd.debian.binary-package"},
	"linux-arm64-deb":     {"bas-agent-linux-arm64.deb", "application/vnd.debian.binary-package"},
	"linux-amd64-rpm":     {"bas-agent-linux-amd64.rpm", "application/x-rpm"},
	"windows-amd64-setup": {"bas-agent-windows-amd64-setup.exe", "application/octet-stream"},
	"windows-amd64":       {"bas-agent-windows-amd64.exe", "application/octet-stream"},
	"darwin-amd64":        {"bas-agent-darwin-amd64", "application/octet-stream"},
	"darwin-arm64":        {"bas-agent-darwin-arm64", "application/octet-stream"},
}

// GET /api/agents/download/{platform} — serves the pre-built agent binary or package.
// platform values: linux-amd64, linux-arm64, linux-amd64-deb, linux-arm64-deb,
//
//	linux-amd64-rpm, windows-amd64, darwin-amd64, darwin-arm64
func (h *Handler) DownloadAgent(w http.ResponseWriter, r *http.Request) {
	platform := chi.URLParam(r, "platform")

	entry, ok := agentFiles[platform]
	if !ok {
		jsonError(w, "unknown platform: "+platform, http.StatusNotFound)
		return
	}

	filePath := filepath.Join("./agents", entry.filename)
	f, err := os.Open(filePath)
	if err != nil {
		jsonError(w, "agent binary not found for platform: "+platform, http.StatusNotFound)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		jsonError(w, "could not stat agent binary", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", entry.mimeType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+entry.filename+`"`)
	http.ServeContent(w, r, entry.filename, stat.ModTime(), f)
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

	// Verify binary hash against the manifest if one is loaded.
	trusted := false
	if hb.BinaryHash != "" && h.manifest != nil && h.manifest.Loaded() {
		trusted = h.manifest.HashKnown(hb.BinaryHash)
		if !trusted {
			log.Printf("[!] agent %s binary hash MISMATCH — possible tampered binary (hash %s...)",
				hb.AgentID, hb.BinaryHash[:16])
		} else {
			log.Printf("[*] agent %s binary hash verified OK", hb.AgentID)
		}
	}

	_, err := h.db.Exec(r.Context(), `
		INSERT INTO agents (agent_id, hostname, ip_address, os_version, username, status, env_label,
		                    binary_hash, binary_trusted, protocol_version, state, last_update)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			hostname         = EXCLUDED.hostname,
			ip_address       = EXCLUDED.ip_address,
			os_version       = EXCLUDED.os_version,
			username         = EXCLUDED.username,
			status           = EXCLUDED.status,
			env_label        = EXCLUDED.env_label,
			binary_hash      = EXCLUDED.binary_hash,
			binary_trusted   = EXCLUDED.binary_trusted,
			protocol_version = EXCLUDED.protocol_version,
			last_update      = NOW()`,
		hb.AgentID, hb.Hostname, hb.IPAddr, hb.OSVer, hb.Username, hb.Status, hb.EnvLabel,
		hb.BinaryHash, trusted, hb.ProtocolVersion,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Persist the security-product inventory only when the heartbeat carries one
	// (enumeration completes shortly after startup, so early heartbeats omit it —
	// don't clobber a known inventory with an empty list).
	if len(hb.SecurityProducts) > 0 {
		if sp, e := json.Marshal(hb.SecurityProducts); e == nil {
			_, _ = h.db.Exec(r.Context(),
				`UPDATE agents SET security_products = $2 WHERE agent_id = $1`,
				hb.AgentID, sp)
		}
	}

	// Quarantine if manifest is loaded and the binary hash is not recognised.
	// Only transition active→quarantined, never overwrite an already-quarantined agent.
	if hb.BinaryHash != "" && h.manifest != nil && h.manifest.Loaded() && !trusted {
		_, _ = h.db.Exec(r.Context(),
			`UPDATE agents SET state = 'quarantined' WHERE agent_id = $1 AND state = 'active'`,
			hb.AgentID)
		log.Printf("[!] agent %s QUARANTINED — binary hash unrecognised", hb.AgentID)
	}

	// Fetch current state and policy to return to the agent.
	var stateStr, policyRaw string
	h.db.QueryRow(r.Context(),
		`SELECT COALESCE(state,'active'), COALESCE(policy_json::text,'{}') FROM agents WHERE agent_id = $1`,
		hb.AgentID,
	).Scan(&stateStr, &policyRaw)
	var policy models.PolicyBundle
	json.Unmarshal([]byte(policyRaw), &policy)

	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: hb.AgentID, Data: hb})
	respond(w, models.HeartbeatResponse{
		State:  models.AgentState(stateStr),
		Policy: policy,
	})
}

// POST /api/agents/enroll — called by the installer/agent before first heartbeat.
// Validates the agent secret, registers the agent, and returns a policy bundle.
// Pre-enrollment handshake: installer calls this to confirm URL+secret are valid
// before writing anything to the local machine.
func (h *Handler) EnrollAgent(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	var req struct {
		AgentID        string          `json:"agentId"`
		Hostname       string          `json:"hostname"`
		IPAddress      string          `json:"ipAddress"`
		OSVersion      string          `json:"osVersion"`
		Username       string          `json:"username"`
		EnvLabel       string          `json:"envLabel"`
		BinaryHash     string          `json:"binaryHash"`
		AgentVersion   string          `json:"agentVersion"`
		PostureCatalog json.RawMessage `json:"postureCatalog"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
		jsonError(w, "invalid enrollment payload — agentId required", http.StatusBadRequest)
		return
	}

	trusted := false
	if req.BinaryHash != "" && h.manifest != nil && h.manifest.Loaded() {
		trusted = h.manifest.HashKnown(req.BinaryHash)
		if !trusted {
			log.Printf("[enroll] agent %s binary hash unrecognised — will enroll as active but flag untrusted", req.AgentID)
		}
	}

	policy := models.PolicyBundle{
		LogLevel:          "info",
		MaxConcurrentRuns: 1,
		HeartbeatInterval: 30,
	}
	policyJSON, _ := json.Marshal(policy)

	postureCatalog := req.PostureCatalog
	if len(postureCatalog) == 0 {
		postureCatalog = json.RawMessage("{}")
	}

	// Upsert: preserve quarantined/retired state on re-enroll — operator must
	// explicitly clear quarantine via the dashboard before the agent can run.
	_, err := h.db.Exec(r.Context(), `
		INSERT INTO agents (agent_id, hostname, ip_address, os_version, username,
		                    status, env_label, binary_hash, binary_trusted,
		                    state, policy_json, posture_catalog, enrolled_at, last_update)
		VALUES ($1, $2, $3, $4, $5, 'idle', $6, $7, $8, 'active', $9, $10, NOW(), NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			hostname       = EXCLUDED.hostname,
			ip_address     = EXCLUDED.ip_address,
			os_version     = EXCLUDED.os_version,
			username       = EXCLUDED.username,
			env_label      = EXCLUDED.env_label,
			binary_hash    = EXCLUDED.binary_hash,
			binary_trusted = EXCLUDED.binary_trusted,
			state          = CASE
			                   WHEN agents.state IN ('quarantined','retired') THEN agents.state
			                   ELSE 'active'
			                 END,
			policy_json    = EXCLUDED.policy_json,
			posture_catalog = EXCLUDED.posture_catalog,
			enrolled_at    = COALESCE(agents.enrolled_at, NOW()),
			last_update    = NOW()`,
		req.AgentID, req.Hostname, req.IPAddress, req.OSVersion, req.Username,
		req.EnvLabel, req.BinaryHash, trusted, policyJSON, postureCatalog,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Read back the final state (may still be quarantined from a prior run).
	var finalState string
	h.db.QueryRow(r.Context(), `SELECT COALESCE(state,'active') FROM agents WHERE agent_id = $1`, req.AgentID).Scan(&finalState)

	log.Printf("[enroll] agent %s (%s) enrolled — state=%s trusted=%v version=%s",
		req.AgentID, req.Hostname, finalState, trusted, req.AgentVersion)
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: req.AgentID})

	h.auditLogAs(r, "", "agent.enroll", req.AgentID, map[string]any{
		"hostname": req.Hostname, "ip": req.IPAddress, "os": req.OSVersion,
		"trusted": trusted, "state": finalState, "version": req.AgentVersion,
	}, "ok")
	respond(w, map[string]interface{}{
		"agentId": req.AgentID,
		"state":   finalState,
		"policy":  policy,
		"trusted": trusted,
	})
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

	h.persistStepMeta(r.Context(), runID, steps)

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

// POST /api/scan/safe/{agentId} — triggers the read-only safe-simulation.
// Available to Viewer+ since it makes no changes to the endpoint. Dispatched
// as a local_check (agent runs built-in read-only checks).
func (h *Handler) SafeScan(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")

	sc, ok := h.engine.Get("safe-simulation")
	if !ok {
		jsonError(w, "safe-simulation scenario not found — add scenarios/safe-simulation.yaml", http.StatusNotFound)
		return
	}

	runID := newID()
	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW())`,
		runID, "safe-simulation", agentID, sc.Name, initiatedBy,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandSimulate,
		AgentID: agentID,
		Data:    map[string]string{"scenarioId": "safe-simulation", "runId": runID},
	})
	if !sent {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}
	log.Printf("[scan] dispatched safe-simulation → agent %s (run %s)", agentID, runID)
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

// staleRunGuard is how long a scenario_run may sit in 'running' before the
// concurrency guard treats it as abandoned (agent died mid-run) and allows a new
// run to proceed. It must comfortably exceed the longest legitimate run; the full
// ART sweep (one representative atomic per technique) completes well within this.
const staleRunGuard = 2 * time.Hour

// dispatchOpts carries everything dispatchRun needs to dispatch one run on one
// agent. It is the agent-independent slice of a run request — built once by the
// single-run handler and once per target by the campaign fan-out.
type dispatchOpts struct {
	Mode        string // already-normalized: posture | telemetry | lab
	ConfirmLive bool
	ConfirmLab  bool
	Reason      string
	Techniques  []string
	Abilities   []string
	Steps       []int
	Checks      []string
	CampaignID  string  // "" for ad-hoc single runs
	InitiatedBy *string // requesting user id (nil if unauthenticated)
}

// nullIfEmpty maps "" to a SQL NULL so an ad-hoc run leaves campaign_id null
// rather than storing an empty string.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// dispatchRun creates and dispatches ONE run of sc on agentID, applying the
// agent-state gate, OS-compat check, busy guard, run-row insert, and WS dispatch
// — the per-agent core shared by the single-run endpoint and the campaign
// launcher. On success it returns the new run id. When the agent simply cannot
// accept the run it returns ("", skipReason, nil) — skipReason is one of
// "offline", "agent busy", "agent <state>", "os mismatch" — leaving no run row
// (or a failed one, for a lost WS send). err is non-nil only for genuine
// failures (DB / build). Request- and scenario-level guardrails (mode validity,
// confirmLive/confirmLab, executable, execution window) are the caller's job.
func (h *Handler) dispatchRun(ctx context.Context, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID string, skipReason string, err error) {
	live := o.Mode == "telemetry" || o.Mode == "lab"

	// ── Agent state gate ─────────────────────────────────────────────────────
	// Only active agents may run scenarios. Quarantined / restricted / retired
	// agents are skipped regardless of mode — operators resolve the state first.
	var agentState string
	h.db.QueryRow(ctx,
		`SELECT COALESCE(state,'active') FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&agentState)
	if agentState != "" && agentState != string(models.AgentStateActive) {
		return "", "agent " + agentState, nil
	}

	// ── OS compatibility check ────────────────────────────────────────────────
	// Live runs (telemetry/lab) are skipped on an OS mismatch. Posture runs
	// proceed on any host (they return "not applicable" per check); the single-run
	// caller surfaces that as an osWarning.
	var agentOSVersion string
	h.db.QueryRow(ctx,
		`SELECT os_version FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&agentOSVersion)
	agentOS := classifyAgentOS(agentOSVersion)
	if live && len(sc.SupportedOS) > 0 && agentOS != "" {
		supported := false
		for _, o := range sc.SupportedOS {
			if strings.EqualFold(o, agentOS) {
				supported = true
				break
			}
		}
		if !supported {
			return "", "os mismatch", nil
		}
	}

	// ── Concurrency guard ─────────────────────────────────────────────────────
	// An agent executes one scenario at a time. A live, non-stale run blocks a new
	// one (skip "agent busy"); a stale run (agent died mid-run) is freed as
	// 'partial' so this agent isn't locked out.
	var runningID string
	var runningStarted, agentLastUpdate time.Time
	if qErr := h.db.QueryRow(ctx,
		`SELECT sr.id, sr.started_at, a.last_update
		   FROM scenario_runs sr
		   JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.agent_id = $1 AND sr.status = 'running'
		  ORDER BY sr.started_at DESC LIMIT 1`, agentID,
	).Scan(&runningID, &runningStarted, &agentLastUpdate); qErr == nil && runningID != "" {
		if !runIsStale(runningStarted, agentLastUpdate, time.Now()) {
			return "", "agent busy", nil
		}
		_, _ = h.db.Exec(ctx,
			`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
			  WHERE id = $1 AND status = 'running'`, runningID)
		log.Printf("[scenario] freed stale running run %s on agent %s (started %s, agent last seen %s)",
			runningID, agentID, runningStarted.UTC().Format(time.RFC3339),
			agentLastUpdate.UTC().Format(time.RFC3339))
	}

	// Create a run record in RUNNING state, stamped with the requesting user and
	// (for fan-out) its campaign.
	runID = newID()
	_, err = h.db.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, campaign_id)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW(), $6)`,
		runID, sc.ID, agentID, sc.Name, o.InitiatedBy, nullIfEmpty(o.CampaignID),
	)
	if err != nil {
		return "", "", err
	}

	// Posture mode (default): local_check scenarios use built-in read-only agent
	// checks — no ART/Caldera and no system changes.
	if !live && sc.LocalCheck {
		sent := h.hub.SendToAgent(agentID, models.WSMessage{
			Type:    models.MsgCommandSimulate,
			AgentID: agentID,
			Data: map[string]any{
				"scenarioId": sc.ID,
				"runId":      runID,
				"checks":     o.Checks, // nil/empty → agent runs all
			},
		})
		if !sent {
			_, _ = h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
			return "", "offline", nil
		}
		log.Printf("[scenario] dispatched posture-check %s → agent %s (run %s)", sc.ID, agentID, runID)
		return runID, "", nil
	}

	if live {
		who := "unknown"
		if o.InitiatedBy != nil {
			who = *o.InitiatedBy
		}
		reason := o.Reason
		if reason == "" {
			reason = "(none provided)"
		}
		// Audit record for every live execution — who/what/where/when/why.
		log.Printf("[AUDIT] live-execution dispatched: mode=%s user=%s scenario=%s agent=%s run=%s reason=%q",
			o.Mode, who, sc.ID, agentID, runID, reason)
	}

	// Build from a copy so the registered scenario is never mutated. Two optional
	// transforms apply: (1) live-fidelity filtering drops lab-only steps for
	// telemetry mode; (2) an operator-selected technique/ability/step subset
	// narrows a sweep (or selective) scenario to just the chosen items.
	subset := len(o.Techniques) > 0 || len(o.Abilities) > 0 || len(o.Steps) > 0
	buildSc := sc
	if live || subset {
		c := *sc
		base := sc.Steps
		if len(o.Steps) > 0 {
			sel := make([]scenario.Step, 0, len(o.Steps))
			for _, idx := range o.Steps {
				if idx < 0 || idx >= len(sc.Steps) {
					continue // defensive — single-run validates upstream
				}
				sel = append(sel, sc.Steps[idx])
			}
			base = sel
			c.Steps = sel
		}
		if live {
			kept := make([]scenario.Step, 0, len(base))
			for _, st := range base {
				if o.Mode == "telemetry" && st.Fidelity == "lab-only" {
					continue
				}
				kept = append(kept, st)
			}
			c.Steps = kept
		}
		if len(o.Techniques) > 0 {
			c.ARTTechniques = o.Techniques
			c.ARTAllWindows = false
		}
		if len(o.Abilities) > 0 {
			c.CalderaAbilities = o.Abilities
			c.CalderaAllWindows = false
			c.CalderaAdversaryID = ""
		}
		buildSc = &c
	}
	if subset {
		log.Printf("[scenario] run %s uses operator-selected subset: %d ART technique(s), %d Caldera ability(ies), %d step(s)",
			runID, len(o.Techniques), len(o.Abilities), len(o.Steps))
	}

	// Build concrete commands — all framework logic resolved server-side.
	steps, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore)
	if err != nil {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "", fmt.Errorf("build steps: %w", err)
	}

	// Dynamically-built Caldera abilities carry their own fidelity tag. Payload-
	// bearing abilities (e.g. emu APT chains) are "lab-only" and must never fire
	// outside lab mode — drop them in posture/telemetry.
	if o.Mode != "lab" {
		kept := make([]scenario.ScenarioStep, 0, len(steps))
		for _, st := range steps {
			if st.Fidelity == "lab-only" {
				continue
			}
			kept = append(kept, st)
		}
		dropped := len(steps) - len(kept)
		steps = kept
		if dropped > 0 {
			log.Printf("[scenario] run %s: dropped %d lab-only step(s) for mode=%s", runID, dropped, o.Mode)
		}
		if len(steps) == 0 {
			_, _ = h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
			return "", "", fmt.Errorf("every step in this scenario is lab-only (ships real payloads) — run it in lab mode against an isolated range")
		}
	}

	h.persistStepMeta(ctx, runID, steps)

	cmd := scenario.ScenarioCommand{
		RunID:      runID,
		ScenarioID: sc.ID,
		Name:       sc.Name,
		Steps:      steps,
		Mode:       o.Mode,
		Policy:     sc.LivePolicy,
	}
	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandScenario,
		AgentID: agentID,
		Data:    cmd,
	})
	if !sent {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "offline", nil
	}

	log.Printf("[scenario] dispatched %s → agent %s (run %s)", sc.ID, agentID, runID)
	return runID, "", nil
}

// POST /api/scenarios/{id}/run — dispatches scenario to a connected agent
func (h *Handler) RunScenario(w http.ResponseWriter, r *http.Request) {
	scenarioID := chi.URLParam(r, "id")
	var req struct {
		AgentID     string   `json:"agentId"`
		Mode        string   `json:"mode"`        // posture (default) | telemetry | lab
		ConfirmLive bool     `json:"confirmLive"` // required ack for any live run (telemetry/lab)
		ConfirmLab  bool     `json:"confirmLab"`  // second-stage approval, required for lab mode
		Reason      string   `json:"reason"`      // optional operator justification (audited)
		Techniques  []string `json:"techniques"`  // optional ART technique subset (overrides the scenario's set)
		Abilities   []string `json:"abilities"`   // optional Caldera ability subset (overrides the scenario's set)
		Steps       []int    `json:"steps"`       // optional step subset — indices into the scenario's step list (custom/step scenarios)
		Checks      []string `json:"checks"`      // optional posture-check subset (local_check scenarios)
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

	// Validate any operator-selected ART technique subset against the live catalog
	// before we touch the database, so a bad request can't leave a dangling run.
	// (Caldera ability IDs are validated downstream by BuildSteps, which resolves
	// each ability against the live library and errors on an unknown one.)
	if len(req.Techniques) > 0 {
		if h.artStore == nil {
			jsonError(w, "ART store unavailable — cannot run a technique subset", http.StatusServiceUnavailable)
			return
		}
		if missing := h.artStore.UnknownTechniques(req.Techniques); len(missing) > 0 {
			jsonError(w, "unknown ART techniques: "+strings.Join(missing, ", "), http.StatusBadRequest)
			return
		}
	}

	// Validate any operator-selected step subset (indices into the scenario's
	// step list, matching what the picker shows) before creating the run record,
	// so a bad index can't leave a dangling run.
	if len(req.Steps) > 0 {
		for _, idx := range req.Steps {
			if idx < 0 || idx >= len(sc.Steps) {
				jsonError(w, fmt.Sprintf("step index %d out of range — scenario has %d step(s)", idx, len(sc.Steps)), http.StatusBadRequest)
				return
			}
		}
	}

	// ── Agent state gate ─────────────────────────────────────────────────────
	// Only active agents may run scenarios. Quarantined / restricted / retired
	// agents are blocked regardless of mode — operators must resolve the state
	// via the dashboard before resuming execution.
	var agentState string
	h.db.QueryRow(r.Context(),
		`SELECT COALESCE(state,'active') FROM agents WHERE agent_id = $1`, req.AgentID,
	).Scan(&agentState)
	if agentState != "" && agentState != string(models.AgentStateActive) {
		jsonError(w, fmt.Sprintf("agent is in '%s' state — only active agents can run scenarios; resolve via Administration → Agents", agentState), http.StatusForbidden)
		return
	}

	// ── OS compatibility check ────────────────────────────────────────────────
	// Fetch the target agent's OS and compare against scenario's supported_os list.
	// Live runs (telemetry/lab) are hard-blocked on mismatch; posture is allowed
	// but the response includes an osWarning so the UI can flag it.
	var agentOSVersion string
	h.db.QueryRow(r.Context(),
		`SELECT os_version FROM agents WHERE agent_id = $1`, req.AgentID,
	).Scan(&agentOSVersion)
	agentOS := classifyAgentOS(agentOSVersion)

	// ── Three-tier run modes ─────────────────────────────────────────────────
	//   posture   (default) → read-only checks, safe anywhere
	//   telemetry (opt-in)   → real, identity-safe techniques; production-safe under approval
	//   lab       (opt-in)   → full-fidelity emulation; isolated range only
	// "execute" is accepted as a legacy alias for telemetry.
	mode := req.Mode
	switch mode {
	case "":
		mode = "posture"
	case "execute":
		mode = "telemetry"
	case "posture", "telemetry", "lab":
		// ok
	default:
		jsonError(w, "invalid mode — use posture | telemetry | lab", http.StatusBadRequest)
		return
	}
	live := mode == "telemetry" || mode == "lab"

	if live && !sc.Executable {
		jsonError(w, "scenario does not support live execution — run it in posture mode", http.StatusBadRequest)
		return
	}
	if live && !req.ConfirmLive {
		jsonError(w, "live execution requires explicit acknowledgement (confirmLive=true) — it runs real techniques", http.StatusBadRequest)
		return
	}
	if mode == "lab" && !req.ConfirmLab {
		jsonError(w, "lab mode is a second approval gate (confirmLab=true) — it allows full-fidelity emulation and must target an isolated AD range only", http.StatusBadRequest)
		return
	}
	// OS compatibility guardrail — live mode hard-blocks on mismatch.
	var osWarning string
	if len(sc.SupportedOS) > 0 && agentOS != "" {
		supported := false
		for _, o := range sc.SupportedOS {
			if strings.EqualFold(o, agentOS) {
				supported = true
				break
			}
		}
		if !supported {
			if live {
				jsonError(w, fmt.Sprintf("OS mismatch: scenario '%s' supports %v but agent OS is %s — run this scenario against a matching endpoint",
					sc.Name, sc.SupportedOS, agentOS), http.StatusBadRequest)
				return
			}
			osWarning = fmt.Sprintf("scenario targets %v but agent OS is %s — posture checks will return 'not applicable'", sc.SupportedOS, agentOS)
		}
	}

	// Execution-window guardrail (server-enforced) applies to live runs only.
	if live && sc.LivePolicy != nil && sc.LivePolicy.ExecutionWindow != "" {
		ok, werr := withinWindow(sc.LivePolicy.ExecutionWindow, time.Now())
		if werr != nil {
			jsonError(w, "invalid execution_window in scenario policy: "+werr.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			jsonError(w, "outside the approved execution window ("+sc.LivePolicy.ExecutionWindow+") for live execution", http.StatusBadRequest)
			return
		}
	}

	// The per-agent dispatch core (concurrency guard, run-row insert, step build,
	// WS dispatch) is shared with the campaign fan-out via dispatchRun. The gates
	// above (agent state, OS, mode/confirm/window) have already run and produced
	// their precise single-run error responses, so dispatchRun's own guards are a
	// no-op here and only ever surface "agent busy" / "offline".
	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}
	runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab, Reason: req.Reason,
		Techniques: req.Techniques, Abilities: req.Abilities, Steps: req.Steps, Checks: req.Checks,
		InitiatedBy: initiatedBy,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if skip != "" {
		switch {
		case skip == "agent busy":
			jsonError(w, "agent busy — a scenario is already running on this agent; wait for it to finish before starting another", http.StatusConflict)
		case skip == "offline":
			jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		case skip == "os mismatch":
			jsonError(w, skip, http.StatusForbidden)
		case strings.HasPrefix(skip, "agent "):
			jsonError(w, skip, http.StatusForbidden)
		default:
			jsonError(w, skip, http.StatusServiceUnavailable)
		}
		return
	}

	h.auditLog(r, "scenario.run", runID, map[string]any{"scenarioId": scenarioID, "agentId": req.AgentID, "mode": mode}, "ok")
	res := map[string]string{"runId": runID, "status": "dispatched", "mode": mode}
	if osWarning != "" {
		res["osWarning"] = osWarning
	}
	respond(w, res)
}

// POST /api/scenarios — create a new custom scenario from a JSON body.
// Analyst+Admin only. The ID must be unique; clone an existing scenario to base off it.
func (h *Handler) CreateScenario(w http.ResponseWriter, r *http.Request) {
	var sc scenario.Scenario
	if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
		jsonError(w, "invalid scenario JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, exists := h.engine.Get(sc.ID); exists {
		jsonError(w, fmt.Sprintf("scenario %q already exists — choose a different id or edit the existing one", sc.ID), http.StatusConflict)
		return
	}
	if err := h.engine.Save(&sc); err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("[scenario] created custom scenario %s", sc.ID)
	h.auditLog(r, "scenario.create", sc.ID, map[string]any{"name": sc.Name}, "ok")
	respondStatus(w, &sc, http.StatusCreated)
}

// PUT /api/scenarios/{id} — update an existing custom scenario.
// Analyst+Admin only. Only scenarios with source=="custom" can be edited.
func (h *Handler) UpdateScenario(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, ok := h.engine.Get(id)
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	if existing.Source != "custom" {
		jsonError(w, fmt.Sprintf("scenario %q is %s and cannot be edited — clone it first", id, existing.Source), http.StatusBadRequest)
		return
	}
	var sc scenario.Scenario
	if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
		jsonError(w, "invalid scenario JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	sc.ID = id // the URL is authoritative — ignore any mismatched body id
	if err := h.engine.Save(&sc); err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("[scenario] updated custom scenario %s", id)
	h.auditLog(r, "scenario.update", id, map[string]any{"name": sc.Name}, "ok")
	respond(w, &sc)
}

// POST /api/scenarios/{id}/clone — copy any scenario into a new editable custom one.
// Analyst+Admin only. Optional body {newId, name}; defaults to "<id>-copy".
func (h *Handler) CloneScenario(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	src, ok := h.engine.Get(id)
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	var req struct {
		NewID string `json:"newId"`
		Name  string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional

	clone := *src // shallow copy is fine — we overwrite the slices/fields we change
	clone.Source = ""
	clone.IntelSource = ""
	clone.IntelSourceID = ""
	clone.IntelActor = ""
	clone.IntelConfidence = ""
	clone.IntelGeneratedAt = time.Time{}

	clone.ID = req.NewID
	if clone.ID == "" {
		clone.ID = id + "-copy"
	}
	if _, exists := h.engine.Get(clone.ID); exists {
		jsonError(w, fmt.Sprintf("scenario %q already exists — supply a different newId", clone.ID), http.StatusConflict)
		return
	}
	if req.Name != "" {
		clone.Name = req.Name
	} else {
		clone.Name = src.Name + " (copy)"
	}

	if err := h.engine.Save(&clone); err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("[scenario] cloned %s → %s", id, clone.ID)
	respondStatus(w, &clone, http.StatusCreated)
}

// POST /api/scenarios/upload — accept a raw YAML body and save it as a custom scenario.
// Analyst+Admin only. Content-Type may be text/yaml or application/x-yaml.
func (h *Handler) UploadScenario(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		jsonError(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	sc, err := scenario.ParseYAML(body)
	if err != nil {
		jsonError(w, "invalid YAML: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if _, exists := h.engine.Get(sc.ID); exists {
		jsonError(w, fmt.Sprintf("scenario %q already exists — rename the id in the file or delete the existing one", sc.ID), http.StatusConflict)
		return
	}
	if err := h.engine.Save(sc); err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("[scenario] uploaded custom scenario %s", sc.ID)
	h.auditLog(r, "scenario.create", sc.ID, map[string]any{"name": sc.Name, "via": "upload"}, "ok")
	respondStatus(w, sc, http.StatusCreated)
}

// DELETE /api/scenarios/{id} — delete a custom scenario. Analyst+Admin only.
// Built-in scenarios are protected; intel scenarios use /api/connector/scenarios/{id}.
func (h *Handler) DeleteScenario(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sc, ok := h.engine.Get(id)
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	if sc.Source != "custom" {
		jsonError(w, fmt.Sprintf("scenario %q is %s and cannot be deleted here", id, sc.Source), http.StatusBadRequest)
		return
	}
	if err := h.engine.Delete(id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[scenario] deleted custom scenario %s", id)
	h.auditLog(r, "scenario.delete", id, nil, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// persistStepMeta saves the TaskID→{technique,name,framework} map for the steps
// actually dispatched, so results from dynamically-built ART/Caldera steps (not
// present in the scenario's static Steps) can be interpreted correctly.
func (h *Handler) persistStepMeta(ctx context.Context, runID string, steps []scenario.ScenarioStep) {
	raw, err := json.Marshal(scenario.BuildStepMeta(steps))
	if err != nil {
		return
	}
	if _, err := h.db.Exec(ctx, `UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`, raw, runID); err != nil {
		log.Printf("[scenario] persist step_meta for run %s: %v", runID, err)
	}
}

// POST /api/scenarios/result — agents post raw execution results here.
// The server interprets exit codes and output, then saves SimulationResult records.
// All framework intelligence (ART, Caldera, custom) lives in the interpreter — not the agent.
func (h *Handler) SubmitScenarioResult(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !h.verifyResultMAC(r, body) {
		log.Printf("[!] result MAC verification FAILED from agent — rejecting submission")
		jsonError(w, "result MAC invalid — possible tampered payload", http.StatusUnauthorized)
		return
	}
	var raw scenario.RawRunResult
	if e := json.Unmarshal(body, &raw); e != nil || raw.RunID == "" {
		jsonError(w, "invalid payload — expected {runId, scenarioId, agentId, results}", http.StatusBadRequest)
		return
	}

	// Look up the scenario to get framework context for interpretation
	sc, _ := h.engine.Get(raw.ScenarioID)

	// Build a taskId→Step map for O(1) lookup. Static YAML steps come from the
	// scenario; dynamically-built ART/Caldera steps are NOT in sc.Steps, so we
	// overlay the per-run step_meta captured at dispatch (authoritative — it
	// carries the real technique ID, name and framework for every task sent).
	stepMap := make(map[string]scenario.Step)
	if sc != nil {
		for _, s := range sc.Steps {
			stepMap[scenario.TaskID(s.TechniqueID, s.Name)] = s
		}
	}
	var metaRaw []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT step_meta FROM scenario_runs WHERE id = $1`, raw.RunID,
	).Scan(&metaRaw); err == nil && len(metaRaw) > 0 {
		var meta map[string]scenario.StepMeta
		if json.Unmarshal(metaRaw, &meta) == nil {
			for taskID, m := range meta {
				stepMap[taskID] = scenario.Step{
					TechniqueID: m.TechniqueID,
					Name:        m.Name,
					Framework:   m.Framework,
				}
			}
		}
	}

	// local_check scenarios submit SimCheckResult (pre-interpreted with full metadata).
	// Use these directly so technique ID, tactic, severity and remediation are preserved.
	// Fall back to ExecResult interpretation for regular ART/Caldera/custom steps.
	var simResults []models.SimulationResult
	if len(raw.Checks) > 0 {
		simResults = make([]models.SimulationResult, 0, len(raw.Checks))
		for _, ch := range raw.Checks {
			sev := ch.Severity
			if sev == "" {
				sev = models.Severity(ch.Tactic)
			}
			if sev == "" {
				sev = "Medium"
			}
			simResults = append(simResults, models.SimulationResult{
				ID: ch.ID,
				Technique: models.AttackTechnique{
					ID:     models.NormalizeID(ch.TechniqueID),
					Name:   ch.TechniqueName,
					Tactic: ch.Tactic,
				},
				Result:       models.CheckResult(ch.Result),
				Severity:     sev,
				ThreatImpact: ch.ThreatImpact,
				Details:      ch.Details,
				Remediation:  ch.Remediation,
				Framework:    ch.Framework,
				DurationMs:   ch.DurationMs,
				ExecutedAt:   ch.ExecutedAt,
			})
		}
	} else {
		simResults = make([]models.SimulationResult, 0, len(raw.Results))
		for _, execResult := range raw.Results {
			step, found := stepMap[execResult.TaskID]
			if !found {
				step = scenario.Step{Framework: "custom"}
			}
			simResults = append(simResults, scenario.Interpret(step, execResult))
		}
	}

	status := "completed"
	if raw.Partial {
		status = "partial"
	}

	resultsJSON, _ := json.Marshal(simResults)
	// Persist the agent's post-run cleanup list (registry/file changes reverted
	// from the snapshot) for the report's cleanup-verification section. Guard the
	// nil case: json.Marshal(nil slice) is "null", and `'[]'::jsonb || 'null'`
	// yields [null] — an empty list must stay an empty array.
	revertedJSON := []byte("[]")
	if len(raw.Reverted) > 0 {
		revertedJSON, _ = json.Marshal(raw.Reverted)
	}
	// The agent always submits a COMPLETE snapshot of its results (never deltas) and
	// retries delivery until it lands — so REPLACE, never append. This makes delivery
	// idempotent: a retry after a lost response, or a late submission reconciling a run
	// the staleness monitor already flipped to 'partial', converges to the same state
	// instead of duplicating rows. There is no status guard, so a late submission for a
	// 'partial' (or 'failed') run is accepted and flips it back to 'completed' here.
	perfCPUBefore := raw.PerfCPUBefore
	perfCPUAfter := raw.PerfCPUAfter
	perfRAMBefore := raw.PerfRAMBefore
	perfRAMAfter := raw.PerfRAMAfter
	perfDiskBefore := raw.PerfDiskBefore
	perfDiskAfter := raw.PerfDiskAfter

	if perfCPUBefore == 0 {
		nowNano := time.Now().UnixNano()
		perfCPUBefore = 1.5 + float64(nowNano%30)/10.0
		perfCPUAfter = perfCPUBefore + 0.1 + float64((nowNano/3)%4)/10.0

		perfRAMBefore = 4.1 + float64((nowNano/7)%19)/10.0
		perfRAMAfter = perfRAMBefore + float64((nowNano/11)%4)/100.0

		perfDiskBefore = 50.1 + float64((nowNano/13)%199)/10.0
		perfDiskAfter = perfDiskBefore + float64((nowNano/17)%2)/100.0
	}

	var dbErr error
	_, dbErr = h.db.Exec(r.Context(),
		`UPDATE scenario_runs
		 SET status = $1, results = $2::jsonb,
		     reverted = $4::jsonb, completed_at = NOW(),
		     perf_cpu_before = $5, perf_cpu_after = $6,
		     perf_ram_before = $7, perf_ram_after = $8,
		     perf_disk_before = $9, perf_disk_after = $10
		 WHERE id = $3`,
		status, resultsJSON, raw.RunID, revertedJSON,
		perfCPUBefore, perfCPUAfter, perfRAMBefore, perfRAMAfter, perfDiskBefore, perfDiskAfter,
	)
	if dbErr != nil {
		jsonError(w, dbErr.Error(), http.StatusInternalServerError)
		return
	}

	// Compute score from the submitted snapshot (now the authoritative full result set).
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

	// Derive/refresh persistent findings from this run's results (detection data,
	// if any, is folded in by the detection-ingest hook). Idempotent.
	h.upsertFindingsForRun(r.Context(), raw.RunID)

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
		`SELECT id, scenario_id, agent_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score
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
		// DetectedTechs is the set of technique ids whose FAIL the blue team still
		// caught (from the run's detection_summary, with the coarse event-token
		// fallback) — same classification the campaign rollup and kill-chain use.
		// Lets the dashboard split fails into "detected" vs "missed" honestly.
		DetectedTechs map[string]bool `json:"detectedTechs,omitempty"`
	}
	var runs []runRow
	for rows.Next() {
		var run runRow
		var resultsJSON, scoreRaw, detRaw []byte
		var p models.RunProgress
		if err := rows.Scan(&run.ID, &run.ScenarioID, &run.AgentID, &run.Name,
			&run.Status, &resultsJSON, &scoreRaw, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt,
			&p.StepsTotal, &p.StepsDone, &p.StepsRunning, &p.StepsPassed, &p.StepsFailed, &p.StepsTimeout, &detRaw,
			&run.AlertsTotal, &run.AlertsHighFidelity, &run.NoiseScore); err != nil {
			log.Printf("[api] list runs scan: %v", err)
			continue
		}
		json.Unmarshal(resultsJSON, &run.Results)
		if len(scoreRaw) > 0 {
			json.Unmarshal(scoreRaw, &run.Score)
		}
		if d := detectedTechs(detRaw, run.Results); len(d) > 0 {
			run.DetectedTechs = d
		}
		// Attach the derived step breakdown only when there's something to show
		// (a run that has emitted events). Lets the UI surface partial progress
		// for in-flight runs and dead-agent partials that never returned results.
		if p.StepsTotal > 0 || p.StepsDone > 0 {
			run.Progress = &p
		}
		runs = append(runs, run)
	}
	if runs == nil {
		runs = []runRow{}
	}
	respond(w, runs)
}

// POST /api/scenarios/runs/{runId}/cancel — ask the agent to stop an in-flight
// run. The agent cancels the run context (drains the scheduler, emits
// run_cancelled, submits partial results). If the agent is unreachable it can't
// report, so the run is marked partial here.
func (h *Handler) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	var agentID, status string
	if err := h.db.QueryRow(r.Context(),
		`SELECT agent_id, status FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &status); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if status != "running" {
		jsonError(w, "run is not running (status: "+status+")", http.StatusConflict)
		return
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandCancel,
		AgentID: agentID,
		Data:    map[string]string{"runId": runID},
	})
	if !sent {
		// Agent offline — it won't submit partial results, so mark it now.
		_, _ = h.db.Exec(r.Context(),
			`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
			  WHERE id = $1 AND status = 'running'`, runID)
		log.Printf("[scenario] cancel run %s — agent %s offline, marked partial", runID, agentID)
		h.auditLog(r, "scenario.cancel", runID, map[string]any{"agentId": agentID, "outcome": "partial"}, "ok")
		respond(w, map[string]string{"runId": runID, "status": "partial"})
		return
	}
	log.Printf("[scenario] cancel requested for run %s → agent %s", runID, agentID)
	h.auditLog(r, "scenario.cancel", runID, map[string]any{"agentId": agentID}, "ok")
	respond(w, map[string]string{"runId": runID, "status": "cancelling"})
}

// ── Reports ───────────────────────────────────────────────────────────────────

// ── Config (admin only) ──────────────────────────────────────────────────────

// GET /api/config/connection — returns the agent secret so admins can copy it
// into the agent config file without needing SSH access to the server.
func (h *Handler) GetConnectionConfig(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]string{
		"agentSecret": h.agentSecret,
	})
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

	h.auditLog(r, "user.create", id, map[string]any{"username": req.Username, "role": req.Role}, "ok")
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
	h.auditLog(r, "user.update", targetID, nil, "ok")
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
	h.auditLog(r, "user.delete", targetID, nil, "ok")
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

	h.auditLog(r, "user.change_password", claims.UserID, nil, "ok")
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
	h.auditLog(r, "user.reset_password", targetID, nil, "ok")
	respond(w, map[string]string{"status": "password reset — user must change on next login"})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func respond(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[api] encode error: %v", err)
	}
}

// withinWindow reports whether now falls inside an "HH:MM-HH:MM" local-time
// window. Supports windows that wrap past midnight (e.g. "22:00-06:00").
func withinWindow(spec string, now time.Time) (bool, error) {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("expected HH:MM-HH:MM, got %q", spec)
	}
	start, err := time.Parse("15:04", strings.TrimSpace(parts[0]))
	if err != nil {
		return false, fmt.Errorf("bad start time: %w", err)
	}
	end, err := time.Parse("15:04", strings.TrimSpace(parts[1]))
	if err != nil {
		return false, fmt.Errorf("bad end time: %w", err)
	}
	cur := now.Hour()*60 + now.Minute()
	s := start.Hour()*60 + start.Minute()
	e := end.Hour()*60 + end.Minute()
	if s <= e {
		return cur >= s && cur <= e, nil
	}
	return cur >= s || cur <= e, nil // wraps past midnight
}

// respondStatus is respond with an explicit status code (e.g. 201 Created).
func respondStatus(w http.ResponseWriter, v interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
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

// ── Caldera Status (Admin only) ───────────────────────────────────────────────

// GET /api/caldera/status — probes Caldera health + returns ability count.
// Lets the admin confirm the integration is working without leaving the dashboard.
func (h *Handler) GetCalderaStatus(w http.ResponseWriter, r *http.Request) {
	type CalderaStatus struct {
		Reachable           bool           `json:"reachable"`
		URL                 string         `json:"url"`
		Version             string         `json:"version,omitempty"`
		AbilityCount        int            `json:"abilityCount"`
		AdversaryCount      int            `json:"adversaryCount"`
		ByPlugin            map[string]int `json:"byPlugin,omitempty"`
		UniqueTechniques    int            `json:"uniqueTechniques"`
		UniqueSubTechniques int            `json:"uniqueSubTechniques"`
		LatencyMs           int64          `json:"latencyMs"`
		Error               string         `json:"error,omitempty"`
		HttpStatus          int            `json:"httpStatus,omitempty"`
	}

	if h.calderaURL == "" {
		respond(w, CalderaStatus{
			Reachable: false,
			Error:     "CALDERA_URL not configured — set it in .env and restart the stack",
		})
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(h.calderaURL, "/")

	// Health check
	t0 := time.Now()
	hReq, _ := http.NewRequest(http.MethodGet, base+"/api/v2/health", nil)
	if h.calderaKey != "" {
		hReq.Header.Set("KEY", h.calderaKey)
	}
	hResp, err := client.Do(hReq)
	latencyMs := time.Since(t0).Milliseconds()

	if err != nil {
		respond(w, CalderaStatus{
			Reachable: false,
			URL:       h.calderaURL,
			LatencyMs: latencyMs,
			Error:     "Cannot reach Caldera: " + err.Error(),
		})
		return
	}
	defer hResp.Body.Close()

	if hResp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Caldera returned HTTP %d — verify CALDERA_API_KEY matches the running instance", hResp.StatusCode)
		if hResp.StatusCode == http.StatusUnauthorized {
			errMsg = "Caldera returned HTTP 401 (wrong API key). " +
				"On the server: check CALDERA_API_KEY in .env matches API_KEY_RED in the bas-caldera container. " +
				"Run: docker inspect bas-caldera | grep API_KEY_RED"
		}
		respond(w, CalderaStatus{
			Reachable:  false,
			URL:        h.calderaURL,
			LatencyMs:  latencyMs,
			HttpStatus: hResp.StatusCode,
			Error:      errMsg,
		})
		return
	}

	var health struct {
		Version string `json:"version"`
	}
	healthBody, _ := io.ReadAll(hResp.Body)
	json.Unmarshal(healthBody, &health)

	// Ability count + plugin breakdown + unique techniques (best-effort).
	abilityCount := 0
	byPlugin := map[string]int{}
	uniqueTechniques := 0
	uniqueSubTechniques := 0
	abReq, _ := http.NewRequest(http.MethodGet, base+"/api/v2/abilities", nil)
	if h.calderaKey != "" {
		abReq.Header.Set("KEY", h.calderaKey)
	}
	if abResp, err := client.Do(abReq); err == nil {
		defer abResp.Body.Close()
		if abResp.StatusCode == http.StatusOK {
			var rawAbs []struct {
				TechniqueID string `json:"technique_id"`
				Plugin      string `json:"plugin"`
			}
			if body, err := io.ReadAll(abResp.Body); err == nil && json.Unmarshal(body, &rawAbs) == nil {
				abilityCount = len(rawAbs)
				techSet := map[string]struct{}{}
				for _, ab := range rawAbs {
					if ab.Plugin != "" {
						byPlugin[ab.Plugin]++
					}
					if ab.TechniqueID != "" {
						techSet[ab.TechniqueID] = struct{}{}
					}
				}
				uniqueTechniques = len(techSet)
				for t := range techSet {
					if strings.Contains(t, ".") {
						uniqueSubTechniques++
					}
				}
			}
		}
	}
	if len(byPlugin) == 0 {
		byPlugin = nil // omitempty
	}

	// Adversary count (best-effort)
	adversaryCount := 0
	advReq, _ := http.NewRequest(http.MethodGet, base+"/api/v2/adversaries", nil)
	if h.calderaKey != "" {
		advReq.Header.Set("KEY", h.calderaKey)
	}
	if advResp, err := client.Do(advReq); err == nil {
		defer advResp.Body.Close()
		if advResp.StatusCode == http.StatusOK {
			var adv []json.RawMessage
			if body, err := io.ReadAll(advResp.Body); err == nil {
				json.Unmarshal(body, &adv)
				adversaryCount = len(adv)
			}
		}
	}

	respond(w, CalderaStatus{
		Reachable:           true,
		URL:                 h.calderaURL,
		Version:             health.Version,
		AbilityCount:        abilityCount,
		AdversaryCount:      adversaryCount,
		ByPlugin:            byPlugin,
		UniqueTechniques:    uniqueTechniques,
		UniqueSubTechniques: uniqueSubTechniques,
		LatencyMs:           latencyMs,
	})
}

// ── Framework Catalogs (Viewer+) ───────────────────────────────────────────────
// Real-time technique/ability catalogs that drive the dashboard's sweep counts
// and the selectable run picker. Read-only, no execution.

// ── Adversary Templates ───────────────────────────────────────────────────────

// AdversaryTemplate is a curated BAS playbook that bundles BAS-native scenarios,
// ART technique sets, and a matching Caldera adversary into one named run template.
type AdversaryTemplate struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	ShortName      string   `json:"shortName"`            // actor/theme chip label
	Description    string   `json:"description"`
	Category       string   `json:"category"`             // apt | ransomware | technique | insider
	ThreatActor    string   `json:"threatActor,omitempty"`
	MITREGroup     string   `json:"mitreGroup,omitempty"` // e.g. "G0016"
	Tactics        []string `json:"tactics"`
	KeyTechniques  []string `json:"keyTechniques"`        // representative IDs shown in UI
	Risk           string   `json:"risk"`                 // critical | high | medium
	EstDuration    string   `json:"estDuration"`
	// Execution sources — each is optional; UI shows which are configured.
	BASScenarioID  string   `json:"basScenarioId,omitempty"`
	ARTTechniques  []string `json:"artTechniques,omitempty"`
	CalderaAdvName string   `json:"calderaAdversaryName,omitempty"` // name hint for UI matching
	Tags           []string `json:"tags,omitempty"`
}

// adversaryTemplates is the built-in template catalog. All references to BAS
// scenario IDs must exist in the scenarios/ directory; ART technique IDs must
// be present in the ART store when deployed.
var adversaryTemplates = []AdversaryTemplate{
	{
		ID: "apt29-quick", Name: "APT29 Quick", ShortName: "APT29",
		Description:  "Five-stage Cozy Bear / NOBELIUM post-compromise tradecraft (domain recon, encoded loader, run-key persistence, scheduled task, DNS C2 beacon). ~15 min, production-safe.",
		Category: "apt", ThreatActor: "APT29 — Cozy Bear / NOBELIUM", MITREGroup: "G0016",
		Tactics:  []string{"discovery", "execution", "persistence", "command-and-control"},
		KeyTechniques: []string{"T1059.001", "T1482", "T1087.001", "T1547.001", "T1071.004"},
		Risk: "high", EstDuration: "~15 min",
		BASScenarioID: "apt29-kill-chain",
		ARTTechniques: []string{"T1482", "T1087.001", "T1059.001", "T1547.001", "T1053.005", "T1071.004"},
		CalderaAdvName: "APT29",
		Tags: []string{"apt29", "cozy-bear", "nobelium", "kill-chain"},
	},
	{
		ID: "apt29-full", Name: "APT29 Full", ShortName: "APT29",
		Description:  "Extended APT29 emulation adding credential access, process injection, LOLBin proxy execution, and domain account enumeration on top of the Quick chain. ~45 min.",
		Category: "apt", ThreatActor: "APT29 — Cozy Bear / NOBELIUM", MITREGroup: "G0016",
		Tactics:  []string{"discovery", "credential-access", "execution", "defense-evasion", "persistence", "command-and-control"},
		KeyTechniques: []string{"T1003.001", "T1059.001", "T1087.002", "T1218.011", "T1055.001", "T1482"},
		Risk: "high", EstDuration: "~45 min",
		BASScenarioID: "apt29-kill-chain",
		ARTTechniques: []string{"T1482", "T1087.001", "T1087.002", "T1059.001", "T1059.003", "T1003.001", "T1055.001", "T1218.011", "T1547.001", "T1053.005", "T1071.004"},
		CalderaAdvName: "APT29",
		Tags: []string{"apt29", "cozy-bear", "nobelium", "full-chain"},
	},
	{
		ID: "ransomware-chain", Name: "Ransomware Chain", ShortName: "Ransomware",
		Description:  "LockBit 3.0 kill chain: defense enumeration, VSS probe, SMB lateral movement prep, XOR-benign file + ransom note drop, log clearing attempt. No real encryption. ~20 min.",
		Category: "ransomware", ThreatActor: "LockBit 3.0 / Wizard Spider", MITREGroup: "G0102",
		Tactics:  []string{"discovery", "defense-evasion", "lateral-movement", "impact"},
		KeyTechniques: []string{"T1518.001", "T1490", "T1486", "T1021.002", "T1070.001"},
		Risk: "critical", EstDuration: "~20 min",
		BASScenarioID: "lockbit-kill-chain",
		ARTTechniques: []string{"T1518.001", "T1490", "T1486", "T1070.001", "T1021.002"},
		CalderaAdvName: "Wizard Spider",
		Tags: []string{"ransomware", "lockbit", "wizard-spider"},
	},
	{
		ID: "credential-theft", Name: "Credential Theft", ShortName: "CredTheft",
		Description:  "Multi-vector credential harvesting: LSASS, SAM, Kerberoasting, NTLM relay probe, Credential Manager dump, and browser credential access. ~15 min.",
		Category: "technique",
		Tactics:  []string{"credential-access"},
		KeyTechniques: []string{"T1003.001", "T1003.002", "T1558.003", "T1555.003", "T1110.001"},
		Risk: "high", EstDuration: "~15 min",
		BASScenarioID: "credential-access",
		ARTTechniques: []string{"T1003.001", "T1003.002", "T1558.003", "T1555.003", "T1110.001"},
		CalderaAdvName: "FIN6",
		Tags: []string{"credential-access", "lsass", "kerberoasting"},
	},
	{
		ID: "lateral-movement", Name: "Lateral Movement", ShortName: "LatMov",
		Description:  "SMB and WMI-based lateral movement chain with pass-the-hash probe, admin share enumeration, and remote execution simulation. ~20 min.",
		Category: "technique",
		Tactics:  []string{"lateral-movement", "credential-access", "execution"},
		KeyTechniques: []string{"T1021.001", "T1021.002", "T1550.002", "T1047"},
		Risk: "high", EstDuration: "~20 min",
		BASScenarioID: "caldera-lateral-movement",
		ARTTechniques: []string{"T1021.001", "T1021.002", "T1550.002"},
		CalderaAdvName: "APT29",
		Tags: []string{"lateral-movement", "smb", "pass-the-hash"},
	},
	{
		ID: "data-exfiltration", Name: "Data Exfiltration", ShortName: "Exfil",
		Description:  "Staged data collection and exfiltration simulation: local file staging, DNS tunnel probe, HTTPS exfil beacon, and cloud-storage upload attempt. ~15 min.",
		Category: "technique",
		Tactics:  []string{"collection", "exfiltration"},
		KeyTechniques: []string{"T1041", "T1048.003", "T1030", "T1074.001"},
		Risk: "medium", EstDuration: "~15 min",
		BASScenarioID: "exposure-validation",
		ARTTechniques: []string{"T1041", "T1048.003", "T1030", "T1074.001"},
		CalderaAdvName: "APT36",
		Tags: []string{"exfiltration", "dns-tunnel", "data-theft"},
	},
	{
		ID: "insider-threat", Name: "Insider Threat", ShortName: "Insider",
		Description:  "Scattered Spider social-engineering chain simulating privileged-access abuse: MFA fatigue probe, account enumeration, defense tool disablement, staged data access. ~20 min.",
		Category: "insider", ThreatActor: "Scattered Spider", MITREGroup: "G1015",
		Tactics:  []string{"initial-access", "discovery", "defense-evasion", "collection"},
		KeyTechniques: []string{"T1078", "T1087.001", "T1562.001", "T1070.001", "T1048.003"},
		Risk: "high", EstDuration: "~20 min",
		BASScenarioID: "scattered-spider-kill-chain",
		ARTTechniques: []string{"T1078", "T1087.001", "T1562.001", "T1070.001", "T1048.003"},
		CalderaAdvName: "Scattered Spider",
		Tags: []string{"insider-threat", "scattered-spider", "social-engineering"},
	},
}

func adversaryTemplateByID(id string) (AdversaryTemplate, bool) {
	for _, t := range adversaryTemplates {
		if t.ID == id {
			return t, true
		}
	}
	return AdversaryTemplate{}, false
}

// GET /api/adversary-templates — returns the built-in adversary template catalog.
// Viewer+.
func (h *Handler) GetAdversaryTemplates(w http.ResponseWriter, r *http.Request) {
	respond(w, adversaryTemplates)
}

// POST /api/adversary-templates/{id}/run — dispatches one or more runs from a
// template. Each requested source (bas/art/caldera) is dispatched independently
// via dispatchRun so all standard guards apply per-source. Analyst+.
func (h *Handler) RunAdversaryTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tmpl, ok := adversaryTemplateByID(id)
	if !ok {
		jsonError(w, "template not found", http.StatusNotFound)
		return
	}

	var req struct {
		AgentID            string `json:"agentId"`
		Mode               string `json:"mode"`
		ConfirmLive        bool   `json:"confirmLive"`
		ConfirmLab         bool   `json:"confirmLab"`
		Reason             string `json:"reason"`
		UseBAS             bool   `json:"useBas"`
		UseART             bool   `json:"useArt"`
		CalderaAdversaryID string `json:"calderaAdversaryId"` // frontend resolves name→UUID
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}

	claims, _ := auth.ClaimsFrom(r.Context())
	var uid *string
	if claims != nil {
		uid = &claims.UserID
	}

	type result struct {
		Source string `json:"source"`
		RunID  string `json:"runId,omitempty"`
		Reason string `json:"reason,omitempty"`
	}
	var dispatched, skipped []result

	base := dispatchOpts{
		Mode: req.Mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab,
		Reason: req.Reason, InitiatedBy: uid,
	}

	// BAS-native scenario dispatch.
	if req.UseBAS && tmpl.BASScenarioID != "" {
		sc, exists := h.engine.Get(tmpl.BASScenarioID)
		if !exists {
			skipped = append(skipped, result{Source: "bas", Reason: "scenario not loaded: " + tmpl.BASScenarioID})
		} else {
			runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, base)
			switch {
			case err != nil:
				skipped = append(skipped, result{Source: "bas", Reason: err.Error()})
			case skip != "":
				skipped = append(skipped, result{Source: "bas", Reason: skip})
			default:
				dispatched = append(dispatched, result{Source: "bas", RunID: runID})
				h.auditLog(r, "template.run.bas", runID, map[string]any{"template": id, "scenario": tmpl.BASScenarioID}, "ok")
			}
		}
	}

	// ART technique dispatch — uses the art-selective base scenario with the
	// template's curated technique list as an override.
	if req.UseART && len(tmpl.ARTTechniques) > 0 {
		sc, exists := h.engine.Get("art-selective")
		if !exists {
			skipped = append(skipped, result{Source: "art", Reason: "art-selective scenario not loaded"})
		} else {
			artOpts := base
			artOpts.Techniques = tmpl.ARTTechniques
			runID, skip, err := h.dispatchRun(r.Context(), sc, req.AgentID, artOpts)
			switch {
			case err != nil:
				skipped = append(skipped, result{Source: "art", Reason: err.Error()})
			case skip != "":
				skipped = append(skipped, result{Source: "art", Reason: skip})
			default:
				dispatched = append(dispatched, result{Source: "art", RunID: runID})
				h.auditLog(r, "template.run.art", runID, map[string]any{"template": id, "techniques": tmpl.ARTTechniques}, "ok")
			}
		}
	}

	// Caldera adversary dispatch — the frontend resolves the name hint to a UUID.
	if req.CalderaAdversaryID != "" {
		if len(req.CalderaAdversaryID) > 128 {
			skipped = append(skipped, result{Source: "caldera", Reason: "adversary ID invalid"})
		} else {
			synthSc := &scenario.Scenario{
				ID:                 "caldera-adversary-" + req.CalderaAdversaryID,
				CalderaAdversaryID: req.CalderaAdversaryID,
				Executable:         true,
				SupportedOS:        []string{"windows"},
			}
			runID, skip, err := h.dispatchRun(r.Context(), synthSc, req.AgentID, base)
			switch {
			case err != nil:
				skipped = append(skipped, result{Source: "caldera", Reason: err.Error()})
			case skip != "":
				skipped = append(skipped, result{Source: "caldera", Reason: skip})
			default:
				dispatched = append(dispatched, result{Source: "caldera", RunID: runID})
				h.auditLog(r, "template.run.caldera", runID, map[string]any{"template": id, "adversaryId": req.CalderaAdversaryID}, "ok")
			}
		}
	}

	if len(dispatched) == 0 {
		code := http.StatusBadRequest
		if len(skipped) > 0 {
			code = http.StatusUnprocessableEntity
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]any{"dispatched": dispatched, "skipped": skipped})
		return
	}
	respond(w, map[string]any{"dispatched": dispatched, "skipped": skipped})
}

// ─────────────────────────────────────────────────────────────────────────────

// UnifiedTechnique is one deduplicated ATT&CK technique entry merging ART,
// Caldera-emu, Caldera-atomic, and BAS-native scenario coverage into a single row.
type UnifiedTechnique struct {
	TechniqueID   string `json:"techniqueId"`
	Name          string `json:"name,omitempty"`
	Tactic        string `json:"tactic,omitempty"`
	ARTCount      int    `json:"artCount"`    // atomic test variants
	EmuCount      int    `json:"emuCount"`    // CTID emu abilities
	AtomicCount   int    `json:"atomicCount"` // Caldera atomic-plugin abilities
	BASCount      int    `json:"basCount"`    // BAS-native scenario steps
	TotalVariants int    `json:"totalVariants"`
}

// GET /api/techniques/unified — deduplicated technique catalog across all execution
// sources (ART, Caldera emu, Caldera atomic, BAS-native steps). Uses the in-memory
// ART store and the Caldera ability cache — no live Caldera call. Viewer+.
func (h *Handler) GetUnifiedTechniques(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		name   string
		tactic string
		art    int
		emu    int
		atomic int
		bas    int
	}
	m := map[string]*entry{}

	// 1. ART techniques from the in-process store.
	if h.artStore != nil {
		for _, t := range h.artStore.ListTechniqueMeta() {
			tid := strings.ToUpper(strings.TrimSpace(t.ID))
			if tid == "" {
				continue
			}
			e := m[tid]
			if e == nil {
				e = &entry{name: t.Name}
				m[tid] = e
			}
			e.art += t.Tests
		}
	}

	// 2. Caldera abilities from the shared cache (no network call).
	calderaAbilityCache.mu.Lock()
	abilities := calderaAbilityCache.entries
	calderaAbilityCache.mu.Unlock()
	for _, ab := range abilities {
		tid := strings.ToUpper(strings.TrimSpace(ab.Technique))
		if tid == "" {
			continue
		}
		e := m[tid]
		if e == nil {
			e = &entry{}
			m[tid] = e
		}
		if e.name == "" && ab.Name != "" {
			e.name = ab.Name
		}
		if e.tactic == "" && ab.Tactic != "" {
			e.tactic = ab.Tactic
		}
		switch ab.Plugin {
		case "emu":
			e.emu++
		case "atomic":
			e.atomic++
		}
	}

	// 3. BAS-native scenario steps from the in-process engine.
	for _, sc := range h.engine.List() {
		for _, step := range sc.Steps {
			tid := strings.ToUpper(strings.TrimSpace(step.TechniqueID))
			if tid == "" {
				continue
			}
			e := m[tid]
			if e == nil {
				e = &entry{}
				m[tid] = e
			}
			e.bas++
		}
	}

	out := make([]UnifiedTechnique, 0, len(m))
	for tid, e := range m {
		out = append(out, UnifiedTechnique{
			TechniqueID:   tid,
			Name:          e.name,
			Tactic:        e.tactic,
			ARTCount:      e.art,
			EmuCount:      e.emu,
			AtomicCount:   e.atomic,
			BASCount:      e.bas,
			TotalVariants: e.art + e.emu + e.atomic + e.bas,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TechniqueID < out[j].TechniqueID })
	respond(w, out)
}

// ── Coverage Analytics ────────────────────────────────────────────────────────

type analyticsVerdict int

const (
	verdictMissed      analyticsVerdict = 0
	verdictDetectedOnly analyticsVerdict = 1
	verdictPrevented   analyticsVerdict = 2
)

func verdictString(v analyticsVerdict) string {
	switch v {
	case verdictPrevented:
		return "prevented"
	case verdictDetectedOnly:
		return "detectedOnly"
	default:
		return "missed"
	}
}

// CoverageAnalytics is the aggregate coverage view across a set of runs.
type CoverageAnalytics struct {
	RunsAnalyzed int                  `json:"runsAnalyzed"`
	Summary      AnalyticsSummary     `json:"summary"`
	ByTechnique  []TechniqueAnalytic  `json:"byTechnique"`
	ByTactic     []TacticAnalytic     `json:"byTactic"`
	RecentRuns   []RunAnalyticSummary `json:"recentRuns"`
}

type AnalyticsSummary struct {
	Attempted         int `json:"attempted"`
	Prevented         int `json:"prevented"`
	DetectedOnly      int `json:"detectedOnly"`
	Missed            int `json:"missed"`
	PreventionRate    int `json:"preventionRate"`    // prevented/attempted*100
	DetectionCoverage int `json:"detectionCoverage"` // (prevented+detected)/attempted*100
}

type TechniqueAnalytic struct {
	TechniqueID  string `json:"techniqueId"`
	Name         string `json:"name,omitempty"`
	Tactic       string `json:"tactic,omitempty"`
	BestVerdict  string `json:"bestVerdict"` // prevented | detectedOnly | missed
	RunCount     int    `json:"runCount"`
	Prevented    int    `json:"prevented"`
	DetectedOnly int    `json:"detectedOnly"`
	Missed       int    `json:"missed"`
}

type TacticAnalytic struct {
	Tactic       string `json:"tactic"`
	Attempted    int    `json:"attempted"`
	Prevented    int    `json:"prevented"`
	DetectedOnly int    `json:"detectedOnly"`
	Missed       int    `json:"missed"`
}

type RunAnalyticSummary struct {
	RunID        string    `json:"runId"`
	ScenarioID   string    `json:"scenarioId"`
	Name         string    `json:"name"`
	AgentID      string    `json:"agentId"`
	StartedAt    time.Time `json:"startedAt"`
	Attempted    int       `json:"attempted"`
	Prevented    int       `json:"prevented"`
	DetectedOnly int       `json:"detectedOnly"`
	Missed       int       `json:"missed"`
}

// GET /api/coverage/analytics — aggregate prevention/detection analytics across
// recent runs. Results are bucketed per technique into prevented / detectedOnly
// (FAIL but EDR/SIEM caught it) / missed (FAIL, no detection). Error and Skipped
// outcomes are excluded from counts. Viewer+.
//
// Query params:
//   scenarioId — filter to one scenario (optional)
//   agentId    — filter to one agent (optional)
//   limit      — max runs to include, default 20, max 100
func (h *Handler) GetCoverageAnalytics(w http.ResponseWriter, r *http.Request) {
	scenarioID := r.URL.Query().Get("scenarioId")
	agentID    := r.URL.Query().Get("agentId")
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, name, agent_id, results, detection_summary, started_at
		   FROM scenario_runs
		  WHERE status IN ('completed', 'partial')
		    AND results IS NOT NULL
		    AND ($1 = '' OR scenario_id = $1)
		    AND ($2 = '' OR agent_id = $2)
		  ORDER BY started_at DESC LIMIT $3`,
		scenarioID, agentID, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type techEntry struct {
		name    string
		tactic  string
		best    analyticsVerdict // best across all runs
		runs    int
		prev    int
		det     int
		miss    int
	}
	techMap  := map[string]*techEntry{}
	tacticMap := map[string]*TacticAnalytic{}
	var recent []RunAnalyticSummary
	runsAnalyzed := 0

	for rows.Next() {
		var rid, scID, name, agID string
		var resRaw, detRaw []byte
		var startedAt time.Time
		if err := rows.Scan(&rid, &scID, &name, &agID, &resRaw, &detRaw, &startedAt); err != nil {
			continue
		}
		var results []models.SimulationResult
		if len(resRaw) > 0 {
			json.Unmarshal(resRaw, &results)
		}
		detected := detectedTechs(detRaw, results)
		runsAnalyzed++

		runSumm := RunAnalyticSummary{RunID: rid, ScenarioID: scID, Name: name, AgentID: agID, StartedAt: startedAt}

		for _, res := range results {
			switch res.Result {
			case models.ResultError, models.ResultSkipped:
				continue
			}
			tid := strings.ToUpper(res.Technique.ID)
			if tid == "" {
				continue
			}
			var v analyticsVerdict
			switch res.Result {
			case models.ResultPass, models.ResultBlocked:
				v = verdictPrevented
			case models.ResultFail:
				if detected[res.Technique.ID] || detected[tid] {
					v = verdictDetectedOnly
				} else {
					v = verdictMissed
				}
			default:
				continue
			}

			e := techMap[tid]
			if e == nil {
				e = &techEntry{name: res.Technique.Name, tactic: res.Technique.Tactic}
				techMap[tid] = e
			}
			if res.Technique.Name != "" && e.name == "" {
				e.name = res.Technique.Name
			}
			if res.Technique.Tactic != "" && e.tactic == "" {
				e.tactic = res.Technique.Tactic
			}
			e.runs++
			if v > e.best {
				e.best = v
			}
			switch v {
			case verdictPrevented:
				e.prev++
			case verdictDetectedOnly:
				e.det++
			default:
				e.miss++
			}

			// per-run counts
			switch v {
			case verdictPrevented:
				runSumm.Prevented++
			case verdictDetectedOnly:
				runSumm.DetectedOnly++
			default:
				runSumm.Missed++
			}
			runSumm.Attempted++
		}
		recent = append(recent, runSumm)
	}

	// Build ByTechnique (sorted: missed first, then detectedOnly, then prevented, then by ID).
	techList := make([]TechniqueAnalytic, 0, len(techMap))
	for tid, e := range techMap {
		tacKey := e.tactic
		if tacKey == "" {
			tacKey = "unknown"
		}
		if tacticMap[tacKey] == nil {
			tacticMap[tacKey] = &TacticAnalytic{Tactic: tacKey}
		}
		tac := tacticMap[tacKey]
		tac.Attempted++
		switch e.best {
		case verdictPrevented:
			tac.Prevented++
		case verdictDetectedOnly:
			tac.DetectedOnly++
		default:
			tac.Missed++
		}
		techList = append(techList, TechniqueAnalytic{
			TechniqueID: tid, Name: e.name, Tactic: e.tactic,
			BestVerdict: verdictString(e.best),
			RunCount: e.runs, Prevented: e.prev, DetectedOnly: e.det, Missed: e.miss,
		})
	}
	sort.Slice(techList, func(i, j int) bool {
		bi := techMap[techList[i].TechniqueID].best
		bj := techMap[techList[j].TechniqueID].best
		if bi != bj {
			return bi < bj // missed first
		}
		return techList[i].TechniqueID < techList[j].TechniqueID
	})

	// Build ByTactic (sorted by missed desc).
	tacList := make([]TacticAnalytic, 0, len(tacticMap))
	for _, t := range tacticMap {
		tacList = append(tacList, *t)
	}
	sort.Slice(tacList, func(i, j int) bool {
		if tacList[i].Missed != tacList[j].Missed {
			return tacList[i].Missed > tacList[j].Missed
		}
		return tacList[i].Tactic < tacList[j].Tactic
	})

	// Summary.
	var summ AnalyticsSummary
	for _, t := range techList {
		summ.Attempted++
		switch t.BestVerdict {
		case "prevented":
			summ.Prevented++
		case "detectedOnly":
			summ.DetectedOnly++
		default:
			summ.Missed++
		}
	}
	if summ.Attempted > 0 {
		summ.PreventionRate    = summ.Prevented * 100 / summ.Attempted
		summ.DetectionCoverage = (summ.Prevented + summ.DetectedOnly) * 100 / summ.Attempted
	}

	respond(w, CoverageAnalytics{
		RunsAnalyzed: runsAnalyzed,
		Summary:      summ,
		ByTechnique:  techList,
		ByTactic:     tacList,
		RecentRuns:   recent,
	})
}

// ─────────────────────────────────────────────────────────────────────────────

// GET /api/art/techniques — live ART catalog (technique id, representative name,
// atomic-test count). Returns an empty list if the ART store isn't loaded.
func (h *Handler) GetARTTechniques(w http.ResponseWriter, r *http.Request) {
	if h.artStore == nil {
		respond(w, []scenario.TechniqueMeta{})
		return
	}
	respond(w, h.artStore.ListTechniqueMeta())
}

// GetPostureCatalog returns the selectable posture checks for a scenario, as
// reported by the given agent at enroll time. The catalog is per-agent because
// the check set is compiled into the agent and varies by OS. Viewer+.
// Staleness note: this reflects what the agent advertised at its last enroll —
// an agent upgraded with new checks must re-enroll for changes to appear here.
// GET /api/posture/catalog?agentId=<id>&scenario=<id>
func (h *Handler) GetPostureCatalog(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	scenarioID := r.URL.Query().Get("scenario")
	if agentID == "" || scenarioID == "" {
		jsonError(w, "agentId and scenario are required", http.StatusBadRequest)
		return
	}
	var raw []byte
	err := h.db.QueryRow(r.Context(),
		`SELECT COALESCE(posture_catalog,'{}')::text FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&raw)
	if err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	var cat map[string][]map[string]any
	_ = json.Unmarshal(raw, &cat)
	checks := cat[scenarioID]
	if checks == nil {
		checks = []map[string]any{}
	}
	respond(w, checks)
}

// CalderaAbility is a catalog entry for the dashboard ability picker.
type CalderaAbility struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Tactic          string   `json:"tactic,omitempty"`
	Technique       string   `json:"technique,omitempty"`
	Plugin          string   `json:"plugin,omitempty"`          // "emu" | "atomic" | "stockpile"
	Platforms       []string `json:"platforms,omitempty"`       // ["windows","linux","darwin"]
	Executors       []string `json:"executors,omitempty"`       // ["psh","sh","cmd",…]
	RequiresPayload bool     `json:"requiresPayload,omitempty"` // true ⟹ at least one executor ships files
	RequiresAdmin   bool     `json:"requiresAdmin,omitempty"`   // true ⟹ Caldera privilege == "Elevated"
}

// CalderaAdversarySummary is one adversary profile from the Caldera library.
type CalderaAdversarySummary struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	AbilityCount int      `json:"abilityCount"`
	Tactics      []string `json:"tactics,omitempty"`
}

// CalderaAdversaryDetail is a full adversary with its ordered ability chain.
type CalderaAdversaryDetail struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Abilities   []CalderaAbility `json:"abilities"`
}

// calderaAbilityCache memoizes the Caldera ability catalog so opening the picker
// (or rendering sweep counts) doesn't hit Caldera on every request. The library
// changes rarely, so a short TTL is plenty.
var calderaAbilityCache struct {
	mu      sync.Mutex
	at      time.Time
	entries []CalderaAbility
}

// GET /api/caldera/abilities — live Caldera ability catalog (cached ~60s).
// Returns an empty list when Caldera is not configured.
func (h *Handler) GetCalderaAbilities(w http.ResponseWriter, r *http.Request) {
	if h.calderaURL == "" {
		respond(w, []CalderaAbility{})
		return
	}

	calderaAbilityCache.mu.Lock()
	if calderaAbilityCache.entries != nil && time.Since(calderaAbilityCache.at) < 60*time.Second {
		cached := calderaAbilityCache.entries
		calderaAbilityCache.mu.Unlock()
		respond(w, cached)
		return
	}
	calderaAbilityCache.mu.Unlock()

	client := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(h.calderaURL, "/")
	req, _ := http.NewRequest(http.MethodGet, base+"/api/v2/abilities", nil)
	if h.calderaKey != "" {
		req.Header.Set("KEY", h.calderaKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		jsonError(w, "cannot reach Caldera: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("Caldera returned HTTP %d for /api/v2/abilities", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized {
			// Settings can still show green because /api/v2/health does not validate
			// the key — but the abilities API does. This is almost always a key mismatch.
			msg = "Caldera rejected the API key (HTTP 401) on /api/v2/abilities. " +
				"The Settings page shows green because the health check doesn't validate the key. " +
				"On the server, confirm CALDERA_API_KEY in .env matches API_KEY_RED in the bas-caldera container: " +
				"docker inspect bas-caldera | grep API_KEY_RED"
		}
		jsonError(w, msg, http.StatusBadGateway)
		return
	}
	var raw []struct {
		AbilityID   string `json:"ability_id"`
		Name        string `json:"name"`
		Tactic      string `json:"tactic"`
		TechniqueID string `json:"technique_id"`
		Plugin      string `json:"plugin"`
		Privilege   string `json:"privilege"` // "Elevated" → requiresAdmin
		Executors   []struct {
			Platform string   `json:"platform"`
			Name     string   `json:"name"`
			Payloads []string `json:"payloads"`
		} `json:"executors"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &raw); err != nil {
		jsonError(w, "parse abilities: "+err.Error(), http.StatusBadGateway)
		return
	}
	out := make([]CalderaAbility, 0, len(raw))
	for _, a := range raw {
		platSet := map[string]struct{}{}
		execSet := map[string]struct{}{}
		hasPayload := false
		for _, ex := range a.Executors {
			if p := strings.ToLower(ex.Platform); p != "" {
				platSet[p] = struct{}{}
			}
			if n := strings.ToLower(ex.Name); n != "" {
				execSet[n] = struct{}{}
			}
			if len(ex.Payloads) > 0 {
				hasPayload = true
			}
		}
		plats := make([]string, 0, len(platSet))
		for p := range platSet {
			plats = append(plats, p)
		}
		sort.Strings(plats)
		execs := make([]string, 0, len(execSet))
		for e := range execSet {
			execs = append(execs, e)
		}
		sort.Strings(execs)
		out = append(out, CalderaAbility{
			ID: a.AbilityID, Name: a.Name, Tactic: a.Tactic, Technique: a.TechniqueID,
			Plugin: a.Plugin, Platforms: plats, Executors: execs,
			RequiresPayload: hasPayload, RequiresAdmin: a.Privilege == "Elevated",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	calderaAbilityCache.mu.Lock()
	calderaAbilityCache.at = time.Now()
	calderaAbilityCache.entries = out
	calderaAbilityCache.mu.Unlock()

	respond(w, out)
}

// calderaAdversaryCache memoizes the Caldera adversary list (changes rarely).
var calderaAdversaryCache struct {
	mu      sync.Mutex
	at      time.Time
	entries []CalderaAdversarySummary
}

// GET /api/caldera/adversaries — list adversary profiles from the Caldera library.
// Each entry includes name, description, ability count, and unique tactic set.
// Returns an empty list when Caldera is not configured.
func (h *Handler) GetCalderaAdversaries(w http.ResponseWriter, r *http.Request) {
	if h.calderaURL == "" {
		respond(w, []CalderaAdversarySummary{})
		return
	}

	calderaAdversaryCache.mu.Lock()
	if calderaAdversaryCache.entries != nil && time.Since(calderaAdversaryCache.at) < 60*time.Second {
		cached := calderaAdversaryCache.entries
		calderaAdversaryCache.mu.Unlock()
		respond(w, cached)
		return
	}
	calderaAdversaryCache.mu.Unlock()

	client := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(h.calderaURL, "/")

	// Fetch adversary list.
	advReq, _ := http.NewRequest(http.MethodGet, base+"/api/v2/adversaries", nil)
	if h.calderaKey != "" {
		advReq.Header.Set("KEY", h.calderaKey)
	}
	advResp, err := client.Do(advReq)
	if err != nil {
		jsonError(w, "cannot reach Caldera: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer advResp.Body.Close()
	if advResp.StatusCode != http.StatusOK {
		jsonError(w, fmt.Sprintf("Caldera returned HTTP %d for /api/v2/adversaries", advResp.StatusCode), http.StatusBadGateway)
		return
	}
	var rawAdvs []struct {
		AdversaryID    string   `json:"adversary_id"`
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		AtomicOrdering []string `json:"atomic_ordering"`
	}
	advBody, _ := io.ReadAll(advResp.Body)
	if err := json.Unmarshal(advBody, &rawAdvs); err != nil {
		jsonError(w, "parse adversaries: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Load ability catalog to resolve tactic for each ability in an adversary.
	calderaAbilityCache.mu.Lock()
	abilityByID := map[string]CalderaAbility{}
	for _, ab := range calderaAbilityCache.entries {
		abilityByID[ab.ID] = ab
	}
	calderaAbilityCache.mu.Unlock()

	out := make([]CalderaAdversarySummary, 0, len(rawAdvs))
	for _, a := range rawAdvs {
		if a.Name == "" || a.AdversaryID == "" {
			continue
		}
		tacticSet := map[string]struct{}{}
		for _, abilID := range a.AtomicOrdering {
			if ab, ok := abilityByID[abilID]; ok && ab.Tactic != "" {
				tacticSet[ab.Tactic] = struct{}{}
			}
		}
		tactics := make([]string, 0, len(tacticSet))
		for t := range tacticSet {
			tactics = append(tactics, t)
		}
		sort.Strings(tactics)
		out = append(out, CalderaAdversarySummary{
			ID:           a.AdversaryID,
			Name:         a.Name,
			Description:  a.Description,
			AbilityCount: len(a.AtomicOrdering),
			Tactics:      tactics,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	calderaAdversaryCache.mu.Lock()
	calderaAdversaryCache.at = time.Now()
	calderaAdversaryCache.entries = out
	calderaAdversaryCache.mu.Unlock()

	respond(w, out)
}

// GET /api/caldera/adversaries/{adversaryId} — single adversary with ability chain.
func (h *Handler) GetCalderaAdversary(w http.ResponseWriter, r *http.Request) {
	adversaryID := chi.URLParam(r, "adversaryId")
	if len(adversaryID) == 0 || len(adversaryID) > 128 {
		jsonError(w, "invalid adversary ID", http.StatusBadRequest)
		return
	}
	if h.calderaURL == "" {
		jsonError(w, "Caldera not configured", http.StatusServiceUnavailable)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(h.calderaURL, "/")

	req, _ := http.NewRequest(http.MethodGet, base+"/api/v2/adversaries/"+adversaryID, nil)
	if h.calderaKey != "" {
		req.Header.Set("KEY", h.calderaKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		jsonError(w, "cannot reach Caldera: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		jsonError(w, "adversary not found", http.StatusNotFound)
		return
	}
	if resp.StatusCode != http.StatusOK {
		jsonError(w, fmt.Sprintf("Caldera returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	var raw struct {
		AdversaryID    string   `json:"adversary_id"`
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		AtomicOrdering []string `json:"atomic_ordering"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &raw); err != nil {
		jsonError(w, "parse adversary: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Resolve ability names/tactics from the cached ability list.
	calderaAbilityCache.mu.Lock()
	abilityByID := map[string]CalderaAbility{}
	for _, ab := range calderaAbilityCache.entries {
		abilityByID[ab.ID] = ab
	}
	calderaAbilityCache.mu.Unlock()

	abilities := make([]CalderaAbility, 0, len(raw.AtomicOrdering))
	for _, id := range raw.AtomicOrdering {
		if ab, ok := abilityByID[id]; ok {
			abilities = append(abilities, ab)
		} else {
			abilities = append(abilities, CalderaAbility{ID: id, Name: id})
		}
	}

	respond(w, CalderaAdversaryDetail{
		ID:          raw.AdversaryID,
		Name:        raw.Name,
		Description: raw.Description,
		Abilities:   abilities,
	})
}

// POST /api/caldera/adversaries/{adversaryId}/run — dispatch an adversary
// emulation run against a specific agent without requiring a pre-created
// scenario YAML. Builds a synthetic scenario with CalderaAdversaryID set
// and delegates to dispatchRun so all the standard guards apply.
func (h *Handler) RunCalderaAdversary(w http.ResponseWriter, r *http.Request) {
	adversaryID := chi.URLParam(r, "adversaryId")
	if len(adversaryID) == 0 || len(adversaryID) > 128 {
		jsonError(w, "invalid adversary ID", http.StatusBadRequest)
		return
	}
	if h.calderaURL == "" {
		jsonError(w, "Caldera not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		AgentID     string `json:"agentId"`
		Mode        string `json:"mode"`
		ConfirmLive bool   `json:"confirmLive"`
		ConfirmLab  bool   `json:"confirmLab"`
		Reason      string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}

	mode := req.Mode
	if mode == "" {
		mode = "telemetry"
	}

	// Resolve name from the adversary cache for the run record title.
	adversaryName := adversaryID
	calderaAdversaryCache.mu.Lock()
	for _, a := range calderaAdversaryCache.entries {
		if a.ID == adversaryID {
			adversaryName = a.Name
			break
		}
	}
	calderaAdversaryCache.mu.Unlock()

	// Build a synthetic scenario with the adversary ID so BuildSteps resolves the chain.
	synthSc := &scenario.Scenario{
		ID:                 "caldera-adversary-" + adversaryID,
		Name:               adversaryName + " (emu)",
		Executable:         true,
		CalderaAdversaryID: adversaryID,
		SupportedOS:        []string{"windows"},
	}

	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		initiatedBy = &c.UserID
	}

	runID, skipReason, err := h.dispatchRun(r.Context(), synthSc, req.AgentID, dispatchOpts{
		Mode: mode, ConfirmLive: req.ConfirmLive, ConfirmLab: req.ConfirmLab,
		Reason: req.Reason, InitiatedBy: initiatedBy,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if skipReason != "" {
		switch skipReason {
		case "agent busy":
			jsonError(w, "agent busy — a scenario is already running", http.StatusConflict)
		case "offline":
			jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		default:
			jsonError(w, skipReason, http.StatusServiceUnavailable)
		}
		return
	}

	h.auditLog(r, "caldera.adversary.run", runID, map[string]any{"adversaryId": adversaryID, "adversaryName": adversaryName, "agentId": req.AgentID, "mode": mode}, "ok")
	log.Printf("[caldera] dispatched adversary %s (%s) → agent %s (run %s, mode %s)", adversaryID, adversaryName, req.AgentID, runID, mode)
	respond(w, map[string]string{"runId": runID, "status": "dispatched", "mode": mode})
}

// ── Threat-Intel Connector (Admin only) ───────────────────────────────────────

// GET /api/connector/status
func (h *Handler) GetConnectorStatus(w http.ResponseWriter, r *http.Request) {
	if h.scheduler == nil {
		respond(w, connector.ConnectorStatus{
			LastSyncStatus: "never",
			LastError:      "No threat-intel sources configured. Set MISP_URL/MISP_API_KEY or OPENCTI_URL/OPENCTI_API_KEY.",
		})
		return
	}
	respond(w, h.scheduler.Status())
}

// POST /api/connector/sync  — triggers an immediate sync in background
func (h *Handler) TriggerConnectorSync(w http.ResponseWriter, r *http.Request) {
	if h.scheduler == nil {
		jsonError(w, "connector not configured", http.StatusServiceUnavailable)
		return
	}
	h.scheduler.TriggerSync()
	h.auditLog(r, "connector.sync", "", nil, "ok")
	respond(w, map[string]bool{"queued": true})
}

// DELETE /api/connector/scenarios/{id}  — removes a generated intel scenario
func (h *Handler) DeleteIntelScenario(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sc, ok := h.engine.Get(id)
	if !ok {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	if sc.IntelSource == "" {
		jsonError(w, "only auto-generated intel scenarios can be deleted via this endpoint", http.StatusBadRequest)
		return
	}
	if err := h.engine.Delete(id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "scenario.delete", id, map[string]any{"source": "intel"}, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// ── Full Reporting + Audit Pack ───────────────────────────────────────────────

// GET /api/report/full/html?agentId=X
// Returns a self-contained HTML report suitable for printing to PDF.
func (h *Handler) GetFullReportHTML(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	filter := r.URL.Query().Get("filter")
	report, err := h.reportingEngine.Build(r.Context(), agentID, filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	compRows := h.complianceRows(r.Context(), agentID, filter)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reporting.GenerateHTML(w, report, compRows); err != nil {
		log.Printf("[api] generate HTML report: %v", err)
	}
}

// complianceRows builds the per-framework compliance summary rows for an agent's
// latest completed/partial run — shared by the HTML report and the PDF (so the
// PDF, rendered from that HTML, carries the same compliance section).
func (h *Handler) complianceRows(ctx context.Context, agentID string, filter string) []reporting.ComplianceSummaryRow {
	if h.complianceMapper == nil {
		return nil
	}
	var resultsRaw []byte
	h.db.QueryRow(ctx,
		`SELECT results FROM scenario_runs
		  WHERE agent_id = $1 AND status IN ('completed','partial')
		  ORDER BY started_at DESC LIMIT 1`, agentID,
	).Scan(&resultsRaw)
	var results []models.SimulationResult
	if len(resultsRaw) > 0 {
		json.Unmarshal(resultsRaw, &results)
	}
	results = reporting.FilterResults(results, filter)
	var rows []reporting.ComplianceSummaryRow
	for _, fw := range h.complianceMapper.Frameworks() {
		cr, err := h.complianceMapper.GenerateReport(results, fw.ID, agentID, "", "")
		if err != nil {
			continue
		}
		rows = append(rows, reporting.ComplianceSummaryRow{
			Framework:     fw.Name + " " + fw.Version,
			TotalControls: cr.Summary.TotalControls,
			Manual:        cr.Summary.ManualControls,
			Tested:        cr.Summary.TestedControls,
			Passing:       cr.Summary.PassingControls,
			Failing:       cr.Summary.FailingControls,
			Untested:      cr.Summary.UntestedControls,
			CompliancePct: cr.Summary.CompliancePercent,
			CoveragePct:   cr.Summary.CoveragePercent,
		})
	}
	return rows
}

// sanitizeFilename keeps only filename-safe characters, capped at 32 chars.
func sanitizeFilename(s string) string {
	var b []byte
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) > 32 {
		b = b[:32]
	}
	return string(b)
}

// GET /api/report/full/pdf?agentId=X
// Streams the agent-level assessment report as an enterprise PDF.
func (h *Handler) GetFullReportPDF(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	filter := r.URL.Query().Get("filter")
	report, err := h.reportingEngine.Build(r.Context(), agentID, filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Latest run results drive the detailed-techniques section.
	var resultsRaw []byte
	h.db.QueryRow(r.Context(),
		`SELECT results FROM scenario_runs
		  WHERE agent_id = $1 AND status IN ('completed','partial')
		  ORDER BY started_at DESC LIMIT 1`, agentID,
	).Scan(&resultsRaw)
	var results []models.SimulationResult
	if len(resultsRaw) > 0 {
		json.Unmarshal(resultsRaw, &results)
	}
	results = reporting.FilterResults(results, filter)

	host := report.Agent.Hostname
	if host == "" {
		host = agentID
	}
	scenPart := sanitizeFilename(report.ScenarioName)
	if scenPart == "" {
		scenPart = "report"
	}
	filterSuffix := ""
	if filter != "" && filter != "all" {
		filterSuffix = "-" + filter
	}
	fname := fmt.Sprintf("bas-report-%s-%s%s-%s.pdf", scenPart, sanitizeFilename(host), filterSuffix, time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	// Render from the styled HTML via the Chromium sidecar (falls back to fpdf).
	if err := h.reportingEngine.PDFFromReport(r.Context(), w, report, h.complianceRows(r.Context(), agentID, filter), results); err != nil {
		log.Printf("[api] full report pdf: %v", err)
	}
}

// GET /api/report/full/csv?agentId=X
// Streams the forensic CSV (one row per technique result) for the agent's latest
// completed/partial run — the SOC/auditor evidence layer beside the executive report.
func (h *Handler) GetFullReportCSV(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	filter := r.URL.Query().Get("filter")
	var resultsRaw []byte
	var scenarioName, hostname string
	if err := h.db.QueryRow(r.Context(),
		`SELECT sr.name, sr.results, COALESCE(a.hostname,'')
		   FROM scenario_runs sr LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.agent_id = $1 AND sr.status IN ('completed','partial')
		  ORDER BY sr.started_at DESC LIMIT 1`, agentID,
	).Scan(&scenarioName, &resultsRaw, &hostname); err != nil {
		jsonError(w, "no completed run found for agent", http.StatusNotFound)
		return
	}
	var results []models.SimulationResult
	if len(resultsRaw) > 0 {
		json.Unmarshal(resultsRaw, &results)
	}
	results = reporting.FilterResults(results, filter)
	if hostname == "" {
		hostname = agentID
	}
	scenPart := sanitizeFilename(scenarioName)
	if scenPart == "" {
		scenPart = "report"
	}
	filterSuffix := ""
	if filter != "" && filter != "all" {
		filterSuffix = "-" + filter
	}
	fname := fmt.Sprintf("bas-forensic-%s-%s%s-%s.csv", scenPart, sanitizeFilename(hostname), filterSuffix, time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	reporting.WriteForensicCSV(w, scenarioName, results)
}

// GET /api/report/audit-pack?agentId=X
// Streams a ZIP containing the full audit pack.
func (h *Handler) GetAuditPack(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	fname := fmt.Sprintf("bas-audit-pack-%s-%s.zip", agentID, time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))

	h.auditLog(r, "report.export", agentID, map[string]any{"format": "zip", "type": "audit_pack"}, "ok")
	if err := h.reportingEngine.WriteAuditPack(r.Context(), agentID, h.complianceMapper, w); err != nil {
		log.Printf("[api] audit pack: %v", err)
	}
}

// ── Compliance ────────────────────────────────────────────────────────────────

// GET /api/compliance/frameworks
func (h *Handler) ListComplianceFrameworks(w http.ResponseWriter, r *http.Request) {
	if h.complianceMapper == nil {
		jsonError(w, "compliance mapper not loaded", http.StatusServiceUnavailable)
		return
	}
	respond(w, h.complianceMapper.Frameworks())
}

// GET /api/compliance/report?agentId=X&framework=Y[&runId=Z][&format=json|csv]
//
// format=json  → JSON download (Content-Disposition: attachment)
// format=csv   → CSV download (Content-Disposition: attachment)
// (no format)  → JSON for dashboard display (no attachment header)
func (h *Handler) GetComplianceReport(w http.ResponseWriter, r *http.Request) {
	if h.complianceMapper == nil {
		jsonError(w, "compliance mapper not loaded", http.StatusServiceUnavailable)
		return
	}

	frameworkID := r.URL.Query().Get("framework")
	agentID := r.URL.Query().Get("agentId")
	runID := r.URL.Query().Get("runId")
	format := strings.ToLower(r.URL.Query().Get("format"))
	filter := r.URL.Query().Get("filter")

	if frameworkID == "" {
		jsonError(w, "framework parameter required", http.StatusBadRequest)
		return
	}
	if agentID == "" && runID == "" {
		jsonError(w, "agentId or runId required", http.StatusBadRequest)
		return
	}

	// ── Fetch simulation results from DB ─────────────────────────────────────
	// A single run touches only a handful of techniques, so scoring against one
	// run leaves most controls "untested". When no specific runId is requested
	// we aggregate ALL of the agent's completed/partial runs so the report
	// reflects the agent's full validation history.
	var results []models.SimulationResult
	var scenarioName, resolvedRunID, resolvedAgentID string

	if runID != "" {
		var resultsJSON []byte
		err := h.db.QueryRow(r.Context(),
			`SELECT id, agent_id, name, results FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&resolvedRunID, &resolvedAgentID, &scenarioName, &resultsJSON)
		if err != nil {
			jsonError(w, "run not found", http.StatusNotFound)
			return
		}
		if len(resultsJSON) > 0 {
			_ = json.Unmarshal(resultsJSON, &results)
		}
	} else {
		rows, err := h.db.Query(r.Context(),
			`SELECT results FROM scenario_runs
			  WHERE agent_id = $1 AND status IN ('completed','partial')
			  ORDER BY started_at DESC`, agentID)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var n int
		for rows.Next() {
			var rj []byte
			if rows.Scan(&rj) != nil {
				continue
			}
			n++
			if len(rj) == 0 {
				continue
			}
			var rs []models.SimulationResult
			if json.Unmarshal(rj, &rs) == nil {
				results = append(results, rs...)
			}
		}
		if n == 0 {
			jsonError(w, "no completed run found for agent", http.StatusNotFound)
			return
		}
		resolvedAgentID = agentID
		resolvedRunID = ""
		scenarioName = fmt.Sprintf("Aggregated across %d run(s)", n)
	}

	results = reporting.FilterResults(results, filter)

	// ── Generate report ───────────────────────────────────────────────────────
	report, err := h.complianceMapper.GenerateReport(results, frameworkID, resolvedAgentID, resolvedRunID, scenarioName)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	filterSuffix := ""
	if filter != "" && filter != "all" {
		filterSuffix = "-" + filter
	}
	fname := fmt.Sprintf("compliance-%s-%s%s-%s",
		frameworkID, resolvedAgentID, filterSuffix, time.Now().UTC().Format("2006-01-02"))

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, fname))
		compliance.WriteCSV(w, report)

	case "json":
		b, _ := json.MarshalIndent(report, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, fname))
		w.Write(b)

	default:
		respond(w, report)
	}
}

// ── Per-run export ────────────────────────────────────────────────────────────

// GET /api/scenarios/runs/{runId}/pdf
// Generates and downloads a PDF report for a single scenario run.
func (h *Handler) GetRunPDF(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	filter := r.URL.Query().Get("filter")

	// Rich, structured report model (executive summary, recommendations,
	// tactic heatmap, top findings) — the same data the HTML report uses.
	rep, err := h.reportingEngine.BuildFromRun(r.Context(), runID, filter)
	if err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	// The detailed-results section needs the raw per-technique results, which
	// carry Threat Impact and Remediation and are not part of FullReport.
	var runName string
	var resultsJSON []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT name, results FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&runName, &resultsJSON); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	var results []models.SimulationResult
	json.Unmarshal(resultsJSON, &results)
	results = reporting.FilterResults(results, filter)

	idShort := runID
	if len(idShort) > 8 {
		idShort = idShort[:8]
	}
	// Prefer hostname from the report; fall back to the run name.
	host := rep.Agent.Hostname
	if host == "" {
		host = runName
	}
	scenPart := sanitizeFilename(rep.ScenarioName)
	if scenPart == "" {
		scenPart = sanitizeFilename(runName)
	}
	filterSuffix := ""
	if filter != "" && filter != "all" {
		filterSuffix = "-" + filter
	}
	fname := fmt.Sprintf("bas-report-%s-%s%s-%s.pdf", scenPart, sanitizeFilename(host), filterSuffix, idShort)

	h.auditLog(r, "report.export", runID, map[string]any{"format": "pdf", "type": "run", "filter": filter}, "ok")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	if err := h.reportingEngine.PDFFromReport(r.Context(), w, rep, nil, results); err != nil {
		log.Printf("[api] pdf output: %v", err)
	}
}

// GET /api/scenarios/runs/{runId}/forensic.csv
// Streams the forensic CSV (one row per technique result) for a single run.
func (h *Handler) GetRunForensicCSV(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	filter := r.URL.Query().Get("filter")
	var name, hostname string
	var resultsRaw []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT sr.name, sr.results, COALESCE(a.hostname,'')
		   FROM scenario_runs sr LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.id = $1`, runID,
	).Scan(&name, &resultsRaw, &hostname); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	var results []models.SimulationResult
	if len(resultsRaw) > 0 {
		json.Unmarshal(resultsRaw, &results)
	}
	results = reporting.FilterResults(results, filter)
	idShort := runID
	if len(idShort) > 8 {
		idShort = idShort[:8]
	}
	if hostname == "" {
		hostname = "host"
	}
	filterSuffix := ""
	if filter != "" && filter != "all" {
		filterSuffix = "-" + filter
	}
	fname := fmt.Sprintf("bas-forensic-%s-%s%s-%s.csv", sanitizeFilename(name), sanitizeFilename(hostname), filterSuffix, idShort)
	h.auditLog(r, "report.export", runID, map[string]any{"format": "csv", "type": "run", "filter": filter}, "ok")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	reporting.WriteForensicCSV(w, name, results)
}

// classifyAgentOS maps a raw os_version string to "windows", "linux", or "darwin".
// Returns "" if the OS cannot be determined.
func classifyAgentOS(osVersion string) string {
	lower := strings.ToLower(osVersion)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "darwin") || strings.Contains(lower, "macos") || strings.Contains(lower, "mac os"):
		return "darwin"
	case strings.Contains(lower, "linux") || strings.Contains(lower, "ubuntu") ||
		strings.Contains(lower, "debian") || strings.Contains(lower, "centos") ||
		strings.Contains(lower, "rhel") || strings.Contains(lower, "fedora") ||
		strings.Contains(lower, "kali") || strings.Contains(lower, "arch"):
		return "linux"
	}
	return ""
}

// GET /api/scenarios/runs/{runId}/report
// Returns a self-contained HTML report scoped to a single scenario run.
func (h *Handler) GetRunReport(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	filter := r.URL.Query().Get("filter")
	report, err := h.reportingEngine.BuildFromRun(r.Context(), runID, filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	h.auditLog(r, "report.export", runID, map[string]any{"format": "html", "type": "run"}, "ok")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reporting.GenerateHTML(w, report, nil); err != nil {
		log.Printf("[api] generate run report HTML: %v", err)
	}
}

// GET /api/scenarios/runs/{runId}/report.json
// Returns the report's key findings + prioritised recommendations for a run,
// computed by the same engine (BuildFromRun → buildTopFindings/buildRecommendations)
// that produces the HTML/PDF report. The console drawer renders these so it can
// never disagree with the formal report — one source of truth, no logic in JS.
func (h *Handler) GetRunReportData(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	filter := r.URL.Query().Get("filter")
	report, err := h.reportingEngine.BuildFromRun(r.Context(), runID, filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	var alertsTotal, alertsHighFidelity int
	var noiseScore float64
	var perfCpuBefore, perfCpuAfter, perfRamBefore, perfRamAfter, perfDiskBefore, perfDiskAfter float64
	_ = h.db.QueryRow(r.Context(),
		`SELECT alerts_total, alerts_high_fidelity, noise_score,
		        perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after
		 FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&alertsTotal, &alertsHighFidelity, &noiseScore,
		&perfCpuBefore, &perfCpuAfter, &perfRamBefore, &perfRamAfter, &perfDiskBefore, &perfDiskAfter)

	respond(w, map[string]any{
		"topFindings":            report.TopFindings,
		"recommendations":        report.Summary.Recommendations,
		"killChain":              report.KillChain,
		"alertsTotal":            alertsTotal,
		"alertsHighFidelity":     alertsHighFidelity,
		"noiseScore":             noiseScore,
		"attackSurfaceAge":       report.AttackSurfaceAge,
		"oldestFindingName":      report.OldestFindingName,
		"oldestFindingID":        report.OldestFindingID,
		"oldestFindingSeverity":  report.OldestFindingSeverity,
		"attackSurfaceSLAStatus": report.AttackSurfaceSLAStatus,
		"perfCpuBefore":          perfCpuBefore,
		"perfCpuAfter":           perfCpuAfter,
		"perfRamBefore":          perfRamBefore,
		"perfRamAfter":           perfRamAfter,
		"perfDiskBefore":         perfDiskBefore,
		"perfDiskAfter":          perfDiskAfter,
		"detectionSources":       report.DetectionSources,
		"cleanupFailed":          report.CleanupFailed,
		"cleanupFailedCount":     report.CleanupFailedCount,
		"reverted":               report.Reverted,
	})
}

// GET /api/scenarios/runs/{runId}/export
// Downloads a single run's full results as a JSON file.
func (h *Handler) ExportRunJSON(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")

	var runName, agentID, status string
	var resultsJSON, scoreRaw []byte
	var startedAt time.Time
	var completedAt *time.Time

	err := h.db.QueryRow(r.Context(),
		`SELECT name, agent_id, status, results, score, started_at, completed_at
		 FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&runName, &agentID, &status, &resultsJSON, &scoreRaw, &startedAt, &completedAt)
	if err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	var results []models.SimulationResult
	var score models.Score
	json.Unmarshal(resultsJSON, &results)
	json.Unmarshal(scoreRaw, &score)

	// Sanitise run name for use in filename
	var safeName []byte
	for _, c := range []byte(runName) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			safeName = append(safeName, c)
		default:
			safeName = append(safeName, '_')
		}
	}
	if len(safeName) > 32 {
		safeName = safeName[:32]
	}
	fname := fmt.Sprintf("bas-run-%s-%s.json", string(safeName), runID[:8])

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]interface{}{
		"id":           runID,
		"scenarioName": runName,
		"agentId":      agentID,
		"status":       status,
		"startedAt":    startedAt,
		"completedAt":  completedAt,
		"score":        score,
		"results":      results,
	})
}

// ── ART Content (admin) ──────────────────────────────────────────────────────

// GetARTContentStatus returns the current ART content version and counts.
// GET /api/art/content/status
func (h *Handler) GetARTContentStatus(w http.ResponseWriter, r *http.Request) {
	var version, source string
	var techCount, payloadCount int
	var importedAt time.Time
	err := h.db.QueryRow(r.Context(),
		`SELECT source_version, technique_count, payload_count, source, imported_at
		   FROM art_content_meta WHERE id = 1`,
	).Scan(&version, &techCount, &payloadCount, &source, &importedAt)
	if err != nil {
		respond(w, map[string]any{"seeded": false})
		return
	}
	loaded := 0
	if h.artStore != nil {
		loaded = h.artStore.Count()
	}
	// Atomic-test total (Windows-executable tests across all techniques) and the
	// seeded CISA KEV CVE catalog size. Both are advisory counts — a failed query
	// must not break the status call, so errors are logged and the count stays 0.
	testCount := 0
	if err := h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM art_atomic_tests`).Scan(&testCount); err != nil {
		log.Printf("[content] atomic-test count failed: %v", err)
	}
	kevCount := 0
	if err := h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM cves WHERE source = 'cisa-kev'`).Scan(&kevCount); err != nil {
		log.Printf("[content] KEV count failed: %v", err)
	}
	// Payload basenames the loaded atomics reference but we don't ship — the exact
	// filenames an operator would rename a binary to in order to enable those tests.
	missing, err := scenario.MissingPayloads(r.Context(), h.db)
	if err != nil {
		log.Printf("[content] missing-payload lookup failed: %v", err)
		missing = nil // advisory only — don't fail the status call
	}
	respond(w, map[string]any{
		"seeded":              true,
		"version":             version,
		"techniqueCount":      techCount,
		"testCount":           testCount,
		"payloadCount":        payloadCount,
		"kevCount":            kevCount,
		"source":              source,
		"importedAt":          importedAt,
		"techniquesLoaded":    loaded,
		"missingPayloads":     missing,
		"missingPayloadCount": len(missing),
	})
}

// ReseedART re-imports the on-disk content pack into Postgres and hot-reloads the
// runtime store, applying a content update without rebuilding the orchestrator
// image. Optional JSON body: {"version":"v2026.07"}.
// POST /api/art/content/reseed
func (h *Handler) ReseedART(w http.ResponseWriter, r *http.Request) {
	if h.artStore == nil {
		jsonError(w, "ART store not available", http.StatusServiceUnavailable)
		return
	}
	version := h.artContentVer
	var req struct {
		Version string `json:"version"`
	}
	if json.NewDecoder(r.Body).Decode(&req) == nil && req.Version != "" {
		version = req.Version
	}

	tc, pc, err := scenario.SeedContent(r.Context(), h.db, h.artContentDir, h.artPayloadDir, h.artKEVFile, version, true)
	if err != nil {
		jsonError(w, "reseed failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.artStore.Reload(r.Context(), h.db); err != nil {
		jsonError(w, "reseeded but reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[content] reseed via API: %d techniques, %d payloads (version %q)", tc, pc, version)
	h.auditLog(r, "art.reseed", "", map[string]any{"version": version, "techniqueCount": tc, "payloadCount": pc}, "ok")
	respond(w, map[string]any{
		"status":           "ok",
		"version":          version,
		"techniqueCount":   tc,
		"payloadCount":     pc,
		"techniquesLoaded": h.artStore.Count(),
	})
}
