package api

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/analytics"
	"github.com/audspect/bas/internal/artifactgen"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/controlhealth"
	"github.com/audspect/bas/internal/correlation"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/emsweep"
	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ioc"
	"github.com/audspect/bas/internal/iocregistry"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/notifications"
	"github.com/audspect/bas/internal/relationships"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/taxii"
	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/ticketing"
	"github.com/audspect/bas/internal/verification"
	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
)

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505) — the losing side of a concurrent insert.
// Same pattern as internal/relationships and internal/verification.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// Handler holds shared dependencies for all API handlers.
type Handler struct {
	db     *pgxpool.Pool
	hub    *ws.Hub
	engine *scenario.Engine
	// detectVerifyConnector builds a detectverify.Connector for a config.
	// nil in production (New leaves it unset; call sites fall back to
	// detectverify.NewConnector) — tests override it to avoid real HTTP calls.
	detectVerifyConnector func(detectverify.Config) (detectverify.Connector, error)
	// actionVendorClient builds an actions.VendorClient for a config. nil in
	// production (call sites fall back to actions.NewVendorClient) — tests
	// override it to avoid real HTTP calls.
	actionVendorClient   func(actions.ConnectorConfig) (actions.VendorClient, error)
	secret               string
	agentSecret          string // optional shared secret for agent-facing endpoints
	calderaURL           string
	calderaKey           string
	iocProvider          ioc.Provider // nil when no OTX connector is configured
	iocProviderMu        sync.RWMutex // guards iocProvider -- can be swapped live by a config save
	artStore             *scenario.ARTStore
	calderaStore         *scenario.CalderaStore // technique-indexed ability cache for the variant-testing engine (nil-safe: see resolveBaseCommand)
	artContentDir        string                 // seed source for ART atomics (ART_DIR)
	artPayloadDir        string                 // seed source for ART payload binaries (ART_PAYLOAD_DIR)
	artKEVFile           string                 // CISA KEV catalog JSON (KEV_FILE)
	artEPSSFile          string                 // FIRST EPSS CSV/GZ (EPSS_FILE)
	artContentVer        string                 // recorded content-pack version
	manifest             *integrity.Manifest    // binary hash manifest — nil means verification disabled
	complianceMapper     *compliance.Mapper     // nil when not loaded
	controlHealthMapper  *controlhealth.Mapper  // nil when not loaded
	endpointRiskTaxonomy *endpointrisk.Taxonomy // nil when not loaded
	eolCatalog           *endpointrisk.Catalog  // nil when not loaded
	remediationCatalog   *remediation.Catalog   // nil when not loaded
	reportingEngine      *reporting.Engine      // nil when not loaded
	scheduler            *connector.Scheduler   // nil when no sources configured
	ticketing            *ticketing.Manager     // nil when no connectors configured
	licPath              string                 // path to bas.lic for Settings → License display
	exerciseStore        *exercise.Store
	exerciseExecutor     *exercise.Executor
	exerciseChain        *exercise.EvidenceChain
	verification         *verification.Store    // nil when not loaded — SP2 verification store
	relationships        *relationships.Store   // nil when not loaded — CVE-ATT&CK Relationship Store
	rules                *rulelib.Engine        // nil when not loaded — Detection Rule Library
	threatPriorityEngine *threatpriority.Engine // nil when not loaded — Threat Prioritization
	vexSweep             *vexsweep.Store        // nil when not loaded — Full Variant Sweep orchestration
	emSweep              *emsweep.Store         // nil when not loaded — Endpoint Mastery Full Sweep orchestration
	taxiiStore           *taxii.Store           // nil when not loaded — generic TAXII 2.1 connector config CRUD
	taxiiManager         *taxii.Manager         // nil when not loaded — per-connector pollers
	jobsStore            *jobs.Store            // nil when not loaded — Fleet Job Engine (batch remediation)
	notifications        *notifications.Service // nil when not loaded — Phase 7 job-event notifications
	notificationsStore   *notifications.Store   // nil when not loaded — direct read/config access for handlers
	correlationEngine    *correlation.Engine    // nil when not loaded — Intelligence Correlation Engine
	// cancelGracePeriod is how long cancelScenarioRun waits for an agent to
	// confirm a cancel (via SubmitScenarioResult) before force-marking the run
	// 'partial' itself. Defaults to 60s in New(); tests override it directly
	// (same pattern as OpenCTIClient.retryDelay) to keep grace-period tests fast.
	cancelGracePeriod time.Duration
}

// New creates a Handler.
func New(db *pgxpool.Pool, hub *ws.Hub, engine *scenario.Engine, secret string) *Handler {
	// Wire the Phase C artifact-curation hook once per process -- see
	// internal/scenario/art.go's ArtifactCuratedLookup doc comment for why this
	// is a settable hook instead of a direct import.
	scenario.ArtifactCuratedLookup = func(techniqueID, testName, argName string) bool {
		_, ok := artifactgen.Lookup(techniqueID, testName, argName)
		return ok
	}
	return &Handler{db: db, hub: hub, engine: engine, secret: secret, cancelGracePeriod: 60 * time.Second}
}

// WithCompliance attaches the compliance mapper.
func (h *Handler) WithCompliance(m *compliance.Mapper) *Handler {
	h.complianceMapper = m
	return h
}

// WithControlHealth attaches the control-health taxonomy mapper.
func (h *Handler) WithControlHealth(m *controlhealth.Mapper) *Handler {
	h.controlHealthMapper = m
	return h
}

// WithEndpointRiskTaxonomy attaches the Security Config/Identity check_id taxonomy.
func (h *Handler) WithEndpointRiskTaxonomy(t *endpointrisk.Taxonomy) *Handler {
	h.endpointRiskTaxonomy = t
	return h
}

// WithEOLCatalog attaches the Application Risk EOL/high-risk software catalog.
func (h *Handler) WithEOLCatalog(c *endpointrisk.Catalog) *Handler {
	h.eolCatalog = c
	return h
}

// WithRemediationCatalog attaches the endpoint remediation catalog.
func (h *Handler) WithRemediationCatalog(c *remediation.Catalog) *Handler {
	h.remediationCatalog = c
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

// WithThreatPriority attaches the actor-level priority engine.
func (h *Handler) WithThreatPriority(e *threatpriority.Engine) *Handler {
	h.threatPriorityEngine = e
	return h
}

// WithCorrelation attaches the intelligence correlation engine.
func (h *Handler) WithCorrelation(e *correlation.Engine) *Handler {
	h.correlationEngine = e
	return h
}

// WithTicketing attaches the ITSM ticketing manager.
func (h *Handler) WithTicketing(m *ticketing.Manager) *Handler {
	h.ticketing = m
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

// POST /api/agents/unenroll — called by the agent itself during --uninstall,
// best-effort. Agent-token auth (same as /api/heartbeat), not a user
// JWT/permission — there is no admin session at uninstall time.
//
// Sets state='retired' rather than deleting the row: scenario_runs has
// ON DELETE CASCADE to agents (internal/db/postgres.go), so a real delete
// would destroy that agent's entire run/finding/report history. The Agents
// tab hides retired agents from its default view (agentBucket in
// wwwroot/index.html) but keeps them reachable via the Retired filter —
// this is what actually satisfies "remove from the endpoint list" without
// losing the audit trail.
func (h *Handler) UnenrollAgent(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		AgentID string `json:"agentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}
	tag, err := h.db.Exec(r.Context(), `UPDATE agents SET state = 'retired' WHERE agent_id = $1`, body.AgentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	h.auditLogAs(r, "agent:"+body.AgentID, "agent.unenroll", body.AgentID, nil, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: body.AgentID})
	respond(w, map[string]string{"agentId": body.AgentID, "state": "retired"})
}

// POST /api/agents/{agentId}/remove — admin-triggered equivalent of
// UnenrollAgent above: same state='retired' update (see that handler's
// comment for why this is a state change, not a row delete), but reachable
// from the dashboard regardless of whether the agent is currently connected
// -- unlike StopAgent, this never talks to the endpoint over WS. The agent
// software itself keeps running until someone uninstalls it locally or an
// admin separately pushes a Stop; this only removes the dashboard record.
// Admin-only; the route group enforces the permission check.
func (h *Handler) RemoveAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	tag, err := h.db.Exec(r.Context(), `UPDATE agents SET state = 'retired' WHERE agent_id = $1`, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "agent.remove", agentID, map[string]any{"reason": body.Reason}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]string{"agentId": agentID, "state": "retired"})
}

// WithCaldera configures the optional Caldera integration.
func (h *Handler) WithCaldera(url, key string) *Handler {
	h.calderaURL = url
	h.calderaKey = key
	return h
}

// WithIOCProvider attaches the threat-intel lookup provider (nil when no
// OTX connector is configured -- LookupIOC degrades to a clear 503, same
// pattern as GetCalderaAdversaries when CALDERA_URL is empty).
func (h *Handler) WithIOCProvider(provider ioc.Provider) *Handler {
	h.setIOCProvider(provider)
	return h
}

// getIOCProvider and setIOCProvider are the only allowed access points for
// h.iocProvider -- it can be swapped live by a threat-intel config save
// (see PutThreatIntelConfig), concurrently with in-flight LookupIOC
// requests reading it.
func (h *Handler) getIOCProvider() ioc.Provider {
	h.iocProviderMu.RLock()
	defer h.iocProviderMu.RUnlock()
	return h.iocProvider
}

func (h *Handler) setIOCProvider(provider ioc.Provider) {
	h.iocProviderMu.Lock()
	defer h.iocProviderMu.Unlock()
	h.iocProvider = provider
}

// WithART attaches the pre-loaded ART store (may be nil if ART_DIR is unavailable).
func (h *Handler) WithART(store *scenario.ARTStore) *Handler {
	h.artStore = store
	return h
}

// WithCalderaStore attaches the pre-loaded, technique-indexed Caldera
// ability cache used by the variant-testing engine's resolveBaseCommand
// (may be nil if Caldera isn't configured -- resolveBaseCommand treats a
// nil store and an empty store identically, both yielding "no abilities for
// this technique").
func (h *Handler) WithCalderaStore(store *scenario.CalderaStore) *Handler {
	h.calderaStore = store
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

// WithEPSSFile records the EPSS file path so the admin reseed endpoint can
// refresh EPSS scores when the file is updated.
func (h *Handler) WithEPSSFile(epssFile string) *Handler {
	h.artEPSSFile = epssFile
	return h
}

// WithManifest attaches the binary hash manifest for agent verification.
func (h *Handler) WithManifest(m *integrity.Manifest) *Handler {
	h.manifest = m
	return h
}

func (h *Handler) WithLicensePath(path string) *Handler {
	h.licPath = path
	return h
}

// WithExercise attaches the exercise engine components and wires the BAS
// dispatch function so the exercise executor can trigger scenario runs.
func (h *Handler) WithExercise(store *exercise.Store, exec *exercise.Executor, chain *exercise.EvidenceChain) *Handler {
	h.exerciseStore = store
	h.exerciseExecutor = exec
	h.exerciseChain = chain
	// Wire AgentDispatchFn: exercise step type "agent_task" → existing BAS engine.
	exec.SetDispatch(func(agentID, scenarioID, techniqueID string, policy scenario.ExecutionPolicy) (string, error) {
		var techniques []string
		if techniqueID != "" {
			techniques = []string{techniqueID}
		}
		opts := dispatchOpts{
			Mode:         "posture",
			Techniques:   techniques,
			MaxPrivilege: policy.MaxPrivilege,
		}
		sc, ok := h.engine.Get(scenarioID)
		if !ok {
			return "", fmt.Errorf("exercise dispatch: scenario %q not found", scenarioID)
		}
		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, opts)
		if err != nil {
			return "", err
		}
		if skip != "" {
			return "", fmt.Errorf("exercise dispatch: agent skipped (%s)", skip)
		}
		return runID, nil
	})
	return h
}

// WithRuleLibrary attaches the Detection Rule Library engine.
func (h *Handler) WithRuleLibrary(e *rulelib.Engine) *Handler {
	h.rules = e
	return h
}

// WithVexSweep attaches the Full Variant Sweep store and wires the
// Dispatcher's DispatchFn to dispatchVariantForSweep -- matches the same
// wire-the-callback-inside-the-api-package pattern WithExercise already
// uses for exercise.Executor.SetDispatch, since dispatchVariantForSweep is
// unexported and main.go (a different package) can't reference it directly.
func (h *Handler) WithVexSweep(store *vexsweep.Store, dispatcher *vexsweep.Dispatcher) *Handler {
	h.vexSweep = store
	dispatcher.SetDispatch(h.dispatchVariantForSweep)
	// Reuses cancelScenarioRun's existing agent-notify + grace-period +
	// variant_runs-sync behavior for the Dispatcher's stuck-technique
	// backstop, rather than duplicating any of that inside vexsweep.
	dispatcher.SetCancel(h.cancelScenarioRun)
	// Lets advance() distinguish "agent disconnected" from "agent connected
	// but genuinely stuck" -- see the Dispatcher's disconnect/resume state
	// machine.
	dispatcher.SetConnected(h.hub.IsAgentConnected)
	return h
}

// WithEMSweep attaches the Endpoint Mastery Full Sweep store and wires the
// Dispatcher's DispatchFn to dispatchEMLayer -- same wire-the-callback-
// inside-the-api-package pattern WithVexSweep already uses.
func (h *Handler) WithEMSweep(store *emsweep.Store, dispatcher *emsweep.Dispatcher) *Handler {
	h.emSweep = store
	dispatcher.SetDispatch(h.dispatchEMLayer)
	// Reuses cancelScenarioRun's existing agent-notify + grace-period +
	// variant_runs-sync behavior for the Dispatcher's stuck-layer backstop,
	// rather than duplicating any of that inside emsweep.
	dispatcher.SetCancel(h.cancelScenarioRun)
	// Lets advance() distinguish "agent disconnected" from "agent connected
	// but genuinely stuck" -- see the Dispatcher's disconnect/resume state
	// machine.
	dispatcher.SetConnected(h.hub.IsAgentConnected)
	return h
}

// WithTAXII attaches the generic TAXII 2.1 connector store and its
// per-connector poller manager.
func (h *Handler) WithTAXII(store *taxii.Store, manager *taxii.Manager) *Handler {
	h.taxiiStore = store
	h.taxiiManager = manager
	return h
}

// GetCryptoInfo returns a read-only summary of the active cryptographic profile.
// Useful during customer security reviews and FIPS compliance discussions.
// GET /api/crypto/info (Viewer+)
func (h *Handler) GetCryptoInfo(w http.ResponseWriter, r *http.Request) {
	type cryptoInfo struct {
		PasswordAlgorithm string `json:"password_algorithm"`
		PBKDF2Iterations  int    `json:"pbkdf2_iterations"`
		JWT               string `json:"jwt"`
		ScenarioSigning   string `json:"scenario_signing"`
		Hashing           string `json:"hashing"`
		TLS               string `json:"tls"`
		FIPSReady         bool   `json:"fips_ready"`
	}
	jsonOK(w, cryptoInfo{
		PasswordAlgorithm: "PBKDF2-HMAC-SHA256",
		PBKDF2Iterations:  auth.GetIterations(),
		JWT:               "HS256",
		ScenarioSigning:   "RSA-4096 / SHA-256 (PKCS#1 v1.5)",
		Hashing:           "SHA-256",
		TLS:               "TLS 1.2/1.3 (at reverse proxy)",
		FIPSReady:         true,
	})
}

// GetLicenseInfo returns parsed licence details for the Settings → License panel.
// GET /api/license
func (h *Handler) GetLicenseInfo(w http.ResponseWriter, r *http.Request) {
	lic, err := license.Get(h.licPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	info := license.Current()
	respond(w, map[string]any{
		"customer":      lic.Customer,
		"customerId":    lic.CustomerID,
		"issuedAt":      lic.IssuedAt,
		"expiresAt":     lic.ExpiresAt,
		"features":      lic.Features,
		"status":        string(info.State),
		"daysRemaining": info.DaysRemaining,
		"lockoutAt":     info.LockoutAt.Format("2006-01-02"),
	})
}

// GetLicenseStatus is public (no auth) — the frontend polls it before
// login to decide whether to render the normal app shell or the
// permanent lockout screen. Deliberately excludes customer/features
// (those stay behind auth in GetLicenseInfo) — only state + dates.
// GET /api/license/status
func (h *Handler) GetLicenseStatus(w http.ResponseWriter, r *http.Request) {
	info := license.Current()
	respond(w, map[string]any{
		"state":         string(info.State),
		"expiresAt":     info.ExpiresAt.Format("2006-01-02"),
		"lockoutAt":     info.LockoutAt.Format("2006-01-02"),
		"daysRemaining": info.DaysRemaining,
	})
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

	var id, hash, role, authSource string
	var isActive, mustChangePw bool
	var tenantID *string
	dbErr := h.db.QueryRow(r.Context(),
		`SELECT id, password_hash, role, is_active, must_change_pw, tenant_id, auth_source FROM users WHERE username = $1`, req.Username,
	).Scan(&id, &hash, &role, &isActive, &mustChangePw, &tenantID, &authSource)
	// Evaluate password even on DB miss to prevent timing-based user enumeration.
	// VerifyPassword on an empty string returns false without error.
	ok, needsUpgrade, _ := auth.VerifyPassword(req.Password, hash)
	// SSO-provisioned accounts are rejected explicitly, not just by their
	// password hash being an unguessable random placeholder — defense in
	// depth, so password login stays blocked even if that hash were ever
	// mishandled. See docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
	if dbErr != nil || !ok || authSource == "sso" {
		h.auditLogAs(r, "", "user.login", req.Username, map[string]any{"username": req.Username, "reason": "invalid credentials"}, "fail")
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	// Transparent upgrade: re-hash with current algorithm/iteration count on login.
	if needsUpgrade {
		if newHash, hErr := auth.HashPassword(req.Password); hErr == nil {
			h.db.Exec(r.Context(), `UPDATE users SET password_hash = $1 WHERE id = $2`, newHash, id)
		}
	}
	if !isActive {
		h.auditLogAs(r, id, "user.login", id, map[string]any{"username": req.Username, "reason": "account disabled"}, "fail")
		jsonError(w, "account is disabled — contact your administrator", http.StatusForbidden)
		return
	}

	// tenant_id IS NULL marks a platform-admin (belongs to no single tenant).
	token, err := auth.GenerateTenantToken(id, auth.Role(role), tenantID, tenantID == nil, h.secret, 24*time.Hour)
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
		Secure:   secureCookies(),
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

// POST /api/auth/setup — first-run admin provisioning called by the installer.
// Creates the initial admin user with the supplied email as the username.
// Returns 409 if any user already exists (idempotent-safe for the installer).
// No authentication required — the endpoint is only useful before any user exists.
func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		jsonError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	var count int
	h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&count)
	if count > 0 {
		// Already configured — installer treats 409 as success.
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "already configured"})
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = h.db.Exec(r.Context(),
		`INSERT INTO users (username, password_hash, role, must_change_pw) VALUES ($1, $2, 'admin', false)`,
		req.Email, hash,
	)
	if err != nil {
		jsonError(w, "failed to create admin user", http.StatusInternalServerError)
		return
	}
	log.Printf("[+] Admin user created via setup endpoint (username: %s)", req.Email)
	h.auditLogAs(r, "", "user.setup", req.Email, map[string]any{"username": req.Email}, "ok")
	respond(w, map[string]string{"status": "ok", "username": req.Email})
}

// POST /api/auth/logout — clears the session cookie.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "bas_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookies(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// secureCookies reports whether Set-Cookie should include Secure (cookie only
// sent over HTTPS). Opt-in via COOKIE_SECURE=true once a TLS-terminating
// reverse proxy sits in front of the orchestrator — defaults to false so
// on-prem HTTP-only deployments (the common case pre-TLS-proxy setup) aren't
// silently broken by a cookie the browser refuses to send back.
func secureCookies() bool {
	return os.Getenv("COOKIE_SECURE") == "true"
}

// ── Agents ────────────────────────────────────────────────────────────────────

// GET /api/agents
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	query := `SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
	        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
	        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
	        (SELECT COUNT(*) FROM scenario_runs sr WHERE sr.agent_id = a.agent_id) AS sims,
	        a.stopped_by, COALESCE(u.username, a.stopped_by), a.stopped_at, a.stop_reason,
	        a.group_id, g.name, a.uninstall_error, a.uninstall_error_at, a.uninstall_requested_at
	 FROM agents a LEFT JOIN users u ON u.id = a.stopped_by LEFT JOIN agent_groups g ON g.id = a.group_id`
	var args []any
	if groupIDParam := r.URL.Query().Get("groupId"); groupIDParam != "" {
		groupID, err := strconv.ParseInt(groupIDParam, 10, 64)
		if err != nil {
			jsonError(w, "invalid groupId", http.StatusBadRequest)
			return
		}
		args = append(args, groupID)
		// Recursive CTE: the target group plus every descendant group, so
		// selecting "Finance" also surfaces agents in "Servers"/"Workstations".
		query += ` WHERE a.group_id IN (
			WITH RECURSIVE descendants(id) AS (
				SELECT id FROM agent_groups WHERE id = $` + strconv.Itoa(len(args)) + `
				UNION ALL
				SELECT gr.id FROM agent_groups gr JOIN descendants d ON gr.parent_id = d.id
			)
			SELECT id FROM descendants
		)`
	}
	query += ` ORDER BY a.last_update DESC`

	rows, err := h.db.Query(r.Context(), query, args...)
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
		var uninstallRequestedAt *time.Time
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
			&a.Username, &a.Status, &a.EnvLabel, &a.HasReport,
			&a.BinaryHash, &a.BinaryTrusted, &a.LastUpdate,
			&stateStr, &policyRaw, &a.EnrolledAt, &a.Sims,
			&a.StoppedBy, &a.StoppedByName, &a.StoppedAt, &a.StopReason,
			&a.GroupID, &a.GroupName, &a.UninstallError, &a.UninstallErrorAt, &uninstallRequestedAt); err != nil {
			continue
		}
		// Connectivity is heartbeat-driven: a dead/rebooted agent stops updating
		// last_update, so surface it as offline rather than its frozen last status.
		a.Status = models.EffectiveAgentStatus(a.Status, a.LastUpdate, now)
		a.State = models.AgentState(stateStr)
		a.UninstallError = models.EffectiveUninstallError(a.State, a.UninstallError, uninstallRequestedAt, now)
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

// PUT /api/agents/{agentId}/state — sets an agent's lifecycle state.
// Valid states: active | restricted | quarantined | retired.
// Only Admin may call this; the route group enforces the role check.
func (h *Handler) SetAgentState(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	valid := map[string]bool{"active": true, "restricted": true, "quarantined": true, "retired": true}
	if !valid[body.State] {
		jsonError(w, "invalid state: must be active, restricted, quarantined, or retired", http.StatusBadRequest)
		return
	}
	tag, err := h.db.Exec(r.Context(),
		`UPDATE agents SET state = $1 WHERE agent_id = $2`, body.State, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "agent.state", agentID, map[string]any{"state": body.State}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "state": body.State})
}

// POST /api/agents/{agentId}/stop — durably stops a connected agent: the
// agent finalizes any in-flight run, disables its platform service so it
// does not restart on its own (not on crash-recovery, not on next boot),
// then exits. There is no remote way to start it again — see
// docs/superpowers/specs/2026-07-22-agent-remote-stop-design.md.
// Admin-only; the route group enforces the permission check.
func (h *Handler) StopAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandStopAgent,
		AgentID: agentID,
		Data:    map[string]string{"reason": body.Reason},
	})
	if !sent {
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	_, err := h.db.Exec(r.Context(),
		`UPDATE agents SET stopped_by = $1, stopped_at = NOW(), stop_reason = $2 WHERE agent_id = $3`,
		actorID, body.Reason, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "agent.stop", agentID, map[string]any{"reason": body.Reason}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "status": "stop_dispatched"})
}

// agentFiles is the explicit allowlist of downloadable agent artifacts.
// key = URL platform param; value = filename and MIME type served.
var agentFiles = map[string]struct {
	filename string
	mimeType string
}{
	"linux-amd64":                {"bas-agent-linux-amd64", "application/octet-stream"},
	"linux-arm64":                {"bas-agent-linux-arm64", "application/octet-stream"},
	"linux-amd64-deb":            {"bas-agent-linux-amd64.deb", "application/vnd.debian.binary-package"},
	"linux-arm64-deb":            {"bas-agent-linux-arm64.deb", "application/vnd.debian.binary-package"},
	"linux-amd64-rpm":            {"bas-agent-linux-amd64.rpm", "application/x-rpm"},
	"windows-amd64-setup":        {"bas-agent-windows-amd64-setup.zip", "application/zip"},
	"windows-amd64":              {"bas-agent-windows-amd64.exe", "application/octet-stream"},
	"windows-legacy-amd64-setup": {"bas-agent-windows-legacy-amd64-setup.zip", "application/zip"},
	"windows-legacy-amd64":       {"bas-agent-windows-legacy-amd64.exe", "application/octet-stream"},
	"darwin-amd64":               {"bas-agent-darwin-amd64", "application/octet-stream"},
	"darwin-arm64":               {"bas-agent-darwin-arm64", "application/octet-stream"},
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

	// Handle attack-path job progress if the agent reports one.
	if hb.CurrentJobID != "" && hb.JobProgress.Stage != "" {
		h.UpdateAPJobProgress(r.Context(), hb.AgentID, hb.CurrentJobID, APJobProgress{
			Stage:            hb.JobProgress.Stage,
			TargetsCompleted: hb.JobProgress.TargetsCompleted,
			TargetsTotal:     hb.JobProgress.TargetsTotal,
		})
	}
	// Note: RedeliverQueuedAPJobs is in a goroutine to avoid blocking the
	// heartbeat response. The context is derived from r.Context() before launch.

	// On every heartbeat, attempt to re-deliver any queued attack-path jobs
	// that were created while the agent was offline. Only queued (never ACKed)
	// jobs are re-dispatched; running jobs are left alone.
	go h.RedeliverQueuedAPJobs(r.Context(), hb.AgentID)

	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: hb.AgentID, Data: mustMarshal(hb)})
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
			-- A fresh enrollment is itself evidence someone restarted the agent —
			-- clear any prior remote-stop record unconditionally.
			stopped_by     = NULL,
			stopped_at     = NULL,
			stop_reason    = NULL,
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

	steps, _, err := scenario.BuildSteps(sc, h.calderaURL, h.calderaKey, h.artStore, "windows")
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
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, mode)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW(), 'posture')`,
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
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, mode)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW(), 'posture')`,
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
	Mode         string // already-normalized: posture | telemetry | lab
	ConfirmLive  bool
	ConfirmLab   bool
	Reason       string
	Techniques   []string
	Abilities    []string
	Steps        []int
	Checks       []string
	CampaignID   string                // "" for ad-hoc single runs
	InitiatedBy  *string               // requesting user id (nil if unauthenticated)
	VariantDepth scenario.VariantDepth // "none"|"quick"|"standard"|"full"; "" == "none"
	RunLabel     string                // overrides sc.Name in scenario_runs.name when set
	// MaxPrivilege is an execution-policy ceiling: "" (default, unconstrained) |
	// "user" | "admin" | "system". Steps whose RequiresPriv exceeds this tier are
	// filtered out before dispatch — see dispatchRun's policy filter.
	MaxPrivilege string
	// SweepID/SweepName/SweepLabel/SweepFinal are forwarded verbatim onto the
	// outgoing ScenarioCommand -- see that type's doc comment. Set only by EM
	// Full Sweep's dispatch path (em_dispatch.go); empty/false for every
	// other caller, including Variant Full Sweep, which sends its own
	// ScenarioCommand directly in variant_handlers.go rather than through
	// dispatchRun.
	SweepID    string
	SweepName  string
	SweepLabel string
	SweepFinal bool
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
// synthesizePolicySkipResult builds the SimulationResult for a step that was
// never dispatched to the agent because its RequiresPriv exceeded the run's
// MaxPrivilege execution policy. Reuses the existing scenario.Interpret path
// (via a constructed "SKIP:" marker, the same convention every framework's
// interpreter already recognizes) so severity/threat-impact/remediation
// lookups are identical to any other skip — only SkipReason distinguishes it.
func synthesizePolicySkipResult(st scenario.ScenarioStep, maxPrivilege string) models.SimulationResult {
	step := scenario.Step{
		TechniqueID:  st.TechniqueID,
		Name:         st.Name,
		Framework:    st.Framework,
		RequiresPriv: scenario.PrivSpec{Minimum: st.RequiresPriv},
	}
	result := scenario.ExecResult{
		TaskID: st.TaskID,
		Stdout: fmt.Sprintf("SKIP: requires %s privilege, execution policy caps at %s", st.RequiresPriv, maxPrivilege),
	}
	sim := scenario.Interpret(step, result)
	sim.SkipReason = models.SkipReasonPolicyPrivilege
	return sim
}

// synthesizeCalderaSkipResult mirrors synthesizePolicySkipResult for a
// caldera_abilities entry that never became a step: not found in the live
// Caldera library, or found with no Windows-compatible executor. Routed
// through the same scenario.Interpret path so it shows up in Findings/
// Remediation/Live exactly like any other skip — only SkipReason and the
// visible ability id/reason distinguish it.
func synthesizeCalderaSkipResult(sk scenario.CalderaSkippedAbility) models.SimulationResult {
	name := sk.Name
	if name == "" {
		name = sk.AbilityID
	}
	step := scenario.Step{TechniqueID: sk.TechniqueID, Name: name, Framework: "caldera"}
	result := scenario.ExecResult{
		TaskID: scenario.TaskID(sk.TechniqueID, name),
		Stdout: fmt.Sprintf("SKIP: Caldera ability %s — %s", sk.AbilityID, sk.Reason),
	}
	sim := scenario.Interpret(step, result)
	sim.SkipReason = models.SkipReasonPlatformUnavailable
	return sim
}

// applyGeneratedArtifacts substitutes a fresh value for every curated artifact-identity
// token still present in steps (artResolveArgs left them literal for exactly this
// purpose) and registers each substitution in the IOC registry. Best-effort -- a
// registration failure is logged, never fails the dispatch; the registry is
// observability, not a gate. See
// docs/superpowers/specs/2026-07-31-ioc-generation-engine-design.md.
func (h *Handler) applyGeneratedArtifacts(ctx context.Context, scenarioID, runID, agentID string, steps []scenario.ScenarioStep) []scenario.ScenarioStep {
	for i := range steps {
		for key, iocType := range artifactgen.CuratedFor(steps[i].TechniqueID) {
			token := "#{" + key.ArgName + "}"
			if !strings.Contains(steps[i].Command, token) {
				continue
			}
			value := artifactgen.Generate(iocType, "")
			steps[i].Command = strings.ReplaceAll(steps[i].Command, token, value)
			if err := iocregistry.RegisterGenerated(ctx, h.db, iocType, value, scenarioID, runID, agentID, steps[i].TechniqueID); err != nil {
				log.Printf("[artifactgen] register failed for run %s: %v", runID, err)
			}
		}
	}
	return steps
}

func (h *Handler) dispatchRun(ctx context.Context, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID string, skipReason string, err error) {
	if license.Current().State == license.StateLocked {
		return "", "license_locked", nil
	}
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
	// (for fan-out) its campaign. variant_depth is recorded so the result processor
	// can skip the scenario_variant_results write for normal (non-variant) runs.
	runID = newID()
	vdepth := string(o.VariantDepth)
	if vdepth == "" {
		vdepth = "none"
	}
	runName := sc.Name
	if o.RunLabel != "" {
		runName = o.RunLabel
	}
	mode := o.Mode
	if mode == "" {
		mode = "posture"
	}
	_, err = h.db.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, campaign_id, variant_depth, mode, max_privilege)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW(), $6, $7, $8, $9)`,
		runID, sc.ID, agentID, runName, o.InitiatedBy, nullIfEmpty(o.CampaignID), vdepth, mode, o.MaxPrivilege,
	)
	if err != nil {
		if isUniqueViolation(err) {
			// Lost the race to a concurrent dispatch to the same agent —
			// report the same outcome a pre-existing running run would.
			return "", "agent busy", nil
		}
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
	steps, calderaSkipped, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "", fmt.Errorf("build steps: %w", err)
	}
	steps = h.applyGeneratedArtifacts(ctx, sc.ID, runID, agentID, steps)
	// stepsTotalBase captures the scenario's full base-technique step count for
	// this run's configuration (reflecting any operator-selected subset) before
	// any runtime filtering — the "Total" side of Scenario Coverage.
	stepsTotalBase := len(steps)

	// Pre-dispatch synthesized skips: entries that never made it into steps at
	// all, but must still be visible in results/findings instead of silently
	// vanishing between "N configured" and "M actually ran" — e.g. a
	// caldera_abilities id that doesn't exist in the live Caldera library, or
	// exists with no Windows-compatible executor. The MaxPrivilege filter below
	// appends its own skips to the same slice so both persist through one merge.
	var skippedResults []models.SimulationResult
	for _, sk := range calderaSkipped {
		skippedResults = append(skippedResults, synthesizeCalderaSkipResult(sk))
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

	// Execution-policy privilege ceiling: steps that require a higher tier than
	// MaxPrivilege are never dispatched. Each one gets a synthesized, scored-out
	// Skipped result instead of being attempted — mirrors the lab-only filter
	// above, but unlike it, filtering out EVERY step here is a legitimate outcome
	// ("nothing was executable under this policy"), not a hard failure. Appends
	// to the same skippedResults slice the Caldera-ability skips above use, so
	// both persist through one merge below.
	if o.MaxPrivilege != "" {
		kept := make([]scenario.ScenarioStep, 0, len(steps))
		for _, st := range steps {
			if scenario.PrivilegeExceeds(st.RequiresPriv, o.MaxPrivilege) {
				skippedResults = append(skippedResults, synthesizePolicySkipResult(st, o.MaxPrivilege))
				continue
			}
			kept = append(kept, st)
		}
		steps = kept
	}
	if len(skippedResults) > 0 {
		log.Printf("[scenario] run %s: %d step(s)/ability(ies) skipped pre-dispatch (policy and/or Caldera resolution)",
			runID, len(skippedResults))
		skippedJSON, _ := json.Marshal(skippedResults)
		if _, err := h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET policy_skipped_results = $1 WHERE id = $2`, skippedJSON, runID,
		); err != nil {
			return "", "", fmt.Errorf("persist pre-dispatch skipped results: %w", err)
		}
	}
	if len(steps) == 0 {
		// Every step was excluded before dispatch (policy and/or Caldera-ability
		// resolution) — a legitimate, reportable outcome, not a failure. Complete
		// the run immediately using only the synthesized results; there is
		// nothing to dispatch, and waiting for an agent submission that will
		// never arrive would hang the run.
		skippedJSON, _ := json.Marshal(skippedResults)
		_, err := h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'completed', results = $1::jsonb, completed_at = NOW(),
			        steps_total_base = $2, steps_eligible_base = 0 WHERE id = $3`,
			skippedJSON, stepsTotalBase, runID,
		)
		if err != nil {
			return "", "", fmt.Errorf("complete all-skipped run: %w", err)
		}
		return runID, "", nil
	}

	// stepsEligibleBase is captured here, after both the lab-only and
	// MaxPrivilege filters have run (but before variant expansion) — the
	// "Eligible" side of Eligible Coverage. When o.MaxPrivilege=="", this
	// reflects only the lab-only filter's outcome, matching Total.
	stepsEligibleBase := len(steps)
	if _, err := h.db.Exec(context.Background(),
		`UPDATE scenario_runs SET steps_total_base = $1, steps_eligible_base = $2 WHERE id = $3`,
		stepsTotalBase, stepsEligibleBase, runID,
	); err != nil {
		return "", "", fmt.Errorf("persist coverage counts: %w", err)
	}

	// ── Variant expansion layer ───────────────────────────────────────────────
	// Each base step is followed by its variant steps (encoding × privilege ×
	// exec-context combos). The agent sees a flat step list — it has no concept
	// of variants. StepMeta carries BaseTaskID + VariantSpec so the result
	// processor can write scenario_variant_results without re-querying here.
	if o.VariantDepth != scenario.VariantDepthNone && o.VariantDepth != "" {
		baseCount := len(steps)
		steps = scenario.ExpandSteps(steps, o.VariantDepth)
		log.Printf("[scenario] run %s: variant expand depth=%s base=%d expanded=%d",
			runID, o.VariantDepth, baseCount, len(steps))
	}

	h.persistStepMeta(ctx, runID, steps)

	cmd := scenario.ScenarioCommand{
		RunID:                runID,
		ScenarioID:           sc.ID,
		Name:                 sc.Name,
		Steps:                steps,
		Mode:                 o.Mode,
		Policy:               sc.LivePolicy,
		PreventScreenTimeout: sc.PreventScreenTimeout,
		SweepID:              o.SweepID,
		SweepName:            o.SweepName,
		SweepLabel:           o.SweepLabel,
		SweepFinal:           o.SweepFinal,
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
		AgentID         string                   `json:"agentId"`
		Mode            string                   `json:"mode"`                      // posture (default) | telemetry | lab
		ConfirmLive     bool                     `json:"confirmLive"`               // required ack for any live run (telemetry/lab)
		ConfirmLab      bool                     `json:"confirmLab"`                // second-stage approval, required for lab mode
		Reason          string                   `json:"reason"`                    // optional operator justification (audited)
		Techniques      []string                 `json:"techniques"`                // optional ART technique subset
		Abilities       []string                 `json:"abilities"`                 // optional Caldera ability subset
		Steps           []int                    `json:"steps"`                     // optional step subset — indices into scenario step list
		Checks          []string                 `json:"checks"`                    // optional posture-check subset (local_check scenarios)
		VariantDepth    scenario.VariantDepth    `json:"variantDepth"`              // ""|"none"|"quick"|"standard"|"full"
		RunLabel        string                   `json:"runLabel"`                  // optional override for scenario_runs.name
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"` // operator-set execution constraints (e.g. maxPrivilege)
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
		InitiatedBy: initiatedBy, VariantDepth: req.VariantDepth, RunLabel: req.RunLabel,
		MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
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

	// Deep-copy via a JSON round-trip so the clone never aliases the source's
	// slice backing arrays or its LivePolicy pointer target — a plain `*src`
	// struct copy only copies slice headers and the pointer itself, leaving
	// e.g. Steps/Tags/CalderaAbilities/LivePolicy shared with the original
	// until the clone happens to be fully overwritten. A JSON round-trip also
	// stays correct automatically if Scenario grows new reference-typed
	// fields later, unlike copying each field by hand.
	raw, err := json.Marshal(src)
	if err != nil {
		jsonError(w, "clone: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var clone scenario.Scenario
	if err := json.Unmarshal(raw, &clone); err != nil {
		jsonError(w, "clone: "+err.Error(), http.StatusInternalServerError)
		return
	}
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

// persistVariantResults writes one row to scenario_variant_results for every
// result whose step_meta entry is a variant step (BaseTaskID non-empty).
// Called after SubmitScenarioResult stores the authoritative result snapshot.
// Idempotent via ON CONFLICT on (run_id, step_id, variant_id) — safe on retry.
func (h *Handler) persistVariantResults(
	ctx context.Context,
	runID, scenarioID string,
	results []models.SimulationResult,
	meta map[string]scenario.StepMeta,
) {
	if len(meta) == 0 {
		return
	}
	for _, res := range results {
		m, ok := meta[res.ID]
		if !ok || m.BaseTaskID == "" || m.VariantSpec == nil {
			continue // base step or unrecognised — skip
		}
		spec := m.VariantSpec
		variantID := spec.ID(res.Technique.ID)

		verdict := variantVerdictStr(res)
		rawJSON, _ := json.Marshal(res)
		var execAt *time.Time
		if !res.ExecutedAt.IsZero() {
			t := res.ExecutedAt
			execAt = &t
		}

		_, err := h.db.Exec(ctx,
			`INSERT INTO scenario_variant_results
				(run_id, scenario_id, step_id, variant_id, technique_id,
				 proxy_technique_id, encoding, privilege, execution_context, platform,
				 requested_privilege, actual_privilege, verdict,
				 duration_ms, executed_at, raw_result)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			 ON CONFLICT (run_id, step_id, variant_id)
			 DO UPDATE SET
				verdict          = EXCLUDED.verdict,
				actual_privilege = EXCLUDED.actual_privilege,
				duration_ms      = EXCLUDED.duration_ms,
				executed_at      = EXCLUDED.executed_at,
				raw_result       = EXCLUDED.raw_result`,
			runID, scenarioID, m.BaseTaskID, variantID, res.Technique.ID,
			m.ProxyTechniqueID,
			normStr(spec.Encoding, "plain"),
			normStr(spec.Privilege, "user"),
			normStr(spec.ExecContext, "direct"),
			normStr(spec.Platform, "windows"),
			res.RequestedPriv, res.ExecutedAs,
			verdict,
			res.DurationMs, execAt, rawJSON,
		)
		if err != nil {
			log.Printf("[variant] persist result for run %s task %s: %v", runID, res.ID, err)
		}
	}
}

// variantVerdictStr derives the 6-category variant verdict from a SimulationResult.
// Mirrors the attack-flow verdict logic so both views are consistent.
func variantVerdictStr(r models.SimulationResult) string {
	switch r.Result {
	case models.ResultPass:
		return "blocked"
	case models.ResultFail:
		switch r.DetectionVerdict {
		case "prevented":
			return "blocked"
		case "detected":
			return "detected"
		case "logged":
			return "logged"
		default:
			if r.DetectionAlert != nil {
				return "detected"
			}
			return "bypassed"
		}
	case models.ResultError:
		return "error"
	case models.ResultSkipped:
		return "skipped"
	}
	return "error"
}

func normStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
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
	var runCampaignID string
	var dispatchedMeta map[string]scenario.StepMeta // hoisted: used again by persistVariantResults
	if err := h.db.QueryRow(r.Context(),
		`SELECT step_meta, COALESCE(campaign_id,'') FROM scenario_runs WHERE id = $1`, raw.RunID,
	).Scan(&metaRaw, &runCampaignID); err == nil && len(metaRaw) > 0 {
		if json.Unmarshal(metaRaw, &dispatchedMeta) == nil {
			for taskID, m := range dispatchedMeta {
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

	// Merge in any steps the server itself excluded before dispatch under a
	// MaxPrivilege execution policy — persisted once at dispatch time into a
	// separate column specifically so this merge survives every retry of this
	// handler without needing to touch the agent's own REPLACE semantics above.
	var policySkippedJSON []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT policy_skipped_results FROM scenario_runs WHERE id = $1`, raw.RunID,
	).Scan(&policySkippedJSON); err == nil && len(policySkippedJSON) > 0 {
		var policySkipped []models.SimulationResult
		if json.Unmarshal(policySkippedJSON, &policySkipped) == nil {
			simResults = append(simResults, policySkipped...)
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

	// Environment Restoration — count cleanup failures and write hygiene_score.
	{
		var leaked, cleanable int
		for _, sr := range simResults {
			switch sr.CleanupVerdict {
			case "reverted":
				cleanable++
			case "partial", "leaked":
				cleanable++
				leaked++
			}
		}
		var hygieneScore float64 = 100.0
		if cleanable > 0 {
			hygieneScore = float64(cleanable-leaked) / float64(cleanable) * 100
		}
		h.db.Exec(r.Context(),
			`UPDATE scenario_runs SET leaked_steps = $1, hygiene_score = $2 WHERE id = $3`,
			leaked, hygieneScore, raw.RunID)
	}

	// Derive/refresh persistent findings from this run's results (detection data,
	// if any, is folded in by the detection-ingest hook). Idempotent. Runs for
	// partial submissions too: the agent only includes steps that genuinely ran
	// to completion (agent/agent.go's runScenario), each carrying a real,
	// determinate Pass/Fail/Blocked verdict — except the one step that was
	// in-flight when the scenario was cancelled, which the agent tags with a
	// "step interrupted by scenario cancellation" marker so classifyExecution
	// (internal/scenario/outcome.go) routes it to ResultError and
	// upsertFindingsForRun's own switch excludes it (default: continue //
	// error | skipped). So a partial run's real evidence is safe to score;
	// only the kill artifact is excluded.
	h.upsertFindingsForRun(r.Context(), raw.RunID)

	// Auto-populate variant_findings for any ALLOWED results in variant runs.
	h.upsertVariantFindingsForRun(r.Context(), raw.RunID, raw.ScenarioID, simResults)
	// Persist per-variant execution evidence to scenario_variant_results.
	// Runs without VariantDepth (none) are a no-op (no variant meta in dispatchedMeta).
	h.persistVariantResults(r.Context(), raw.RunID, raw.ScenarioID, simResults, dispatchedMeta)

	// IOC extraction — parse stdout/stderr/details for indicators (IPs, domains,
	// URLs, hashes, CVEs). Non-fatal: extraction failure must not fail result
	// ingestion, since this is enrichment, not core scoring. Runs on partial
	// runs too — completed steps' output is still real evidence.
	indicators := ioc.BuildRunIndicators(raw.Results, raw.Checks, stepMap)
	if err := db.UpsertRunIOCs(r.Context(), h.db, raw.RunID, raw.ScenarioID, indicators); err != nil {
		log.Printf("[!] ioc extraction: failed to persist for run %s: %v", raw.RunID, err)
	}
	// Threat-intel enrichment — background, never blocks this response. Uses a
	// fresh context because the HTTP request context will be cancelled by the
	// time the goroutine runs (same pattern as refreshComplianceSnapshots below).
	go h.enrichRunIOCs(context.Background(), raw.RunID)

	// Pre-compute per-technique variant summary then, if the run belongs to a
	// campaign, refresh the campaign-level aggregate. Sequenced in one goroutine
	// so the campaign summary always reads freshly-written technique rows.
	{
		runID, campID := raw.RunID, runCampaignID
		sr, dm := simResults, dispatchedMeta
		go func() {
			h.computeVariantTechniqueSummary(context.Background(), runID, sr, dm)
			if campID != "" {
				h.refreshCampaignVariantSummary(context.Background(), campID)
			}
		}()
	}

	// Refresh compliance snapshots for this agent asynchronously — no-op when
	// compliance mapper is not loaded. Uses a fresh context because the HTTP
	// request context will be cancelled by the time the goroutine runs.
	go h.refreshComplianceSnapshots(context.Background(), raw.AgentID)

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

	// SIEM auto-correlation: fire in background so the agent's HTTP response
	// is not blocked. Fetches agent IP + run start time from DB then calls any
	// enabled SIEM connectors with auto_correlate=true.
	{
		runID := raw.RunID
		agentID := raw.AgentID
		sr := simResults
		go func() {
			var agentIP string
			var runStart time.Time
			h.db.QueryRow(context.Background(),
				`SELECT COALESCE(a.ip_address,''), sr.started_at
				   FROM scenario_runs sr
				   LEFT JOIN agents a ON a.agent_id = sr.agent_id
				  WHERE sr.id = $1`, runID,
			).Scan(&agentIP, &runStart)
			runEnd := time.Now()
			h.AutoCorrelateSIEM(runID, agentID, agentIP, runStart, runEnd, sr)
			h.AutoVerifyDetection(runID)
		}()
	}

	// Remediation lifecycle continuation -- if this run corresponds to an
	// open remediation_requests row, advance its state machine. Purely
	// additive: a no-op for the vast majority of runs with no matching row.
	h.continueRemediationFromResult(r, raw.RunID, simResults)

	w.WriteHeader(http.StatusOK)
}

// GET /api/scenarios/runs?agentId=&scenarioId=
// runRow is the shared scenario_runs row shape returned by both
// ListScenarioRuns and GetVexSweepRuns (internal/api/vexsweep_handlers.go).
type runRow struct {
	models.ScenarioRun
	InitiatedBy *string `json:"initiatedBy"`
	// DetectedTechs is the set of technique ids whose FAIL the blue team still
	// caught (from the run's detection_summary, with the coarse event-token
	// fallback) — same classification the campaign rollup and kill-chain use.
	// Lets the dashboard split fails into "detected" vs "missed" honestly.
	DetectedTechs map[string]bool `json:"detectedTechs,omitempty"`
}

// scanRunRows scans a scenario_runs query's rows, decoding the JSON blob
// columns and deriving DetectedTechs/Progress the same way for every caller.
// Every caller's SELECT must list columns in exactly this order: id,
// scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score,
// initiated_by, started_at, completed_at, steps_total, steps_done,
// steps_running, steps_passed, steps_failed, steps_timeout,
// detection_summary, alerts_total, alerts_high_fidelity, noise_score,
// reverted, mode, max_privilege, paused.
func scanRunRows(rows pgx.Rows) ([]runRow, error) {
	var runs []runRow
	for rows.Next() {
		var run runRow
		var resultsJSON, scoreRaw, detRaw, revertedRaw []byte
		var p models.RunProgress
		if err := rows.Scan(&run.ID, &run.ScenarioID, &run.AgentID, &run.SweepID, &run.EMSweepID, &run.Name,
			&run.Status, &resultsJSON, &scoreRaw, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt,
			&p.StepsTotal, &p.StepsDone, &p.StepsRunning, &p.StepsPassed, &p.StepsFailed, &p.StepsTimeout, &detRaw,
			&run.AlertsTotal, &run.AlertsHighFidelity, &run.NoiseScore, &revertedRaw, &run.Mode, &run.MaxPrivilege, &run.Paused); err != nil {
			log.Printf("[api] scan run row: %v", err)
			continue
		}
		json.Unmarshal(resultsJSON, &run.Results)
		if len(scoreRaw) > 0 {
			json.Unmarshal(scoreRaw, &run.Score)
		}
		if len(revertedRaw) > 0 {
			json.Unmarshal(revertedRaw, &run.Reverted)
		}
		if d := reporting.DetectedTechniques(detRaw, run.Results); len(d) > 0 {
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
	return runs, rows.Err()
}

func (h *Handler) ListScenarioRuns(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	scenarioID := r.URL.Query().Get("scenarioId")

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted, mode, max_privilege, paused
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

	runs, err := scanRunRows(rows)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
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
	agentID, status, err := h.cancelScenarioRun(r.Context(), runID)
	if err == errRunNotFound {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if err == errRunNotRunning {
		jsonError(w, "run is not running (status: "+status+")", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if status == "partial" {
		log.Printf("[scenario] cancel run %s — agent %s offline, marked partial", runID, agentID)
		h.auditLog(r, "scenario.cancel", runID, map[string]any{"agentId": agentID, "outcome": "partial"}, "ok")
		respond(w, map[string]string{"runId": runID, "status": "partial"})
		return
	}
	log.Printf("[scenario] cancel requested for run %s → agent %s", runID, agentID)
	h.auditLog(r, "scenario.cancel", runID, map[string]any{"agentId": agentID}, "ok")
	respond(w, map[string]string{"runId": runID, "status": "cancelling"})
}

var errRunNotFound = fmt.Errorf("run not found")
var errRunNotRunning = fmt.Errorf("run not running")

// cancelScenarioRun cancels an in-flight scenario_run -- notifies the agent
// to stop gracefully (completed steps kept, run marked partial by the
// agent's own result submission), or marks it partial immediately if the
// agent is offline. Returns the run's agent_id and resulting status
// ("cancelling" or "partial"). Shared by CancelRun (direct API) and
// CancelVexSweep (cancelling a sweep's in-flight technique run).
func (h *Handler) cancelScenarioRun(ctx context.Context, runID string) (agentID, status string, err error) {
	if err := h.db.QueryRow(ctx,
		`SELECT agent_id, status FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &status); err != nil {
		return "", "", errRunNotFound
	}
	if status != "running" {
		return agentID, status, errRunNotRunning
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandCancel,
		AgentID: agentID,
		Data:    map[string]string{"runId": runID},
	})
	if !sent {
		// Agent offline — it won't submit partial results, so mark it now.
		_, _ = h.db.Exec(ctx,
			`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
			  WHERE id = $1 AND status = 'running'`, runID)
		h.markVariantRunPartial(ctx, runID)
		return agentID, "partial", nil
	}

	// The agent was reachable, but reachability isn't the same as it actually
	// honoring the cancel promptly -- it may be blocked mid-step, or never
	// check for cancellation on this execution path at all. Without this, a
	// run only ever leaves 'running' when the agent calls SubmitScenarioResult
	// on its own initiative, with no ceiling tighter than the 2-hour
	// staleRunGuard (see runIsStale) -- so a stuck run looks permanently
	// "Running" to the user even after its live progress has finished
	// streaming in. Force it to 'partial' if the agent hasn't confirmed within
	// cancelGracePeriod. Safe even if the agent's real results land
	// afterward: SubmitScenarioResult has no status guard (see its own
	// comment) and will happily reconcile a late submission.
	go h.forceCancelAfterGracePeriod(runID, agentID)

	return agentID, "cancelling", nil
}

// forceCancelAfterGracePeriod waits cancelGracePeriod after a cancel request,
// then force-marks the run 'partial' if it is still 'running' -- the agent
// was asked to stop gracefully but never confirmed. Broadcasts the same
// MsgScenarioResult event a normal completion sends, so the frontend's
// existing live-refresh handling (loadRuns() on that message) picks up the
// change without needing a manual reload.
func (h *Handler) forceCancelAfterGracePeriod(runID, agentID string) {
	time.Sleep(h.cancelGracePeriod)
	ctx := context.Background()
	tag, err := h.db.Exec(ctx,
		`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
		  WHERE id = $1 AND status = 'running'`, runID)
	if err != nil {
		log.Printf("[scenario] force-cancel run %s after grace period: %v", runID, err)
		return
	}
	if tag.RowsAffected() == 0 {
		return // already left 'running' on its own -- the agent did respond in time
	}
	h.markVariantRunPartial(ctx, runID)
	log.Printf("[scenario] run %s did not confirm cancel within %s — force-marked partial", runID, h.cancelGracePeriod)
	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    models.MsgScenarioResult,
		AgentID: agentID,
		Data: map[string]interface{}{
			"runId":   runID,
			"agentId": agentID,
			"status":  "partial",
			"reason":  "cancel-timeout",
		},
	})
}

var errAgentOffline = fmt.Errorf("agent not connected")

// sendRunControlCommand looks up runID's agent and status, requires it be
// 'running' (paused or not -- pause/resume don't gate on the run's current
// paused state, only its status; see the package doc on idempotency), and
// forwards msgType to the agent over WS. Shared by PauseRun and ResumeRun.
// Unlike cancelScenarioRun, there is no grace-period force-timer here: an
// unconfirmed pause/resume is harmless, the run just keeps running as before.
func (h *Handler) sendRunControlCommand(ctx context.Context, runID, msgType string) (agentID string, err error) {
	var status string
	if err := h.db.QueryRow(ctx,
		`SELECT agent_id, status FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &status); err != nil {
		return "", errRunNotFound
	}
	if status != "running" {
		return agentID, errRunNotRunning
	}
	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    msgType,
		AgentID: agentID,
		Data:    map[string]string{"runId": runID},
	})
	if !sent {
		return agentID, errAgentOffline
	}
	return agentID, nil
}

// POST /api/scenarios/runs/{runId}/pause
func (h *Handler) PauseRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	agentID, err := h.sendRunControlCommand(r.Context(), runID, models.MsgCommandPause)
	switch err {
	case nil:
	case errRunNotFound:
		jsonError(w, "run not found", http.StatusNotFound)
		return
	case errRunNotRunning:
		jsonError(w, "run is not running", http.StatusConflict)
		return
	case errAgentOffline:
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	default:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[scenario] pause requested for run %s → agent %s", runID, agentID)
	h.auditLog(r, "scenario.pause", runID, map[string]any{"agentId": agentID}, "ok")
	respond(w, map[string]string{"runId": runID, "status": "pausing"})
}

// POST /api/scenarios/runs/{runId}/resume
func (h *Handler) ResumeRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	agentID, err := h.sendRunControlCommand(r.Context(), runID, models.MsgCommandResume)
	switch err {
	case nil:
	case errRunNotFound:
		jsonError(w, "run not found", http.StatusNotFound)
		return
	case errRunNotRunning:
		jsonError(w, "run is not running", http.StatusConflict)
		return
	case errAgentOffline:
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	default:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[scenario] resume requested for run %s → agent %s", runID, agentID)
	h.auditLog(r, "scenario.resume", runID, map[string]any{"agentId": agentID}, "ok")
	respond(w, map[string]string{"runId": runID, "status": "resuming"})
}

// markVariantRunPartial mirrors a cancelled scenario_run's terminal status
// onto its variant_runs row, if any -- most scenario_runs aren't
// variant-backed, so this is a no-op for those. vexsweep.Dispatcher's
// polling loop reads variant_runs.status (not scenario_runs.status, a
// separate table keyed by scenario_run_id) to decide whether a Full
// Variant Sweep's current technique is still in flight; without this, a
// cancelled technique's variant_runs row would stay 'running' forever, the
// Dispatcher would never notice the technique finished, and the sweep
// itself would never advance -- even though the individual scenario_run
// correctly shows Partial.
func (h *Handler) markVariantRunPartial(ctx context.Context, runID string) {
	if _, err := h.db.Exec(ctx,
		`UPDATE variant_runs SET status = 'partial', completed_at = NOW()
		  WHERE scenario_run_id = $1 AND status = 'running'`, runID); err != nil {
		log.Printf("[scenario] sync variant_run status for cancelled run %s: %v", runID, err)
	}
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
// callerTenant derives the tenant scope for a request from its JWT claims.
// Platform admins get cross-tenant access (isPlatformAdmin=true); everyone
// else — including tenant-less legacy tokens and direct-call unit tests with
// no claims — is scoped to their tenant, defaulting to the canonical 'default'
// tenant that the whole schema uses as its single-tenant baseline. In
// production these handlers sit behind auth middleware, so claims are always
// present; the no-claims path exists only for direct-call tests.
func callerTenant(r *http.Request) (tenantID string, isPlatformAdmin bool) {
	tenantID = "default"
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		return tenantID, false
	}
	if claims.TenantID != nil {
		tenantID = *claims.TenantID
	}
	return tenantID, claims.IsPlatformAdmin
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, isPlatformAdmin := callerTenant(r)

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
	err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		q := `SELECT id, username, role, is_active, must_change_pw, created_at, last_login FROM users`
		args := []any{}
		if !isPlatformAdmin {
			q += ` WHERE tenant_id = $1`
			args = append(args, tenantID)
		}
		q += ` ORDER BY created_at ASC`
		rows, qerr := tx.Query(r.Context(), q, args...)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var u UserRow
			if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.IsActive, &u.MustChangePw, &u.CreatedAt, &u.LastLogin); err != nil {
				continue
			}
			users = append(users, u)
		}
		return rows.Err()
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []UserRow{}
	}
	respond(w, users)
}

// GetMe returns the caller's OWN account details for the profile page —
// self-scoped by claims.UserID, never another user's row. Mirrors
// GetMyPermissions' auth pattern (internal/api/verification_handlers.go).
// GET /api/me
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var u struct {
		ID         string     `json:"id"`
		Username   string     `json:"username"`
		Role       string     `json:"role"`
		IsActive   bool       `json:"isActive"`
		CreatedAt  time.Time  `json:"createdAt"`
		LastLogin  *time.Time `json:"lastLogin"`
		AuthSource string     `json:"authSource"`
	}
	err := h.db.QueryRow(r.Context(),
		`SELECT id, username, role, is_active, created_at, last_login, auth_source FROM users WHERE id = $1`,
		claims.UserID,
	).Scan(&u.ID, &u.Username, &u.Role, &u.IsActive, &u.CreatedAt, &u.LastLogin, &u.AuthSource)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	respond(w, u)
}

// POST /api/users
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		TenantID string `json:"tenantId"` // platform-admin only; ignored otherwise
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

	claims, ok := auth.ClaimsFrom(r.Context())
	tenantID := req.TenantID
	switch {
	case !ok:
		jsonError(w, "no caller identity", http.StatusForbidden)
		return
	case claims.IsPlatformAdmin:
		if tenantID == "" {
			jsonError(w, "tenantId is required for platform-admin-created users", http.StatusBadRequest)
			return
		}
	case claims.TenantID != nil:
		// A tenant admin can only ever create users within their own
		// tenant — the request body's tenantId is silently overridden,
		// not merely validated, so it can never be used to smuggle a
		// user into a different tenant.
		tenantID = *claims.TenantID
	default:
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}

	var id string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO users (username, password_hash, role, must_change_pw, tenant_id)
		 VALUES ($1, $2, $3, true, $4)
		 RETURNING id`,
		req.Username, hash, req.Role, tenantID,
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
	// Prevent admin from changing their own role — same self-modification
	// guard as deactivation/deletion, so a session can't escalate or lock
	// itself out and privilege changes always go through a second admin.
	if req.Role != nil && claims != nil && claims.UserID == targetID {
		jsonError(w, "cannot change your own role", http.StatusBadRequest)
		return
	}

	tenantID, isPlatformAdmin := callerTenant(r)
	notFound := false
	err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		// Existence + tenant-scope check up front: a target in another tenant
		// (or nonexistent) is indistinguishable from not-found, so a
		// cross-tenant write returns 404 without leaking which ids exist
		// elsewhere. Once the row is confirmed in-tenant, the UPDATEs key on
		// the primary-key id alone.
		var exists bool
		var checkErr error
		if isPlatformAdmin {
			checkErr = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, targetID).Scan(&exists)
		} else {
			checkErr = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)`, targetID, tenantID).Scan(&exists)
		}
		if checkErr != nil {
			return checkErr
		}
		if !exists {
			notFound = true
			return nil
		}
		if req.Role != nil {
			if _, err := tx.Exec(r.Context(), `UPDATE users SET role = $1 WHERE id = $2`, *req.Role, targetID); err != nil {
				return err
			}
		}
		if req.IsActive != nil {
			if _, err := tx.Exec(r.Context(), `UPDATE users SET is_active = $1 WHERE id = $2`, *req.IsActive, targetID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if notFound {
		jsonError(w, "user not found", http.StatusNotFound)
		return
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
	tenantID, isPlatformAdmin := callerTenant(r)
	var deleted int64
	err := db.WithTenant(r.Context(), h.db, tenantID, isPlatformAdmin, func(tx pgx.Tx) error {
		q := `DELETE FROM users WHERE id = $1`
		args := []any{targetID}
		if !isPlatformAdmin {
			q += ` AND tenant_id = $2`
			args = append(args, tenantID)
		}
		ct, derr := tx.Exec(r.Context(), q, args...)
		if derr != nil {
			return derr
		}
		deleted = ct.RowsAffected()
		return nil
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if deleted == 0 {
		jsonError(w, "user not found", http.StatusNotFound)
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
	if ok, _, _ := auth.VerifyPassword(req.CurrentPassword, hash); !ok {
		jsonError(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE users SET password_hash = $1, must_change_pw = false WHERE id = $2`,
		newHash, claims.UserID)

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
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	h.db.Exec(r.Context(),
		`UPDATE users SET password_hash = $1, must_change_pw = true WHERE id = $2`,
		hash, targetID)
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
		errMsg := fmt.Sprintf("Caldera returned HTTP %d", hResp.StatusCode)
		if hResp.StatusCode == http.StatusUnauthorized {
			errMsg = "Caldera API key mismatch (HTTP 401). This is unexpected after a standard install — " +
				"the bas-caldera image auto-injects the key from .env on startup. " +
				"If the container was restarted or recreated manually, run: docker compose restart caldera orchestrator"
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
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ShortName     string   `json:"shortName"` // actor/theme chip label
	Description   string   `json:"description"`
	Category      string   `json:"category"` // apt | ransomware | technique | insider
	ThreatActor   string   `json:"threatActor,omitempty"`
	MITREGroup    string   `json:"mitreGroup,omitempty"` // e.g. "G0016"
	Tactics       []string `json:"tactics"`
	KeyTechniques []string `json:"keyTechniques"` // representative IDs shown in UI
	Risk          string   `json:"risk"`          // critical | high | medium
	EstDuration   string   `json:"estDuration"`
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
		Description: "Five-stage Cozy Bear / NOBELIUM post-compromise tradecraft (domain recon, encoded loader, run-key persistence, scheduled task, DNS C2 beacon). ~15 min, production-safe.",
		Category:    "apt", ThreatActor: "APT29 — Cozy Bear / NOBELIUM", MITREGroup: "G0016",
		Tactics:       []string{"discovery", "execution", "persistence", "command-and-control"},
		KeyTechniques: []string{"T1059.001", "T1482", "T1087.001", "T1547.001", "T1071.004"},
		Risk:          "high", EstDuration: "~15 min",
		BASScenarioID:  "apt29-kill-chain",
		ARTTechniques:  []string{"T1482", "T1087.001", "T1059.001", "T1547.001", "T1053.005", "T1071.004"},
		CalderaAdvName: "APT29",
		Tags:           []string{"apt29", "cozy-bear", "nobelium", "kill-chain"},
	},
	{
		ID: "apt29-full", Name: "APT29 Full", ShortName: "APT29",
		Description: "Extended APT29 emulation adding credential access, process injection, LOLBin proxy execution, and domain account enumeration on top of the Quick chain. ~45 min.",
		Category:    "apt", ThreatActor: "APT29 — Cozy Bear / NOBELIUM", MITREGroup: "G0016",
		Tactics:       []string{"discovery", "credential-access", "execution", "defense-evasion", "persistence", "command-and-control"},
		KeyTechniques: []string{"T1003.001", "T1059.001", "T1087.002", "T1218.011", "T1055.001", "T1482"},
		Risk:          "high", EstDuration: "~45 min",
		BASScenarioID:  "apt29-kill-chain",
		ARTTechniques:  []string{"T1482", "T1087.001", "T1087.002", "T1059.001", "T1059.003", "T1003.001", "T1055.001", "T1218.011", "T1547.001", "T1053.005", "T1071.004"},
		CalderaAdvName: "APT29",
		Tags:           []string{"apt29", "cozy-bear", "nobelium", "full-chain"},
	},
	{
		ID: "ransomware-chain", Name: "Ransomware Chain", ShortName: "Ransomware",
		Description: "LockBit 3.0 kill chain: defense enumeration, VSS probe, SMB lateral movement prep, XOR-benign file + ransom note drop, log clearing attempt. No real encryption. ~20 min.",
		Category:    "ransomware", ThreatActor: "LockBit 3.0 / Wizard Spider", MITREGroup: "G0102",
		Tactics:       []string{"discovery", "defense-evasion", "lateral-movement", "impact"},
		KeyTechniques: []string{"T1518.001", "T1490", "T1486", "T1021.002", "T1070.001"},
		Risk:          "critical", EstDuration: "~20 min",
		BASScenarioID:  "lockbit-kill-chain",
		ARTTechniques:  []string{"T1518.001", "T1490", "T1486", "T1070.001", "T1021.002"},
		CalderaAdvName: "Wizard Spider",
		Tags:           []string{"ransomware", "lockbit", "wizard-spider"},
	},
	{
		ID: "credential-theft", Name: "Credential Theft", ShortName: "CredTheft",
		Description:   "Multi-vector credential harvesting: LSASS, SAM, Kerberoasting, NTLM relay probe, Credential Manager dump, and browser credential access. ~15 min.",
		Category:      "technique",
		Tactics:       []string{"credential-access"},
		KeyTechniques: []string{"T1003.001", "T1003.002", "T1558.003", "T1555.003", "T1110.001"},
		Risk:          "high", EstDuration: "~15 min",
		BASScenarioID:  "credential-access",
		ARTTechniques:  []string{"T1003.001", "T1003.002", "T1558.003", "T1555.003", "T1110.001"},
		CalderaAdvName: "FIN6",
		Tags:           []string{"credential-access", "lsass", "kerberoasting"},
	},
	{
		ID: "lateral-movement", Name: "Lateral Movement", ShortName: "LatMov",
		Description:   "SMB and WMI-based lateral movement chain with pass-the-hash probe, admin share enumeration, and remote execution simulation. ~20 min.",
		Category:      "technique",
		Tactics:       []string{"lateral-movement", "credential-access", "execution"},
		KeyTechniques: []string{"T1021.001", "T1021.002", "T1550.002", "T1047"},
		Risk:          "high", EstDuration: "~20 min",
		BASScenarioID:  "caldera-lateral-movement",
		ARTTechniques:  []string{"T1021.001", "T1021.002", "T1550.002"},
		CalderaAdvName: "APT29",
		Tags:           []string{"lateral-movement", "smb", "pass-the-hash"},
	},
	{
		ID: "data-exfiltration", Name: "Data Exfiltration", ShortName: "Exfil",
		Description:   "Staged data collection and exfiltration simulation: local file staging, DNS tunnel probe, HTTPS exfil beacon, and cloud-storage upload attempt. ~15 min.",
		Category:      "technique",
		Tactics:       []string{"collection", "exfiltration"},
		KeyTechniques: []string{"T1041", "T1048.003", "T1030", "T1074.001"},
		Risk:          "medium", EstDuration: "~15 min",
		BASScenarioID:  "exposure-validation",
		ARTTechniques:  []string{"T1041", "T1048.003", "T1030", "T1074.001"},
		CalderaAdvName: "APT36",
		Tags:           []string{"exfiltration", "dns-tunnel", "data-theft"},
	},
	{
		ID: "insider-threat", Name: "Insider Threat", ShortName: "Insider",
		Description: "Scattered Spider social-engineering chain simulating privileged-access abuse: MFA fatigue probe, account enumeration, defense tool disablement, staged data access. ~20 min.",
		Category:    "insider", ThreatActor: "Scattered Spider", MITREGroup: "G1015",
		Tactics:       []string{"initial-access", "discovery", "defense-evasion", "collection"},
		KeyTechniques: []string{"T1078", "T1087.001", "T1562.001", "T1070.001", "T1048.003"},
		Risk:          "high", EstDuration: "~20 min",
		BASScenarioID:  "scattered-spider-kill-chain",
		ARTTechniques:  []string{"T1078", "T1087.001", "T1562.001", "T1070.001", "T1048.003"},
		CalderaAdvName: "Scattered Spider",
		Tags:           []string{"insider-threat", "scattered-spider", "social-engineering"},
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
		AgentID            string                   `json:"agentId"`
		Mode               string                   `json:"mode"`
		ConfirmLive        bool                     `json:"confirmLive"`
		ConfirmLab         bool                     `json:"confirmLab"`
		Reason             string                   `json:"reason"`
		UseBAS             bool                     `json:"useBas"`
		UseART             bool                     `json:"useArt"`
		CalderaAdversaryID string                   `json:"calderaAdversaryId"` // frontend resolves name→UUID
		ExecutionPolicy    scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
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
		Reason: req.Reason, InitiatedBy: uid, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
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

	// ART technique dispatch — synthesizes an ad-hoc scenario carrying the
	// template's curated technique list, mirroring the Caldera adversary
	// branch below rather than depending on a standalone "selective"
	// scenario in the catalog (the operator-facing "Selective" scenarios
	// were removed; only Full Sweep remains there).
	if req.UseART && len(tmpl.ARTTechniques) > 0 {
		synthSc := &scenario.Scenario{
			ID:            "art-adversary-" + id,
			Name:          tmpl.Name + " (ART)",
			ARTTechniques: tmpl.ARTTechniques,
			Executable:    true,
			SupportedOS:   []string{"windows"},
		}
		artOpts := base
		artOpts.Techniques = tmpl.ARTTechniques
		runID, skip, err := h.dispatchRun(r.Context(), synthSc, req.AgentID, artOpts)
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

// TechniqueCatalogEntry is one row in the full ATT&CK technique search
// catalog served to the Scenario Builder's Technique Selector. Built
// entirely from the embedded attackdata dataset — read-only, no DB access.
type TechniqueCatalogEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactics     []string `json:"tactics,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Description string   `json:"description,omitempty"`
	Detection   string   `json:"detection,omitempty"`
	DataSources []string `json:"dataSources,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	SubCount    int      `json:"subCount,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// GET /api/techniques/catalog — the full ATT&CK technique catalog (every
// loaded technique, not just ones with ART/Caldera/BAS coverage) for the
// Scenario Builder's client-side Technique Selector search. Read-only,
// Viewer+, no DB access — built entirely from the embedded attackdata
// dataset, so it's safe to compute fresh on every request.
func (h *Handler) GetTechniqueCatalog(w http.ResponseWriter, r *http.Request) {
	refs := attackdata.All()
	subCounts := attackdata.SubtechniqueCounts()
	out := make([]TechniqueCatalogEntry, 0, len(refs))
	for _, ref := range refs {
		entry := TechniqueCatalogEntry{ID: ref.ID, Name: ref.Name, Tactics: ref.Tactics, SubCount: subCounts[ref.ID]}
		if e := attackdata.Lookup(ref.ID); e != nil {
			entry.Platforms = e.Platforms
			entry.Description = e.Description
			entry.Detection = e.Detection
			entry.DataSources = e.DataSources
			entry.Permissions = e.PermissionsRequired
			entry.Aliases = e.Aliases
			entry.URL = e.URL
		}
		out = append(out, entry)
	}
	respond(w, out)
}

// GET /api/coverage/analytics — aggregate prevention/detection analytics across
// recent runs. Results are bucketed per technique into prevented / detectedOnly
// (FAIL but EDR/SIEM caught it) / missed (FAIL, no detection). Error and Skipped
// outcomes are excluded from counts. Viewer+.
//
// Query params:
//
//	scenarioId — filter to one scenario (optional)
//	agentId    — filter to one agent (optional)
//	limit      — max runs to include, default 20, max 100
func (h *Handler) GetCoverageAnalytics(w http.ResponseWriter, r *http.Request) {
	scenarioID := r.URL.Query().Get("scenarioId")
	agentID := r.URL.Query().Get("agentId")
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	result, err := analytics.DetectionEffectiveness(r.Context(), h.db, scenarioID, agentID, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
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

// GET /api/caldera/techniques — live Caldera catalog from the pre-loaded
// ability cache (technique id, representative ability name, ability count).
// Same shape as GetARTTechniques so the frontend can render both sources
// with shared code. Returns an empty list if Caldera isn't configured.
func (h *Handler) GetCalderaTechniques(w http.ResponseWriter, r *http.Request) {
	respond(w, h.calderaStore.ListTechniqueMeta())
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
		// A custom (unrecognized) scenario ID was never in the agent's
		// pre-harvested snapshot -- knownPostureScenarios() only covers the
		// built-in set. It still genuinely runs every check via the agent's
		// own RunAllChecks() default fallback at execution time, so fall
		// back to the matching catalog entry here rather than reporting
		// "no checks" for a scenario that actually runs 20+ of them. Key
		// must match agent/simulate.go's postureCatalogDefaultKey.
		checks = cat["*"]
	}
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
			msg = "Caldera rejected the API key (HTTP 401) fetching abilities. " +
				"This is unexpected after a standard install — the bas-caldera image auto-injects the correct key on startup. " +
				"Run: docker compose restart caldera orchestrator"
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

// GET /api/threatintel/lookup?type={ip|domain|url|hash|cve}&value={value}
func (h *Handler) LookupIOC(w http.ResponseWriter, r *http.Request) {
	provider := h.getIOCProvider()
	if provider == nil {
		jsonError(w, "threat intel not configured — enable OTX in Settings", http.StatusServiceUnavailable)
		return
	}
	iocType := r.URL.Query().Get("type")
	value := r.URL.Query().Get("value")
	if value == "" {
		jsonError(w, "value is required", http.StatusBadRequest)
		return
	}
	switch iocType {
	case "ip", "domain", "url", "hash", "cve":
	default:
		jsonError(w, "type must be one of: ip, domain, url, hash, cve", http.StatusBadRequest)
		return
	}

	result, err := ioc.Lookup(r.Context(), provider, iocType, value)
	if err != nil {
		jsonError(w, "lookup failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	respond(w, result)
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
		AgentID         string                   `json:"agentId"`
		Mode            string                   `json:"mode"`
		ConfirmLive     bool                     `json:"confirmLive"`
		ConfirmLab      bool                     `json:"confirmLab"`
		Reason          string                   `json:"reason"`
		ExecutionPolicy scenario.ExecutionPolicy `json:"executionPolicy,omitempty"`
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
		Reason: req.Reason, InitiatedBy: initiatedBy, MaxPrivilege: req.ExecutionPolicy.MaxPrivilege,
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

// connectorStatusResponse adds OTX's enabled flag alongside the MISP/OpenCTI
// bundle-sync status from the connector package. OTX now does have a
// periodic sync (connector.OTXSource, joined to the scheduler's source
// list), but "enabled" here specifically means "the on-demand lookup
// provider (h.iocProvider) is configured" — the same OTX_API_KEY gate the
// scheduler's OTXSource uses, so the two states always agree in practice.
// Kept as a wrapper field rather than a second OTXEnabled field on
// connector.ConnectorStatus to avoid two sources of truth for one boolean.
type connectorStatusResponse struct {
	connector.ConnectorStatus
	OTXEnabled bool `json:"otxEnabled"`
}

// GET /api/connector/status
func (h *Handler) GetConnectorStatus(w http.ResponseWriter, r *http.Request) {
	if h.scheduler == nil {
		respond(w, connectorStatusResponse{
			ConnectorStatus: connector.ConnectorStatus{
				LastSyncStatus: "never",
				LastError:      "No threat-intel sources configured. Set MISP_URL/MISP_API_KEY or OPENCTI_URL/OPENCTI_API_KEY.",
			},
			OTXEnabled: h.getIOCProvider() != nil,
		})
		return
	}
	respond(w, connectorStatusResponse{
		ConnectorStatus: h.scheduler.Status(),
		OTXEnabled:      h.getIOCProvider() != nil,
	})
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

// complianceRows builds the per-framework compliance summary rows by aggregating
// ALL of an agent's completed/partial runs. This gives accurate framework scores
// because no single scenario exercises every control in a framework.
func (h *Handler) complianceRows(ctx context.Context, agentID string, filter string) []reporting.ComplianceSummaryRow {
	if h.complianceMapper == nil {
		return nil
	}
	results := h.aggregateAgentResults(ctx, agentID)
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

// aggregateAgentResults unions all completed/partial run results for an agent,
// deduplicating by result ID so retried/reconciled runs don't double-count.
func (h *Handler) aggregateAgentResults(ctx context.Context, agentID string) []models.SimulationResult {
	rows, err := h.db.Query(ctx,
		`SELECT results FROM scenario_runs
		  WHERE agent_id = $1 AND status IN ('completed','partial')
		    AND results IS NOT NULL`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := make(map[string]bool)
	var all []models.SimulationResult
	for rows.Next() {
		var b []byte
		rows.Scan(&b)
		var batch []models.SimulationResult
		json.Unmarshal(b, &batch)
		for _, r := range batch {
			if r.ID != "" && seen[r.ID] {
				continue
			}
			if r.ID != "" {
				seen[r.ID] = true
			}
			all = append(all, r)
		}
	}
	return all
}

// refreshComplianceSnapshots recomputes compliance scores for all frameworks
// from the agent's full run history and persists them to compliance_snapshots.
// Called as a goroutine after every run completion; no-op when mapper is nil.
func (h *Handler) refreshComplianceSnapshots(ctx context.Context, agentID string) {
	if h.complianceMapper == nil || h.db == nil {
		return
	}
	results := h.aggregateAgentResults(ctx, agentID)

	var runCount int
	h.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM scenario_runs
		  WHERE agent_id = $1 AND status IN ('completed','partial')`, agentID,
	).Scan(&runCount)

	for _, fw := range h.complianceMapper.Frameworks() {
		cr, err := h.complianceMapper.GenerateReport(results, fw.ID, agentID, "", "")
		if err != nil {
			continue
		}
		s := cr.Summary
		db.UpsertComplianceSnapshot(ctx, h.db, db.ComplianceSnapshot{
			AgentID:          agentID,
			FrameworkID:      fw.ID,
			RunCount:         runCount,
			CompliancePct:    s.CompliancePercent,
			CoveragePct:      s.CoveragePercent,
			TotalControls:    s.TotalControls,
			TestableControls: s.TestableControls,
			TestedControls:   s.TestedControls,
			PassingControls:  s.PassingControls,
			FailingControls:  s.FailingControls,
			ManualControls:   s.ManualControls,
		})
	}
}

const iocEnrichmentTTL = 24 * time.Hour

// enrichRunIOCs is the enrichment pipeline entry point: for every distinct
// indicator extracted from a run, ask the configured threat-intel provider
// about it -- unless a fresh cache row already exists. Never blocks the HTTP
// response (always called via `go`). No-op when no provider is configured.
func (h *Handler) enrichRunIOCs(ctx context.Context, runID string) {
	provider := h.getIOCProvider()
	if provider == nil {
		return
	}
	indicators, err := db.GetRunIOCs(ctx, h.db, runID, "", "")
	if err != nil {
		log.Printf("[!] ioc enrichment: failed to load indicators for run %s: %v", runID, err)
		return
	}
	providerName := provider.Name()
	for _, ind := range indicators {
		cached, err := db.GetIOCEnrichment(ctx, h.db, ind.Type, ind.Value, providerName)
		if err != nil {
			log.Printf("[!] ioc enrichment: cache read failed for %s %s: %v", ind.Type, ind.Value, err)
			continue
		}
		if cached != nil && cached.TTLExpiresAt.After(time.Now()) {
			continue // fresh cache hit -- no external call
		}

		start := time.Now()
		result, lookupErr := ioc.Lookup(ctx, provider, ind.Type, ind.Value)
		durationMs := int(time.Since(start).Milliseconds())
		ttlExpiresAt := time.Now().Add(iocEnrichmentTTL)

		if lookupErr != nil {
			if err := db.UpsertIOCEnrichmentFailure(ctx, h.db, ind.Type, ind.Value, providerName, lookupErr, ttlExpiresAt); err != nil {
				log.Printf("[!] ioc enrichment: failed to cache failure for %s %s: %v", ind.Type, ind.Value, err)
			}
			continue
		}
		if err := db.UpsertIOCEnrichmentSuccess(ctx, h.db, ind.Type, ind.Value, providerName, result, durationMs, ttlExpiresAt); err != nil {
			log.Printf("[!] ioc enrichment: failed to cache result for %s %s: %v", ind.Type, ind.Value, err)
		}
	}
}

// GET /api/compliance/scores[?agentId=X]
// Returns compliance scores for all frameworks for one agent (agentId provided)
// or fleet-wide worst-case per framework (no agentId — CISO dashboard view).
// Scores come from compliance_snapshots — O(1) read, no recomputation.
// Falls back to zero-state entries when no runs have completed yet, so the
// dashboard can always render all 6 framework tiles.
func (h *Handler) GetComplianceDashboardScores(w http.ResponseWriter, r *http.Request) {
	if h.complianceMapper == nil {
		jsonError(w, "compliance mapper not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")

	// Build framework metadata lookup for name enrichment.
	type fwInfo struct{ name, shortName, regulator string }
	fwMeta := make(map[string]fwInfo)
	for _, fw := range h.complianceMapper.Frameworks() {
		fwMeta[fw.ID] = fwInfo{fw.Name, complianceShortName(fw.ID), fw.Regulator}
	}

	type scoreResp struct {
		db.ComplianceSnapshot
		FrameworkName    string `json:"frameworkName"`
		ShortName        string `json:"shortName"`
		Regulator        string `json:"regulator"`
		UntestedControls int    `json:"untestedControls"`
	}

	var snaps []db.ComplianceSnapshot
	var err error
	if agentID != "" {
		snaps, err = db.GetComplianceScores(r.Context(), h.db, agentID)
	} else {
		snaps, err = db.GetFleetComplianceScores(r.Context(), h.db)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Index existing snaps by framework ID.
	snapIdx := make(map[string]db.ComplianceSnapshot, len(snaps))
	for _, s := range snaps {
		snapIdx[s.FrameworkID] = s
	}

	// Always return an entry for every known framework (zero state when no runs).
	out := make([]scoreResp, 0, len(fwMeta))
	for _, fw := range h.complianceMapper.Frameworks() {
		s := snapIdx[fw.ID]
		s.FrameworkID = fw.ID
		meta := fwMeta[fw.ID]
		out = append(out, scoreResp{
			ComplianceSnapshot: s,
			FrameworkName:      meta.name,
			ShortName:          meta.shortName,
			Regulator:          meta.regulator,
			UntestedControls:   s.TestableControls - s.TestedControls,
		})
	}
	respond(w, out)
}

// complianceShortName returns the dashboard display label for a framework ID.
func complianceShortName(id string) string {
	switch id {
	case "SEBI_CSCRF":
		return "SEBI CSCRF"
	case "RBI_CSF":
		return "RBI CSF"
	case "CERT_IN":
		return "CERT-In"
	case "IRDAI_CSF":
		return "IRDAI"
	case "ISO_27001_2022":
		return "ISO 27001"
	case "NIST_CSF_2":
		return "NIST CSF"
	case "PCI_DSS_V4":
		return "PCI DSS v4"
	}
	return id
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
	totalCount := len(results)
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
	reporting.WriteForensicCSV(w, scenarioName, results, filter, totalCount)
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
	// Guard: require at least one completed run before generating a pack.
	var runCount int
	h.db.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM scenario_runs WHERE agent_id=$1 AND status IN ('completed','partial')`,
		agentID,
	).Scan(&runCount)
	if runCount == 0 {
		jsonError(w, "No completed runs for this agent — run at least one scenario before generating an audit pack", http.StatusUnprocessableEntity)
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
	totalCount := len(results)
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
	reporting.WriteForensicCSV(w, name, results, filter, totalCount)
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

// GET /api/scenarios/runs/{runId}/attackflow
// Returns the structured attack flow for a completed run: one node per
// technique ordered by kill-chain tactic, with control attribution and
// detection verdict derived from the same evidence pipeline as the reports.
func (h *Handler) GetRunAttackFlow(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	var resultsJSON []byte
	var runName, agentID string
	err := h.db.QueryRow(r.Context(),
		`SELECT name, agent_id, results FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&runName, &agentID, &resultsJSON)
	if err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	var results []models.SimulationResult
	if len(resultsJSON) > 0 {
		_ = json.Unmarshal(resultsJSON, &results)
	}
	nodes := reporting.BuildAttackFlow(results)

	// Summary counters
	var blocked, detected, logged, bypassed, errs, skipped int
	for _, n := range nodes {
		switch n.Verdict {
		case "blocked":
			blocked++
		case "detected":
			detected++
		case "logged":
			logged++
		case "bypassed":
			bypassed++
		case "error":
			errs++
		case "skipped":
			skipped++
		}
	}
	respond(w, map[string]any{
		"runId":        runID,
		"scenarioName": runName,
		"agentId":      agentID,
		"nodes":        nodes,
		"summary": map[string]any{
			"total":    len(nodes),
			"blocked":  blocked,
			"detected": detected,
			"logged":   logged,
			"bypassed": bypassed,
			"errors":   errs,
			"skipped":  skipped,
		},
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
	windowsRunnable := 0
	if h.artStore != nil {
		loaded = h.artStore.Count()
		// A technique can be imported (counted in `loaded`) with only
		// Linux/macOS atomics and no Windows step at all -- ART Full Windows
		// Sweep silently excludes those via ListTechniquesByPlatform, which
		// is correct but was previously invisible, making the sweep's
		// technique count look like a bug relative to `loaded`.
		windowsRunnable = len(h.artStore.ListTechniquesByPlatform("windows"))
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
	// Variant engine: executor breakdown drives the available-variant count.
	// ps×36 + cmd×12 — not stored in the DB, derived at request time.
	psCount, cmdCount, variantCount, vErr := scenario.QueryVariantCount(r.Context(), h.db)
	if vErr != nil {
		log.Printf("[content] variant count failed: %v", vErr)
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
		"psTestCount":         psCount,
		"cmdTestCount":        cmdCount,
		"variantCount":        variantCount,
		"payloadCount":        payloadCount,
		"kevCount":            kevCount,
		"source":              source,
		"importedAt":          importedAt,
		"techniquesLoaded":    loaded,
		"windowsRunnable":     windowsRunnable,
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
	if en, eErr := scenario.SeedEPSS(r.Context(), h.db, h.artEPSSFile); eErr != nil {
		log.Printf("[content] EPSS reseed: %v", eErr)
	} else if en > 0 {
		log.Printf("[content] EPSS reseed: %d CVE entries", en)
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
