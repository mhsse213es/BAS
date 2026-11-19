package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/aleef/campaign"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/aleef/safety"
	aleefstore "github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/targetscope"
)

// Aleef API discovery: engagements, campaign runs and findings. The routes are licensed by the
// separate "addon:aleef" token (see license.ProductAleef) and authorised by CanViewAleef and
// CanRunAleef.
//
// Safety: the handlers never send a request to the target. Every request to the target goes
// through the campaign's guard (internal/aleef/safety), which enforces the engagement. The handlers
// refuse an invalid engagement, an out-of-window engagement and an unauthorised base URL before the
// campaign starts. Credentials never enter the API: an account names a token reference, and the
// server-side secret resolver turns it into the token inside the campaign.

const (
	maxAleefRunBody        = 5 << 20
	maxAleefEngagementBody = 64 << 10
	maxAleefSmallBody      = 4 << 10
	maxAleefAccounts       = 20
	maxAleefSetup          = 100
	maxAleefClasses        = 5000
	maxAleefVariations     = 50
	maxAleefMaxTests       = 100000
	maxAleefReproductions  = 10
	aleefKeepFinished      = 24 * time.Hour
)

// Run statuses.
const (
	aleefRunning   = "running"
	aleefStopping  = "stopping"
	aleefCompleted = "completed"
	aleefHalted    = "halted"
	aleefStopped   = "stopped"
	aleefFailed    = "failed"
)

var (
	aleefIDRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	aleefRefRe = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,64}$`)
)

// aleefRun is one in-memory campaign run. Its mutable fields are guarded by aleefState.mu.
type aleefRun struct {
	id, engagementID string
	startedAt        time.Time
	cancel           context.CancelFunc
	status           string
	stopRequested    bool
	stopReason       string // "stopped by operator" or "server shutdown"
	finishedAt       time.Time
	report           *campaign.Report
	errMsg           string
}

type aleefState struct {
	store   *aleefstore.Store
	secrets model.SecretResolver
	// httpClient optionally supplies the campaign's base transport (tests).
	httpClient *http.Client

	// runFn runs a campaign; campaign.Run unless a test replaces it.
	runFn func(context.Context, campaign.Config) (campaign.Report, error)
	// afterCreateRun, when set (tests), is called between creating the run row and registering the run.
	afterCreateRun func()

	// rootCtx is the parent of every run's context; shutdown cancels it.
	rootCtx    context.Context
	rootCancel context.CancelFunc
	wg         sync.WaitGroup // one per running campaign goroutine

	mu     sync.Mutex
	closed bool // set by shutdown: no new runs
	runs   map[string]*aleefRun
	active map[string]string // engagement id -> run id
}

// WithAleef enables the Aleef API. secrets resolves account token references server-side; nil
// uses AleefEnvSecrets.
func (h *Handler) WithAleef(st *aleefstore.Store, secrets model.SecretResolver) *Handler {
	if secrets == nil {
		secrets = AleefEnvSecrets{}
	}
	root, cancel := context.WithCancel(context.Background())
	h.aleef = &aleefState{store: st, secrets: secrets, runFn: campaign.Run, rootCtx: root, rootCancel: cancel,
		runs: map[string]*aleefRun{}, active: map[string]string{}}
	return h
}

// RecoverAleefRuns marks runs still 'running' in the database as 'interrupted'. Call once at server
// start. It is global: it assumes a single orchestrator instance per database (the documented on-prem
// model); with two instances it would mark the other's live runs interrupted. The process that was running them is gone, so their campaigns did not finish and objects they
// created on the target may remain. It logs the run ids.
func (h *Handler) RecoverAleefRuns(ctx context.Context) error {
	if h.aleef == nil {
		return nil
	}
	ids, err := h.aleef.store.MarkRunsInterrupted(ctx)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		log.Printf("[aleef] marked %d unfinished run(s) interrupted by a restart: %s", len(ids), strings.Join(ids, ", "))
	}
	return nil
}

// ShutdownAleef cancels every running campaign and waits up to timeout for their cleanup sweeps.
// Call it before the HTTP servers shut down. Runs that do not finish in time stay 'running' in the
// database and are marked interrupted at the next start.
func (h *Handler) ShutdownAleef(timeout time.Duration) {
	if h.aleef != nil {
		h.aleef.shutdown(timeout)
	}
}

func (st *aleefState) shutdown(timeout time.Duration) {
	st.mu.Lock()
	st.closed = true
	for _, run := range st.runs {
		if run.status == aleefRunning || run.status == aleefStopping {
			run.stopRequested, run.stopReason, run.status = true, "server shutdown", aleefStopping
		}
	}
	st.mu.Unlock()
	st.rootCancel()
	done := make(chan struct{})
	go func() { st.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Printf("[aleef] shutdown: campaigns still cleaning up after %s; marking them interrupted", timeout)
		// Best effort. The cleanup sweep's partial orphan list lives inside campaign.Run and cannot be read
		// without racing it, so only the status and a reason are recorded: objects may remain on the target.
		st.mu.Lock()
		var ids []string
		for id, run := range st.runs {
			if run.finishedAt.IsZero() {
				ids = append(ids, id)
			}
		}
		st.mu.Unlock()
		pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, id := range ids {
			if err := st.store.MarkRunFinished(pctx, id, aleefstore.RunInterrupted,
				"server shutdown: cleanup did not finish in time; objects created on the target may remain", nil, nil); err != nil {
				log.Printf("[aleef] shutdown: could not mark run %s interrupted: %v", id, err)
			}
		}
	}
}

// AleefEnvSecrets resolves a token reference from the server environment. The reference
// "bank/uat/alice" is read from ALEEF_SECRET_BANK_UAT_ALICE (every character outside A-Z, 0-9
// becomes "_", upper-cased). There is no other server-side secret store yet, as for the API BAS
// runner; production deployments should put a secret manager behind model.SecretResolver. Errors
// never contain the reference or the value.
type AleefEnvSecrets struct{}

// aleefEnvName is the environment variable a reference is read from.
func aleefEnvName(ref string) string {
	return "ALEEF_SECRET_" + strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		}
		return '_'
	}, ref)
}

// errAleefSecret is the only error Resolve returns. A refused reference and a reference with no
// configured secret are indistinguishable to the caller, so a ref's existence is not revealed.
var errAleefSecret = errors.New("secret reference could not be resolved")

// Resolve returns the token behind ref. When ALEEF_SECRETS_FILE is set and readable the file is
// consulted first (file wins over the process environment when both define the name); the
// ALEEF_SECRET_* process environment is the fallback. A missing file means no file secrets.
func (AleefEnvSecrets) Resolve(ref string) (string, error) {
	if !aleefRefRe.MatchString(ref) {
		return "", errAleefSecret
	}
	name := aleefEnvName(ref)
	if path := os.Getenv(aleefSecretsFileEnv); path != "" {
		m, err := parseAleefSecretsFile(path)
		if err != nil {
			log.Printf("[aleef] %v; ignoring the file", err)
		} else if v := m[name]; v != "" {
			return v, nil
		}
	}
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	return "", errAleefSecret
}

func (h *Handler) aleefReady(w http.ResponseWriter) bool {
	if h.aleef == nil {
		jsonError(w, "aleef is not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func aleefActor(r *http.Request) string {
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		return "user:" + c.UserID
	}
	return ""
}

// decodeAleefBody decodes a JSON body strictly with a size limit.
func decodeAleefBody(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			jsonError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	if dec.More() {
		jsonError(w, "invalid request body: trailing data", http.StatusBadRequest)
		return false
	}
	return true
}

// storedEngagement is the body kept in aleef_engagements.body.
type storedEngagement struct {
	Engagement    json.RawMessage `json:"engagement"`
	TargetScopeID string          `json:"target_scope_id,omitempty"`
}

// CreateAleefEngagement stores an engagement (admin only: aleef:authorize). The body is the
// safety.Engagement fields minus approver (the server sets it), plus an optional target_scope_id naming
// an existing target scope import, and token_refs (the allowed secret reference names).
//
// "classes" (the ceiling for every run) and "operations" (the money/notifying allow-list) are keyed by
// SIGNATURE, "METHOD /path-template" such as "POST /payments/{id}/settle". An operation id is refused:
// ids come from the document under test, which the analyst supplies. The names of path parameters do
// not matter. Engagements created before signatures must be recreated. Production and unknown
// environments are refused.
func (h *Handler) CreateAleefEngagement(w http.ResponseWriter, r *http.Request) {
	if !h.aleefReady(w) {
		return
	}
	var raw map[string]json.RawMessage
	if !decodeAleefBody(w, r, maxAleefEngagementBody, &raw) {
		return
	}
	scopeID := ""
	if v, ok := raw["target_scope_id"]; ok {
		delete(raw, "target_scope_id")
		if err := json.Unmarshal(v, &scopeID); err != nil || (scopeID != "" && !aleefIDRe.MatchString(scopeID)) {
			jsonError(w, "target_scope_id is invalid", http.StatusBadRequest)
			return
		}
	}
	// The administrator declares which secret references runs under this engagement may use. The API
	// field is token_refs; the engagement record calls it tokenRefs.
	if v, ok := raw["token_refs"]; ok {
		delete(raw, "token_refs")
		if _, dup := raw["tokenRefs"]; dup {
			jsonError(w, "token_refs and tokenRefs are the same field", http.StatusBadRequest)
			return
		}
		raw["tokenRefs"] = v
	}
	delete(raw, "id") // the engagement id is assigned by the server
	// The approver is the authenticated user, never a value from the body: an operator cannot name
	// someone else (or themselves under another name) as the approver of their own scope.
	for k := range raw {
		if strings.EqualFold(k, "approver") {
			jsonError(w, "approver is set by the server from the authenticated user and must not be supplied", http.StatusBadRequest)
			return
		}
	}
	actor := aleefActor(r)
	if actor == "" {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	raw["approver"], _ = json.Marshal(actor)
	body, err := json.Marshal(raw)
	if err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	e, err := safety.Parse(body)
	if err != nil {
		h.auditLog(r, "aleef.engagement.create", "", map[string]any{"reason": "refused"}, "refused")
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if msg := checkAleefTokenRefs(e.TokenRefs); msg != "" {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	if scopeID != "" {
		if _, err := db.GetTargetScopeImport(r.Context(), h.db, scopeID); err != nil {
			jsonError(w, "target scope import not found", http.StatusBadRequest)
			return
		}
	}
	engJSON, err := json.Marshal(e)
	if err != nil {
		jsonError(w, "could not encode engagement", http.StatusInternalServerError)
		return
	}
	stored, _ := json.Marshal(storedEngagement{Engagement: engJSON, TargetScopeID: scopeID})
	id, err := h.aleef.store.CreateEngagement(r.Context(), aleefstore.Engagement{
		Customer: e.Customer, Environment: e.Environment, ApprovedHosts: e.Hosts, Approver: e.Approver,
		Window: e.NotBefore.UTC().Format(time.RFC3339) + "/" + e.NotAfter.UTC().Format(time.RFC3339),
		Body:   stored,
	})
	if err != nil {
		log.Printf("[aleef] create engagement: %v", err)
		jsonError(w, "could not store engagement", http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "aleef.engagement.create", id, map[string]any{"environment": e.Environment, "customer": e.Customer}, "ok")
	respondStatus(w, map[string]any{"id": id, "environment": e.Environment, "customer": e.Customer,
		"not_before": e.NotBefore, "not_after": e.NotAfter, "hosts": e.Hosts}, http.StatusCreated)
}

// checkAleefTokenRefs validates the allowed token references of an engagement: at least one, valid
// names, no duplicates, and no two that read the same environment variable.
func checkAleefTokenRefs(refs []string) string {
	if len(refs) == 0 || len(refs) > maxAleefAccounts {
		return fmt.Sprintf("token_refs: between 1 and %d secret references are required", maxAleefAccounts)
	}
	seen := map[string]string{}
	for _, ref := range refs {
		if !aleefRefRe.MatchString(ref) {
			return "token_refs: a reference must be a short name of letters, digits, '.', '/', '_' or '-' (never a credential)"
		}
		env := aleefEnvName(ref)
		if prev, ok := seen[env]; ok {
			if prev == ref {
				return "token_refs: duplicate reference"
			}
			return "token_refs: two references map to the same server secret (" + env + ")"
		}
		seen[env] = ref
	}
	return ""
}

type aleefAccountReq struct {
	Name       string `json:"name"`
	CustomerID string `json:"customer_id"`
	TokenRef   string `json:"token_ref"`
	Role       string `json:"role"`
}

type aleefSetupReq struct {
	OperationID string         `json:"operation_id"`
	Body        map[string]any `json:"body"`
	Compensate  string         `json:"compensate"`
}

type aleefOptionsReq struct {
	Seed          int64    `json:"seed"`
	MaxTests      int      `json:"max_tests"`
	Reproductions int      `json:"reproductions"`
	Variations    []string `json:"variations"`
}

type aleefRunReq struct {
	EngagementID string            `json:"engagement_id"`
	OpenAPI      json.RawMessage   `json:"openapi"`
	BaseURL      string            `json:"base_url"`
	Accounts     []aleefAccountReq `json:"accounts"`
	Setup        []aleefSetupReq   `json:"setup"`
	Classes      map[string]string `json:"classes"`
	Options      aleefOptionsReq   `json:"options"`
}

const aleefTokenRefRefused = "token reference not permitted for this engagement"

var aleefClasses = []model.OpClass{model.ClassUnknown, model.ClassRead, model.ClassSetupSafe, model.ClassReversible, model.ClassMoney, model.ClassNotifying}

// presetRunRecorder makes the campaign use the run created by the handler, so the run id is
// known before the campaign starts and can be returned with the 202.
type presetRunRecorder struct {
	*aleefstore.Store
	runID string
	used  bool
}

func (p *presetRunRecorder) CreateRun(ctx context.Context, engagementID string) (string, error) {
	if p.used {
		return "", errors.New("aleef: run already created")
	}
	p.used = true
	return p.runID, nil
}

// StartAleefRun validates the engagement and request, then starts the campaign in the background.
func (h *Handler) StartAleefRun(w http.ResponseWriter, r *http.Request) {
	if !h.aleefReady(w) {
		return
	}
	var req aleefRunReq
	if !decodeAleefBody(w, r, maxAleefRunBody, &req) {
		return
	}
	if !aleefIDRe.MatchString(req.EngagementID) {
		jsonError(w, "engagement_id is required", http.StatusBadRequest)
		return
	}
	cfg, status, msg := h.buildAleefConfig(r.Context(), req)
	if msg != "" {
		h.auditLog(r, "aleef.run.start", req.EngagementID, map[string]any{"reason": "refused"}, "refused")
		jsonError(w, msg, status)
		return
	}

	st := h.aleef
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		jsonError(w, "the server is shutting down", http.StatusServiceUnavailable)
		return
	}
	st.pruneLocked()
	if cur, busy := st.active[req.EngagementID]; busy {
		st.mu.Unlock()
		h.auditLog(r, "aleef.run.start", req.EngagementID, map[string]any{"reason": "campaign already active", "active_run": cur}, "refused")
		jsonError(w, "a campaign is already active for this engagement", http.StatusConflict)
		return
	}
	st.active[req.EngagementID] = "pending"
	st.mu.Unlock()
	// Release the placeholder on every path that does not hand it to a started run (including a panic).
	started := false
	defer func() {
		if !started {
			st.mu.Lock()
			if st.active[req.EngagementID] == "pending" {
				delete(st.active, req.EngagementID)
			}
			st.mu.Unlock()
		}
	}()

	runID, err := st.store.CreateRun(r.Context(), req.EngagementID)
	if err != nil {
		log.Printf("[aleef] create run: %v", err)
		jsonError(w, "could not create run", http.StatusInternalServerError)
		return
	}
	if st.afterCreateRun != nil {
		st.afterCreateRun() // test hook: pause between CreateRun and registration
	}
	ctx, cancel := context.WithCancel(st.rootCtx)
	run := &aleefRun{id: runID, engagementID: req.EngagementID, startedAt: time.Now().UTC(), cancel: cancel, status: aleefRunning}
	st.mu.Lock()
	if st.closed {
		// shutdown began after the first check: nothing is registered, no goroutine starts, and the
		// run row just created must not stay 'running'. wg.Add happens only below, under this lock
		// and only when not closed, so it can never race shutdown's wg.Wait.
		st.mu.Unlock()
		cancel()
		pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := st.store.MarkRunFinished(pctx, runID, aleefstore.RunHalted, "server shutdown", nil, nil); err != nil {
			log.Printf("[aleef] run %s: could not mark the run halted: %v", runID, err)
		}
		pcancel()
		jsonError(w, "the server is shutting down", http.StatusServiceUnavailable)
		return
	}
	st.runs[runID] = run
	st.active[req.EngagementID] = runID
	st.wg.Add(1)
	started = true
	st.mu.Unlock()

	cfg.Recorder = &presetRunRecorder{Store: st.store, runID: runID}
	h.auditLog(r, "aleef.run.start", runID, map[string]any{"engagement_id": req.EngagementID}, "ok")
	go st.execute(ctx, run, cfg)
	respondStatus(w, map[string]any{"run_id": runID, "status": aleefRunning, "engagement_id": req.EngagementID}, http.StatusAccepted)
}

// execute runs the campaign and records its outcome, in the database and in memory, on every path
// including a panic. The database write uses its own context so a cancelled run still persists.
func (st *aleefState) execute(ctx context.Context, run *aleefRun, cfg campaign.Config) {
	defer st.wg.Done()
	var rep campaign.Report
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("campaign panicked: %v", p)
			}
		}()
		rep, err = st.runFn(ctx, cfg)
	}()
	run.cancel()

	st.mu.Lock()
	stopReason := run.stopReason
	stopped := run.stopRequested
	st.mu.Unlock()
	if stopped && stopReason == "" {
		stopReason = "stopped by operator"
	}
	var memStatus, dbStatus, reason string
	switch {
	case err != nil:
		memStatus, dbStatus, reason = aleefFailed, aleefstore.RunFailed, truncate(err.Error(), 500)
		log.Printf("[aleef] run %s failed: %s", run.id, reason)
	case stopped:
		memStatus, dbStatus, reason = aleefStopped, aleefstore.RunHalted, stopReason
		if rep.Halted != "" {
			reason += "; " + rep.Halted
		}
	case rep.Halted != "":
		memStatus, dbStatus, reason = aleefHalted, aleefstore.RunHalted, rep.Halted
	default:
		memStatus, dbStatus = aleefCompleted, aleefstore.RunCompleted
	}
	var reportJSON []byte
	if err == nil || rep.RunID != "" {
		reportJSON, _ = json.Marshal(rep)
	}
	orphans := rep.Orphans
	if orphans == nil {
		orphans = []model.CreatedObject{}
	}
	orphansJSON, _ := json.Marshal(orphans)
	pctx, pcancel := context.WithTimeout(context.Background(), 15*time.Second)
	if perr := st.store.MarkRunFinished(pctx, run.id, dbStatus, reason, reportJSON, orphansJSON); perr != nil {
		log.Printf("[aleef] run %s: could not persist the outcome: %v", run.id, perr)
	}
	pcancel()

	st.mu.Lock()
	defer st.mu.Unlock()
	run.finishedAt = time.Now().UTC()
	run.report = &rep
	run.status = memStatus
	if err != nil {
		run.errMsg = reason
	}
	if st.active[run.engagementID] == run.id {
		delete(st.active, run.engagementID)
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// pruneLocked drops finished runs kept longer than aleefKeepFinished.
func (st *aleefState) pruneLocked() {
	for id, run := range st.runs {
		if !run.finishedAt.IsZero() && time.Since(run.finishedAt) > aleefKeepFinished {
			delete(st.runs, id)
		}
	}
}

// buildAleefConfig validates the request against the stored engagement and builds the campaign
// config. It sends no request. On refusal it returns the HTTP status and message.
func (h *Handler) buildAleefConfig(ctx context.Context, req aleefRunReq) (campaign.Config, int, string) {
	var zero campaign.Config
	rec, err := h.aleef.store.GetEngagement(ctx, req.EngagementID)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, http.StatusBadRequest, "engagement not found"
	}
	if err != nil {
		log.Printf("[aleef] load engagement: %v", err)
		return zero, http.StatusInternalServerError, "could not load engagement"
	}
	var se storedEngagement
	if err := json.Unmarshal(rec.Body, &se); err != nil || len(se.Engagement) == 0 {
		return zero, http.StatusBadRequest, "engagement record is unreadable"
	}
	eng, err := safety.Parse(se.Engagement)
	if err != nil {
		return zero, http.StatusBadRequest, "engagement is not valid: " + err.Error()
	}
	eng.ID = rec.ID
	if err := eng.InWindow(time.Now()); err != nil {
		return zero, http.StatusConflict, "engagement is outside its approved window"
	}
	var scope *targetscope.TargetScopeImport
	if se.TargetScopeID != "" {
		scope, err = db.GetTargetScopeImport(ctx, h.db, se.TargetScopeID)
		if err != nil {
			return zero, http.StatusBadRequest, "engagement target scope not found"
		}
	}
	u, err := url.Parse(req.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return zero, http.StatusBadRequest, "base_url must be an http(s) URL without credentials"
	}
	if err := eng.Authorize(u.Scheme+"://"+u.Host, scope, time.Now()); err != nil {
		return zero, http.StatusBadRequest, "base_url is not authorised by the engagement: " + err.Error()
	}

	// input shape and size limits
	if len(req.OpenAPI) == 0 {
		return zero, http.StatusBadRequest, "openapi is required"
	}
	spec := []byte(req.OpenAPI)
	if spec[0] == '"' {
		var s string
		if err := json.Unmarshal(spec, &s); err != nil {
			return zero, http.StatusBadRequest, "openapi is not valid"
		}
		spec = []byte(s)
	}
	if n := len(req.Accounts); n == 0 || n > maxAleefAccounts {
		return zero, http.StatusBadRequest, fmt.Sprintf("accounts: between 1 and %d are required", maxAleefAccounts)
	}
	if len(req.Setup) > maxAleefSetup || len(req.Classes) > maxAleefClasses || len(req.Options.Variations) > maxAleefVariations {
		return zero, http.StatusBadRequest, "setup, classes or variations exceed the limits"
	}
	if o := req.Options; o.MaxTests < 0 || o.MaxTests > maxAleefMaxTests || o.Reproductions < 0 || o.Reproductions > maxAleefReproductions {
		return zero, http.StatusBadRequest, "options out of range"
	}
	accounts := make([]model.Account, 0, len(req.Accounts))
	for i, a := range req.Accounts {
		if a.Name == "" || a.CustomerID == "" || a.Role == "" || len(a.Name) > 64 || len(a.CustomerID) > 128 || len(a.Role) > 64 {
			return zero, http.StatusBadRequest, fmt.Sprintf("accounts[%d]: name, customer_id and role are required", i)
		}
		// Only references the administrator declared for this engagement may be used. "Not allowed",
		// "does not exist" and "cannot be resolved" all answer with the same message, so the response
		// is no oracle for which references exist on the server. The value is never repeated.
		if !slices.Contains(eng.TokenRefs, a.TokenRef) {
			return zero, http.StatusBadRequest, aleefTokenRefRefused
		}
		if _, err := h.aleef.secrets.Resolve(a.TokenRef); err != nil {
			return zero, http.StatusBadRequest, aleefTokenRefRefused
		}
		accounts = append(accounts, model.Account{Name: a.Name, CustomerID: a.CustomerID, TokenRef: a.TokenRef, Role: a.Role})
	}
	setup := make([]model.SetupOp, 0, len(req.Setup))
	for _, s := range req.Setup {
		setup = append(setup, model.SetupOp{OperationID: s.OperationID, Body: s.Body, Compensate: s.Compensate})
	}
	classes := make(map[string]model.OpClass, len(req.Classes))
	for op, c := range req.Classes {
		if !slices.Contains(aleefClasses, model.OpClass(c)) {
			return zero, http.StatusBadRequest, fmt.Sprintf("classes: %q is not an operation class", c)
		}
		classes[op] = model.OpClass(c)
	}
	cfg := campaign.Config{
		OpenAPI: spec, BaseURL: req.BaseURL, Engagement: eng, Scope: scope,
		Accounts: accounts, Setup: setup, Classes: classes,
		Secrets: h.aleef.secrets, HTTP: h.aleef.httpClient,
		Options: campaign.Options{Seed: req.Options.Seed, MaxTests: req.Options.MaxTests,
			Reproductions: req.Options.Reproductions, Variations: req.Options.Variations},
	}
	// The engagement's classes are the ceiling: a request may keep or tighten a class, never loosen it,
	// and setup and compensating operations are checked against the engagement's classification.
	// Nothing is sent to the target here.
	if err := campaign.Validate(cfg); err != nil {
		return zero, http.StatusBadRequest, err.Error()
	}
	return cfg, 0, ""
}

type aleefRunView struct {
	RunID        string     `json:"run_id"`
	EngagementID string     `json:"engagement_id,omitempty"`
	Status       string     `json:"status"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	Error        string     `json:"error,omitempty"`
	HaltedReason string     `json:"halted_reason,omitempty"`
	Orphans      any        `json:"orphans,omitempty"`
	Report       any        `json:"report,omitempty"`
}

func (st *aleefState) view(id string) (aleefRunView, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	run, ok := st.runs[id]
	if !ok {
		return aleefRunView{}, false
	}
	// Same vocabulary as the database: an operator or shutdown stop reads 'halted'.
	status := run.status
	if status == aleefStopped || status == aleefHalted {
		status = aleefstore.RunHalted
	}
	v := aleefRunView{RunID: run.id, EngagementID: run.engagementID, Status: status, Error: run.errMsg}
	t := run.startedAt
	v.StartedAt = &t
	if !run.finishedAt.IsZero() {
		f := run.finishedAt
		v.FinishedAt = &f
	}
	if run.report != nil {
		rep := *run.report
		v.Report = &rep
		v.Orphans = rep.Orphans
	}
	v.HaltedReason = run.stopReason
	if v.HaltedReason == "" && run.report != nil {
		v.HaltedReason = run.report.Halted
	}
	return v, true
}

// GetAleefRun returns a run's status and, once finished, the campaign report (ids, counts,
// per-operation coverage, halted reason). The report holds no secrets or bodies.
func (h *Handler) GetAleefRun(w http.ResponseWriter, r *http.Request) {
	if !h.aleefReady(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if !aleefIDRe.MatchString(id) {
		jsonError(w, "aleef run not found", http.StatusNotFound)
		return
	}
	if v, ok := h.aleef.view(id); ok {
		respond(w, v)
		return
	}
	rec, err := h.aleef.store.GetRunRecord(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, "aleef run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load run", http.StatusInternalServerError)
		return
	}
	// Not in memory (server restart or retention): the persisted outcome is authoritative. A run
	// that was cut short by a restart reads 'interrupted'.
	v := aleefRunView{RunID: id, EngagementID: rec.EngagementID, Status: rec.Status, StartedAt: &rec.CreatedAt,
		FinishedAt: rec.FinishedAt, HaltedReason: rec.HaltedReason}
	if len(rec.Report) > 0 {
		v.Report = json.RawMessage(rec.Report)
		if v.HaltedReason == "" {
			var h struct{ Halted string }
			if json.Unmarshal(rec.Report, &h) == nil {
				v.HaltedReason = h.Halted
			}
		}
	}
	if len(rec.Orphans) > 0 && string(rec.Orphans) != "[]" {
		v.Orphans = json.RawMessage(rec.Orphans)
	}
	respond(w, v)
}

// StopAleefRun cancels a running campaign. It is idempotent: it answers 200 for a run that is
// stopping or already finished. The campaign still compensates everything it created.
func (h *Handler) StopAleefRun(w http.ResponseWriter, r *http.Request) {
	if !h.aleefReady(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if !aleefIDRe.MatchString(id) {
		jsonError(w, "aleef run not found", http.StatusNotFound)
		return
	}
	st := h.aleef
	st.mu.Lock()
	run, ok := st.runs[id]
	if ok {
		status := run.status
		if status == aleefRunning || status == aleefStopping {
			run.stopRequested = true
			if run.stopReason == "" {
				run.stopReason = "stopped by operator"
			}
			run.status = aleefStopping
			status = aleefStopping
			run.cancel()
		}
		if status == aleefStopped {
			status = aleefstore.RunHalted // database vocabulary
		}
		st.mu.Unlock()
		h.auditLog(r, "aleef.run.stop", id, map[string]any{"status": status}, "ok")
		respond(w, map[string]any{"run_id": id, "status": status})
		return
	}
	st.mu.Unlock()
	if _, _, err := st.store.GetRun(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "aleef run not found", http.StatusNotFound)
			return
		}
		jsonError(w, "could not load run", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"run_id": id, "status": "not_running"})
}

type aleefFindingView struct {
	ID             string    `json:"id"`
	RunID          string    `json:"run_id"`
	TestID         string    `json:"test_id"`
	PropertyID     string    `json:"property_id"`
	Title          string    `json:"title"`
	State          string    `json:"state"`
	EvidenceHash   string    `json:"evidence_hash,omitempty"`
	PriorKnowledge string    `json:"prior_knowledge"`
	NoveltyLabel   string    `json:"novelty_label"`
	RegressionID   string    `json:"regression_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

var aleefPropertyClassTitles = map[string]string{
	"OWN": "Object ownership", "ROLE": "Function-level authorization", "AUTH": "Authentication",
	"MC": "Maker-checker", "IDEM": "Idempotency", "STATE": "State transition", "RACE": "Race condition",
}

func aleefTitle(propertyID string) string {
	for _, p := range property.All() {
		if p.ID() == propertyID {
			if t, ok := aleefPropertyClassTitles[p.Class()]; ok {
				return t + " property " + propertyID + " violated"
			}
		}
	}
	return "Property " + propertyID + " violated"
}

// aleefNovelty states what is known about prior reports. "new to Audspect" only means the
// reviewer found no public or vendor report; it never claims a finding is a zero-day.
func aleefNovelty(prior string) string {
	switch prior {
	case "checked_none_found":
		return "new to Audspect: no public or vendor report found by the reviewer"
	case "known_public":
		return "known: publicly reported"
	case "known_vendor":
		return "known: reported by the vendor"
	default:
		return "prior reports not checked"
	}
}

func aleefView(f aleefstore.Finding, regressionID string) aleefFindingView {
	return aleefFindingView{ID: f.ID, RunID: f.RunID, TestID: f.TestID, PropertyID: f.Property, Title: aleefTitle(f.Property),
		State: f.State, EvidenceHash: f.EvidenceHash, PriorKnowledge: f.PriorKnowledge, NoveltyLabel: aleefNovelty(f.PriorKnowledge),
		RegressionID: regressionID, CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt}
}

// ListAleefFindings returns findings in separate arrays that are never merged: candidates,
// verified, unconfirmed and rejected. verified comes from ListVerifiedWithRegression, so a verified
// finding without a saved regression is never listed as verified; it appears in
// pending_regression instead. Optional ?run_id= filters to one run.
func (h *Handler) ListAleefFindings(w http.ResponseWriter, r *http.Request) {
	if !h.aleefReady(w) {
		return
	}
	runID := r.URL.Query().Get("run_id")
	if runID != "" && !aleefIDRe.MatchString(runID) {
		jsonError(w, "run_id is invalid", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	st := h.aleef.store
	candidates, others, err := st.ListFindingsBy(ctx, runID)
	if err != nil {
		log.Printf("[aleef] list findings: %v", err)
		jsonError(w, "could not list findings", http.StatusInternalServerError)
		return
	}
	verified, err := st.ListVerifiedWithRegression(ctx, runID)
	if err != nil {
		jsonError(w, "could not list findings", http.StatusInternalServerError)
		return
	}
	pending, err := st.ListUnregressedVerified(ctx, runID)
	if err != nil {
		jsonError(w, "could not list findings", http.StatusInternalServerError)
		return
	}
	out := map[string][]aleefFindingView{
		"candidates": {}, "verified": {}, "unconfirmed": {}, "rejected": {}, "pending_regression": {},
	}
	for _, f := range candidates {
		out["candidates"] = append(out["candidates"], aleefView(f, ""))
	}
	for _, f := range others {
		key := "unconfirmed"
		if f.State == aleefstore.StateRejected {
			key = "rejected"
		}
		out[key] = append(out[key], aleefView(f, ""))
	}
	for _, f := range verified {
		regID := ""
		if reg, err := st.GetRegression(ctx, f.ID); err == nil {
			regID = reg.RegressionID
		}
		out["verified"] = append(out["verified"], aleefView(f, regID))
	}
	for _, f := range pending {
		v := aleefView(f, "")
		v.State = "verified_without_regression"
		out["pending_regression"] = append(out["pending_regression"], v)
	}
	respond(w, out)
}

// GetAleefRegression returns the stored regression bundle of a finding.
func (h *Handler) GetAleefRegression(w http.ResponseWriter, r *http.Request) {
	if !h.aleefReady(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if !aleefIDRe.MatchString(id) {
		jsonError(w, "finding not found", http.StatusNotFound)
		return
	}
	if _, err := h.aleef.store.GetFinding(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "finding not found", http.StatusNotFound)
			return
		}
		jsonError(w, "could not load finding", http.StatusInternalServerError)
		return
	}
	reg, err := h.aleef.store.GetRegression(r.Context(), id)
	if err != nil {
		jsonError(w, "no regression is saved for this finding", http.StatusNotFound)
		return
	}
	if !json.Valid(reg.BundleJSON) {
		jsonError(w, "stored regression is unreadable", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"finding_id": reg.FindingID, "regression_id": reg.RegressionID, "bundle": json.RawMessage(bytes.TrimSpace(reg.BundleJSON)),
		"yaml_note": reg.YAMLNote, "has_scenario_yaml": len(reg.ScenarioYAML) > 0, "created_at": reg.CreatedAt,
	})
}

// SetAleefPriorKnowledge records the reviewer's prior-knowledge check for a finding. The actor is
// the authenticated user. It never changes the finding's state.
func (h *Handler) SetAleefPriorKnowledge(w http.ResponseWriter, r *http.Request) {
	if !h.aleefReady(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if !aleefIDRe.MatchString(id) {
		jsonError(w, "finding not found", http.StatusNotFound)
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if !decodeAleefBody(w, r, maxAleefSmallBody, &body) {
		return
	}
	if !slices.Contains(aleefstore.PriorKnowledgeValues, body.Value) {
		jsonError(w, "value must be one of "+strings.Join(aleefstore.PriorKnowledgeValues, ", "), http.StatusBadRequest)
		return
	}
	if _, err := h.aleef.store.GetFinding(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "finding not found", http.StatusNotFound)
			return
		}
		jsonError(w, "could not load finding", http.StatusInternalServerError)
		return
	}
	if err := h.aleef.store.SetPriorKnowledge(r.Context(), id, body.Value, aleefActor(r)); err != nil {
		log.Printf("[aleef] set prior knowledge: %v", err)
		jsonError(w, "could not record prior knowledge", http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "aleef.finding.prior_knowledge", id, map[string]any{"value": body.Value}, "ok")
	respond(w, map[string]any{"finding_id": id, "prior_knowledge": body.Value, "novelty_label": aleefNovelty(body.Value)})
}
