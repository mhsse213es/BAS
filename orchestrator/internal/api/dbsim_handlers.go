package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/reporting"
)

// Database security simulation: Admin settings, the target registry and the
// stored-run read endpoints. The decisions live in internal/dbsim/dbadmin (pure,
// testable without Docker); this file only maps HTTP to those calls.
//
// What is NOT here: a run API. Nothing yet builds a scenario from a registered
// target, dispatches it to an agent or persists the result, and no
// dbadmin.CheckRunner is installed, so POST /api/dbsim-targets/{id}/identity-check
// answers 501 until the dispatch path exists (see docs/dbsim-mastery-qa-log.md,
// Task 16 open items).

// dbsimAuditor writes audit rows synchronously (unlike the fire-and-forget
// auditLogAs) and reports failure, for rows that do not accompany a state change.
// State changes carry their audit row into the store's transaction instead.
type dbsimAuditor struct{ h *Handler }

func (a dbsimAuditor) Log(e dbadmin.AuditEntry) error {
	if a.h.db == nil {
		return errors.New("audit store unavailable")
	}
	detail := []byte("{}")
	if e.Detail != nil {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		detail = b
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := a.h.db.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome) VALUES ($1,$2,$3,$4,$5,$6)`,
		e.ActorID, e.Action, e.Resource, detail, e.IP, e.Outcome)
	return err
}

// dbsimAgentDirectory answers whether an agent id is enrolled, over the agents
// table (parameterised). Any failure answers "not known" with the error, so a
// registration is refused (fail closed).
type dbsimAgentDirectory struct{ h *Handler }

func (d dbsimAgentDirectory) Exists(ctx context.Context, agentID string) (bool, error) {
	if d.h == nil || d.h.db == nil {
		return false, errors.New("agents store unavailable")
	}
	var ok bool
	if err := d.h.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = $1)`, agentID).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

// WithDBSimCheckRunner installs the dispatcher that runs the read-only identity
// check on an agent. Until one is installed the check endpoint reports 501.
func (h *Handler) WithDBSimCheckRunner(r dbadmin.CheckRunner) *Handler {
	h.dbsimCheckRunner = r
	return h
}

// DBSimClientModeGate is the ClientModeGate to inject into dbsim.Authorize /
// dbbuild.Options: the stored setting, read fail closed.
func (h *Handler) DBSimClientModeGate() dbsim.ClientModeGate {
	return (&dbadmin.Service{Settings: db.DBSimSettingsStore{Pool: h.db}}).Gate()
}

// dbsimService builds the per-request Admin service (stateless over the pool).
func (h *Handler) dbsimService(r *http.Request) (*dbadmin.Service, dbadmin.Actor) {
	actor := dbadmin.Actor{}
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		actor = dbadmin.Actor{ID: c.UserID, Role: c.Role}
	}
	actor.IP = r.Header.Get("X-Real-IP")
	if actor.IP == "" {
		actor.IP = r.RemoteAddr
	}
	return &dbadmin.Service{
		Settings: db.DBSimSettingsStore{Pool: h.db},
		Targets:  db.DBSimTargetStore{Pool: h.db},
		Audit:    dbsimAuditor{h: h},
		Runner:   h.dbsimCheckRunner,
		Agents:   dbsimAgentDirectory{h: h},
	}, actor
}

// dbsimFail maps a service error to an HTTP status. Unexpected errors are logged
// and answered generically (no internals in the body).
func dbsimFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, dbadmin.ErrForbidden):
		jsonError(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, dbsim.ErrTargetInvalid):
		jsonError(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, dbsim.ErrTargetExists):
		jsonError(w, "a target with that id is already registered", http.StatusConflict)
	case errors.Is(err, dbsim.ErrTargetChanged):
		jsonError(w, "the target was changed or re-registered while the check ran; nothing was recorded, run the check again", dbadmin.StatusFor(err))
	case errors.Is(err, dbsim.ErrIdentityCheckSuperseded):
		jsonError(w, "a newer identity check result is already recorded; this older result was discarded", dbadmin.StatusFor(err))
	case errors.Is(err, dbsim.ErrTargetNotFound):
		jsonError(w, "target not found", http.StatusNotFound)
	case errors.Is(err, dbadmin.ErrIdentityCheckUnavailable):
		jsonError(w, "the read-only identity check cannot be dispatched yet: no agent dispatch is configured; the target stays unverified", http.StatusNotImplemented)
	default:
		log.Printf("[api] dbsim: %v", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
	}
}

type dbsimIdentityCheckView struct {
	Checked bool      `json:"checked"`
	Passed  bool      `json:"passed"`
	At      time.Time `json:"at"`
	By      string    `json:"by"`
	Reasons []string  `json:"reasons"`
}

type dbsimTargetView struct {
	ID               string                 `json:"id"`
	DisplayName      string                 `json:"displayName"`
	Engine           string                 `json:"engine"`
	Host             string                 `json:"host"`
	Port             int                    `json:"port"`
	DBServerHost     string                 `json:"dbServerHost"`
	Database         string                 `json:"database"`
	TLSMode          string                 `json:"tlsMode"`
	CredentialRef    string                 `json:"credentialRef"`
	AgentID          string                 `json:"agentId"`
	ExpectedIdentity string                 `json:"expectedIdentity"`
	Mode             string                 `json:"mode"`
	LabConfirmed     bool                   `json:"labConfirmed"`
	CreatedBy        string                 `json:"createdBy"`
	CreatedAt        time.Time              `json:"createdAt"`
	IdentityCheck    dbsimIdentityCheckView `json:"identityCheck"`
	// ClientEligible is true only for a client target whose latest read-only
	// identity check passed. It still needs the Admin client-mode setting.
	ClientEligible bool `json:"clientEligible"`
}

// now is the service clock (Service.Clock), so the view and the gates agree on expiry.
func dbsimView(r dbsim.TargetRecord, now time.Time) dbsimTargetView {
	reasons := r.IdentityCheck.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	return dbsimTargetView{
		ID: r.ID, DisplayName: r.DisplayName, Engine: r.Engine, Host: r.Host, Port: r.Port, DBServerHost: r.DBServerHost,
		Database: r.Database, TLSMode: r.TLSMode, CredentialRef: r.CredentialRef, AgentID: r.AgentID, ExpectedIdentity: r.ExpectedIdentity,
		Mode: string(r.Mode), LabConfirmed: r.LabConfirmed, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		IdentityCheck:  dbsimIdentityCheckView{Checked: r.IdentityCheck.Checked, Passed: r.IdentityCheck.Passed, At: r.IdentityCheck.At, By: r.IdentityCheck.By, Reasons: reasons},
		ClientEligible: r.ToTargetAt(now, dbsim.DefaultIdentityCheckMaxAge).ReadOnlyIdentityVerified,
	}
}

// GetDBSimSettings returns the DB client mode setting (fail closed: false when
// unset or unreadable).
// GET /api/dbsim/settings
func (h *Handler) GetDBSimSettings(w http.ResponseWriter, r *http.Request) {
	svc, _ := h.dbsimService(r)
	respond(w, map[string]any{"clientModeEnabled": svc.ClientModeEnabled()})
}

// SetDBSimClientMode switches DB client mode (Admin only, audited).
// PUT /api/dbsim/settings/client-mode  {"enabled": true|false}
func (h *Handler) SetDBSimClientMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Enabled == nil {
		jsonError(w, `body must be {"enabled": true|false}`, http.StatusBadRequest)
		return
	}
	svc, actor := h.dbsimService(r)
	if err := svc.SetClientMode(r.Context(), actor, *req.Enabled); err != nil {
		dbsimFail(w, err)
		return
	}
	respond(w, map[string]any{"clientModeEnabled": svc.ClientModeEnabled()})
}

// ListDBSimTargets lists registered targets.
// GET /api/dbsim-targets
func (h *Handler) ListDBSimTargets(w http.ResponseWriter, r *http.Request) {
	svc, actor := h.dbsimService(r)
	recs, err := svc.ListTargets(r.Context(), actor)
	if err != nil {
		dbsimFail(w, err)
		return
	}
	out := make([]dbsimTargetView, 0, len(recs))
	for _, rec := range recs {
		out = append(out, dbsimView(rec, svc.Clock()))
	}
	respond(w, map[string]any{"targets": out})
}

// GetDBSimTarget returns one target.
// GET /api/dbsim-targets/{id}
func (h *Handler) GetDBSimTarget(w http.ResponseWriter, r *http.Request) {
	svc, actor := h.dbsimService(r)
	rec, err := svc.GetTarget(r.Context(), actor, chi.URLParam(r, "id"))
	if err != nil {
		dbsimFail(w, err)
		return
	}
	respond(w, dbsimView(rec, svc.Clock()))
}

// RegisterDBSimTarget registers a target with its expected identity (Admin
// only, audited). Unknown JSON fields are refused, so a password sent by
// mistake is rejected rather than ignored or stored.
// POST /api/dbsim-targets
func (h *Handler) RegisterDBSimTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID               string `json:"id"`
		DisplayName      string `json:"displayName"`
		Engine           string `json:"engine"`
		Host             string `json:"host"`
		Port             int    `json:"port"`
		DBServerHost     string `json:"dbServerHost"`
		Database         string `json:"database"`
		TLSMode          string `json:"tlsMode"`
		CredentialRef    string `json:"credentialRef"`
		AgentID          string `json:"agentId"`
		ExpectedIdentity string `json:"expectedIdentity"`
		Mode             string `json:"mode"`
		LabConfirmed     bool   `json:"labConfirmed"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonError(w, "invalid body: unknown or malformed fields (a target holds a credentialRef, never a password)", http.StatusBadRequest)
		return
	}
	svc, actor := h.dbsimService(r)
	rec, err := svc.RegisterTarget(r.Context(), actor, dbsim.TargetRegistration{
		ID: req.ID, DisplayName: req.DisplayName, Engine: req.Engine, Host: req.Host, Port: req.Port,
		DBServerHost: req.DBServerHost, Database: req.Database, TLSMode: req.TLSMode, CredentialRef: req.CredentialRef, AgentID: req.AgentID,
		ExpectedIdentity: req.ExpectedIdentity, Mode: dbsim.ExecMode(req.Mode), LabConfirmed: req.LabConfirmed,
	})
	if err != nil {
		dbsimFail(w, err)
		return
	}
	respondStatus(w, dbsimView(rec, svc.Clock()), http.StatusCreated)
}

// DeleteDBSimTarget removes a target (Admin only, audited).
// DELETE /api/dbsim-targets/{id}
func (h *Handler) DeleteDBSimTarget(w http.ResponseWriter, r *http.Request) {
	svc, actor := h.dbsimService(r)
	if err := svc.DeleteTarget(r.Context(), actor, chi.URLParam(r, "id")); err != nil {
		dbsimFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RunDBSimIdentityCheck runs the read-only identity check (Admin only, audited).
// 501 until an agent dispatch is installed (WithDBSimCheckRunner).
// POST /api/dbsim-targets/{id}/identity-check
func (h *Handler) RunDBSimIdentityCheck(w http.ResponseWriter, r *http.Request) {
	svc, actor := h.dbsimService(r)
	verdict, rec, err := svc.RunIdentityCheck(r.Context(), actor, chi.URLParam(r, "id"))
	if err != nil {
		dbsimFail(w, err)
		return
	}
	reasons := verdict.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	respond(w, map[string]any{"passed": verdict.Passed, "reasons": reasons, "target": dbsimView(rec, svc.Clock())})
}

type dbsimRunView struct {
	ID              string          `json:"id"`
	ScenarioID      string          `json:"scenarioId"`
	ScenarioVersion string          `json:"scenarioVersion"`
	TargetID        string          `json:"targetId"`
	Engine          string          `json:"engine"`
	RunID           string          `json:"runId"`
	Result          string          `json:"result"`
	CreatedAt       time.Time       `json:"createdAt"`
	Report          json.RawMessage `json:"report,omitempty"`
}

func dbsimRunToView(r db.DBSimRun, withReport bool) dbsimRunView {
	v := dbsimRunView{ID: r.ID, ScenarioID: r.ScenarioID, ScenarioVersion: r.ScenarioVersion, TargetID: r.TargetID,
		Engine: r.Engine, RunID: r.RunID, Result: r.Result, CreatedAt: r.CreatedAt}
	if withReport && json.Valid(r.Report) {
		v.Report = json.RawMessage(r.Report)
	}
	return v
}

// ListDBSimRuns lists stored runs, newest first, without report bodies.
// GET /api/dbsim-runs?scenario=&target=&limit=
func (h *Handler) ListDBSimRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := db.ListDBSimRuns(r.Context(), h.db, r.URL.Query().Get("scenario"), r.URL.Query().Get("target"), limit)
	if err != nil {
		dbsimFail(w, err)
		return
	}
	out := make([]dbsimRunView, 0, len(runs))
	for _, run := range runs {
		out = append(out, dbsimRunToView(run, false))
	}
	respond(w, map[string]any{"runs": out})
}

// GetDBSimRun returns one stored run including its report.
// GET /api/dbsim-runs/{id}
func (h *Handler) GetDBSimRun(w http.ResponseWriter, r *http.Request) {
	run, err := db.GetDBSimRun(r.Context(), h.db, chi.URLParam(r, "id"))
	if errors.Is(err, db.ErrDBSimRunNotFound) {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		dbsimFail(w, err)
		return
	}
	respond(w, dbsimRunToView(run, true))
}

// GetDBSimRunReport renders one stored run as a printable HTML report. It
// renders the persisted report only; it never re-grades and never touches any
// score.
// GET /api/dbsim-runs/{id}/report
func (h *Handler) GetDBSimRunReport(w http.ResponseWriter, r *http.Request) {
	run, err := db.GetDBSimRun(r.Context(), h.db, chi.URLParam(r, "id"))
	writeDBSimRunReport(w, run, err)
}

// writeDBSimRunReport answers the report request from an already-loaded run
// (or the load error). Split out so it is testable without a database.
func writeDBSimRunReport(w http.ResponseWriter, run db.DBSimRun, err error) {
	reporting.SetDBSimReportHeaders(w.Header())
	if errors.Is(err, db.ErrDBSimRunNotFound) {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("dbsim: load run for report: %v", err)
		jsonError(w, "could not load run", http.StatusInternalServerError)
		return
	}
	var stored dbsim.StoredReport
	if err := json.Unmarshal(run.Report, &stored); err != nil {
		log.Printf("dbsim: report for run %s is not readable: %v", run.ID, err)
		jsonError(w, "stored report is not readable", http.StatusInternalServerError)
		return
	}
	page, err := reporting.BuildDBSimReport(stored, reporting.DBSimReportOptions{RunID: run.RunID})
	if err != nil {
		log.Printf("dbsim: render report for run %s: %v", run.ID, err)
		jsonError(w, "could not render report", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(page))
}
