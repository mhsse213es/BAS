package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/dbsim/dbjobs"
	"github.com/audspect/bas/internal/dbsim/dbrun"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// The dbsim run path. Every dependency is the one the normal scenario path
// uses: the hub for dispatch and cancel, the scenario engine for lookups, the
// same stale-run rule for the agent-busy check, and the same audit writer.
// Nothing here is a spike.

// dbsimDispatch sends command_scenario to an agent over the hub.
type dbsimDispatch struct{ h *Handler }

func (d dbsimDispatch) Dispatch(_ context.Context, agentID string, cmd scenario.ScenarioCommand) bool {
	return d.h.hub.SendToAgent(agentID, models.WSMessage{Type: models.MsgCommandScenario, AgentID: agentID, Data: cmd})
}

// dbsimCancel sends command_cancel for one run to an agent.
type dbsimCancel struct{ h *Handler }

func (c dbsimCancel) Cancel(_ context.Context, agentID, runID string) bool {
	return c.h.hub.SendToAgent(agentID, models.WSMessage{Type: models.MsgCommandCancel, AgentID: agentID, Data: map[string]string{"runId": runID}})
}

// dbsimActivity reports whether an agent is running a normal scenario, using the
// same rule as the normal dispatch path (a stale run does not block).
type dbsimActivity struct{ h *Handler }

func (a dbsimActivity) HasRunningScenario(ctx context.Context, agentID string) (bool, error) {
	var started, lastUpdate time.Time
	var id string
	err := a.h.db.QueryRow(ctx,
		`SELECT sr.id, sr.started_at, a.last_update
		   FROM scenario_runs sr
		   JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.agent_id = $1 AND sr.status = 'running'
		  ORDER BY sr.started_at DESC LIMIT 1`, agentID,
	).Scan(&id, &started, &lastUpdate)
	if err != nil {
		// No running row is the normal answer; any other error fails closed.
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return !runIsStale(started, lastUpdate, time.Now()), nil
}

// dbsimPresence reports whether an agent is connected to the hub.
type dbsimPresence struct{ h *Handler }

func (p dbsimPresence) Online(agentID string) bool {
	return slices.Contains(p.h.hub.ConnectedAgents(), agentID)
}

// dbsimSink stores one graded row per scenario in dbsim_runs. A row for the same
// run and scenario already present is a duplicate, so re-submitted results
// are idempotent.
type dbsimSink struct{ h *Handler }

func (s dbsimSink) Save(ctx context.Context, rec dbjobs.RunRecord) (bool, error) {
	var n int
	if err := s.h.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM dbsim_runs WHERE run_id = $1 AND scenario_id = $2`, rec.RunID, rec.ScenarioID,
	).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	_, err := db.SaveDBSimRun(ctx, s.h.db, db.DBSimRun{
		ScenarioID: rec.ScenarioID, ScenarioVersion: rec.ScenarioVersion, TargetID: rec.TargetID,
		Engine: rec.Engine, RunID: rec.RunID, Result: rec.Result, Report: rec.Report,
	})
	return false, err
}

func (s dbsimSink) Count(ctx context.Context, runID string) (int, error) {
	var n int
	err := s.h.db.QueryRow(ctx, `SELECT COUNT(*) FROM dbsim_runs WHERE run_id = $1`, runID).Scan(&n)
	return n, err
}

// dbsimJobService wires the job service for one request. The Admin client-mode
// gate and the audit writer come from the same dbsim service the target
// handlers use.
func (h *Handler) dbsimJobService(svc *dbadmin.Service) *dbjobs.Service {
	return &dbjobs.Service{
		Targets:    db.DBSimTargetStore{Pool: h.db},
		Scenarios:  h.engine,
		Jobs:       db.DBSimJobStore{Pool: h.db},
		Dispatcher: dbsimDispatch{h: h},
		Canceller:  dbsimCancel{h: h},
		Activity:   dbsimActivity{h: h},
		Gate:       svc.Gate(),
		Audit:      dbsimAuditor{h: h},
		Sink:       dbsimSink{h: h},
		Presence:   dbsimPresence{h: h},
	}
}

// dbsimStartBody is the POST /api/dbsim-runs request. It has no mode field: the
// mode is the target's, never the request's.
type dbsimStartBody struct {
	TargetID        string   `json:"targetId"`
	ScenarioIDs     []string `json:"scenarioIds"`
	LabConfirmation string   `json:"labConfirmation"`
}

// dbsimStartStatus maps a start or cancel error to an HTTP status. Messages are
// the service's own redacted text.
func dbsimStartStatus(err error) int {
	switch {
	case errors.Is(err, dbjobs.ErrNotPermitted):
		return http.StatusForbidden
	case errors.Is(err, dbjobs.ErrBusy):
		return http.StatusConflict
	case errors.Is(err, dbjobs.ErrConfirmationRequired), errors.Is(err, dbjobs.ErrInvalidRequest):
		return http.StatusBadRequest
	case errors.Is(err, dbjobs.ErrTargetNotReady):
		return http.StatusConflict
	case errors.Is(err, dbjobs.ErrAgentOffline):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// StartDBSimRun handles POST /api/dbsim-runs.
func (h *Handler) StartDBSimRun(w http.ResponseWriter, r *http.Request) {
	var body dbsimStartBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		jsonError(w, "body must be {targetId, scenarioIds, labConfirmation}", http.StatusBadRequest)
		return
	}
	svc, actor := h.dbsimService(r)
	job, err := h.dbsimJobService(svc).Start(r.Context(), actor, dbjobs.StartRequest{
		TargetID: body.TargetID, ScenarioIDs: body.ScenarioIDs, LabConfirmation: body.LabConfirmation,
	})
	if err != nil {
		jsonError(w, dbsim.Redact(err.Error()), dbsimStartStatus(err))
		return
	}
	respondStatus(w, map[string]any{"runId": job.ID, "status": string(job.Status)}, http.StatusAccepted)
}

// CancelDBSimRun handles POST /api/dbsim-runs/{runId}/cancel.
func (h *Handler) CancelDBSimRun(w http.ResponseWriter, r *http.Request) {
	svc, actor := h.dbsimService(r)
	if err := h.dbsimJobService(svc).Cancel(r.Context(), actor, chi.URLParam(r, "runId")); err != nil {
		jsonError(w, dbsim.Redact(err.Error()), dbsimStartStatus(err))
		return
	}
	respond(w, map[string]any{"cancelled": true})
}

// GetDBSimJob handles GET /api/dbsim-jobs/{runId}: status and reason only.
func (h *Handler) GetDBSimJob(w http.ResponseWriter, r *http.Request) {
	job, err := (db.DBSimJobStore{Pool: h.db}).Get(r.Context(), chi.URLParam(r, "runId"))
	if err != nil {
		if errors.Is(err, dbsim.ErrJobNotFound) {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		jsonError(w, "could not load job", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"runId": job.ID, "status": string(job.Status), "reason": job.Reason, "targetId": job.TargetID, "agentId": job.AgentID})
}

// dbsimResultWire is the part of a submitted result the dbsim grader reads.
// Other fields (the normal path's) are left to that path.
type dbsimResultWire struct {
	RunID   string `json:"runId"`
	AgentID string `json:"agentId"`
	Partial bool   `json:"partial"`
	Results []struct {
		TaskID               string          `json:"taskId"`
		ExitCode             int             `json:"exitCode"`
		Stderr               string          `json:"stderr"`
		TimedOut             bool            `json:"timedOut"`
		Vetoed               bool            `json:"vetoed"`
		VetoedBlockSource    string          `json:"vetoedBlockSource"`
		VetoedActionKey      string          `json:"vetoedActionKey"`
		VetoedExecutionClass string          `json:"vetoedExecutionClass"`
		DBProbe              json.RawMessage `json:"dbProbe"`
	} `json:"results"`
}

// dbsimIngestResults maps a submitted result to the grader's input. The agent's
// probe output is decoded here; grading itself never trusts the agent's verdict.
func dbsimIngestResults(wire dbsimResultWire) ([]dbrun.AgentExec, error) {
	out := make([]dbrun.AgentExec, 0, len(wire.Results))
	for _, res := range wire.Results {
		e := dbrun.AgentExec{
			TaskID: res.TaskID, ExitCode: res.ExitCode, Stderr: res.Stderr, TimedOut: res.TimedOut,
			Vetoed: res.Vetoed, VetoedBlockSource: res.VetoedBlockSource,
			VetoedActionKey: res.VetoedActionKey, VetoedExecutionClass: res.VetoedExecutionClass,
		}
		if len(res.DBProbe) > 0 && string(res.DBProbe) != "null" {
			var p dbsim.DBProbeResult
			if err := json.Unmarshal(res.DBProbe, &p); err != nil {
				return nil, err
			}
			e.DBProbe = &p
		}
		out = append(out, e)
	}
	return out, nil
}

// dbsimIngestHook runs at the top of SubmitScenarioResult, after MAC
// verification. It returns true only when the run is a dbsim job and the
// response has been written. Any other run id returns false and the normal
// path runs unchanged.
func (h *Handler) dbsimIngestHook(w http.ResponseWriter, r *http.Request, body []byte) bool {
	var wire dbsimResultWire
	if err := json.Unmarshal(body, &wire); err != nil || wire.RunID == "" {
		return false
	}
	if _, err := (db.DBSimJobStore{Pool: h.db}).Get(r.Context(), wire.RunID); err != nil {
		// Not a dbsim job: the normal path handles it.
		return false
	}
	results, err := dbsimIngestResults(wire)
	if err != nil {
		jsonError(w, "dbsim: malformed probe result", http.StatusBadRequest)
		return true
	}
	svc, _ := h.dbsimService(r)
	handled, ierr := h.dbsimJobService(svc).Ingest(r.Context(), dbjobs.Submission{
		RunID: wire.RunID, AgentID: wire.AgentID, Partial: wire.Partial, Results: results,
	})
	if ierr != nil {
		log.Printf("dbsim: ingest run %s: %v", wire.RunID, ierr)
		jsonError(w, "dbsim: result not accepted", http.StatusConflict)
		return true
	}
	if !handled {
		return false
	}
	respond(w, map[string]any{"accepted": true, "dbsim": true})
	return true
}

// dbsimRunRoutes registers the run endpoints. They sit under the same
// permission gates as the other dbsim routes.
func registerDBSimRunRoutes(r chi.Router, h *Handler) {
	r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/dbsim-runs", h.StartDBSimRun)
	r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/dbsim-runs/{runId}/cancel", h.CancelDBSimRun)
	r.With(auth.RequirePermission(auth.CanViewDBSim)).Get("/api/dbsim-jobs/{runId}", h.GetDBSimJob)
}
