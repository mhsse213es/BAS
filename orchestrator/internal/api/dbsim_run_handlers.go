package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/dbsim/dbjobs"
	"github.com/audspect/bas/internal/dbsim/dbrun"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// dbsimRunRecorder writes the scenario_runs row for a database run (dbjobs.RunRecorder).
type dbsimRunRecorder struct{ h *Handler }

func (r dbsimRunRecorder) RecordRun(ctx context.Context, row dbjobs.RunRow) error {
	if r.h == nil || r.h.db == nil {
		return errors.New("runs store unavailable")
	}
	return db.DBSimRunRecorder{Pool: r.h.db}.InsertRun(ctx, row.ID, row.ScenarioID, row.AgentID, row.Name, row.InitiatedBy, row.StartedAt)
}

// dbsimDispatcher sends command_scenario to an agent over the live connection
// (dbjobs.Dispatcher). An offline agent or a missing hub is "not sent".
type dbsimDispatcher struct{ h *Handler }

func (d dbsimDispatcher) Dispatch(_ context.Context, agentID string, cmd scenario.ScenarioCommand) bool {
	if d.h == nil || d.h.hub == nil {
		return false
	}
	return d.h.hub.SendToAgent(agentID, models.WSMessage{Type: models.MsgCommandScenario, AgentID: agentID, Data: cmd})
}

// dbsimCanceller sends command_cancel for a database run (dbjobs.Canceller).
type dbsimCanceller struct{ h *Handler }

func (c dbsimCanceller) Cancel(_ context.Context, agentID, runID string) bool {
	if c.h == nil || c.h.hub == nil {
		return false
	}
	return c.h.hub.SendToAgent(agentID, models.WSMessage{Type: models.MsgCommandCancel, AgentID: agentID, Data: map[string]string{"runId": runID}})
}

// dbsimRunService returns the job service, building it on first use. It returns
// nil when the scenario engine or the database is not loaded, so the route answers
// 503 instead of starting anything.
func (h *Handler) dbsimRunService() *dbjobs.Service {
	if h.engine == nil || h.db == nil {
		return nil
	}
	h.dbsimRunOnce.Do(func() {
		h.dbsimGrants = loadDBSimGrantSource()
		h.dbsimRunSvc = &dbjobs.Service{
			Targets:     db.DBSimTargetStore{Pool: h.db},
			Scenarios:   h.engine,
			Jobs:        db.DBSimJobStore{Pool: h.db},
			Dispatcher:  dbsimDispatcher{h: h},
			Canceller:   dbsimCanceller{h: h},
			Activity:    db.DBSimAgentActivity{Pool: h.db},
			Gate:        h.DBSimClientModeGate(),
			Audit:       dbsimAuditor{h: h},
			Runs:        dbsimRunRecorder{h: h},
			Sink:        dbsimRunSink{h: h},
			GrantPolicy: h.dbsimGrants.dbsimGrantPolicy,
		}
	})
	return h.dbsimRunSvc
}

type dbsimRunRequest struct {
	ScenarioIDs     []string `json:"scenarioIds"`
	LabConfirmation string   `json:"labConfirmation"`
}

// StartDBSimRun starts a database simulation run on a target's bound agent.
// POST /api/dbsim-targets/{id}/runs  {"scenarioIds":[...],"labConfirmation":"<target id>"}
func (h *Handler) StartDBSimRun(w http.ResponseWriter, r *http.Request) {
	svc := h.dbsimRunService()
	if svc == nil {
		jsonError(w, "database simulation runs are not configured on this server", http.StatusServiceUnavailable)
		return
	}
	var body dbsimRunRequest
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid run request", http.StatusBadRequest)
		return
	}
	actor := dbadmin.Actor{}
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		actor = dbadmin.Actor{ID: c.UserID, Role: c.Role}
	}
	actor.IP = r.Header.Get("X-Real-IP")
	if actor.IP == "" {
		actor.IP = r.RemoteAddr
	}
	job, err := svc.Start(r.Context(), actor, dbjobs.StartRequest{
		TargetID:        chi.URLParam(r, "id"),
		ScenarioIDs:     body.ScenarioIDs,
		LabConfirmation: body.LabConfirmation,
	})
	if err != nil {
		dbsimRunError(w, err)
		return
	}
	respond(w, map[string]any{"runId": job.ID, "status": job.Status, "agentId": job.AgentID, "scenarioIds": job.ScenarioIDs})
}

func dbsimRunError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, dbjobs.ErrNotPermitted):
		jsonError(w, "not permitted to start database runs", http.StatusForbidden)
	case errors.Is(err, dbjobs.ErrBusy):
		jsonError(w, "the target or its agent already has an active job", http.StatusConflict)
	case errors.Is(err, dbjobs.ErrAgentOffline):
		jsonError(w, "the target's agent is offline; nothing was run", http.StatusConflict)
	case errors.Is(err, dbjobs.ErrNoRunRecorder):
		jsonError(w, "run recording is not configured; nothing was run", http.StatusServiceUnavailable)
	case errors.Is(err, dbjobs.ErrTargetNotReady):
		jsonError(w, "the target is not ready to run; check its identity first", http.StatusConflict)
	case errors.Is(err, dbjobs.ErrConfirmationRequired), errors.Is(err, dbjobs.ErrInvalidRequest):
		jsonError(w, err.Error(), http.StatusBadRequest)
	default:
		jsonError(w, "could not start the run", http.StatusInternalServerError)
	}
}

// submitDBSimResult grades an agent's result for a database run. The dbjobs
// service checks the agent is the one the job was bound to, grades every step,
// and stores the rows; the scenario grader never sees these results.
func (h *Handler) submitDBSimResult(ctx context.Context, w http.ResponseWriter, body []byte) {
	svc := h.dbsimRunService()
	if svc == nil {
		jsonError(w, "database simulation runs are not configured on this server", http.StatusServiceUnavailable)
		return
	}
	var sub struct {
		RunID   string            `json:"runId"`
		AgentID string            `json:"agentId"`
		Partial bool              `json:"partial"`
		Results []dbrun.AgentExec `json:"results"`
	}
	if err := json.Unmarshal(body, &sub); err != nil || sub.RunID == "" {
		jsonError(w, "invalid database result payload", http.StatusBadRequest)
		return
	}
	handled, err := svc.Ingest(ctx, dbjobs.Submission{RunID: sub.RunID, AgentID: sub.AgentID, Partial: sub.Partial, Results: sub.Results})
	if !handled {
		jsonError(w, "unknown database run", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("[dbsim] result for run %s not recorded: %v", sub.RunID, err)
		jsonError(w, "the result could not be graded or stored", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"status": "accepted", "runId": sub.RunID})
}
