//go:build dbsim_spike

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbbuild"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// TEMPORARY (dbsim run-experience Task 1 spike, build tag dbsim_spike). Proves a
// command_scenario can be dispatched with NO scenario_runs row, that events flow,
// and that the result reaches a hook placed after MAC verification. Never merged.
// It never logs secrets (a target holds only a credential reference, and the
// reference is not logged either) and never touches the database.

var dbsimSpikeRuns sync.Map // runID -> spikeRun

type spikeRun struct {
	AgentID    string
	ScenarioID string
	Steps      int
	SentAt     time.Time
}

func registerDBSimSpikeRoutes(r chi.Router, h *Handler) {
	r.With(auth.RequirePermission(auth.CanManageDBSimTargets)).Post("/api/dbsim-spike/run", h.dbsimSpikeRun)
}

type spikeTarget struct {
	Engine           string `json:"engine"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Database         string `json:"database"`
	TLSMode          string `json:"tlsMode"`
	CredentialRef    string `json:"credentialRef"`
	ExpectedIdentity string `json:"expectedIdentity"`
	Mode             string `json:"mode"`
}

// spikeResolver answers every target id the scenario names (for example
// "lab-db") with the one inline lab target, carrying the requested id.
type spikeResolver struct{ t dbsim.Target }

func (s spikeResolver) Resolve(ctx context.Context, id string) (dbsim.Target, error) {
	if err := ctx.Err(); err != nil {
		return dbsim.Target{}, err
	}
	t := s.t
	t.ID = id
	return t, nil
}

// POST /api/dbsim-spike/run
// {"agentId":"...","scenarioId":"dbsim-db01-auth-policy","target":{...mode "lab"}}
func (h *Handler) dbsimSpikeRun(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil || c.Role != auth.RoleAdmin {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		AgentID    string      `json:"agentId"`
		ScenarioID string      `json:"scenarioId"`
		Target     spikeTarget `json:"target"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.AgentID == "" || req.ScenarioID == "" {
		jsonError(w, "body must be {agentId, scenarioId, target{engine,host,port,database,tlsMode,credentialRef,expectedIdentity,mode}}", http.StatusBadRequest)
		return
	}
	if req.Target.Mode != "lab" {
		jsonError(w, `spike is lab only: target.mode must be "lab"`, http.StatusBadRequest)
		return
	}
	sc, found := h.engine.Get(req.ScenarioID)
	if !found || sc == nil {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	if !strings.EqualFold(sc.ProductLine, "dbsim") {
		jsonError(w, "spike refuses any scenario whose product line is not dbsim", http.StatusBadRequest)
		return
	}
	tgt := dbsim.Target{
		Engine: req.Target.Engine, Host: req.Target.Host, Port: req.Target.Port, Database: req.Target.Database,
		TLSMode: req.Target.TLSMode, CredentialRef: req.Target.CredentialRef,
		ExpectedIdentity: req.Target.ExpectedIdentity, Mode: dbsim.ModeLab, LabConfirmed: true,
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	runID := "spike-" + hex.EncodeToString(b)
	steps, err := dbbuild.BuildSteps(r.Context(), sc, dbbuild.Options{
		Resolver: spikeResolver{t: tgt}, ClientGate: nil, MutationApproved: true,
		RunExpiry: time.Now().Add(10 * time.Minute), RunID: runID,
	})
	if err != nil {
		jsonError(w, "build steps: "+dbsim.Redact(err.Error()), http.StatusBadRequest)
		return
	}
	cmd := scenario.ScenarioCommand{
		RunID: runID, ScenarioID: sc.ID, Name: sc.Name, Steps: steps, Mode: "lab",
		Policy: sc.LivePolicy, PreventScreenTimeout: sc.PreventScreenTimeout,
	}
	dbsimSpikeRuns.Store(runID, spikeRun{AgentID: req.AgentID, ScenarioID: sc.ID, Steps: len(steps), SentAt: time.Now()})
	sent := h.hub.SendToAgent(req.AgentID, models.WSMessage{Type: models.MsgCommandScenario, AgentID: req.AgentID, Data: cmd})
	if !sent {
		dbsimSpikeRuns.Delete(runID)
		jsonError(w, "agent is offline", http.StatusConflict)
		return
	}
	log.Printf("[dbsim-spike] dispatched run=%s scenario=%s agent=%s steps=%d (no scenario_runs row)", runID, sc.ID, req.AgentID, len(steps))
	respond(w, map[string]any{"runId": runID, "scenarioId": sc.ID, "agentId": req.AgentID, "steps": len(steps)})
}

// dbsimSpikeHook runs at the top of SubmitScenarioResult after MAC verification.
// If the run id was dispatched by the spike it logs the decoded results and
// answers 200 without touching the database; otherwise it returns false and the
// normal path continues unchanged.
func dbsimSpikeHook(_ *Handler, w http.ResponseWriter, body []byte) bool {
	var raw struct {
		RunID      string `json:"runId"`
		ScenarioID string `json:"scenarioId"`
		AgentID    string `json:"agentId"`
		Partial    bool   `json:"partial"`
		Results    []struct {
			TaskID   string          `json:"taskId"`
			ExitCode int             `json:"exitCode"`
			TimedOut bool            `json:"timedOut"`
			Vetoed   bool            `json:"vetoed"`
			DBProbe  json.RawMessage `json:"dbProbe"`
		} `json:"results"`
	}
	if json.Unmarshal(body, &raw) != nil || raw.RunID == "" {
		return false
	}
	v, ok := dbsimSpikeRuns.Load(raw.RunID)
	if !ok {
		return false
	}
	sr := v.(spikeRun)
	agentMatch := raw.AgentID == "" || raw.AgentID == sr.AgentID
	log.Printf("[dbsim-spike] RESULT run=%s scenario=%s agent=%q dispatchedAgent=%q agentMatch=%v results=%d expectedSteps=%d partial=%v elapsed=%s",
		raw.RunID, raw.ScenarioID, raw.AgentID, sr.AgentID, agentMatch, len(raw.Results), sr.Steps, raw.Partial, time.Since(sr.SentAt).Round(time.Millisecond))
	for i, res := range raw.Results {
		var pr struct {
			ProbeID    string `json:"probeId"`
			ErrorClass string `json:"errorClass"`
		}
		_ = json.Unmarshal(res.DBProbe, &pr) // field names are best effort; presence is what matters
		log.Printf("[dbsim-spike]   step %d task=%s exit=%d timedOut=%v vetoed=%v dbProbePresent=%v probe=%q errorClass=%q",
			i, res.TaskID, res.ExitCode, res.TimedOut, res.Vetoed, len(res.DBProbe) > 0 && string(res.DBProbe) != "null", pr.ProbeID, pr.ErrorClass)
	}
	dbsimSpikeRuns.Delete(raw.RunID)
	respond(w, map[string]any{"accepted": true, "spike": true})
	return true
}
