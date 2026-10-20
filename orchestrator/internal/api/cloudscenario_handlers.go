package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
)

// maxObserveWindow bounds how far either side of the action time an audit
// search may look. A wider window would turn one scenario run into an
// unbounded log query.
const maxObserveWindow = time.Hour

// cloudScenarioRunBody is the POST body for one scenario run. Observe is
// optional; when present, predictions are checked against the provider's audit
// log for an execution at ActionTime.
type cloudScenarioRunBody struct {
	ScenarioID string                  `json:"scenarioId"`
	Account    cloudgraph.AccountScope `json:"account"`
	Principal  string                  `json:"principal"`
	Resource   string                  `json:"resource"`
	Observe    *struct {
		ActionTime    time.Time `json:"actionTime"`
		WindowSeconds int       `json:"windowSeconds"`
	} `json:"observe,omitempty"`
}

// GET /api/cloud-scenarios -- the builtin scenario catalogue. Read-only and
// open to any authenticated user, matching the cloud-runs listing.
func (h *Handler) ListCloudScenarios(w http.ResponseWriter, r *http.Request) {
	type stepView struct {
		Name         string `json:"name"`
		TechniqueTag string `json:"techniqueTag"`
		Kind         string `json:"kind"`
		Action       string `json:"action"`
	}
	type scenarioView struct {
		ID          string     `json:"id"`
		Name        string     `json:"name"`
		Provider    string     `json:"provider"`
		Description string     `json:"description"`
		Steps       []stepView `json:"steps"`
	}
	var out []scenarioView
	for _, s := range cloudgraph.BuiltinCloudScenarios() {
		v := scenarioView{ID: s.ID, Name: s.Name, Provider: s.Provider, Description: s.Description}
		for _, st := range s.Steps {
			v.Steps = append(v.Steps, stepView{Name: st.Name, TechniqueTag: st.TechniqueTag, Kind: st.Kind, Action: st.Action})
		}
		out = append(out, v)
	}
	respond(w, map[string]any{"scenarios": out})
}

// POST /api/cloud-scenario-runs -- runs one builtin scenario against a live
// discovery pass for the named account, optionally observing audit evidence.
// Credentials come from server configuration only.
func (h *Handler) TriggerCloudScenarioRun(w http.ResponseWriter, r *http.Request) {
	var body cloudScenarioRunBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateCloudScenarioRunBody(body); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := db.CloudScenarioRunRequest{
		ScenarioID: body.ScenarioID,
		Account:    body.Account,
		Principal:  body.Principal,
		Resource:   body.Resource,
	}
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		req.InitiatedBy = c.UserID
	}

	discoverer, err := cloudDiscovererFor(r.Context(), body.Account)
	if err != nil {
		h.auditCloudScenario(r, body, "", err)
		jsonError(w, err.Error(), discoveryStatusCode(err))
		return
	}
	req.Discoverer = discoverer

	if body.Observe != nil {
		source, err := cloudEventSourceFor(r.Context(), body.Account)
		if err != nil {
			h.auditCloudScenario(r, body, "", err)
			jsonError(w, err.Error(), discoveryStatusCode(err))
			return
		}
		req.Observe = &db.ObserveSpec{
			ActionTime: body.Observe.ActionTime,
			Window:     time.Duration(body.Observe.WindowSeconds) * time.Second,
			Events:     source,
		}
	}

	run, err := db.ExecuteCloudScenarioRun(r.Context(), h.db, req)
	if err != nil {
		runID := ""
		if run != nil {
			runID = run.ID
		}
		h.auditCloudScenario(r, body, runID, err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditCloudScenario(r, body, run.ID, nil)
	respondStatus(w, run, http.StatusCreated)
}

func (h *Handler) auditCloudScenario(r *http.Request, body cloudScenarioRunBody, runID string, err error) {
	detail := map[string]any{"scenarioId": body.ScenarioID, "provider": body.Account.Provider}
	outcome := "ok"
	if err != nil {
		detail["error"] = err.Error()
		outcome = "error"
	}
	h.auditLog(r, "cloudscenario.run", runID, detail, outcome)
}

// validateCloudScenarioRunBody checks a scenario run request before any
// credential is read or any row is written.
func validateCloudScenarioRunBody(b cloudScenarioRunBody) error {
	scenario := cloudgraph.CloudScenarioByID(b.ScenarioID)
	if scenario == nil {
		return fmt.Errorf("unknown scenarioId %q", b.ScenarioID)
	}
	if b.Account.Provider != scenario.Provider {
		return fmt.Errorf("scenario %s targets %s; account provider is %q", scenario.ID, scenario.Provider, b.Account.Provider)
	}
	if b.Account.AccountID == "" {
		return errors.New("account.accountId required")
	}
	if b.Principal == "" {
		return errors.New("principal required")
	}
	if b.Resource == "" {
		return errors.New("resource required")
	}
	if b.Observe != nil {
		if b.Observe.ActionTime.IsZero() {
			return errors.New("observe.actionTime required")
		}
		if b.Observe.WindowSeconds <= 0 || time.Duration(b.Observe.WindowSeconds)*time.Second > maxObserveWindow {
			return fmt.Errorf("observe.windowSeconds must be between 1 and %d", int(maxObserveWindow.Seconds()))
		}
	}
	return nil
}
