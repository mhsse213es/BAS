package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/k8sscenario"
)

// K8sControlledSwitch is the global kill switch for Controlled execution. Turning it on runs nothing by itself: every
// Controlled run still needs an authorization, a per-run approval, and the gate. Turning it off stops Controlled runs
// in progress.
type K8sControlledSwitch interface {
	Enabled(ctx context.Context) (bool, error)
	// Set changes the switch and records ev in the same transaction.
	Set(ctx context.Context, enabled bool, actor string, at time.Time, ev k8sscenario.Event) error
}

// GetK8sControlledSwitch reports whether Controlled execution is switched on. GET /api/k8s-scenarios/controlled-switch
func (h *Handler) GetK8sControlledSwitch(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.ControlledSwitch == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	on, err := svc.ControlledSwitch.Enabled(r.Context())
	if err != nil {
		jsonError(w, "could not read the Controlled switch", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"enabled": on})
}

// SetK8sControlledSwitch turns Controlled execution on or off. Turning it off stops every Controlled run in progress
// and reports how many it stopped. The change and its audit record are written together.
// POST /api/k8s-scenarios/controlled-switch  body: {"enabled": true|false}
func (h *Handler) SetK8sControlledSwitch(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.ControlledSwitch == nil || svc.Engine == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	actor := actorID(r)
	if actor == "" {
		jsonError(w, "actor identity is required", http.StatusUnauthorized)
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		jsonError(w, `body must be {"enabled": true} or {"enabled": false}`, http.StatusBadRequest)
		return
	}
	enabled := *body.Enabled
	now := svc.now()
	if err := svc.ControlledSwitch.Set(r.Context(), enabled, actor, now, k8sscenario.ControlledSwitchEvent(enabled, actor, now)); err != nil {
		jsonError(w, "the Controlled switch was not changed", http.StatusInternalServerError)
		return
	}
	stopped := 0
	if !enabled {
		// Stop running Controlled work now. The engine rolls each run back and verifies it before it reports.
		stopped = svc.Engine.CancelControlled()
	}
	respond(w, map[string]any{"enabled": enabled, "stoppedRuns": stopped})
}

// CancelK8sRun stops a running live run. Only the requester may cancel it. The engine stops further writes, rolls
// back, and verifies the restore before the outcome is recorded. POST /api/k8s-scenarios/runs/{id}/cancel
func (h *Handler) CancelK8sRun(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Engine == nil || svc.Runs == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	run, ok, err := svc.Runs.GetRun(r.Context(), chi.URLParam(r, "id"))
	if err != nil || !ok {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	actor := actorID(r)
	if actor == "" || actor != run.RequesterID {
		jsonError(w, "only the requester may cancel a run", http.StatusForbidden)
		return
	}
	if !svc.Engine.Cancel(run.ID) {
		jsonError(w, "run is not executing", http.StatusConflict)
		return
	}
	// The stop is already requested. If the request cannot be recorded, say so: the run is still stopped.
	if svc.Audit != nil {
		ev := k8sscenario.CancelRequestEvent(run.ID, actor, run.ClusterID, run.Cluster, run.Namespace, run.ActionID)
		if err := svc.Audit.Write(r.Context(), ev); err != nil {
			jsonError(w, "the run is being stopped, but the cancellation could not be recorded", http.StatusInternalServerError)
			return
		}
	}
	respond(w, map[string]any{"runId": run.ID, "requested": true})
}
