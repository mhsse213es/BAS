package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// apibasBindingRunBody is what a caller chooses when running a target's stored test data. Everything else (the target, its
// credentials, its scope, the scenarios) comes from the registered target, its inventory and its stored binding.
type apibasBindingRunBody struct {
	Key string `json:"key"`
	// ApprovalID is required for a production target and ignored otherwise.
	ApprovalID string `json:"approval_id"`
}

// RunAPIBASBinding queues a job that runs the scenarios bound from a target's stored test data and newest inventory, and starts it
// in the background. POST /api/apibas/targets/{id}/binding/jobs
//
// The job uses the same submission path as any other (enabled target, permitted environment, registered host, one active job per
// target, approval for production) and is bounded by the target's registered path scope. Its scenarios are read-only and graded
// on the response alone. It refuses stored test data that was checked against an older inventory than the newest: save it again
// first, so what runs is what was last validated.
func (h *Handler) RunAPIBASBinding(w http.ResponseWriter, r *http.Request) {
	if h.apibasJobs == nil {
		jsonError(w, "API BAS job execution is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body apibasBindingRunBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Key == "" {
		jsonError(w, "invalid body: a key is required", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	bound, perr := h.buildBoundPlan(r.Context(), id, true)
	if perr != nil {
		var be *buildBoundPlanError
		if errors.As(perr, &be) {
			jsonError(w, be.Msg, be.Status)
		} else {
			jsonError(w, "could not build the plan", http.StatusInternalServerError)
		}
		return
	}
	h.submitJob(w, r, actor, apibasJobBody{Key: body.Key, TargetID: id, ApprovalID: body.ApprovalID}, &bound)
}
