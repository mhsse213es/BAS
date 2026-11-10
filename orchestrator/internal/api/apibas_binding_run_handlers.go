package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
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
	stored, err := db.GetAPIBASBinding(r.Context(), h.db, id)
	if errors.Is(err, db.ErrAPIBASBindingNotFound) {
		jsonError(w, "no test data stored for this target", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read the test data", http.StatusInternalServerError)
		return
	}
	spec, err := decodeBindingSpec(stored.Spec)
	if err != nil {
		jsonError(w, "the stored test data is unreadable", http.StatusInternalServerError)
		return
	}
	rec, err := db.GetAPIBASInventory(r.Context(), h.db, id, 0)
	if errors.Is(err, db.ErrAPIBASInventoryNotFound) {
		jsonError(w, "no inventory for this target", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read the inventory", http.StatusInternalServerError)
		return
	}
	if rec.Version != stored.ValidatedInventory {
		jsonError(w, "the test data was checked against an older inventory; save it again first", http.StatusConflict)
		return
	}
	var inv openapi.Inventory
	if err := json.Unmarshal(rec.Body, &inv); err != nil {
		jsonError(w, "the stored inventory is unreadable", http.StatusInternalServerError)
		return
	}
	bound := runnerproto.BoundPlan{InventoryVersion: rec.Version, Inventory: inv, Spec: spec}
	h.submitJob(w, r, actor, apibasJobBody{Key: body.Key, TargetID: id, ApprovalID: body.ApprovalID}, &bound)
}
