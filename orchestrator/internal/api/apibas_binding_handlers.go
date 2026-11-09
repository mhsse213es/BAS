package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/apibas/binding"
)

// PlanAPIBASBinding previews how a target's stored inventory binds to test data the caller supplies: which scenarios would be
// generated, and which object-level operations are skipped and why. It stores nothing, starts no job, contacts nothing and
// receives no credential value (only the names of credentials the runner would resolve). The newest inventory is used, or the
// version named by ?version=.
func (h *Handler) PlanAPIBASBinding(w http.ResponseWriter, r *http.Request) {
	var spec binding.Spec
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	rec, inv, ok := h.loadInventory(w, r)
	if !ok {
		return
	}
	plan, err := binding.Bind(inv, spec)
	if err != nil {
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	apibasRespond(w, http.StatusOK, map[string]any{
		"inventory_version": rec.Version,
		"scenarios":         len(plan.Scenarios),
		"bound":             plan.Bound,
		"skipped":           plan.Skipped,
		"limits":            plan.Limits,
	})
}
