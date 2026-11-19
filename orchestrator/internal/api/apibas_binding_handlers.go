package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/db"
)

// PlanAPIBASBinding previews how a target's stored inventory binds to test data the caller supplies: which scenarios would be
// generated, and which object-level operations are skipped and why. It stores nothing, starts no job, contacts nothing and
// receives no credential value (only the names of credentials the runner would resolve). The newest inventory is used, or the
// version named by ?version=.
func (h *Handler) PlanAPIBASBinding(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		jsonError(w, "the test data is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		// No body: preview the test data stored on the target.
		b, err := db.GetAPIBASBinding(r.Context(), h.db, chi.URLParam(r, "id"))
		if errors.Is(err, db.ErrAPIBASBindingNotFound) {
			jsonError(w, "no test data stored for this target; send it in the body", http.StatusBadRequest)
			return
		} else if err != nil {
			jsonError(w, "could not read the test data", http.StatusInternalServerError)
			return
		}
		raw = b.Spec
	}
	spec, err := decodeBindingSpec(raw)
	if err != nil {
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
