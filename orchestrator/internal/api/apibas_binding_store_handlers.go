package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/db"
)

// A target's binding spec is stored so a plan can be previewed, and later run, without re-entering test data. The spec holds
// credential names and the values a leak would be detected by; it never holds a credential value. Reading it needs the same
// permission as changing it, because the protected values can themselves be sensitive.

func decodeBindingSpec(raw []byte) (binding.Spec, error) {
	var spec binding.Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err := dec.Decode(&spec)
	return spec, err
}

// SaveAPIBASBinding validates the body against the target's newest inventory and stores it. A spec that does not bind is refused,
// so a stored spec was valid when saved. It stays valid only while the inventory stays the same, which GetAPIBASBinding reports.
func (h *Handler) SaveAPIBASBinding(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		jsonError(w, "the test data is too large", http.StatusRequestEntityTooLarge)
		return
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
	canonical, err := json.Marshal(spec)
	if err != nil {
		jsonError(w, "could not encode the test data", http.StatusInternalServerError)
		return
	}
	saved, err := db.SaveAPIBASBinding(r.Context(), h.db, db.APIBASBinding{TargetID: id, Spec: canonical, UpdatedBy: actor, ValidatedInventory: rec.Version})
	if errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not store the test data", http.StatusInternalServerError)
		return
	}
	// The audit record carries counts, never names or values.
	_ = h.auditDurable(r.Context(), actor, "apibas.binding.save", "apibas-target:"+id, map[string]any{
		"inventory_version": rec.Version, "identities": len(spec.Identities), "objects": len(spec.Objects),
		"scenarios": len(plan.Scenarios), "skipped": len(plan.Skipped),
	}, "success")
	apibasRespond(w, http.StatusOK, map[string]any{
		"inventory_version": rec.Version, "scenarios": len(plan.Scenarios), "bound": plan.Bound, "skipped": plan.Skipped,
		"limits": plan.Limits, "updated_at": saved.UpdatedAt,
	})
}

// GetAPIBASBinding returns the stored spec, who saved it, and whether the newest inventory differs from the one it was checked against.
func (h *Handler) GetAPIBASBinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	b, err := db.GetAPIBASBinding(r.Context(), h.db, id)
	if errors.Is(err, db.ErrAPIBASBindingNotFound) {
		jsonError(w, "no test data stored for this target", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not read the test data", http.StatusInternalServerError)
		return
	}
	newest := 0
	if inv, err := db.GetAPIBASInventory(r.Context(), h.db, id, 0); err == nil {
		newest = inv.Version
	}
	apibasRespond(w, http.StatusOK, map[string]any{
		"spec": json.RawMessage(b.Spec), "updated_by": b.UpdatedBy, "updated_at": b.UpdatedAt,
		"validated_inventory": b.ValidatedInventory, "newest_inventory": newest, "stale": newest != b.ValidatedInventory,
	})
}

// DeleteAPIBASBinding removes the stored spec.
func (h *Handler) DeleteAPIBASBinding(w http.ResponseWriter, r *http.Request) {
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	existed, err := db.DeleteAPIBASBinding(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, "could not remove the test data", http.StatusInternalServerError)
		return
	}
	if !existed {
		jsonError(w, "no test data stored for this target", http.StatusNotFound)
		return
	}
	_ = h.auditDurable(r.Context(), actor, "apibas.binding.delete", "apibas-target:"+id, map[string]any{}, "success")
	w.WriteHeader(http.StatusNoContent)
}
