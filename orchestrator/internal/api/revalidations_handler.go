package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// revalidationEntry is one bas_revalidation Job in a request's chain,
// paired with its single target's technique_verification_runs detail.
type revalidationEntry struct {
	JobID       string     `json:"jobId"`
	State       string     `json:"state"`
	ScheduledAt *time.Time `json:"scheduledAt,omitempty"`
	TargetState string     `json:"targetState"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason"`
}

// GET /api/remediation-requests/{requestId}/revalidations
// Lists every bas_revalidation job tied to requestId, letting an operator
// see e.g. "24h: pass, 7d: pending, 30d: not yet scheduled" for one
// remediation. Read-level, matches GetJob's precedent -- no new permission.
func (h *Handler) GetRemediationRevalidations(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	if h.jobsStore == nil {
		jsonError(w, "job engine not loaded", http.StatusServiceUnavailable)
		return
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT id, state, scheduled_at FROM jobs WHERE type='bas_revalidation' AND payload->>'requestId'=$1 ORDER BY scheduled_at`, requestID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	entries := []revalidationEntry{}
	for rows.Next() {
		var jobID, state string
		var scheduledAt *time.Time
		if err := rows.Scan(&jobID, &state, &scheduledAt); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		entry := revalidationEntry{JobID: jobID, State: state, ScheduledAt: scheduledAt}
		targets, err := h.jobsStore.ListTargets(r.Context(), jobID)
		if err == nil && len(targets) == 1 {
			entry.TargetState = targets[0].State
			if targets[0].RefID != "" {
				h.db.QueryRow(r.Context(), `SELECT status, reason FROM technique_verification_runs WHERE id=$1`, targets[0].RefID).Scan(&entry.Status, &entry.Reason)
			}
		}
		entries = append(entries, entry)
	}
	respond(w, map[string]any{"revalidations": entries})
}
