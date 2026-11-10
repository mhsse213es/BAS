package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
)

// ListAPIBASTargetJobs lists a target's recent jobs, newest first, with how each ended and how its scenarios graded. GET
// /api/apibas/targets/{id}/jobs?limit=N (default 25, at most 100). A job's reports are read with GET /api/apibas/jobs/{id}.
func (h *Handler) ListAPIBASTargetJobs(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	limit := 25
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > db.MaxAPIBASJobList {
			jsonError(w, "limit must be between 1 and "+strconv.Itoa(db.MaxAPIBASJobList), http.StatusBadRequest)
			return
		}
		limit = n
	}
	if _, err := db.GetAPIBASTarget(r.Context(), h.db, id); errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	} else if err != nil {
		jsonError(w, "could not read target", http.StatusInternalServerError)
		return
	}
	jobs, err := db.ListAPIBASJobSummaries(r.Context(), h.db, id, limit)
	if err != nil {
		jsonError(w, "could not list jobs", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, map[string]any{
			"id": j.ID, "requested_by": j.RequestedBy, "environment": j.Environment, "status": j.Status, "failure_reason": j.FailureReason,
			"bound": runnerproto.IsBoundFixture(j.Fixture), "scenarios": j.ScenarioCount,
			"created_at": j.CreatedAt, "started_at": j.StartedAt, "finished_at": j.FinishedAt,
			"results": map[string]int{"pass": j.Pass, "fail": j.Fail, "error": j.Error, "skipped": j.Skipped},
		})
	}
	apibasRespond(w, http.StatusOK, map[string]any{"jobs": out})
}
