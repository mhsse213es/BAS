package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
)

// ListAPIBASTargetJobs lists a target's jobs, newest first, with how each ended and how its scenarios graded. GET
// /api/apibas/targets/{id}/jobs?limit=N&status=S&before=C. limit defaults to 25 (at most 100); status filters on one job status; before
// is the "next" value of the previous page. When more jobs follow, the response carries "next", which is passed back as before. A job's
// reports are read with GET /api/apibas/jobs/{id}.
func (h *Handler) ListAPIBASTargetJobs(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := db.GetAPIBASTarget(r.Context(), h.db, id); errors.Is(err, db.ErrAPIBASTargetNotFound) {
		jsonError(w, "target not found", http.StatusNotFound)
		return
	} else if err != nil {
		jsonError(w, "could not read target", http.StatusInternalServerError)
		return
	}
	h.listAPIBASJobs(w, r, id)
}

// ListAPIBASJobs lists jobs across every target, newest first. GET /api/apibas/jobs?target_id=T&environment=E&source=S&status=S&limit=N&before=C
//
// It takes the same permission as one target's list and returns the same summaries, each with its target_id, so one view can show what ran
// anywhere. target_id narrows to one target (an unknown id gives an empty list, not an error, so a deleted target's history can still be
// asked for), environment to lab, staging or production, and source to "scheduled" or "manual". The other parameters are as for a target's list.
func (h *Handler) ListAPIBASJobs(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target_id")
	if len(target) > 64 {
		jsonError(w, "target_id is too long", http.StatusBadRequest)
		return
	}
	h.listAPIBASJobs(w, r, target)
}

// listAPIBASJobs reads the paging and filter parameters and writes the page. An empty targetID means every target.
func (h *Handler) listAPIBASJobs(w http.ResponseWriter, r *http.Request, targetID string) {
	limit := 25
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > db.MaxAPIBASJobList {
			jsonError(w, "limit must be between 1 and "+strconv.Itoa(db.MaxAPIBASJobList), http.StatusBadRequest)
			return
		}
		limit = n
	}
	opts := db.APIBASJobListOptions{Limit: limit}
	if v := r.URL.Query().Get("status"); v != "" {
		if !db.ValidAPIBASJobStatus(v) {
			jsonError(w, "status must be one of queued, running, completed, failed, cancelled", http.StatusBadRequest)
			return
		}
		opts.Status = v
	}
	if v := r.URL.Query().Get("environment"); v != "" {
		if !db.ValidAPIBASEnvironment(v) {
			jsonError(w, "environment must be one of lab, staging, production", http.StatusBadRequest)
			return
		}
		opts.Environment = v
	}
	if v := r.URL.Query().Get("source"); v != "" {
		if !db.ValidAPIBASJobSource(v) {
			jsonError(w, "source must be scheduled or manual", http.StatusBadRequest)
			return
		}
		opts.Source = v
	}
	if v := r.URL.Query().Get("before"); v != "" {
		at, jobID, ok := parseJobCursor(v)
		if !ok {
			jsonError(w, "before is not a cursor from a previous page", http.StatusBadRequest)
			return
		}
		opts.BeforeAt, opts.BeforeID = &at, jobID
	}
	jobs, more, err := db.ListAPIBASJobSummaries(r.Context(), h.db, targetID, opts)
	if err != nil {
		jsonError(w, "could not list jobs", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, map[string]any{
			"id": j.ID, "target_id": j.TargetID, "requested_by": j.RequestedBy, "scheduled": strings.HasPrefix(j.RequestedBy, "schedule:"),
			"environment": j.Environment, "status": j.Status, "failure_reason": j.FailureReason,
			"bound": runnerproto.IsBoundFixture(j.Fixture), "scenarios": j.ScenarioCount,
			"created_at": j.CreatedAt, "started_at": j.StartedAt, "finished_at": j.FinishedAt,
			"results": map[string]int{"pass": j.Pass, "fail": j.Fail, "error": j.Error, "skipped": j.Skipped},
		})
	}
	resp := map[string]any{"jobs": out}
	if more && len(jobs) > 0 {
		last := jobs[len(jobs)-1]
		resp["next"] = jobCursor(last.CreatedAt, last.ID)
	}
	apibasRespond(w, http.StatusOK, resp)
}

// jobCursor is "<created_at as RFC 3339 with nanoseconds>_<job id>", the position after a job in the newest-first order.
func jobCursor(at time.Time, id string) string { return at.UTC().Format(time.RFC3339Nano) + "_" + id }

var jobIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func parseJobCursor(v string) (time.Time, string, bool) {
	i := strings.LastIndex(v, "_")
	if i < 1 || len(v) > 128 {
		return time.Time{}, "", false
	}
	at, err := time.Parse(time.RFC3339Nano, v[:i])
	if err != nil || !jobIDShape.MatchString(v[i+1:]) {
		return time.Time{}, "", false
	}
	return at, v[i+1:], true
}
