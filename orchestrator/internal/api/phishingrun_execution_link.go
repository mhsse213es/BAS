package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishingrun"
)

// executionIDFromParams returns the exercise execution a run names, or "" when none is
// named. A non-string value is treated as none; checkExecutionLink refuses it first.
func executionIDFromParams(params map[string]any) string {
	id, _ := params["executionId"].(string)
	return id
}

// checkExecutionLink refuses a run that names an execution which does not exist, or
// names one with a value that is not a string. It writes nothing.
func (h *Handler) checkExecutionLink(ctx context.Context, params map[string]any) error {
	raw, present := params["executionId"]
	if !present || raw == nil {
		return nil
	}
	id, ok := raw.(string)
	if !ok {
		return errors.New("executionId must be a string")
	}
	if id == "" {
		return nil
	}
	exists, err := db.ExerciseExecutionExists(ctx, h.db, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("unknown executionId %q", id)
	}
	return nil
}

// GET /api/exercises/executions/{id}/phishing-runs -- the phishing runs linked to one
// execution, so the execution shows its phishing results beside its other evidence.
func (h *Handler) ListExecutionPhishingRuns(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	runs, err := db.ListPhishingRunsForExecution(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*phishingrun.PhishingRun{}
	}
	respond(w, runs)
}
