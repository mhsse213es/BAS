package api

import (
	"context"
	"errors"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim/dbjobs"
)

// dbsimRunSink stores graded database rows in dbsim_runs (dbjobs.RunSink).
type dbsimRunSink struct{ h *Handler }

// Save stores one graded row. A row already stored for the run and scenario is
// reported as a duplicate and stores nothing.
func (k dbsimRunSink) Save(ctx context.Context, rec dbjobs.RunRecord) (bool, error) {
	if k.h == nil || k.h.db == nil {
		return false, errors.New("results store unavailable")
	}
	_, err := db.SaveDBSimRun(ctx, k.h.db, db.DBSimRun{
		ScenarioID: rec.ScenarioID, ScenarioVersion: rec.ScenarioVersion, TargetID: rec.TargetID,
		Engine: rec.Engine, RunID: rec.RunID, Result: rec.Result, Report: rec.Report,
	})
	if errors.Is(err, db.ErrDBSimRunDuplicate) {
		return true, nil
	}
	return false, err
}

// Count returns how many graded rows a run has stored.
func (k dbsimRunSink) Count(ctx context.Context, runID string) (int, error) {
	if k.h == nil || k.h.db == nil {
		return 0, errors.New("results store unavailable")
	}
	return db.CountDBSimRunsForRun(ctx, k.h.db, runID)
}
