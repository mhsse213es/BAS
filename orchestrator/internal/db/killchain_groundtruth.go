package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/killchain"
)

// RunRecordSource names the scenario run record. It is Audspect's own record of
// what it dispatched. It proves the run happened, not that the host executed
// anything, so it is never accepted as independent ground truth.
const RunRecordSource = "scenario run record (not independent of Audspect)"

// GroundTruthRecord is an independent record of whether a run's steps executed on
// the host, with a reference to where that evidence lives.
type GroundTruthRecord struct {
	RunID       string
	Source      string
	SourceClass killchain.SourceClass
	Executed    killchain.Tri
	Reference   string
	RecordedBy  string
	RecordedAt  time.Time
}

// PutGroundTruth stores one run's ground truth. It refuses a source that is
// Audspect's own record, a missing source or reference, an executed value
// other than yes or no, and a run that is missing or not completed.
func (s KillChainStore) PutGroundTruth(ctx context.Context, rec GroundTruthRecord) error {
	if rec.Source == RunRecordSource {
		return errors.New("the scenario run record is not independent; name the host or sensor that observed execution")
	}
	if rec.Source == "" {
		return errors.New("source is required")
	}
	if rec.Reference == "" {
		return errors.New("reference is required: point to the evidence that was checked")
	}
	if rec.Executed != killchain.TriYes && rec.Executed != killchain.TriNo {
		return fmt.Errorf("executed must be yes or no, got %q", rec.Executed)
	}
	var status, scenarioID string
	err := s.Pool.QueryRow(ctx, `SELECT status, scenario_id FROM scenario_runs WHERE id = $1`, rec.RunID).Scan(&status, &scenarioID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("run %q does not exist", rec.RunID)
	}
	if err != nil {
		return err
	}
	if status != "completed" {
		return fmt.Errorf("run %q is %q; only a completed run can carry ground truth", rec.RunID, status)
	}
	if !killchain.SourceClassAllowed(scenarioID, rec.SourceClass) {
		return fmt.Errorf("source class %q is not accepted for scenario %q", rec.SourceClass, scenarioID)
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO killchain_ground_truth
		(run_id, source, source_class, executed, reference, recorded_by, recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (run_id) DO UPDATE SET
			source = EXCLUDED.source, source_class = EXCLUDED.source_class, executed = EXCLUDED.executed,
			reference = EXCLUDED.reference, recorded_by = EXCLUDED.recorded_by, recorded_at = EXCLUDED.recorded_at`,
		rec.RunID, rec.Source, string(rec.SourceClass), string(rec.Executed), rec.Reference, rec.RecordedBy, time.Now().UTC())
	return err
}

// GroundTruthForRun returns the stored record for a run. The bool is false
// when no record exists, and that is never read as executed.
func (s KillChainStore) GroundTruthForRun(ctx context.Context, runID string) (GroundTruthRecord, bool, error) {
	var rec GroundTruthRecord
	var executed, class string
	err := s.Pool.QueryRow(ctx, `SELECT run_id, source, source_class, executed, reference, recorded_by, recorded_at
		FROM killchain_ground_truth WHERE run_id = $1`, runID,
	).Scan(&rec.RunID, &rec.Source, &class, &executed, &rec.Reference, &rec.RecordedBy, &rec.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return GroundTruthRecord{}, false, nil
	}
	if err != nil {
		return GroundTruthRecord{}, false, err
	}
	rec.Executed = killchain.Tri(executed)
	rec.SourceClass = killchain.SourceClass(class)
	return rec, true, nil
}
