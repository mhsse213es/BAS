package api

import (
	"context"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/variant"
)

// recordVariantCleanupState works out the cleanup outcome of the variant run behind a scenario run and writes it to
// the run. It touches only the cleanup columns, never the attack verdicts on the results. A scenario run that is not
// a variant run is a no-op.
func (h *Handler) recordVariantCleanupState(ctx context.Context, scenarioRunID string, results []models.SimulationResult) error {
	var vrID string
	if err := h.db.QueryRow(ctx,
		`SELECT id FROM variant_runs WHERE scenario_run_id = $1 LIMIT 1`, scenarioRunID,
	).Scan(&vrID); err != nil {
		return nil
	}

	byID := make(map[string]models.SimulationResult, len(results))
	for _, r := range results {
		byID[r.ID] = r
	}

	rows, err := h.db.Query(ctx,
		`SELECT task_id, has_cleanup, cleanup_status FROM variant_run_steps WHERE variant_run_id = $1`, vrID)
	if err != nil {
		return err
	}
	var steps []variant.CleanupStep
	for rows.Next() {
		var taskID, cleanupStatus string
		var hasCleanup bool
		if err := rows.Scan(&taskID, &hasCleanup, &cleanupStatus); err != nil {
			rows.Close()
			return err
		}
		st := variant.CleanupStep{
			TaskID:       taskID,
			NeedsCleanup: hasCleanup,
			// Ran with no cleanup and is not known to be read-only: nothing reverted it.
			Unverified: !hasCleanup && cleanupStatus != variant.CleanupReadOnly,
		}
		if r, ok := byID[taskID]; ok {
			st.Verdict = r.CleanupVerdict
			st.Error = r.CleanupError
		}
		steps = append(steps, st)
	}
	rows.Close()

	state, errText, remediation := variant.SummarizeCleanup(steps)
	_, err = h.db.Exec(ctx,
		`UPDATE variant_runs
		    SET cleanup_status = $2, cleanup_error = $3, remediation_required = $4,
		        cleanup_completed_at = CASE WHEN $5 THEN COALESCE(cleanup_completed_at, NOW()) ELSE NULL END
		  WHERE id = $1`,
		vrID, string(state), errText, remediation,
		state == variant.CleanupSucceeded || state == variant.CleanupFailed)
	return err
}
