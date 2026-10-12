package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/rwevidence"
)

// WriteRWCapabilityResults persists one step's complete capability-result
// set (always len 5, see rwevidence.EvaluateStep) as an upsert keyed on
// (run_id, action, capability) -- a retry of the same step overwrites its
// own prior rows rather than duplicating them. Every result is validated
// via CapabilityResult.Valid() before any write is attempted: the DB's own
// CHECK constraint is a backstop, not the primary enforcement point, so a
// caller gets a clear application-level error rather than a raw SQL
// constraint violation. simulated is always written true -- no caller of
// this function in this sub-project can pass false (there is no parameter
// for it). Wrapped in a transaction (same Begin/Rollback/Commit idiom as
// internal/api/enroll_csr_handlers.go's CSR issuance, the only existing
// precedent for a multi-statement write in this codebase) so a failure on
// row 3 of 5 rolls back rows 1-2 -- this is what makes "never represent
// partial coverage" (spec section F) actually true rather than aspirational.
func WriteRWCapabilityResults(ctx context.Context, pool *pgxpool.Pool, runID, action string, results []rwevidence.CapabilityResult) error {
	for _, r := range results {
		if err := r.Valid(); err != nil {
			return fmt.Errorf("rw_capability_results: refusing to write invalid result for %s/%s: %w", r.Capability, r.TechniqueID, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rw_capability_results: begin tx for run=%s action=%s: %w", runID, action, err)
	}
	defer tx.Rollback(ctx)

	for _, r := range results {
		var skipReason *string
		if r.SkipReason != "" {
			s := string(r.SkipReason)
			skipReason = &s
		}
		var provenance []byte
		if r.Provenance != (controlval.CorrelationKey{}) {
			provenance, _ = json.Marshal(r.Provenance)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO rw_capability_results
				(run_id, action, technique_id, capability, verdict, skip_reason, specific_reason, reason, provenance)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (run_id, action, capability) DO UPDATE SET
				technique_id = EXCLUDED.technique_id,
				verdict = EXCLUDED.verdict,
				skip_reason = EXCLUDED.skip_reason,
				specific_reason = EXCLUDED.specific_reason,
				reason = EXCLUDED.reason,
				provenance = EXCLUDED.provenance,
				created_at = NOW()`,
			runID, action, r.TechniqueID, string(r.Capability), string(r.Verdict), skipReason, r.SpecificReason, r.Reason, provenance)
		if err != nil {
			return fmt.Errorf("rw_capability_results: write failed for run=%s action=%s capability=%s: %w", runID, action, r.Capability, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("rw_capability_results: commit for run=%s action=%s: %w", runID, action, err)
	}
	return nil
}

// RWCoverageRow is one (technique, capability, verdict, skip_reason,
// specific_reason) group for a run -- Task 6 builds the full coverage
// query from this.
type RWCoverageRow struct {
	TechniqueID    string
	Capability     string
	Verdict        string
	SkipReason     string
	SpecificReason string
	Count          int
}

func RWCapabilityCoverage(ctx context.Context, pool *pgxpool.Pool, runID string) ([]RWCoverageRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT technique_id, capability, verdict, COALESCE(skip_reason, ''), specific_reason, COUNT(*)
		FROM rw_capability_results
		WHERE run_id = $1
		GROUP BY technique_id, capability, verdict, skip_reason, specific_reason`, runID)
	if err != nil {
		return nil, fmt.Errorf("rw_capability_results coverage query failed for run=%s: %w", runID, err)
	}
	defer rows.Close()
	var out []RWCoverageRow
	for rows.Next() {
		var r RWCoverageRow
		if err := rows.Scan(&r.TechniqueID, &r.Capability, &r.Verdict, &r.SkipReason, &r.SpecificReason, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RWAttemptRow is one individual, non-aggregated capability-result row --
// unlike RWCoverageRow, this preserves action and created_at per row,
// needed by sub-project #5's correlation engine for event ordering.
type RWAttemptRow struct {
	TechniqueID string
	Action      string
	Capability  string
	Verdict     controlval.Verdict
	SkipReason  controlval.SkipReason
	Reason      string
	CreatedAt   time.Time
}

// RWCapabilityAttempts returns every row for runID individually, ordered
// by created_at ascending -- no GROUP BY, no aggregation. Kept entirely
// separate from RWCapabilityCoverage, which rwscore depends on in its
// exact aggregated form.
func RWCapabilityAttempts(ctx context.Context, pool *pgxpool.Pool, runID string) ([]RWAttemptRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT technique_id, action, capability, verdict, COALESCE(skip_reason, ''), reason, created_at
		FROM rw_capability_results
		WHERE run_id = $1
		ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("rw_capability_results attempts query failed for run=%s: %w", runID, err)
	}
	defer rows.Close()

	var out []RWAttemptRow
	for rows.Next() {
		var r RWAttemptRow
		var verdict, skipReason string
		if err := rows.Scan(&r.TechniqueID, &r.Action, &r.Capability, &verdict, &skipReason, &r.Reason, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("rw_capability_results attempts scan failed for run=%s: %w", runID, err)
		}
		r.Verdict = controlval.Verdict(verdict)
		r.SkipReason = controlval.SkipReason(skipReason)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RWCoverageSummary distinguishes a technique-level coverage gap from an
// individual capability evaluation gap, per the spec's coverage-accounting
// requirement. Evaluated counts every row whose evaluator actually ran
// (PASS/FAIL/ERROR, or SKIPPED/insufficient_evidence -- the evaluator ran
// and came back ambiguous, which is still "evaluated", not "not tested").
type RWCoverageSummary struct {
	Evaluated         int
	NotApplicable     int
	NotTestedByReason map[string]int
}

func SummarizeRWCoverage(rows []RWCoverageRow) RWCoverageSummary {
	s := RWCoverageSummary{NotTestedByReason: map[string]int{}}
	for _, r := range rows {
		switch {
		case r.Verdict != "SKIPPED":
			s.Evaluated += r.Count
		case r.SkipReason == "insufficient_evidence":
			s.Evaluated += r.Count
		case r.SkipReason == "not_applicable":
			s.NotApplicable += r.Count
		case r.SkipReason == "not_tested":
			s.NotTestedByReason[r.SpecificReason] += r.Count
		}
	}
	return s
}
