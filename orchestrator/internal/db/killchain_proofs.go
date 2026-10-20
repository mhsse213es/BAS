package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/killchain"
)

// CoverageProof is one scenario's stored proof and the dimensions it reports under.
// Domain, platform, control and campaign are declared by the recorder. They are
// reporting labels only. Maturity comes from the proof references, which are
// checked against stored runs.
type CoverageProof struct {
	ScenarioID  string
	Domain      string
	Platform    string
	Control     string
	Campaign    string
	Unsupported bool
	Proof       killchain.Proof
	RecordedBy  string
	RecordedAt  time.Time
}

// CheckRunRef confirms that runID is a completed run of scenarioID in the
// given mode. A lab proof needs a lab run and a live proof needs a telemetry
// run. Anything else is refused, so no reference can be typed in by hand.
func (s KillChainStore) CheckRunRef(ctx context.Context, runID, scenarioID, wantMode string) error {
	var gotScenario, gotMode, status string
	err := s.Pool.QueryRow(ctx,
		`SELECT scenario_id, mode, status FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&gotScenario, &gotMode, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("run %q does not exist", runID)
	}
	if err != nil {
		return err
	}
	if gotScenario != scenarioID {
		return fmt.Errorf("run %q is a run of %q, not %q", runID, gotScenario, scenarioID)
	}
	if gotMode != wantMode {
		return fmt.Errorf("run %q is a %q run; this proof needs a %q run", runID, gotMode, wantMode)
	}
	if status != "completed" {
		return fmt.Errorf("run %q is %q; only a completed run can prove coverage", runID, status)
	}
	return nil
}

// UpsertCoverageProof stores or replaces one scenario's proof. The caller
// checks the run references first.
func (s KillChainStore) UpsertCoverageProof(ctx context.Context, p CoverageProof) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO killchain_coverage_proofs
		(scenario_id, domain, platform, control, campaign, unsupported,
		 fixture_test_id, adapter_test_id, lab_run_id, live_run_id, recorded_by, recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (scenario_id) DO UPDATE SET
			domain = EXCLUDED.domain, platform = EXCLUDED.platform, control = EXCLUDED.control,
			campaign = EXCLUDED.campaign, unsupported = EXCLUDED.unsupported,
			fixture_test_id = EXCLUDED.fixture_test_id, adapter_test_id = EXCLUDED.adapter_test_id,
			lab_run_id = EXCLUDED.lab_run_id, live_run_id = EXCLUDED.live_run_id,
			recorded_by = EXCLUDED.recorded_by, recorded_at = EXCLUDED.recorded_at`,
		p.ScenarioID, p.Domain, p.Platform, p.Control, p.Campaign, p.Unsupported,
		p.Proof.FixtureTestID, p.Proof.AdapterTestID, p.Proof.LabRunID, p.Proof.LiveRunID,
		p.RecordedBy, time.Now().UTC())
	return err
}

// ListCoverageProofs returns every stored proof, sorted by scenario ID.
func (s KillChainStore) ListCoverageProofs(ctx context.Context) ([]CoverageProof, error) {
	rows, err := s.Pool.Query(ctx, `SELECT scenario_id, domain, platform, control, campaign, unsupported,
		fixture_test_id, adapter_test_id, lab_run_id, live_run_id, recorded_by, recorded_at
		FROM killchain_coverage_proofs ORDER BY scenario_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CoverageProof{}
	for rows.Next() {
		var p CoverageProof
		if err := rows.Scan(&p.ScenarioID, &p.Domain, &p.Platform, &p.Control, &p.Campaign, &p.Unsupported,
			&p.Proof.FixtureTestID, &p.Proof.AdapterTestID, &p.Proof.LabRunID, &p.Proof.LiveRunID,
			&p.RecordedBy, &p.RecordedAt); err != nil {
			return nil, err
		}
		p.Proof.CatalogEntry = true
		out = append(out, p)
	}
	return out, rows.Err()
}
