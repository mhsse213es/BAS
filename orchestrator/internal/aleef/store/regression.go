package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Regression is a stored regression: the export bundle of a verified finding.
type Regression struct {
	FindingID    string
	RegressionID string
	BundleJSON   []byte
	// ScenarioYAML is nil when no catalogue scenario applies (see YAMLNote).
	ScenarioYAML []byte
	YAMLNote     string
	CreatedAt    time.Time
}

// NextRegressionSeq returns the next regression serial, 1..9999, from a
// database sequence (safe under concurrent callers; gaps are possible). It is
// an error once the serials are exhausted.
func (s *Store) NextRegressionSeq(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT nextval('aleef_regression_seq')`).Scan(&n); err != nil {
		return 0, fmt.Errorf("aleef store: regression serials exhausted or unavailable: %w", err)
	}
	return n, nil
}

// SaveRegression stores the regression of a finding. A finding has at most
// one: a second save is an error and never overwrites.
func (s *Store) SaveRegression(ctx context.Context, findingID, regressionID string, bundleJSON, scenarioYAML []byte, yamlNote string) error {
	if findingID == "" || regressionID == "" || len(bundleJSON) == 0 {
		return errors.New("aleef store: finding id, regression id and bundle are required")
	}
	var yaml any
	if len(scenarioYAML) > 0 {
		yaml = string(scenarioYAML)
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO aleef_regressions (finding_id, regression_id, bundle, scenario_yaml, yaml_note)
		VALUES ($1,$2,$3,$4,$5) ON CONFLICT (finding_id) DO NOTHING`, findingID, regressionID, bundleJSON, yaml, yamlNote)
	if err != nil {
		return fmt.Errorf("aleef store: save regression: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("aleef store: regression for finding %s already saved", findingID)
	}
	return nil
}

// GetRegression loads the regression of a finding.
func (s *Store) GetRegression(ctx context.Context, findingID string) (Regression, error) {
	var r Regression
	var bundle string
	var yaml *string
	err := s.pool.QueryRow(ctx, `SELECT finding_id, regression_id, bundle::text, scenario_yaml, yaml_note, created_at
		FROM aleef_regressions WHERE finding_id=$1`, findingID).Scan(&r.FindingID, &r.RegressionID, &bundle, &yaml, &r.YAMLNote, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Regression{}, fmt.Errorf("aleef store: no regression for finding %s", findingID)
		}
		return Regression{}, err
	}
	r.BundleJSON = []byte(bundle)
	if yaml != nil {
		r.ScenarioYAML = []byte(*yaml)
	}
	return r, nil
}

// SetPriorKnowledge records what a human found when checking public and vendor
// sources. It appends a history row and never changes the finding's state.
func (s *Store) SetPriorKnowledge(ctx context.Context, findingID, value, actor string) error {
	switch value {
	case "not_checked", "checked_none_found", "known_public", "known_vendor":
	default:
		return fmt.Errorf("aleef store: unknown prior knowledge value %q", value)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state, prev string
	if err := tx.QueryRow(ctx, `SELECT state, prior_knowledge FROM aleef_findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&state, &prev); err != nil {
		return fmt.Errorf("aleef store: load finding %s: %w", findingID, err)
	}
	if _, err := tx.Exec(ctx, `UPDATE aleef_findings SET prior_knowledge=$2, updated_at=NOW() WHERE id=$1`, findingID, value); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO aleef_finding_history (finding_id, previous_state, new_state, reason, actor)
		VALUES ($1,$2,$2,$3,$4)`, findingID, state, "prior knowledge: "+prev+" -> "+value, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
