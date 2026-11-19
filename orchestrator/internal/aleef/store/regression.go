package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PriorKnowledgeValues are the allowed values of a finding's prior_knowledge.
// The schema CHECK constraint is built from this list and SetPriorKnowledge
// validates against it, so the two cannot drift.
var PriorKnowledgeValues = []string{"not_checked", "checked_none_found", "known_public", "known_vendor"}

func priorKnowledgeSQL() string {
	q := make([]string, len(PriorKnowledgeValues))
	for i, v := range PriorKnowledgeValues {
		q[i] = "'" + v + "'"
	}
	return strings.Join(q, ", ")
}

// ErrRegressionSerialsExhausted: all serials 1..9999 have been issued.
var ErrRegressionSerialsExhausted = errors.New("aleef store: regression serials exhausted")

// regressionGrace is how long a verified finding may lack its regression before
// ListVerifiedWithoutRegression reports it: the campaign saves the regression
// right after verification, so a younger finding is probably in that window.
const regressionGrace = 2 * time.Minute

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
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "2200H" {
			return 0, ErrRegressionSerialsExhausted
		}
		return 0, fmt.Errorf("aleef store: next regression serial: %w", err)
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
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return fmt.Errorf("aleef store: regression id %s already used by another finding", regressionID)
		}
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
	if !slices.Contains(PriorKnowledgeValues, value) {
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

func (s *Store) listVerified(ctx context.Context, runID, where string, args ...any) ([]Finding, error) {
	q := `SELECT ` + findingCols + ` FROM aleef_findings f WHERE f.state='verified' AND ` + where
	if runID != "" {
		args = append(args, runID)
		q += fmt.Sprintf(" AND f.run_id=$%d", len(args))
	}
	rows, err := s.pool.Query(ctx, q+" ORDER BY f.created_at, f.id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListVerifiedWithoutRegression returns verified findings that have no saved
// regression and were verified more than two minutes ago (so a campaign that is
// still saving one is not hit). Such a finding is the trace of a crash between
// MarkVerified and SaveRegression. runID "" means all runs.
func (s *Store) ListVerifiedWithoutRegression(ctx context.Context, runID string) ([]Finding, error) {
	return s.listVerified(ctx, runID,
		`NOT EXISTS (SELECT 1 FROM aleef_regressions r WHERE r.finding_id=f.id) AND f.updated_at < NOW() - $1::interval`,
		fmt.Sprintf("%d seconds", int(regressionGrace.Seconds())))
}

// ListVerifiedWithRegression returns the run's verified findings that have a
// saved regression (runID "" means all runs). This, not the verified slice of
// ListFindings, is the list to show as verified: the owner's criterion is that
// every verified finding has a regression.
func (s *Store) ListVerifiedWithRegression(ctx context.Context, runID string) ([]Finding, error) {
	return s.listVerified(ctx, runID, `EXISTS (SELECT 1 FROM aleef_regressions r WHERE r.finding_id=f.id)`)
}
