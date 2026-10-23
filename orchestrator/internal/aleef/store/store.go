package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
)

// Finding states.
const (
	StateCandidate   = "candidate"
	StateVerified    = "verified"
	StateRejected    = "rejected"
	StateUnconfirmed = "unconfirmed"
)

// Store is the Aleef persistence layer.
type Store struct{ pool *pgxpool.Pool }

// New returns a Store backed by pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Finding is one stored finding.
type Finding struct {
	ID, RunID, TestID, Property, State, PriorKnowledge, EvidenceHash string
	Covered                                                          bool
	CreatedAt, UpdatedAt                                             time.Time
}

// Engagement is the minimal engagement record.
type Engagement struct {
	ID            string
	Customer      string
	Environment   string
	ApprovedHosts []string
	Window        string
	Approver      string
	Body          json.RawMessage
}

// CreateEngagement stores e and returns its id.
func (s *Store) CreateEngagement(ctx context.Context, e Engagement) (string, error) {
	body := []byte(e.Body)
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	hosts := e.ApprovedHosts
	if hosts == nil {
		hosts = []string{}
	}
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO aleef_engagements (customer, environment, approved_hosts, engagement_window, approver, body)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		e.Customer, e.Environment, hosts, e.Window, e.Approver, body).Scan(&id)
	return id, err
}

// GetEngagement loads an engagement by id.
func (s *Store) GetEngagement(ctx context.Context, id string) (Engagement, error) {
	var e Engagement
	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT id, customer, environment, approved_hosts, engagement_window, approver, body
		FROM aleef_engagements WHERE id=$1`, id).
		Scan(&e.ID, &e.Customer, &e.Environment, &e.ApprovedHosts, &e.Window, &e.Approver, &body)
	e.Body = body
	return e, err
}

// CreateRun creates a run, optionally under an engagement (empty for none).
func (s *Store) CreateRun(ctx context.Context, engagementID string) (string, error) {
	var eng any
	if engagementID != "" {
		eng = engagementID
	}
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO aleef_runs (engagement_id) VALUES ($1) RETURNING id`, eng).Scan(&id)
	return id, err
}

// SaveTest stores a generated test (idempotent per run and test id).
func (s *Store) SaveTest(ctx context.Context, runID string, t generate.Test) error {
	params, err := json.Marshal(t.Params)
	if err != nil {
		return err
	}
	scenario, err := json.Marshal(t.Scenario)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO aleef_tests (run_id, id, property, params, scenario, covered)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (run_id, id) DO UPDATE SET property=EXCLUDED.property, params=EXCLUDED.params,
			scenario=EXCLUDED.scenario, covered=EXCLUDED.covered`,
		runID, t.ID, t.Property, params, scenario, t.Covered)
	return err
}

// SaveResult stores one execution of a test. The test must already be saved.
func (s *Store) SaveResult(ctx context.Context, runID string, t generate.Test, execNo int, res exec.Result) error {
	report, err := json.Marshal(res.Report)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO aleef_results
		(run_id, test_id, exec_no, report, verdict_finding, verdict_reason, verdict_oracle)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		runID, t.ID, execNo, report, string(res.Verdict.Finding), res.Verdict.Reason, string(res.Verdict.Oracle))
	return err
}

const findingCols = `id, run_id, test_id, property, state, prior_knowledge, COALESCE(evidence_hash,''), covered, created_at, updated_at`

func scanFinding(row pgx.Row) (Finding, error) {
	var f Finding
	err := row.Scan(&f.ID, &f.RunID, &f.TestID, &f.Property, &f.State, &f.PriorKnowledge, &f.EvidenceHash,
		&f.Covered, &f.CreatedAt, &f.UpdatedAt)
	return f, err
}

// CreateFinding records a candidate finding for a test. The verdict is not
// stored on the finding; it lives in aleef_results.
func (s *Store) CreateFinding(ctx context.Context, runID string, t generate.Test, res exec.Result) (Finding, error) {
	_ = res
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Finding{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	f, err := scanFinding(tx.QueryRow(ctx, `INSERT INTO aleef_findings (run_id, test_id, property, covered)
		VALUES ($1,$2,$3,$4) RETURNING `+findingCols, runID, t.ID, t.Property, t.Covered))
	if err != nil {
		return Finding{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO aleef_finding_history (finding_id, previous_state, new_state, reason, actor)
		VALUES ($1,'',$2,'created','system')`, f.ID, StateCandidate); err != nil {
		return Finding{}, err
	}
	return f, tx.Commit(ctx)
}

// GetFinding loads one finding.
func (s *Store) GetFinding(ctx context.Context, id string) (Finding, error) {
	return scanFinding(s.pool.QueryRow(ctx, `SELECT `+findingCols+` FROM aleef_findings WHERE id=$1`, id))
}

// ListFindings returns a run's findings split into candidates, verified and
// everything else (rejected, unconfirmed). Candidates and verified are never
// merged. The verified slice is raw state: it can include a finding whose
// regression was never saved (see ListVerifiedWithoutRegression); use
// ListVerifiedWithRegression for the list to present as verified.
func (s *Store) ListFindings(ctx context.Context, runID string) (candidates, verified []Finding, others []Finding, err error) {
	rows, err := s.pool.Query(ctx, `SELECT `+findingCols+` FROM aleef_findings WHERE run_id=$1 ORDER BY created_at, id`, runID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, nil, nil, err
		}
		switch f.State {
		case StateCandidate:
			candidates = append(candidates, f)
		case StateVerified:
			verified = append(verified, f)
		default:
			others = append(others, f)
		}
	}
	return candidates, verified, others, rows.Err()
}

// SetFindingState moves a finding to candidate, rejected or unconfirmed. It
// rejects 'verified' (use MarkVerified) and never moves a verified finding
// back to candidate; leaving verified requires a reason.
func (s *Store) SetFindingState(ctx context.Context, id, state, reason, actor string) error {
	switch state {
	case StateCandidate, StateRejected, StateUnconfirmed:
	case StateVerified:
		return errors.New("aleef store: state verified can only be set by MarkVerified")
	default:
		return fmt.Errorf("aleef store: unknown finding state %q", state)
	}
	return s.transition(ctx, id, state, "", reason, actor)
}

// MarkVerified is the only path to state verified. evidenceHash must be
// non-empty.
func (s *Store) MarkVerified(ctx context.Context, id, evidenceHash, actor string) error {
	if evidenceHash == "" {
		return errors.New("aleef store: verified requires a non-empty evidence hash")
	}
	return s.transition(ctx, id, StateVerified, evidenceHash, "verified with evidence", actor)
}

func (s *Store) transition(ctx context.Context, id, next, evidenceHash, reason, actor string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var prev string
	if err := tx.QueryRow(ctx, `SELECT state FROM aleef_findings WHERE id=$1 FOR UPDATE`, id).Scan(&prev); err != nil {
		return fmt.Errorf("aleef store: load finding %s: %w", id, err)
	}
	if prev == next {
		return fmt.Errorf("aleef store: finding is already %s", prev)
	}
	if prev == StateVerified && next == StateCandidate {
		return errors.New("aleef store: a verified finding cannot return to candidate")
	}
	if next == StateVerified && prev != StateCandidate && prev != StateUnconfirmed {
		return fmt.Errorf("aleef store: cannot verify a %s finding", prev)
	}
	if prev == StateVerified && reason == "" {
		return errors.New("aleef store: leaving verified requires a reason")
	}
	if next == StateVerified {
		_, err = tx.Exec(ctx, `UPDATE aleef_findings SET state=$2, evidence_hash=$3, updated_at=NOW() WHERE id=$1`, id, next, evidenceHash)
	} else {
		_, err = tx.Exec(ctx, `UPDATE aleef_findings SET state=$2, updated_at=NOW() WHERE id=$1`, id, next)
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO aleef_finding_history (finding_id, previous_state, new_state, reason, actor)
		VALUES ($1,$2,$3,$4,$5)`, id, prev, next, reason, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
