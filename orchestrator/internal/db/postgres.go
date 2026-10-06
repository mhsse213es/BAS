package db

import (
	"context"
	"fmt"
	"github.com/audspect/bas/internal/db/legacy"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect creates a pgxpool connection and verifies reachability.
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db ping: %w", err)
	}
	return pool, nil
}

// EnsureSchema creates all required tables if they do not exist.
// Idempotent — safe to call on every startup.
func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return legacy.EnsureSchema(ctx, pool)
}

// ── Compliance snapshots ──────────────────────────────────────────────────────

// ComplianceSnapshot is the persisted compliance score for one (agent, framework) pair.
type ComplianceSnapshot struct {
	AgentID            string    `json:"agentId"`
	FrameworkID        string    `json:"frameworkId"`
	SnapshotAt         time.Time `json:"snapshotAt"`
	RunCount           int       `json:"runCount"`
	CompliancePct      float64   `json:"compliancePct"`
	CoveragePct        float64   `json:"coveragePct"`
	TotalControls      int       `json:"totalControls"`
	TestableControls   int       `json:"testableControls"`
	TestedControls     int       `json:"testedControls"`
	PassingControls    int       `json:"passingControls"`
	FailingControls    int       `json:"failingControls"`
	ManualControls     int       `json:"manualControls"`
	EnrolledAgentCount int       `json:"enrolledAgentCount,omitempty"` // fleet-wide only; 0 in single-agent queries
}

// UpsertComplianceSnapshot writes (or overwrites) the compliance score snapshot
// for the given (agent, framework) pair. Called asynchronously after every run.
func UpsertComplianceSnapshot(ctx context.Context, pool *pgxpool.Pool, s ComplianceSnapshot) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO compliance_snapshots
		  (agent_id, framework_id, snapshot_at, run_count,
		   compliance_pct, coverage_pct,
		   total_controls, testable_controls, tested_controls,
		   passing_controls, failing_controls, manual_controls)
		VALUES ($1,$2,NOW(),$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (agent_id, framework_id) DO UPDATE SET
		  snapshot_at       = EXCLUDED.snapshot_at,
		  run_count         = EXCLUDED.run_count,
		  compliance_pct    = EXCLUDED.compliance_pct,
		  coverage_pct      = EXCLUDED.coverage_pct,
		  total_controls    = EXCLUDED.total_controls,
		  testable_controls = EXCLUDED.testable_controls,
		  tested_controls   = EXCLUDED.tested_controls,
		  passing_controls  = EXCLUDED.passing_controls,
		  failing_controls  = EXCLUDED.failing_controls,
		  manual_controls   = EXCLUDED.manual_controls`,
		s.AgentID, s.FrameworkID, s.RunCount,
		s.CompliancePct, s.CoveragePct,
		s.TotalControls, s.TestableControls, s.TestedControls,
		s.PassingControls, s.FailingControls, s.ManualControls)
	return err
}

// GetComplianceScores returns the latest snapshot for every framework for a
// given agent, ordered by framework_id.
func GetComplianceScores(ctx context.Context, pool *pgxpool.Pool, agentID string) ([]ComplianceSnapshot, error) {
	rows, err := pool.Query(ctx, `
		SELECT agent_id, framework_id, snapshot_at, run_count,
		       compliance_pct, coverage_pct,
		       total_controls, testable_controls, tested_controls,
		       passing_controls, failing_controls, manual_controls
		FROM compliance_snapshots
		WHERE agent_id = $1
		ORDER BY framework_id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceSnapshot
	for rows.Next() {
		var s ComplianceSnapshot
		if err := rows.Scan(&s.AgentID, &s.FrameworkID, &s.SnapshotAt, &s.RunCount,
			&s.CompliancePct, &s.CoveragePct,
			&s.TotalControls, &s.TestableControls, &s.TestedControls,
			&s.PassingControls, &s.FailingControls, &s.ManualControls); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// GetFleetComplianceScores returns the worst-case (minimum) compliance percentage
// per framework aggregated across all agents — the fleet-wide CISO view.
func GetFleetComplianceScores(ctx context.Context, pool *pgxpool.Pool) ([]ComplianceSnapshot, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (framework_id)
		       framework_id, agent_id, snapshot_at, run_count,
		       compliance_pct, coverage_pct,
		       total_controls, testable_controls, tested_controls,
		       passing_controls, failing_controls, manual_controls,
		       COUNT(*) OVER (PARTITION BY framework_id) AS enrolled_agent_count
		FROM compliance_snapshots
		ORDER BY framework_id, compliance_pct ASC, snapshot_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceSnapshot
	for rows.Next() {
		var s ComplianceSnapshot
		if err := rows.Scan(&s.FrameworkID, &s.AgentID, &s.SnapshotAt, &s.RunCount,
			&s.CompliancePct, &s.CoveragePct,
			&s.TotalControls, &s.TestableControls, &s.TestedControls,
			&s.PassingControls, &s.FailingControls, &s.ManualControls,
			&s.EnrolledAgentCount); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
