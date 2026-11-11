// Package runstore persists segmentation runs and their per-probe verdicts.
// Stored verdicts are exactly what the verdict engine produced.
package runstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("segmentation run not found")

type Run struct {
	ID            string     `json:"id"`
	PackID        string     `json:"pack_id"`
	RequestedBy   string     `json:"requested_by"`
	Status        string     `json:"status"`
	Runs          int        `json:"runs"`
	Stable        *bool      `json:"stable"`
	FailureReason string     `json:"failure_reason"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
}

type ProbeRow struct {
	RunIndex  int        `json:"run_index"`
	Seq       int        `json:"seq"`
	ProbeID   string     `json:"probe_id"`
	Src       string     `json:"src"`
	Dst       string     `json:"dst"`
	DstPort   int        `json:"dst_port"`
	Proto     string     `json:"proto"`
	Expect    string     `json:"expect"`
	Outcome   string     `json:"outcome"`
	Verdict   string     `json:"verdict"`
	Reason    string     `json:"reason"`
	RuleIDs   []string   `json:"rule_ids"`
	StartedAt *time.Time `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at"`
}

type Store struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const runColumns = `id::text, pack_id, requested_by, status, runs, stable, failure_reason, created_at, started_at, finished_at`

func (s *Store) Create(ctx context.Context, packID, requestedBy string) (Run, error) {
	var r Run
	err := s.pool.QueryRow(ctx,
		`INSERT INTO segmentation_runs (pack_id, requested_by, status) VALUES ($1, $2, 'queued') RETURNING `+runColumns,
		packID, requestedBy).Scan(runFields(&r)...)
	if err != nil {
		return Run{}, fmt.Errorf("create run: %w", err)
	}
	return r, nil
}

func (s *Store) SetRunning(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE segmentation_runs SET status = 'running', started_at = NOW() WHERE id = $1::uuid`, id)
	return err
}

// SaveRunResults stores one repeated pass. All rows of a pass commit together.
func (s *Store) SaveRunResults(ctx context.Context, id string, runIndex int, rows []ProbeRow) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	for seq, row := range rows {
		ruleIDs := []byte("[]")
		if row.RuleIDs != nil {
			ruleIDs, err = json.Marshal(row.RuleIDs)
			if err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO segmentation_probe_results
				(run_id, run_index, seq, probe_id, src, dst, dst_port, proto, expect, outcome, verdict, reason, rule_ids, started_at, ended_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			id, runIndex, seq, row.ProbeID, row.Src, row.Dst, row.DstPort, row.Proto, row.Expect,
			row.Outcome, row.Verdict, row.Reason, ruleIDs, row.StartedAt, row.EndedAt); err != nil {
			return fmt.Errorf("save probe result: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) Finish(ctx context.Context, id, status string, runs int, stable *bool, failure string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE segmentation_runs
		SET status = $2, runs = $3, stable = $4, failure_reason = $5, finished_at = NOW()
		WHERE id = $1::uuid`, id, status, runs, stable, failure)
	return err
}

// FailStale marks runs left queued or running by a previous process as failed.
// It runs at startup, so a crash cannot leave the single-run guard stuck.
func (s *Store) FailStale(ctx context.Context, reason string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE segmentation_runs SET status = 'failed', failure_reason = $1, finished_at = NOW()
		WHERE status IN ('queued', 'running')`, reason)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) List(ctx context.Context, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+runColumns+` FROM segmentation_runs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(runFields(&r)...); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Get(ctx context.Context, id string) (Run, []ProbeRow, error) {
	var r Run
	err := s.pool.QueryRow(ctx,
		`SELECT `+runColumns+` FROM segmentation_runs WHERE id = $1::uuid`, id).Scan(runFields(&r)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, nil, ErrNotFound
	}
	if err != nil {
		return Run{}, nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT run_index, seq, probe_id, src, dst, dst_port, proto, expect, outcome, verdict, reason, rule_ids, started_at, ended_at
		FROM segmentation_probe_results WHERE run_id = $1::uuid ORDER BY run_index, seq`, id)
	if err != nil {
		return Run{}, nil, err
	}
	defer rows.Close()
	probes := []ProbeRow{}
	for rows.Next() {
		var p ProbeRow
		var ruleJSON []byte
		if err := rows.Scan(&p.RunIndex, &p.Seq, &p.ProbeID, &p.Src, &p.Dst, &p.DstPort, &p.Proto, &p.Expect,
			&p.Outcome, &p.Verdict, &p.Reason, &ruleJSON, &p.StartedAt, &p.EndedAt); err != nil {
			return Run{}, nil, err
		}
		if err := json.Unmarshal(ruleJSON, &p.RuleIDs); err != nil {
			return Run{}, nil, err
		}
		probes = append(probes, p)
	}
	return r, probes, rows.Err()
}

func runFields(r *Run) []any {
	return []any{&r.ID, &r.PackID, &r.RequestedBy, &r.Status, &r.Runs, &r.Stable, &r.FailureReason, &r.CreatedAt, &r.StartedAt, &r.FinishedAt}
}
