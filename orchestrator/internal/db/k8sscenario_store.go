package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/k8sscenario"
)

// EnsureK8sScenarioSchema creates the approval and run tables for Kubernetes state-changing scenarios.
// Idempotent. See docs/superpowers/specs/2026-10-23-k8s-state-changing-scenarios-design.md.
func EnsureK8sScenarioSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS k8s_scenario_approvals (
			id           text        PRIMARY KEY,
			approver_id  text        NOT NULL,
			requester_id text        NOT NULL,
			run_id       text        NOT NULL,
			cluster      text        NOT NULL,
			namespace    text        NOT NULL,
			action_id    text        NOT NULL,
			params_hash  text        NOT NULL,
			expires_at   timestamptz NOT NULL,
			used         boolean     NOT NULL DEFAULT false,
			used_at      timestamptz,
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			CONSTRAINT k8s_approval_not_self CHECK (approver_id <> requester_id)
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_scenario_runs (
			id           text        PRIMARY KEY,
			requester_id text        NOT NULL,
			cluster      text        NOT NULL,
			namespace    text        NOT NULL,
			action_id    text        NOT NULL,
			params       jsonb       NOT NULL,
			params_hash  text        NOT NULL,
			approval_id  text        REFERENCES k8s_scenario_approvals(id),
			state        text        NOT NULL,
			detail       text        NOT NULL DEFAULT '',
			created_at   timestamptz NOT NULL DEFAULT NOW(),
			updated_at   timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_k8s_runs_state ON k8s_scenario_runs (state)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("k8s scenario schema: %w", err)
		}
	}
	return nil
}

// K8sApprovalStore is the Postgres-backed approval store used by the scenario engine.
type K8sApprovalStore struct {
	pool *pgxpool.Pool
}

// NewK8sApprovalStore returns a store over the pool.
func NewK8sApprovalStore(pool *pgxpool.Pool) *K8sApprovalStore {
	return &K8sApprovalStore{pool: pool}
}

// Put records a new approval. The CHECK constraint refuses an approver equal to the requester.
func (s *K8sApprovalStore) Put(a k8sscenario.Approval) error {
	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO k8s_scenario_approvals
			(id, approver_id, requester_id, run_id, cluster, namespace, action_id, params_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		a.ID, a.ApproverID, a.RequesterID, a.RunID, a.Cluster, a.Namespace, a.ActionID, a.ParamsHash, a.ExpiresAt)
	return err
}

// Get returns an approval by ID.
func (s *K8sApprovalStore) Get(id string) (k8sscenario.Approval, bool, error) {
	var a k8sscenario.Approval
	err := s.pool.QueryRow(context.Background(), `
		SELECT id, approver_id, requester_id, run_id, cluster, namespace, action_id, params_hash, expires_at, used
		FROM k8s_scenario_approvals WHERE id = $1`, id).Scan(
		&a.ID, &a.ApproverID, &a.RequesterID, &a.RunID, &a.Cluster, &a.Namespace, &a.ActionID, &a.ParamsHash, &a.ExpiresAt, &a.Used)
	if errors.Is(err, pgx.ErrNoRows) {
		return k8sscenario.Approval{}, false, nil
	}
	if err != nil {
		return k8sscenario.Approval{}, false, err
	}
	return a, true, nil
}

// MarkUsed consumes an approval atomically. Exactly one caller can succeed for a given approval.
func (s *K8sApprovalStore) MarkUsed(id string) error {
	tag, err := s.pool.Exec(context.Background(), `
		UPDATE k8s_scenario_approvals SET used = true, used_at = $2
		WHERE id = $1 AND used = false AND expires_at > $2`, id, time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("approval is missing, already used, or expired")
	}
	return nil
}
