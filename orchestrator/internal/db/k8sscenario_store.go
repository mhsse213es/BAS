package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/k8sscenario"
)

// EnsureK8sScenarioSchema creates the approval and run tables for Kubernetes state-changing scenarios, adds the
// execution identity columns, and makes those columns immutable. Idempotent.
//
// The identity columns (cluster ID, authorization ID, customer reference, parameters hash) are the authoritative
// execution context. A trigger refuses any update that changes them. Rows written before these columns existed have an
// empty cluster ID, and execution refuses them: they are never resolved by display name.
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
		// Identity columns, added after the tables existed. Empty on legacy rows, which execution refuses.
		`ALTER TABLE k8s_scenario_runs ADD COLUMN IF NOT EXISTS cluster_id text NOT NULL DEFAULT ''`,
		`ALTER TABLE k8s_scenario_runs ADD COLUMN IF NOT EXISTS authorization_id text NOT NULL DEFAULT ''`,
		`ALTER TABLE k8s_scenario_runs ADD COLUMN IF NOT EXISTS customer_ref text NOT NULL DEFAULT ''`,
		`ALTER TABLE k8s_scenario_approvals ADD COLUMN IF NOT EXISTS cluster_id text NOT NULL DEFAULT ''`,
		`ALTER TABLE k8s_scenario_approvals ADD COLUMN IF NOT EXISTS authorization_id text NOT NULL DEFAULT ''`,
		`ALTER TABLE k8s_scenario_approvals ADD COLUMN IF NOT EXISTS customer_ref text NOT NULL DEFAULT ''`,
		`ALTER TABLE k8s_scenario_approvals ADD COLUMN IF NOT EXISTS approved_at timestamptz NOT NULL DEFAULT NOW()`,
		`CREATE OR REPLACE FUNCTION k8s_identity_immutable() RETURNS trigger AS $$
		BEGIN
			IF NEW.cluster_id IS DISTINCT FROM OLD.cluster_id
			   OR NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
			   OR NEW.customer_ref IS DISTINCT FROM OLD.customer_ref
			   OR NEW.params_hash IS DISTINCT FROM OLD.params_hash THEN
				RAISE EXCEPTION 'execution identity is immutable' USING ERRCODE = 'check_violation';
			END IF;
			RETURN NEW;
		END
		$$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS k8s_runs_identity_immutable ON k8s_scenario_runs`,
		`CREATE TRIGGER k8s_runs_identity_immutable BEFORE UPDATE ON k8s_scenario_runs
			FOR EACH ROW EXECUTE FUNCTION k8s_identity_immutable()`,
		`DROP TRIGGER IF EXISTS k8s_approvals_identity_immutable ON k8s_scenario_approvals`,
		`CREATE TRIGGER k8s_approvals_identity_immutable BEFORE UPDATE ON k8s_scenario_approvals
			FOR EACH ROW EXECUTE FUNCTION k8s_identity_immutable()`,
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
			(id, approver_id, requester_id, run_id, cluster, namespace, action_id, params_hash, expires_at,
			 cluster_id, authorization_id, customer_ref, approved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		a.ID, a.ApproverID, a.RequesterID, a.RunID, a.Cluster, a.Namespace, a.ActionID, a.ParamsHash, a.ExpiresAt,
		a.ClusterID, a.AuthorizationID, a.CustomerRef, a.ApprovedAt)
	return err
}

// Get returns an approval by ID.
func (s *K8sApprovalStore) Get(id string) (k8sscenario.Approval, bool, error) {
	var a k8sscenario.Approval
	err := s.pool.QueryRow(context.Background(), `
		SELECT id, approver_id, requester_id, run_id, cluster, namespace, action_id, params_hash, expires_at, used,
		       cluster_id, authorization_id, customer_ref, approved_at
		FROM k8s_scenario_approvals WHERE id = $1`, id).Scan(
		&a.ID, &a.ApproverID, &a.RequesterID, &a.RunID, &a.Cluster, &a.Namespace, &a.ActionID, &a.ParamsHash, &a.ExpiresAt, &a.Used,
		&a.ClusterID, &a.AuthorizationID, &a.CustomerRef, &a.ApprovedAt)
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

// K8sRunRecord is one scenario run as stored. The api package converts it to and from its own K8sRun type.
//
// ClusterID, AuthorizationID and CustomerRef are the execution context. They are set when the run is planned and cannot
// change afterwards. Cluster is the display name, kept for presentation only.
type K8sRunRecord struct {
	ID              string
	RequesterID     string
	Cluster         string
	ClusterID       string
	AuthorizationID string
	CustomerRef     string
	Namespace       string
	ActionID        string
	Params          map[string]string
	ParamsHash      string
	ApprovalID      string
	State           string
	Detail          string
	CreatedAt       time.Time
}

// K8sRunStore persists scenario runs.
type K8sRunStore struct {
	pool *pgxpool.Pool
}

// NewK8sRunStore returns a run store over the pool.
func NewK8sRunStore(pool *pgxpool.Pool) *K8sRunStore {
	return &K8sRunStore{pool: pool}
}

// InsertRun stores a planned run, with its execution context.
func (s *K8sRunStore) InsertRun(ctx context.Context, r K8sRunRecord) error {
	params, err := json.Marshal(r.Params)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO k8s_scenario_runs
			(id, requester_id, cluster, namespace, action_id, params, params_hash, state, detail, created_at, updated_at,
			 cluster_id, authorization_id, customer_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11, $12, $13)`,
		r.ID, r.RequesterID, r.Cluster, r.Namespace, r.ActionID, params, r.ParamsHash, r.State, r.Detail, r.CreatedAt,
		r.ClusterID, r.AuthorizationID, r.CustomerRef)
	return err
}

// UpdateRun records a state change, approval link or outcome. It does not change the execution context; the database
// trigger would refuse it.
func (s *K8sRunStore) UpdateRun(ctx context.Context, r K8sRunRecord) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE k8s_scenario_runs
		SET approval_id = NULLIF($2, ''), state = $3, detail = $4, updated_at = NOW()
		WHERE id = $1`,
		r.ID, r.ApprovalID, r.State, r.Detail)
	return err
}

// GetRun returns a run by ID.
func (s *K8sRunStore) GetRun(ctx context.Context, id string) (K8sRunRecord, bool, error) {
	var r K8sRunRecord
	var params []byte
	var approval *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, requester_id, cluster, namespace, action_id, params, params_hash, approval_id, state, detail, created_at,
		       cluster_id, authorization_id, customer_ref
		FROM k8s_scenario_runs WHERE id = $1`, id).Scan(
		&r.ID, &r.RequesterID, &r.Cluster, &r.Namespace, &r.ActionID, &params, &r.ParamsHash, &approval, &r.State, &r.Detail, &r.CreatedAt,
		&r.ClusterID, &r.AuthorizationID, &r.CustomerRef)
	if errors.Is(err, pgx.ErrNoRows) {
		return K8sRunRecord{}, false, nil
	}
	if err != nil {
		return K8sRunRecord{}, false, err
	}
	if approval != nil {
		r.ApprovalID = *approval
	}
	if err := json.Unmarshal(params, &r.Params); err != nil {
		return K8sRunRecord{}, false, err
	}
	return r, true, nil
}

// ListRuns returns the most recent runs first.
func (s *K8sRunStore) ListRuns(ctx context.Context, limit int) ([]K8sRunRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, requester_id, cluster, namespace, action_id, params, params_hash, COALESCE(approval_id, ''), state, detail, created_at,
		       cluster_id, authorization_id, customer_ref
		FROM k8s_scenario_runs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []K8sRunRecord
	for rows.Next() {
		var r K8sRunRecord
		var params []byte
		if err := rows.Scan(&r.ID, &r.RequesterID, &r.Cluster, &r.Namespace, &r.ActionID, &params, &r.ParamsHash, &r.ApprovalID,
			&r.State, &r.Detail, &r.CreatedAt, &r.ClusterID, &r.AuthorizationID, &r.CustomerRef); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(params, &r.Params); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
