package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIBASTarget is a registered assessment target. Scope lives here, not in the request: a job can only name a target and
// scenarios, and the target decides the base URL, environment, allowed hosts, allowed scenarios and credential references.
type APIBASTarget struct {
	ID               string
	Name             string
	BaseURL          string
	Environment      string // lab, staging or production; production is registrable but never executed in this release
	AllowedHosts     []string
	// AllowedPaths are the path prefixes (whole segments) the runner may request. Required for staging and production.
	AllowedPaths     []string
	AllowedScenarios []string
	// CredentialRefs maps runner secret names to D4 secret-store references. Never values.
	CredentialRefs map[string]string
	Enabled        bool
	CreatedBy      string
	CreatedAt      time.Time
}

// APIBASApproval is a recorded approval of one exact assessment configuration (see jobs.Binding).
type APIBASApproval struct {
	ID          string
	BindingHash string
	TargetID    string
	RequestedBy string
	ApprovedBy  string
	ApprovedAt  *time.Time
	CreatedAt   time.Time
	// ExpiresAt is set when the approval is granted. An approval is unusable at or after it.
	ExpiresAt *time.Time
	RevokedBy    string
	RevokedAt    *time.Time
	RevokeReason string
	// ConsumedByJob is the job that used the approval. An approval covers one job.
	ConsumedByJob string
	ConsumedAt    *time.Time
}

const (
	// ApprovalValidity is how long a granted approval stays usable.
	ApprovalValidity = 24 * time.Hour
	// ApprovalRequestWindow is how long a request may wait to be approved.
	ApprovalRequestWindow = 72 * time.Hour
)

var (
	// ErrAPIBASTargetNotFound means no target has the given id.
	ErrAPIBASTargetNotFound = errors.New("apibas target not found")
	// ErrAPIBASTargetExists means a target with this id is already registered.
	ErrAPIBASTargetExists = errors.New("apibas target already registered")
	// ErrAPIBASTargetBusy means the target already has a queued or running job.
	ErrAPIBASTargetBusy = errors.New("apibas target already has an active job")
	// ErrAPIBASApprovalNotFound means no approval has the given id.
	ErrAPIBASApprovalNotFound = errors.New("apibas approval not found")
	// ErrAPIBASApprovalUnusable means the approval is not approved, or is expired, revoked or already used.
	ErrAPIBASApprovalUnusable = errors.New("apibas approval is not usable")
)

// CreateAPIBASTarget registers a target. A second registration of the same id is refused, not replaced.
func CreateAPIBASTarget(ctx context.Context, pool *pgxpool.Pool, t APIBASTarget) error {
	hosts, _ := json.Marshal(t.AllowedHosts)
	paths, _ := json.Marshal(nonNil(t.AllowedPaths))
	scen, _ := json.Marshal(t.AllowedScenarios)
	refs, _ := json.Marshal(t.CredentialRefs)
	tag, err := pool.Exec(ctx, `
		INSERT INTO apibas_targets (id, name, base_url, environment, allowed_hosts, allowed_scenarios, credential_refs, enabled, created_by, allowed_paths)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9, $10::jsonb)
		ON CONFLICT (id) DO NOTHING`,
		t.ID, t.Name, t.BaseURL, t.Environment, string(hosts), string(scen), string(refs), t.Enabled, t.CreatedBy, string(paths))
	if err != nil {
		return fmt.Errorf("create apibas target: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAPIBASTargetExists
	}
	return nil
}

// nonNil makes a nil slice encode as [] rather than null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GetAPIBASTarget returns one target by id.
func GetAPIBASTarget(ctx context.Context, pool *pgxpool.Pool, id string) (APIBASTarget, error) {
	var t APIBASTarget
	var hosts, scen, refs, paths string
	err := pool.QueryRow(ctx, `
		SELECT id, name, base_url, environment, allowed_hosts::text, allowed_scenarios::text, credential_refs::text,
		       enabled, created_by, created_at, allowed_paths::text
		  FROM apibas_targets WHERE id = $1`, id).
		Scan(&t.ID, &t.Name, &t.BaseURL, &t.Environment, &hosts, &scen, &refs, &t.Enabled, &t.CreatedBy, &t.CreatedAt, &paths)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIBASTarget{}, ErrAPIBASTargetNotFound
	}
	if err != nil {
		return APIBASTarget{}, fmt.Errorf("read apibas target: %w", err)
	}
	if err := json.Unmarshal([]byte(hosts), &t.AllowedHosts); err != nil {
		return APIBASTarget{}, fmt.Errorf("decode allowed hosts: %w", err)
	}
	if err := json.Unmarshal([]byte(paths), &t.AllowedPaths); err != nil {
		return APIBASTarget{}, fmt.Errorf("decode allowed paths: %w", err)
	}
	if err := json.Unmarshal([]byte(scen), &t.AllowedScenarios); err != nil {
		return APIBASTarget{}, fmt.Errorf("decode allowed scenarios: %w", err)
	}
	if err := json.Unmarshal([]byte(refs), &t.CredentialRefs); err != nil {
		return APIBASTarget{}, fmt.Errorf("decode credential refs: %w", err)
	}
	return t, nil
}

// CreateAPIBASApproval records a pending approval request bound to one configuration hash.
func CreateAPIBASApproval(ctx context.Context, pool *pgxpool.Pool, a APIBASApproval) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO apibas_approvals (binding_hash, target_id, requested_by) VALUES ($1, $2, $3) RETURNING id::text`,
		a.BindingHash, a.TargetID, a.RequestedBy).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create apibas approval: %w", err)
	}
	return id, nil
}

// ApproveAPIBASApproval records the approver. The requester cannot approve their own request, and an approval is recorded once.
func ApproveAPIBASApproval(ctx context.Context, pool *pgxpool.Pool, id, approver string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE apibas_approvals SET approved_by = $2, approved_at = NOW(), expires_at = NOW() + make_interval(secs => $3)
		 WHERE id = $1::uuid AND approved_by = '' AND revoked_at IS NULL AND requested_by <> $2
		   AND created_at > NOW() - make_interval(secs => $4)`,
		id, approver, ApprovalValidity.Seconds(), ApprovalRequestWindow.Seconds())
	if err != nil {
		return fmt.Errorf("approve apibas approval: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAPIBASApprovalNotFound
	}
	return nil
}

// RevokeAPIBASApproval withdraws a pending or approved approval. An approval that was already used or revoked cannot be revoked.
func RevokeAPIBASApproval(ctx context.Context, pool *pgxpool.Pool, id, by, reason string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE apibas_approvals SET revoked_by = $2, revoked_at = NOW(), revoke_reason = $3
		 WHERE id = $1::uuid AND revoked_at IS NULL AND consumed_at IS NULL`, id, by, reason)
	if err != nil {
		return fmt.Errorf("revoke apibas approval: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAPIBASApprovalNotFound
	}
	return nil
}

// ConsumeAPIBASApproval marks an approval used by a job, atomically. It succeeds only for an approved, unexpired, unrevoked,
// unused approval, so two jobs racing for one approval cannot both get it.
func ConsumeAPIBASApproval(ctx context.Context, pool *pgxpool.Pool, id, jobID string) error {
	tag, err := pool.Exec(ctx, `
		UPDATE apibas_approvals SET consumed_by_job = $2, consumed_at = NOW()
		 WHERE id = $1::uuid AND approved_by <> '' AND revoked_at IS NULL AND consumed_at IS NULL
		   AND expires_at IS NOT NULL AND expires_at > NOW()`, id, jobID)
	if err != nil {
		return fmt.Errorf("consume apibas approval: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrAPIBASApprovalUnusable
	}
	return nil
}

// GetAPIBASApproval returns one approval by id.
func GetAPIBASApproval(ctx context.Context, pool *pgxpool.Pool, id string) (APIBASApproval, error) {
	var a APIBASApproval
	err := pool.QueryRow(ctx, `
		SELECT id::text, binding_hash, target_id, requested_by, approved_by, approved_at, created_at,
		       expires_at, revoked_by, revoked_at, revoke_reason, consumed_by_job, consumed_at
		  FROM apibas_approvals WHERE id = $1::uuid`, id).
		Scan(&a.ID, &a.BindingHash, &a.TargetID, &a.RequestedBy, &a.ApprovedBy, &a.ApprovedAt, &a.CreatedAt,
			&a.ExpiresAt, &a.RevokedBy, &a.RevokedAt, &a.RevokeReason, &a.ConsumedByJob, &a.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIBASApproval{}, ErrAPIBASApprovalNotFound
	}
	if err != nil {
		return APIBASApproval{}, fmt.Errorf("read apibas approval: %w", err)
	}
	return a, nil
}

// CreateAPIBASJobExclusive stores a job for a registered target while holding a per-target lock, so two requests cannot both
// start an assessment on one target. A repeated key returns the existing job (created=false). A different key for a target that
// already has a queued or running job returns ErrAPIBASTargetBusy.
func CreateAPIBASJobExclusive(ctx context.Context, pool *pgxpool.Pool, j APIBASJob) (APIBASJob, bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return APIBASJob{}, false, fmt.Errorf("create apibas job: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "apibas-target:"+j.TargetID); err != nil {
		return APIBASJob{}, false, fmt.Errorf("lock apibas target: %w", err)
	}
	var existingID string
	err = tx.QueryRow(ctx, `SELECT id::text FROM apibas_jobs WHERE job_key = $1`, j.JobKey).Scan(&existingID)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return APIBASJob{}, false, err
		}
		got, gerr := GetAPIBASJob(ctx, pool, existingID)
		return got, false, gerr
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return APIBASJob{}, false, fmt.Errorf("create apibas job: %w", err)
	}
	var active int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM apibas_jobs WHERE target_id = $1 AND status IN ('queued', 'running')`, j.TargetID).Scan(&active); err != nil {
		return APIBASJob{}, false, fmt.Errorf("create apibas job: %w", err)
	}
	if active > 0 {
		return APIBASJob{}, false, ErrAPIBASTargetBusy
	}
	scen, _ := json.Marshal(j.ScenarioIDs)
	refs, _ := json.Marshal(j.CredentialRefs)
	hosts, _ := json.Marshal(j.AllowedHosts)
	paths, _ := json.Marshal(nonNil(j.AllowedPaths))
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO apibas_jobs (job_key, requested_by, target_id, target_base_url, environment, fixture, scenario_ids, credential_refs, allowed_hosts, allowed_paths, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, 'queued') RETURNING id::text`,
		j.JobKey, j.RequestedBy, j.TargetID, j.TargetBaseURL, j.Environment, j.Fixture, string(scen), string(refs), string(hosts), string(paths)).Scan(&id); err != nil {
		return APIBASJob{}, false, fmt.Errorf("create apibas job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return APIBASJob{}, false, fmt.Errorf("create apibas job: %w", err)
	}
	got, gerr := GetAPIBASJob(ctx, pool, id)
	return got, true, gerr
}
