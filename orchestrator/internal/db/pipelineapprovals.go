package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/injectionapproval"
)

// ErrApprovalNotFound means no approval exists under that ID.
var ErrApprovalNotFound = errors.New("pipeline approval not found")

// ErrApprovalConsumed means another request used the approval first. Only one of two racing
// consumers can succeed.
var ErrApprovalConsumed = errors.New("pipeline approval already used")

// ErrApprovalDecided means the request was already approved, or refused. It cannot be decided again.
var ErrApprovalDecided = errors.New("pipeline approval already decided")

// RequestApproval records a new approval request for one exact scope. The scope is stored
// with its hash, so later checks compare against what was requested.
func (s KillChainStore) RequestApproval(ctx context.Context, id, requestedBy string, scope injectionapproval.Scope, now time.Time) error {
	if id == "" || requestedBy == "" {
		return fmt.Errorf("approval needs an id and a requester")
	}
	body, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO pipeline_approvals (id, kind, scope, scope_hash, requested_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, string(scope.Kind), body, scope.Hash(), requestedBy, now.UTC()); err != nil {
		return err
	}
	if err := appendApprovalEvent(ctx, tx, id, "requested", requestedBy, map[string]any{"scopeHash": scope.Hash()}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ApproveRequest approves a pending request. It applies the rules in injectionapproval.Approve
// and records the approval, or the refusal, in the history.
func (s KillChainStore) ApproveRequest(ctx context.Context, id, approver string, c injectionapproval.Classification, now time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rec, err := loadApproval(ctx, tx, id)
	if err != nil {
		return err
	}
	if rec.ApprovedBy != "" {
		return ErrApprovalDecided
	}
	if err := injectionapproval.Approve(&rec, approver, now, c); err != nil {
		if aerr := appendApprovalEvent(ctx, tx, id, "refused", approver, map[string]any{"reason": err.Error()}, now); aerr != nil {
			return aerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return cerr
		}
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE pipeline_approvals SET approved_by=$2, approved_at=$3, expires_at=$4
		WHERE id=$1 AND approved_by='' AND consumed_at IS NULL AND refused_at IS NULL`, id, rec.ApprovedBy, rec.ApprovedAt.UTC(), rec.ExpiresAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrApprovalDecided
	}
	if err := appendApprovalEvent(ctx, tx, id, "approved", approver, map[string]any{"expiresAt": rec.ExpiresAt}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ConsumeApproval authorizes one execution. It verifies the approval against the scope about
// to run, then marks it used with a single conditional update. Two concurrent consumers
// cannot both succeed: the second finds consumed_at already set and gets ErrApprovalConsumed.
func (s KillChainStore) ConsumeApproval(ctx context.Context, id, consumer string, presented injectionapproval.Scope, c injectionapproval.Classification, now time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rec, err := loadApproval(ctx, tx, id)
	if err != nil {
		return err
	}
	if verr := injectionapproval.Verify(rec, presented, now, c); verr != nil {
		if aerr := appendApprovalEvent(ctx, tx, id, "refused", consumer, map[string]any{"reason": verr.Error()}, now); aerr != nil {
			return aerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return cerr
		}
		return verr
	}
	tag, err := tx.Exec(ctx, `UPDATE pipeline_approvals SET consumed_at=$2, consumed_by=$3
		WHERE id=$1 AND consumed_at IS NULL AND approved_by <> ''`, id, now.UTC(), consumer)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrApprovalConsumed
	}
	if err := appendApprovalEvent(ctx, tx, id, "consumed", consumer, map[string]any{"scopeHash": presented.Hash()}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ApprovalHistory returns the events for one approval in the order they were written.
func (s KillChainStore) ApprovalHistory(ctx context.Context, id string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT event FROM pipeline_approval_events WHERE approval_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func loadApproval(ctx context.Context, tx pgx.Tx, id string) (injectionapproval.Record, error) {
	var rec injectionapproval.Record
	var body []byte
	var approvedAt, expiresAt, consumedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT id, scope, scope_hash, requested_by, approved_by, approved_at, expires_at, consumed_at
		FROM pipeline_approvals WHERE id=$1 FOR UPDATE`, id).
		Scan(&rec.ID, &body, &rec.ScopeHash, &rec.RequestedBy, &rec.ApprovedBy, &approvedAt, &expiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return injectionapproval.Record{}, ErrApprovalNotFound
	}
	if err != nil {
		return injectionapproval.Record{}, err
	}
	if err := json.Unmarshal(body, &rec.Scope); err != nil {
		return injectionapproval.Record{}, fmt.Errorf("stored approval scope is unreadable: %w", err)
	}
	if approvedAt != nil {
		rec.ApprovedAt = *approvedAt
	}
	if expiresAt != nil {
		rec.ExpiresAt = *expiresAt
	}
	if consumedAt != nil {
		rec.ConsumedAt = *consumedAt
	}
	return rec, nil
}

func appendApprovalEvent(ctx context.Context, tx pgx.Tx, approvalID, event, actor string, detail map[string]any, at time.Time) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pipeline_approval_events (approval_id, event, actor, at, detail)
		VALUES ($1, $2, $3, $4, $5)`, approvalID, event, actor, at.UTC(), body)
	return err
}

// ApprovalView is one approval as an approver sees it, with its full history.
type ApprovalView struct {
	ID          string
	Kind        string
	Scope       injectionapproval.Scope
	ScopeHash   string
	RequestedBy string
	ApprovedBy  string
	ApprovedAt  time.Time
	ExpiresAt   time.Time
	ConsumedAt  time.Time
	ConsumedBy  string
	History     []ApprovalEvent
}

// ApprovalEvent is one entry in an approval's append-only history.
type ApprovalEvent struct {
	Event  string
	Actor  string
	At     time.Time
	Detail map[string]any
}

// GetApproval reads one approval and its history.
func (s KillChainStore) GetApproval(ctx context.Context, id string) (ApprovalView, error) {
	var v ApprovalView
	var body []byte
	var approvedAt, expiresAt, consumedAt *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT id, kind, scope, scope_hash, requested_by, approved_by, approved_at, expires_at,
		consumed_at, consumed_by FROM pipeline_approvals WHERE id=$1`, id).
		Scan(&v.ID, &v.Kind, &body, &v.ScopeHash, &v.RequestedBy, &v.ApprovedBy, &approvedAt, &expiresAt, &consumedAt, &v.ConsumedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApprovalView{}, ErrApprovalNotFound
	}
	if err != nil {
		return ApprovalView{}, err
	}
	if err := json.Unmarshal(body, &v.Scope); err != nil {
		return ApprovalView{}, fmt.Errorf("stored approval scope is unreadable: %w", err)
	}
	if approvedAt != nil {
		v.ApprovedAt = *approvedAt
	}
	if expiresAt != nil {
		v.ExpiresAt = *expiresAt
	}
	if consumedAt != nil {
		v.ConsumedAt = *consumedAt
	}
	rows, err := s.Pool.Query(ctx, `SELECT event, actor, at, detail FROM pipeline_approval_events WHERE approval_id=$1 ORDER BY id`, id)
	if err != nil {
		return ApprovalView{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var e ApprovalEvent
		var raw []byte
		if err := rows.Scan(&e.Event, &e.Actor, &e.At, &raw); err != nil {
			return ApprovalView{}, err
		}
		if err := json.Unmarshal(raw, &e.Detail); err != nil {
			return ApprovalView{}, fmt.Errorf("stored approval event is unreadable: %w", err)
		}
		v.History = append(v.History, e)
	}
	return v, rows.Err()
}

// RefuseApproval records a refusal of a pending request. It does not change the approval, so
// a refused request simply stays unapproved and cannot be used.
func (s KillChainStore) RefuseApproval(ctx context.Context, id, actor, reason string, now time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadApproval(ctx, tx, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE pipeline_approvals SET refused_at=$2
		WHERE id=$1 AND approved_by='' AND consumed_at IS NULL AND refused_at IS NULL`, id, now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrApprovalDecided
	}
	if err := appendApprovalEvent(ctx, tx, id, "refused", actor, map[string]any{"reason": reason}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordExecutionOutcome appends the result of a consumed approval's action: "executed" or
// "failed". An approval that was consumed but has no outcome in its history was interrupted, for
// example by a crash, and its outcome is unknown. Such an approval is never reused. Recovery means
// a new request and a new approval.
func (s KillChainStore) RecordExecutionOutcome(ctx context.Context, id, actor, outcome string, now time.Time) error {
	if outcome != "executed" && outcome != "failed" {
		return fmt.Errorf("outcome must be executed or failed")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rec, err := loadApproval(ctx, tx, id)
	if err != nil {
		return err
	}
	if rec.ConsumedAt.IsZero() {
		return fmt.Errorf("approval %s was not consumed; it has no execution to record", id)
	}
	if err := appendApprovalEvent(ctx, tx, id, outcome, actor, map[string]any{}, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
