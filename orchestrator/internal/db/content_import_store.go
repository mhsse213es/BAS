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

// EnsureContentImportSchema creates the table that holds imported content (Sigma, YARA, chains) while it waits for a
// reviewer. Nothing in it can run on an endpoint: a draft only becomes a scenario when an authorised user approves it.
// Idempotent; safe to call on every startup.
func EnsureContentImportSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS content_import_drafts (
			id          TEXT PRIMARY KEY,
			kind        TEXT NOT NULL,
			title       TEXT NOT NULL,
			marker      TEXT NOT NULL,
			status      TEXT NOT NULL DEFAULT 'draft',
			scenario    JSONB NOT NULL,
			coverage    JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_by  TEXT NOT NULL DEFAULT '',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			reviewed_by TEXT NOT NULL DEFAULT '',
			reviewed_at TIMESTAMPTZ,
			review_note TEXT NOT NULL DEFAULT '',
			scenario_id TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_content_import_drafts_status ON content_import_drafts(status, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_content_import_drafts_marker ON content_import_drafts(marker)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("content import schema: %w", err)
		}
	}
	return nil
}

// Import draft states.
const (
	ImportDraftPending  = "draft"
	ImportDraftApproved = "approved"
	ImportDraftRejected = "rejected"
)

// ImportDraft is one imported item awaiting review.
type ImportDraft struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"` // sigma | yara | chain
	Title      string          `json:"title"`
	Marker     string          `json:"marker"`
	Status     string          `json:"status"`
	Scenario   json.RawMessage `json:"scenario"`
	Coverage   json.RawMessage `json:"coverage"`
	CreatedBy  string          `json:"createdBy"`
	CreatedAt  time.Time       `json:"createdAt"`
	ReviewedBy string          `json:"reviewedBy,omitempty"`
	ReviewedAt *time.Time      `json:"reviewedAt,omitempty"`
	ReviewNote string          `json:"reviewNote,omitempty"`
	ScenarioID string          `json:"scenarioId,omitempty"`
}

const importDraftCols = `id, kind, title, marker, status, scenario, coverage, created_by, created_at, reviewed_by, reviewed_at, review_note, scenario_id`

func scanImportDraft(row pgx.Row) (*ImportDraft, error) {
	var d ImportDraft
	if err := row.Scan(&d.ID, &d.Kind, &d.Title, &d.Marker, &d.Status, &d.Scenario, &d.Coverage, &d.CreatedBy, &d.CreatedAt,
		&d.ReviewedBy, &d.ReviewedAt, &d.ReviewNote, &d.ScenarioID); err != nil {
		return nil, err
	}
	return &d, nil
}

// InsertImportDraft stores a new draft.
func InsertImportDraft(ctx context.Context, pool *pgxpool.Pool, d *ImportDraft) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO content_import_drafts (id, kind, title, marker, scenario, coverage, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		d.ID, d.Kind, d.Title, d.Marker, d.Scenario, d.Coverage, d.CreatedBy)
	return err
}

// FindPendingImportDraft returns the waiting draft with this marker, or nil. Importing the same rule twice reuses it.
func FindPendingImportDraft(ctx context.Context, pool *pgxpool.Pool, marker string) (*ImportDraft, error) {
	d, err := scanImportDraft(pool.QueryRow(ctx,
		`SELECT `+importDraftCols+` FROM content_import_drafts WHERE marker=$1 AND status='draft' ORDER BY created_at DESC LIMIT 1`, marker))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

// GetImportDraft returns one draft, or nil when it does not exist.
func GetImportDraft(ctx context.Context, pool *pgxpool.Pool, id string) (*ImportDraft, error) {
	d, err := scanImportDraft(pool.QueryRow(ctx, `SELECT `+importDraftCols+` FROM content_import_drafts WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

// ListImportDrafts lists drafts, newest first; status "" lists all.
func ListImportDrafts(ctx context.Context, pool *pgxpool.Pool, status string, limit int) ([]ImportDraft, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := pool.Query(ctx, `SELECT `+importDraftCols+` FROM content_import_drafts WHERE ($1='' OR status=$1) ORDER BY created_at DESC LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImportDraft{}
	for rows.Next() {
		d, err := scanImportDraft(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// ClaimImportDraft moves a waiting draft to a reviewed state, and reports whether this call did it. Only one caller can
// claim a draft, so two reviewers cannot both approve it.
func ClaimImportDraft(ctx context.Context, pool *pgxpool.Pool, id, status, reviewer, note, scenarioID string) (bool, error) {
	tag, err := pool.Exec(ctx,
		`UPDATE content_import_drafts SET status=$2, reviewed_by=$3, reviewed_at=NOW(), review_note=$4, scenario_id=$5 WHERE id=$1 AND status='draft'`,
		id, status, reviewer, note, scenarioID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ReleaseImportDraft puts a claimed draft back to waiting (used when saving the scenario failed after the claim).
func ReleaseImportDraft(ctx context.Context, pool *pgxpool.Pool, id string) error {
	_, err := pool.Exec(ctx,
		`UPDATE content_import_drafts SET status='draft', reviewed_by='', reviewed_at=NULL, review_note='', scenario_id='' WHERE id=$1`, id)
	return err
}
