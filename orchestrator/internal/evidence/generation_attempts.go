package evidence

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// maxDetailBytes bounds GenerationAttempt.Detail (spec 2026-10-13 §2.5) --
// an attempt-logging failure must never fail the attempt it's recording,
// so an over-length detail is truncated here, not rejected.
const maxDetailBytes = 2048

// GenerationAttempt is one row of content_generation_attempts (spec §2.1).
// Nullable fields are *string: nil means SQL NULL, never an empty string --
// the unresolved-identity, active-techniques-error, and below-minimum exit
// paths in Generator.Write genuinely have no threat/content id/fingerprint
// yet, and a NOT NULL default would be a lie the caller can't keep.
type GenerationAttempt struct {
	// ID is the content_generation_attempts primary key. When empty it is
	// generated here; a caller may pre-set it (connector.recordAttempt does)
	// to learn the row id for pipeline-event provenance before the insert.
	ID               string
	CycleID          string
	ThreatID         *string
	ContentID        *string
	ContentVersionID *string
	Outcome          string // created | changed | skipped | failed
	ReasonCode       string
	Detail           *string
	GeneratorVersion string
	Fingerprint      *string
	StartedAt        time.Time
}

// RecordGenerationAttempt persists one attempt. Truncating an over-length
// Detail happens here, once, rather than at every call site in generator.go.
func (s *Store) RecordGenerationAttempt(ctx context.Context, a GenerationAttempt) error {
	if a.ID == "" {
		a.ID = "cga-" + uuid.NewString()
	}
	if a.Detail != nil && len(*a.Detail) > maxDetailBytes {
		truncated := (*a.Detail)[:maxDetailBytes]
		a.Detail = &truncated
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO content_generation_attempts
		(id, cycle_id, threat_id, content_id, content_version_id, outcome, reason_code, detail, generator_version, fingerprint, started_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		a.ID, a.CycleID, a.ThreatID, a.ContentID, a.ContentVersionID, a.Outcome, a.ReasonCode, a.Detail, a.GeneratorVersion, a.Fingerprint, a.StartedAt); err != nil {
		return fmt.Errorf("evidence: record generation attempt: %w", err)
	}
	return nil
}

// GenerationAttemptFilter selects a bounded page of attempts (spec §2.6).
// CycleID and ThreatID are mutually usable but typically queried one at a
// time ("what happened on the last poll" vs. "why does this content keep
// regenerating"). Limit <= 0 defaults to 50; the caller (the API handler,
// Task 4) is responsible for its own upper cap.
type GenerationAttemptFilter struct {
	CycleID  string
	ThreatID string
	Since    time.Time
	Limit    int
}

// ListGenerationAttempts reads a bounded page, newest first.
func (s *Store) ListGenerationAttempts(ctx context.Context, f GenerationAttemptFilter) ([]GenerationAttempt, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	query := `SELECT cycle_id, threat_id, content_id, content_version_id, outcome, reason_code, detail, generator_version, fingerprint, started_at
		FROM content_generation_attempts WHERE 1=1`
	args := []any{}
	if f.CycleID != "" {
		args = append(args, f.CycleID)
		query += fmt.Sprintf(" AND cycle_id = $%d", len(args))
	}
	if f.ThreatID != "" {
		args = append(args, f.ThreatID)
		query += fmt.Sprintf(" AND threat_id = $%d", len(args))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		query += fmt.Sprintf(" AND started_at >= $%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("evidence: list generation attempts: %w", err)
	}
	defer rows.Close()

	var out []GenerationAttempt
	for rows.Next() {
		var a GenerationAttempt
		if err := rows.Scan(&a.CycleID, &a.ThreatID, &a.ContentID, &a.ContentVersionID,
			&a.Outcome, &a.ReasonCode, &a.Detail, &a.GeneratorVersion, &a.Fingerprint, &a.StartedAt); err != nil {
			return nil, fmt.Errorf("evidence: scan generation attempt: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
