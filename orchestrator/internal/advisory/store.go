package advisory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/tcv"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAlreadyDecided is returned when an advisory already has its first decision.
// Changes go through Reverse, which records a new row (spec section 8).
var ErrAlreadyDecided = errors.New("advisory: already has a relevance decision; use Reverse")

// ErrNoDecision is returned when Reverse is called on an advisory with no decision yet.
var ErrNoDecision = errors.New("advisory: no relevance decision to reverse")

// ErrInvalidDecision covers a bad decision value, a missing or invalid code, a
// code on a relevant decision, or a non-human decider.
var ErrInvalidDecision = errors.New("advisory: invalid relevance decision")

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// IntakeResult counts what one intake call did. A duplicate is an advisory
// already stored for the same source and external ID, so it is skipped.
type IntakeResult struct {
	Inserted   int
	Duplicates int
}

// Intake stores advisories, skipping duplicates. Each new advisory gets one
// advisory_received ledger event, keyed by its row id.
func (s *Store) Intake(ctx context.Context, items []Item) (IntakeResult, error) {
	var res IntakeResult
	for _, it := range items {
		if it.Source != "cert_in" && it.Source != "fs_isac" {
			return res, fmt.Errorf("advisory: unknown source %q", it.Source)
		}
		var id string
		var receivedAt time.Time
		err := s.pool.QueryRow(ctx,
			`INSERT INTO advisory_intake (source, external_id, title, published_at, source_ref, content_hash, body)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (source, external_id) DO NOTHING
			 RETURNING id, received_at`,
			it.Source, it.ExternalID, it.Title, nullTime(it.PublishedAt), it.SourceRef, hashItem(it), it.Body,
		).Scan(&id, &receivedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			res.Duplicates++
			continue
		}
		if err != nil {
			return res, fmt.Errorf("advisory: insert %s %s: %w", it.Source, it.ExternalID, err)
		}
		res.Inserted++
		tcv.RecordPipelineEvent(ctx, s.pool, tcv.Event{
			Type:        tcv.EventAdvisoryReceived,
			EventTime:   receivedAt,
			SourceTable: "advisory_intake",
			SourcePK:    id,
			Payload:     map[string]any{"source": it.Source},
		})
	}
	return res, nil
}

// Decide records the first relevance decision for an advisory.
// decision is "relevant" or "excluded". An exclusion needs one of the five
// spec codes. A relevant decision takes no code. decidedBy must be a user.
func (s *Store) Decide(ctx context.Context, advisoryID, decidedBy, decision string, code contentregistry.ExclusionReason, note string) error {
	if err := validateDecision(decidedBy, decision, code); err != nil {
		return err
	}
	var id int64
	var at time.Time
	err := s.pool.QueryRow(ctx,
		`INSERT INTO advisory_relevance (advisory_id, decision, reason_code, supersedes, decided_by, note)
		 VALUES ($1,$2,NULLIF($3,''),NULL,$4,$5) RETURNING id, decided_at`,
		advisoryID, decision, string(code), decidedBy, note,
	).Scan(&id, &at)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return ErrAlreadyDecided
		}
		return fmt.Errorf("advisory: record decision: %w", err)
	}
	s.recordClassified(ctx, id, at, decision, code)
	return nil
}

// Reverse records a new decision that supersedes the current one. The old row
// stays, so the audit trail is complete.
func (s *Store) Reverse(ctx context.Context, advisoryID, decidedBy, decision string, code contentregistry.ExclusionReason, note string) error {
	if err := validateDecision(decidedBy, decision, code); err != nil {
		return err
	}
	var current int64
	err := s.pool.QueryRow(ctx,
		`SELECT r.id FROM advisory_relevance r
		  WHERE r.advisory_id = $1
		    AND NOT EXISTS (SELECT 1 FROM advisory_relevance s WHERE s.supersedes = r.id)`,
		advisoryID,
	).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoDecision
	}
	if err != nil {
		return fmt.Errorf("advisory: find current decision: %w", err)
	}
	var id int64
	var at time.Time
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO advisory_relevance (advisory_id, decision, reason_code, supersedes, decided_by, note)
		 VALUES ($1,$2,NULLIF($3,''),$4,$5,$6) RETURNING id, decided_at`,
		advisoryID, decision, string(code), current, decidedBy, note,
	).Scan(&id, &at); err != nil {
		return fmt.Errorf("advisory: record reversal: %w", err)
	}
	s.recordClassified(ctx, id, at, decision, code)
	return nil
}

// Counts returns how many advisories are currently excluded per reason, and how
// many are undecided. Exclusions are never dropped from the denominator (spec section 4).
func (s *Store) Counts(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT CASE
		          WHEN cur.id IS NULL THEN 'undecided'
		          WHEN cur.decision = 'relevant' THEN 'relevant'
		          ELSE 'excluded:' || cur.reason_code
		        END AS bucket, count(*)
		   FROM advisory_intake a
		   LEFT JOIN LATERAL (
		     SELECT r.* FROM advisory_relevance r
		      WHERE r.advisory_id = a.id
		        AND NOT EXISTS (SELECT 1 FROM advisory_relevance s WHERE s.supersedes = r.id)
		      ORDER BY r.id DESC LIMIT 1) cur ON true
		  GROUP BY 1`)
	if err != nil {
		return nil, fmt.Errorf("advisory: counts: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var bucket string
		var n int
		if err := rows.Scan(&bucket, &n); err != nil {
			return nil, err
		}
		out[bucket] = n
	}
	return out, rows.Err()
}

func (s *Store) recordClassified(ctx context.Context, decisionID int64, at time.Time, decision string, code contentregistry.ExclusionReason) {
	payload := map[string]any{"decision": decision}
	if code != "" {
		payload["reason_code"] = string(code)
	}
	tcv.RecordPipelineEvent(ctx, s.pool, tcv.Event{
		Type:        tcv.EventAdvisoryClassified,
		EventTime:   at,
		SourceTable: "advisory_relevance",
		SourcePK:    fmt.Sprintf("%d", decisionID),
		Payload:     payload,
	})
}

func validateDecision(decidedBy, decision string, code contentregistry.ExclusionReason) error {
	if !strings.HasPrefix(decidedBy, "user:") || len(decidedBy) <= len("user:") {
		return fmt.Errorf("%w: decided_by must be a named user, got %q", ErrInvalidDecision, decidedBy)
	}
	switch decision {
	case "relevant":
		if code != "" {
			return fmt.Errorf("%w: a relevant decision takes no reason code", ErrInvalidDecision)
		}
	case "excluded":
		if !code.Valid() {
			return fmt.Errorf("%w: exclusion needs one of the five reason codes, got %q", ErrInvalidDecision, string(code))
		}
	default:
		return fmt.Errorf("%w: decision must be relevant or excluded, got %q", ErrInvalidDecision, decision)
	}
	return nil
}

func hashItem(it Item) string {
	h := sha256.Sum256([]byte(it.Title + "\x00" + it.Body))
	return hex.EncodeToString(h[:])
}

// nullTime maps the zero time to SQL NULL, for an advisory with no published date.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
