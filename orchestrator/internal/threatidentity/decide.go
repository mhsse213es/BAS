package threatidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Action is an admin's terminal decision on a resolution candidate.
type Action string

const (
	ActionLink    Action = "link"
	ActionNew     Action = "new"
	ActionDismiss Action = "dismiss"
)

var (
	ErrCandidateNotFound = errors.New("resolution candidate not found")
	ErrAlreadyDecided    = errors.New("resolution candidate already decided")
	ErrActorNotFound     = errors.New("actor not found")
	ErrNameTaken         = errors.New("an actor with this display name already exists; link to it instead")
	ErrBadDecision       = errors.New("invalid decision")
)

type Candidate struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	Source         string          `json:"source"`
	ExternalID     string          `json:"externalId"`
	RawName        string          `json:"rawName"`
	RefEntityID    string          `json:"refEntityId"`
	Reason         string          `json:"reason"`
	Context        json.RawMessage `json:"resolverContext"`
	ContextHash    string          `json:"resolverContextHash"`
	Status         string          `json:"status"`
	DecidedActorID *string         `json:"decidedActorId"`
	DecidedBy      *string         `json:"decidedBy"`
	DecidedAt      *time.Time      `json:"decidedAt"`
	DecisionReason *string         `json:"decisionReason"`
	CreatedAt      time.Time       `json:"createdAt"`
}

const candidateCols = `id, kind, source, external_id, raw_name, ref_entity_id, reason, resolver_context,
	resolver_context_hash, status, decided_actor_id, decided_by, decided_at, decision_reason, created_at`

func scanCandidate(row pgx.Row) (Candidate, error) {
	var c Candidate
	err := row.Scan(&c.ID, &c.Kind, &c.Source, &c.ExternalID, &c.RawName, &c.RefEntityID, &c.Reason, &c.Context,
		&c.ContextHash, &c.Status, &c.DecidedActorID, &c.DecidedBy, &c.DecidedAt, &c.DecisionReason, &c.CreatedAt)
	return c, err
}

// ListCandidates returns candidates oldest first; status "" means all.
func (s *Store) ListCandidates(ctx context.Context, status string, limit int) ([]Candidate, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+candidateCols+` FROM actor_resolution_candidates
		WHERE ($1 = '' OR status = $1) ORDER BY created_at, id LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Candidate{}
	for rows.Next() {
		c, err := scanCandidate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Decide records one terminal admin decision (spec §3.4). The decision is
// the authoritative resolution event: fuzzy matching is not re-run.
func (s *Store) Decide(ctx context.Context, id string, action Action, actorID, reason, decidedBy string) (Candidate, error) {
	if reason == "" || decidedBy == "" {
		return Candidate{}, fmt.Errorf("%w: decisionReason is required", ErrBadDecision)
	}
	switch action {
	case ActionLink:
		if actorID == "" {
			return Candidate{}, fmt.Errorf("%w: link requires actorId", ErrBadDecision)
		}
	case ActionNew, ActionDismiss:
	default:
		return Candidate{}, fmt.Errorf("%w: unknown action %q", ErrBadDecision, action)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Candidate{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, identityLockKey); err != nil {
		return Candidate{}, err
	}
	c, err := scanCandidate(tx.QueryRow(ctx, `SELECT `+candidateCols+` FROM actor_resolution_candidates WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Candidate{}, ErrCandidateNotFound
	}
	if err != nil {
		return Candidate{}, err
	}
	if c.Status != "unresolved" {
		return Candidate{}, ErrAlreadyDecided
	}

	status := "dismissed"
	var decided *string
	switch action {
	case ActionLink:
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM threat_actor_profiles WHERE id = $1)`, actorID).Scan(&exists); err != nil {
			return Candidate{}, err
		}
		if !exists {
			return Candidate{}, ErrActorNotFound
		}
		status, decided = "linked", &actorID
	case ActionNew:
		newID, conflict, err := insertProfile(ctx, tx, c.RawName, ProfileFields{Source: c.Source})
		if err != nil {
			return Candidate{}, err
		}
		if conflict {
			return Candidate{}, ErrNameTaken
		}
		status, decided = "new_actor", &newID
	}
	if decided != nil {
		if err := s.applyLink(ctx, tx, c, *decided); err != nil {
			return Candidate{}, err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE actor_resolution_candidates
		SET status = $2, decided_actor_id = $3, decided_by = $4, decided_at = NOW(), decision_reason = $5
		WHERE id = $1 AND status = 'unresolved'`, id, status, decided, decidedBy, reason)
	if err != nil {
		return Candidate{}, err
	}
	if tag.RowsAffected() != 1 {
		return Candidate{}, ErrAlreadyDecided
	}
	out, err := scanCandidate(tx.QueryRow(ctx, `SELECT `+candidateCols+` FROM actor_resolution_candidates WHERE id = $1`, id))
	if err != nil {
		return Candidate{}, err
	}
	return out, tx.Commit(ctx)
}

// applyLink makes a link/new decision effective: source records map their
// identity keys to the actor; entity references get their relation row.
// Either way the actor's Threat exists afterwards.
func (s *Store) applyLink(ctx context.Context, tx pgx.Tx, c Candidate, actorID string) error {
	switch c.Kind {
	case "source_record":
		var doc resolverContextDoc
		if err := json.Unmarshal(c.Context, &doc); err != nil {
			return fmt.Errorf("candidate %s context: %w", c.ID, err)
		}
		keys := doc.Incoming.Sources
		if len(keys) == 0 {
			keys = KeysFor(c.Source, c.ExternalID, c.RawName)
		}
		if err := recordIdentities(ctx, tx, keys, actorID, "admin", c.ID); err != nil {
			return err
		}
	default:
		var spec entityLinkSpec
		for _, v := range entityLinkTables {
			if v.candidateKind == c.Kind {
				spec = v
			}
		}
		if spec.table == "" {
			return fmt.Errorf("candidate %s: unknown kind %q", c.ID, c.Kind)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO `+spec.table+` (`+spec.column+`, actor_id, linked_by)
			VALUES ($1, $2, 'admin') ON CONFLICT DO NOTHING`, c.RefEntityID, actorID); err != nil {
			return err
		}
	}
	_, err := s.EnsureThreatForActor(ctx, tx, actorID)
	return err
}
