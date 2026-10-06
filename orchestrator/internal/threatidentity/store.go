package threatidentity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// identityLockKey serializes resolution against admin decisions so a sync
// and a Decide never interleave on the same snapshot.
const identityLockKey int64 = 0x7C0F4D16A7100002

// Querier is the subset of pgx shared by *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store persists actor identity, Threats and resolution candidates.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// ProfileFields are the mutable profile attributes a sync supplies. Name is
// not here on purpose: an existing actor's display name never changes
// through resolution (spec §3.1).
type ProfileFields struct {
	Aliases, Sectors, Regions []string
	Source                    string
	LastSeen                  *time.Time
	Confidence                string
	CanonicalGroupID          string
	Techniques                []string
}

type Resolved struct {
	Outcome     Outcome
	ActorID     string
	ThreatID    string
	DisplayName string
	CandidateID string // set for OutcomeAmbiguous unless previously dismissed
}

// ResolveAndPersist resolves one incoming actor record and makes the result
// durable in one transaction: the profile (by id), its source identities
// and its Threat -- or, when ambiguous, a resolution candidate and nothing
// else (spec §3.3-§3.4).
func (s *Store) ResolveAndPersist(ctx context.Context, in Incoming, f ProfileFields) (Resolved, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Resolved{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, identityLockKey); err != nil {
		return Resolved{}, err
	}
	snap, err := loadSnapshot(ctx, tx)
	if err != nil {
		return Resolved{}, err
	}
	d := Resolve(in, snap)
	f.Aliases = append(append([]string{}, f.Aliases...), in.Aliases...)
	f.CanonicalGroupID = in.CanonicalGroupID

	var res Resolved
	switch d.Outcome {
	case OutcomeExisting:
		name, err := updateProfile(ctx, tx, d.ActorID, in.Name, f)
		if err != nil {
			return Resolved{}, err
		}
		res = Resolved{Outcome: OutcomeExisting, ActorID: d.ActorID, DisplayName: name}
	case OutcomeNew:
		id, conflict, err := insertProfile(ctx, tx, in.Name, f)
		if err != nil {
			return Resolved{}, err
		}
		if conflict {
			d.Outcome, d.Reason, d.Rule = OutcomeAmbiguous, "name_conflict", "none"
			d.Context, d.ContextHash = resolverContext(in, d, map[string]KnownActor{})
			break
		}
		res = Resolved{Outcome: OutcomeNew, ActorID: id, DisplayName: in.Name}
	}
	if d.Outcome == OutcomeAmbiguous {
		cid, err := queueCandidate(ctx, tx, "source_record", in, "", d)
		if err != nil {
			return Resolved{}, err
		}
		return Resolved{Outcome: OutcomeAmbiguous, CandidateID: cid}, tx.Commit(ctx)
	}
	if err := recordIdentities(ctx, tx, in.Sources, res.ActorID, "resolver", ""); err != nil {
		return Resolved{}, err
	}
	if res.ThreatID, err = s.EnsureThreatForActor(ctx, tx, res.ActorID); err != nil {
		return Resolved{}, err
	}
	if f.LastSeen != nil {
		if _, err := tx.Exec(ctx, `UPDATE threats SET last_seen_at = GREATEST(last_seen_at, $2) WHERE id = $1`,
			res.ThreatID, *f.LastSeen); err != nil {
			return Resolved{}, err
		}
	}
	return res, tx.Commit(ctx)
}

func loadSnapshot(ctx context.Context, q Querier) (Snapshot, error) {
	snap := Snapshot{SourceIdentities: map[SourceKey]string{}}
	rows, err := q.Query(ctx, `SELECT id, name, aliases, canonical_group_id FROM threat_actor_profiles ORDER BY id`)
	if err != nil {
		return snap, err
	}
	for rows.Next() {
		var a KnownActor
		if err := rows.Scan(&a.ID, &a.Name, &a.Aliases, &a.CanonicalGroupID); err != nil {
			rows.Close()
			return snap, err
		}
		snap.Actors = append(snap.Actors, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snap, err
	}
	rows, err = q.Query(ctx, `SELECT source, source_id, actor_id FROM actor_source_identities`)
	if err != nil {
		return snap, err
	}
	defer rows.Close()
	for rows.Next() {
		var k SourceKey
		var id string
		if err := rows.Scan(&k.Source, &k.ID, &id); err != nil {
			return snap, err
		}
		snap.SourceIdentities[k] = id
	}
	return snap, rows.Err()
}

// updateProfile refreshes an existing actor by id and returns its stored
// display name. A different incoming name is folded into aliases.
func updateProfile(ctx context.Context, tx pgx.Tx, id, incomingName string, f ProfileFields) (string, error) {
	var stored string
	if err := tx.QueryRow(ctx, `SELECT name FROM threat_actor_profiles WHERE id = $1`, id).Scan(&stored); err != nil {
		return "", fmt.Errorf("load actor %s: %w", id, err)
	}
	aliases := f.Aliases
	if n := NormalizeName(incomingName); n != "" && n != NormalizeName(stored) {
		aliases = append(aliases, incomingName)
	}
	_, err := tx.Exec(ctx, `UPDATE threat_actor_profiles SET
		   aliases = ARRAY(SELECT DISTINCT a FROM UNNEST(aliases || $2::text[]) AS a WHERE btrim(a) <> '' ORDER BY a),
		   sectors = $3, regions = $4, source = $5, last_seen = $6, confidence = $7,
		   canonical_group_id = CASE WHEN $8::text <> '' THEN $8::text ELSE canonical_group_id END,
		   techniques = $9, updated_at = NOW()
		 WHERE id = $1`,
		id, nonNil(aliases), nonNil(f.Sectors), nonNil(f.Regions), f.Source, f.LastSeen, f.Confidence,
		f.CanonicalGroupID, nonNil(f.Techniques))
	return stored, err
}

// insertProfile creates a new actor. conflict=true means the display name
// is held by another row the resolver did not match; the savepoint keeps
// the outer transaction usable.
func insertProfile(ctx context.Context, tx pgx.Tx, name string, f ProfileFields) (string, bool, error) {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	var id string
	err = sp.QueryRow(ctx, `INSERT INTO threat_actor_profiles
		   (name, aliases, sectors, regions, source, last_seen, confidence, canonical_group_id, techniques, updated_at)
		 VALUES ($1, ARRAY(SELECT DISTINCT a FROM UNNEST($2::text[]) AS a WHERE btrim(a) <> '' ORDER BY a),
		         $3, $4, $5, $6, $7, $8, $9, NOW())
		 RETURNING id`,
		name, nonNil(f.Aliases), nonNil(f.Sectors), nonNil(f.Regions), f.Source, f.LastSeen, f.Confidence,
		f.CanonicalGroupID, nonNil(f.Techniques)).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "threat_actor_profiles_name_key" {
		return "", true, sp.Rollback(ctx)
	}
	if err != nil {
		_ = sp.Rollback(ctx)
		return "", false, err
	}
	return id, false, sp.Commit(ctx)
}

func recordIdentities(ctx context.Context, q Querier, keys []SourceKey, actorID, by, ref string) error {
	for _, k := range keys {
		if _, err := q.Exec(ctx, `INSERT INTO actor_source_identities (source, source_id, actor_id, linked_by, linked_ref)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (source, source_id) DO NOTHING`,
			k.Source, k.ID, actorID, by, ref); err != nil {
			return err
		}
	}
	return nil
}

// EnsureThreatForActor returns the actor's Threat, creating it if absent.
func (s *Store) EnsureThreatForActor(ctx context.Context, q Querier, actorID string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		SELECT 'thr-' || gen_random_uuid()::text, 'actor', p.id, p.id, p.name FROM threat_actor_profiles p WHERE p.id = $1
		ON CONFLICT (subject_type, subject_id) DO UPDATE SET title = EXCLUDED.title
		RETURNING id`, actorID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("ensure threat for %s: %w", actorID, err)
	}
	return id, nil
}

// queueCandidate records an ambiguous record unless the same record was
// already dismissed (or, for *_ref kinds, decided in any way). Returns the
// open candidate's id, or "" when suppressed.
func queueCandidate(ctx context.Context, tx pgx.Tx, kind string, in Incoming, refEntityID string, d Decision) (string, error) {
	source, ext := "", ""
	if len(in.Sources) > 0 {
		source, ext = in.Sources[0].Source, in.Sources[0].ID
	}
	suppress := `status = 'dismissed'`
	if kind != "source_record" {
		suppress = `status <> 'unresolved'`
	}
	var decided bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM actor_resolution_candidates
		 WHERE kind = $1 AND source = $2 AND external_id = $3 AND raw_name = $4 AND ref_entity_id = $5 AND `+suppress+`)`,
		kind, source, ext, in.Name, refEntityID).Scan(&decided); err != nil {
		return "", err
	}
	if decided {
		return "", nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO actor_resolution_candidates
		   (kind, source, external_id, raw_name, ref_entity_id, reason, resolver_context, resolver_context_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (kind, source, external_id, raw_name, ref_entity_id) WHERE status = 'unresolved' DO NOTHING`,
		kind, source, ext, in.Name, refEntityID, d.Reason, d.Context, d.ContextHash); err != nil {
		return "", err
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM actor_resolution_candidates
		 WHERE kind = $1 AND source = $2 AND external_id = $3 AND raw_name = $4 AND ref_entity_id = $5 AND status = 'unresolved'`,
		kind, source, ext, in.Name, refEntityID).Scan(&id)
	return id, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
