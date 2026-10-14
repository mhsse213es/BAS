package contentregistry

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// LinkThreat creates an admin-asserted `emulates` link between a custom
// content version and a canonical threat (spec §9.3, acceptance test 33).
// threatID must already exist -- no fuzzy or free-text actor-name
// inference is ever used. If the version is already executable, the
// coverage-first stop is recorded immediately in this same transaction,
// not deferred to a future lifecycle/trust transition.
func (r *Registry) LinkThreat(ctx context.Context, contentID string, version int, threatID, actor, reason string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var vid, origin, trust, lc string
	err = tx.QueryRow(ctx, `SELECT id, origin, trust_level, lifecycle FROM content_versions
		WHERE content_id = $1 AND version = $2 FOR UPDATE`, contentID, version).Scan(&vid, &origin, &trust, &lc)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrVersionNotFound
	}
	if err != nil {
		return err
	}

	var threatExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM threats WHERE id = $1)`, threatID).Scan(&threatExists); err != nil {
		return err
	}
	if !threatExists {
		return ErrThreatNotFound
	}

	if _, err := tx.Exec(ctx, `INSERT INTO content_version_threats
		   (content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
		 VALUES ($1, $2, 'emulates', 'admin', $3)
		 ON CONFLICT (content_version_id, threat_id, relationship_kind) DO NOTHING`,
		vid, threatID, actor); err != nil {
		return err
	}
	if err := r.recordCoverageIfExecutable(ctx, tx, vid, Origin(origin), Trust(trust), Lifecycle(lc)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1, $2, $2, $3, $3, $4, $5)`,
		vid, lc, trust, actor, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
