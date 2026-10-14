package evidence

import (
	"context"
	"fmt"
)

// EnsureSourceInstance creates a source instance if absent, writing the
// source's default trust version as its first trust_versions row (spec
// §5.1's default-trust table). Idempotent: an existing instance's trust is
// left untouched, even if defaultTrust differs from what's stored -- trust
// changes only through SetTrust, an audited admin action.
func (s *Store) EnsureSourceInstance(ctx context.Context, id, sourceType, displayName string, mode ObservationMode, defaultTrust TrustState) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `INSERT INTO source_instances (id, source_type, display_name, observation_mode)
		VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`, id, sourceType, displayName, mode)
	if err != nil {
		return fmt.Errorf("evidence: ensure source instance: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO source_trust_versions (source_instance_id, trust_state, changed_by, reason)
		VALUES ($1, $2, 'system', 'default trust on instance creation')`, id, defaultTrust); err != nil {
		return fmt.Errorf("evidence: default trust version: %w", err)
	}
	return tx.Commit(ctx)
}

// CurrentTrust returns the source instance's trust state in force right
// now (the latest trust_versions row by effective_at), and that row's id --
// every claim/observation written under it must carry this trust_version_id
// (spec §7.4: history answers "was this source trusted when observed",
// never current configuration).
func (s *Store) CurrentTrust(ctx context.Context, instanceID string) (TrustState, int64, error) {
	var state string
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT trust_state, id FROM source_trust_versions
		WHERE source_instance_id = $1 ORDER BY effective_at DESC, id DESC LIMIT 1`, instanceID).Scan(&state, &id)
	if err != nil {
		return "", 0, fmt.Errorf("evidence: current trust for %q: %w", instanceID, err)
	}
	return TrustState(state), id, nil
}

// SetTrust records a new trust version -- an admin-only, audited action
// (spec §5.1). Append-only: never updates or deletes an earlier version.
func (s *Store) SetTrust(ctx context.Context, instanceID string, state TrustState, changedBy, reason string) error {
	if reason == "" {
		return fmt.Errorf("evidence: SetTrust requires a reason")
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO source_trust_versions (source_instance_id, trust_state, changed_by, reason)
		VALUES ($1, $2, $3, $4)`, instanceID, state, changedBy, reason); err != nil {
		return fmt.Errorf("evidence: set trust: %w", err)
	}
	return nil
}
