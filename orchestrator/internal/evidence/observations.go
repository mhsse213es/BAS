package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// RecordObservation writes one append-only source_observations row (spec
// §5.3). recordHash identifies this exact raw record so a later identical
// re-fetch can be recognized without re-deriving meaning from raw.
func (s *Store) RecordObservation(ctx context.Context, syncID, instanceID, externalID, rawName, recordHash string, observedAt time.Time, raw map[string]any, trustVersionID int64) (observationID string, err error) {
	rawJSON, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("evidence: marshal raw observation: %w", err)
	}
	err = s.pool.QueryRow(ctx, `INSERT INTO source_observations
		(sync_id, source_instance_id, external_id, raw_name, record_hash, observed_at, raw, trust_version_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		syncID, instanceID, externalID, rawName, recordHash, observedAt, rawJSON, trustVersionID).Scan(&observationID)
	if err != nil {
		return "", fmt.Errorf("evidence: record observation: %w", err)
	}
	return observationID, nil
}

// LinkThreatSource links one observation's evidence to a resolved threat
// (spec §5.3). An observation is linked at most once -- schema's
// UNIQUE(observation_id) turns a second attempt into an error rather than
// a silently accepted duplicate link.
func (s *Store) LinkThreatSource(ctx context.Context, threatID, observationID, provider, externalID string, observedAt time.Time, sourceConfidence *int, recordHash, linkedBy, linkedRef string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO threat_sources
		(threat_id, observation_id, provider, external_id, observed_at, source_confidence, record_hash, linked_by, linked_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		threatID, observationID, provider, externalID, observedAt, sourceConfidence, recordHash, linkedBy, linkedRef)
	if err != nil {
		return fmt.Errorf("evidence: link threat source: %w", err)
	}
	return nil
}
