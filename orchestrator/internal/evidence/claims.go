package evidence

import (
	"context"
	"fmt"
	"time"
)

// Claim is one (threat, technique) assertion from a single observation.
type Claim struct {
	ObservationID       string
	SyncID              string
	InstanceID          string
	ThreatID            string
	TechniqueID         string
	Kind                ClaimKind
	Via, ViaName        string
	StartTime, StopTime time.Time
	RawConfidence       string
	Source              string // "misp" | "opencti" | "bundle" | "otx" -- selects the confidence mapping
	TrustVersionID      int64
	ObservedAt          time.Time
	RecordHash          string
}

// ErrRetractionRefused is returned by RecordClaims when a retraction is
// requested on a sync that is not authoritative (spec §6.1: absence is not
// retraction, except from a sync that is complete AND a snapshot source).
var ErrRetractionRefused = fmt.Errorf("evidence: retraction refused: sync is not authoritative")

// RecordClaims writes append-only technique_claims rows. A claim is always
// accepted. A retraction is accepted only when its owning sync is
// authoritative -- checked here from source_syncs, never trusting the
// caller's Kind. Any retraction in the batch that fails this check refuses
// the WHOLE call (fail closed, not a partial write).
func (s *Store) RecordClaims(ctx context.Context, claims []Claim) error {
	if len(claims) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	authoritativeBySync := map[string]bool{}
	for _, c := range claims {
		if c.Kind != ClaimRetracted {
			continue
		}
		if _, checked := authoritativeBySync[c.SyncID]; checked {
			continue
		}
		var authoritative bool
		if err := tx.QueryRow(ctx, `SELECT authoritative FROM source_syncs WHERE id = $1`, c.SyncID).Scan(&authoritative); err != nil {
			return fmt.Errorf("evidence: check sync authoritative: %w", err)
		}
		authoritativeBySync[c.SyncID] = authoritative
		if !authoritative {
			return ErrRetractionRefused
		}
	}

	for _, c := range claims {
		rawConf, normConf, mappingVersion := NormalizeConfidence(c.Source, c.RawConfidence)
		var startTime, stopTime *time.Time
		if !c.StartTime.IsZero() {
			startTime = &c.StartTime
		}
		if !c.StopTime.IsZero() {
			stopTime = &c.StopTime
		}
		if _, err := tx.Exec(ctx, `INSERT INTO technique_claims
			(observation_id, sync_id, source_instance_id, threat_id, technique_id, kind, via, via_name,
			 start_time, stop_time, raw_confidence, normalized_confidence, confidence_mapping_version,
			 trust_version_id, observed_at, record_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (source_instance_id, threat_id, technique_id, via, via_name, record_hash) DO NOTHING`,
			c.ObservationID, c.SyncID, c.InstanceID, c.ThreatID, c.TechniqueID, c.Kind, c.Via, c.ViaName,
			startTime, stopTime, rawConf, normConf, mappingVersion,
			c.TrustVersionID, c.ObservedAt, c.RecordHash); err != nil {
			return fmt.Errorf("evidence: record claim (%s, %s): %w", c.ThreatID, c.TechniqueID, err)
		}
	}
	return tx.Commit(ctx)
}

// ClaimedPair identifies one (threat, technique) a source instance's most
// recent top-level claim currently asserts.
type ClaimedPair struct {
	ThreatID    string
	TechniqueID string
}

// ActiveClaimedTechniques returns every (threat, technique) pair this
// instance's latest top-level claim (via = "") still asserts, i.e. kind =
// 'claim' and not superseded by a later retraction. A caller diffs this
// against what the current sync just asserted to detect techniques a
// later, authoritative sync no longer claims (spec §6.1).
func (s *Store) ActiveClaimedTechniques(ctx context.Context, instanceID string) ([]ClaimedPair, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (threat_id, technique_id) threat_id, technique_id, kind
		  FROM technique_claims
		 WHERE source_instance_id = $1 AND via = '' AND via_name = ''
		 ORDER BY threat_id, technique_id, observed_at DESC, id DESC`, instanceID)
	if err != nil {
		return nil, fmt.Errorf("evidence: active claimed techniques: %w", err)
	}
	defer rows.Close()

	var out []ClaimedPair
	for rows.Next() {
		var p ClaimedPair
		var kind ClaimKind
		if err := rows.Scan(&p.ThreatID, &p.TechniqueID, &kind); err != nil {
			return nil, fmt.Errorf("evidence: scan active claimed technique: %w", err)
		}
		if kind == ClaimAsserted {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}
