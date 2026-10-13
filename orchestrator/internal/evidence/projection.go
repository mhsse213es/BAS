package evidence

import (
	"context"
	"fmt"
	"time"
)

// recomputeThreatTechniques rebuilds every threat_techniques row for one
// threat from current technique_claims (spec §7). "Current" for a (source
// instance, technique) pair is its latest claim/retraction row by
// observed_at (§7.2). first_seen_at only advances from claims observed
// under a trust version that was trusted AT THAT TIME (§7.4) -- trust
// granted later never backdates it.
func recomputeThreatTechniques(ctx context.Context, q Querier, threatID string) error {
	rows, err := q.Query(ctx, `
		SELECT technique_id, source_instance_id, kind, observed_at, normalized_confidence,
		       (SELECT trust_state FROM source_trust_versions WHERE id = technique_claims.trust_version_id) AS trust_state_then,
		       (SELECT trust_state FROM source_trust_versions tv2
		          WHERE tv2.source_instance_id = technique_claims.source_instance_id
		          ORDER BY tv2.effective_at DESC, tv2.id DESC LIMIT 1) AS trust_state_now
		  FROM technique_claims
		 WHERE threat_id = $1
		 ORDER BY technique_id, source_instance_id, observed_at`, threatID)
	if err != nil {
		return fmt.Errorf("evidence: load claims for projection: %w", err)
	}
	type claimRow struct {
		techniqueID, instanceID, kind, trustStateThen, trustStateNow string
		observedAt                                                   time.Time
		normalizedConfidence                                         *int
	}
	var all []claimRow
	for rows.Next() {
		var r claimRow
		if err := rows.Scan(&r.techniqueID, &r.instanceID, &r.kind, &r.observedAt, &r.normalizedConfidence,
			&r.trustStateThen, &r.trustStateNow); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Latest row per (technique, source instance) is "current" (spec §7.2).
	type key struct{ technique, instance string }
	latest := map[key]claimRow{}
	for _, r := range all {
		k := key{r.techniqueID, r.instanceID}
		if existing, ok := latest[k]; !ok || r.observedAt.After(existing.observedAt) {
			latest[k] = r
		}
	}

	type techState struct {
		active            bool
		supportingSources int
		bestConfidence    *int
		firstSeenAt       *time.Time
		lastSeenAt        time.Time
		sourceRetracted   bool
		trustRevoked      bool
	}
	states := map[string]*techState{}
	for k, r := range latest {
		st, ok := states[k.technique]
		if !ok {
			st = &techState{}
			states[k.technique] = st
		}
		if r.observedAt.After(st.lastSeenAt) {
			st.lastSeenAt = r.observedAt
		}
		isClaim := r.kind == string(ClaimAsserted)
		trustedNow := r.trustStateNow == string(TrustTrusted)
		if isClaim && trustedNow {
			st.active = true
			st.supportingSources++
			if r.normalizedConfidence != nil && (st.bestConfidence == nil || *r.normalizedConfidence > *st.bestConfidence) {
				st.bestConfidence = r.normalizedConfidence
			}
		}
		if !isClaim {
			st.sourceRetracted = true
		}
		if isClaim && !trustedNow {
			st.trustRevoked = true
		}
		if isClaim && r.trustStateThen == string(TrustTrusted) {
			if st.firstSeenAt == nil || r.observedAt.Before(*st.firstSeenAt) {
				st.firstSeenAt = &r.observedAt
			}
		}
	}

	for techniqueID, st := range states {
		status, reason := "retracted", "source_retraction"
		switch {
		case st.active:
			status, reason = "active", "supported"
		case st.trustRevoked && !st.sourceRetracted:
			reason = "trust_revocation"
		}
		if _, err := q.Exec(ctx, `INSERT INTO threat_techniques
			(threat_id, technique_id, first_seen_at, last_seen_at, supporting_source_count, best_confidence, status, status_reason, projected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
			ON CONFLICT (threat_id, technique_id) DO UPDATE SET
				first_seen_at = CASE
					WHEN threat_techniques.first_seen_at IS NULL THEN EXCLUDED.first_seen_at
					WHEN EXCLUDED.first_seen_at IS NULL THEN threat_techniques.first_seen_at
					ELSE LEAST(threat_techniques.first_seen_at, EXCLUDED.first_seen_at) END,
				last_seen_at = GREATEST(threat_techniques.last_seen_at, EXCLUDED.last_seen_at),
				supporting_source_count = EXCLUDED.supporting_source_count,
				best_confidence = EXCLUDED.best_confidence,
				status = EXCLUDED.status,
				status_reason = EXCLUDED.status_reason,
				projected_at = NOW()`,
			threatID, techniqueID, st.firstSeenAt, st.lastSeenAt, st.supportingSources, st.bestConfidence, status, reason); err != nil {
			return fmt.Errorf("evidence: upsert threat_techniques (%s, %s): %w", threatID, techniqueID, err)
		}
	}
	return nil
}

// RecomputeThreatTechniques is the Store's entry point, called immediately
// after RecordClaims and after SetTrust for every threat the triggering
// write touched (see this plan's Global Constraints note on why this is a
// separate transaction from the write itself).
func (s *Store) RecomputeThreatTechniques(ctx context.Context, threatID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := recomputeThreatTechniques(ctx, tx, threatID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
