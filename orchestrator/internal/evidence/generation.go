package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// ActiveTechniques returns a threat's currently-active technique ids (spec
// §7.2's active set), sorted for a stable hash.
func (s *Store) ActiveTechniques(ctx context.Context, threatID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT technique_id FROM threat_techniques
		WHERE threat_id = $1 AND status = 'active' ORDER BY technique_id`, threatID)
	if err != nil {
		return nil, fmt.Errorf("evidence: active techniques for %q: %w", threatID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// NextGenerationNumber returns the next sequential generation_number for a
// threat (spec §8). The caller must use it promptly -- the UNIQUE
// (threat_id, generation_number) constraint on content_generations catches
// a concurrent double-use rather than silently overwriting one.
func (s *Store) NextGenerationNumber(ctx context.Context, threatID string) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(max(generation_number), 0) + 1 FROM content_generations WHERE threat_id = $1`,
		threatID).Scan(&n); err != nil {
		return 0, fmt.Errorf("evidence: next generation number: %w", err)
	}
	return n, nil
}

type evidenceSnapshot struct {
	ThreatID   string                      `json:"threatId"`
	Techniques []evidenceSnapshotTechnique `json:"techniques"`
}

type evidenceSnapshotTechnique struct {
	TechniqueID          string   `json:"techniqueId"`
	ClaimIDs             []string `json:"claimIds"`
	TrustVersionIDs      []int64  `json:"trustVersionIds"`
	NormalizedConfidence *int     `json:"normalizedConfidence,omitempty"`
}

// RecordGeneration writes one content_generations row, computing
// technique_set_hash and evidence_snapshot_hash from the threat's current
// active claims (spec §8) -- "why did generation N include T1059 when
// generation N-1 did not" is answerable from the two rows' snapshots alone.
func (s *Store) RecordGeneration(ctx context.Context, threatID, contentID, contentVersionID string, generationNumber int, policyVersion string) error {
	rows, err := s.pool.Query(ctx, `
		SELECT c.technique_id, c.id, c.trust_version_id, c.normalized_confidence
		  FROM technique_claims c
		 WHERE c.threat_id = $1 AND c.kind = 'claim'
		   AND c.technique_id IN (SELECT technique_id FROM threat_techniques WHERE threat_id = $1 AND status = 'active')
		 ORDER BY c.technique_id, c.id`, threatID)
	if err != nil {
		return fmt.Errorf("evidence: load active claims for generation: %w", err)
	}
	byTechnique := map[string]*evidenceSnapshotTechnique{}
	var order []string
	for rows.Next() {
		var techniqueID, claimID string
		var trustVersionID int64
		var normConf *int
		if err := rows.Scan(&techniqueID, &claimID, &trustVersionID, &normConf); err != nil {
			rows.Close()
			return err
		}
		t, ok := byTechnique[techniqueID]
		if !ok {
			t = &evidenceSnapshotTechnique{TechniqueID: techniqueID}
			byTechnique[techniqueID] = t
			order = append(order, techniqueID)
		}
		t.ClaimIDs = append(t.ClaimIDs, claimID)
		t.TrustVersionIDs = append(t.TrustVersionIDs, trustVersionID)
		if normConf != nil && (t.NormalizedConfidence == nil || *normConf > *t.NormalizedConfidence) {
			t.NormalizedConfidence = normConf
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	sort.Strings(order)
	snap := evidenceSnapshot{ThreatID: threatID}
	techniqueIDs := make([]string, 0, len(order))
	for _, id := range order {
		snap.Techniques = append(snap.Techniques, *byTechnique[id])
		techniqueIDs = append(techniqueIDs, id)
	}

	techniqueSetHash := sha256.Sum256([]byte(fmt.Sprintf("%v", techniqueIDs)))
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("evidence: marshal evidence snapshot: %w", err)
	}
	evidenceHash := sha256.Sum256(snapJSON)

	if _, err := s.pool.Exec(ctx, `INSERT INTO content_generations
		(threat_id, content_id, content_version_id, generation_number, policy_version, technique_set_hash, evidence_snapshot_hash, evidence_snapshot)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		threatID, contentID, contentVersionID, generationNumber, policyVersion,
		hex.EncodeToString(techniqueSetHash[:]), hex.EncodeToString(evidenceHash[:]), snapJSON); err != nil {
		return fmt.Errorf("evidence: record generation: %w", err)
	}
	return nil
}
