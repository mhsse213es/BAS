package evidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestActiveTechniquesAndRecordGeneration(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	threatID := seedThreat(t, sharedDB.Pool, "APT-generation-test")

	for _, tc := range []struct{ id, status string }{
		{"T1059", "active"}, {"T1055", "active"}, {"T1021", "retracted"},
	} {
		if _, err := sharedDB.Pool.Exec(ctx, `INSERT INTO threat_techniques
			(threat_id, technique_id, last_seen_at, status, status_reason)
			VALUES ($1, $2, NOW(), $3, 'supported')`, threatID, tc.id, tc.status); err != nil {
			t.Fatal(err)
		}
	}

	active, err := store.ActiveTechniques(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0] != "T1055" || active[1] != "T1059" {
		t.Fatalf("ActiveTechniques = %v, want [T1055 T1059] (sorted, retracted excluded)", active)
	}

	genNum, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if genNum != 1 {
		t.Fatalf("NextGenerationNumber = %d, want 1 (first generation)", genNum)
	}

	if err := store.RecordGeneration(ctx, threatID, "intel-abc123", "cv-1", genNum, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	var hash1 string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT technique_set_hash FROM content_generations WHERE threat_id = $1 AND generation_number = 1`,
		threatID).Scan(&hash1); err != nil {
		t.Fatal(err)
	}
	if hash1 == "" {
		t.Fatal("technique_set_hash must be set")
	}

	genNum2, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if genNum2 != 2 {
		t.Fatalf("NextGenerationNumber after one generation = %d, want 2", genNum2)
	}
}

// TestRecordGeneration_SnapshotExcludesSupersededClaims pins the 2B final
// review's second Important finding: the snapshot query selected every
// kind='claim' row for an active technique, not just each source
// instance's current (non-superseded) one. An instance that retracted a
// technique must not still appear as "supporting" evidence in the
// snapshot, even though the technique stays active via another instance.
func TestRecordGeneration_SnapshotExcludesSupersededClaims(t *testing.T) {
	ctx := context.Background()
	storeA, syncA, instanceA, tvA, obsA := claimsFixture(t, "misp-gen-superseded-A", TrustTrusted, Complete)
	storeB, syncB, instanceB, tvB, obsB := claimsFixture(t, "misp-gen-superseded-B", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-generation-superseded")

	claimA1 := "hash-gen-superseded-a1"
	if err := storeA.RecordClaims(ctx, []Claim{{
		ObservationID: obsA(threatID, claimA1), SyncID: syncA, InstanceID: instanceA, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvA, ObservedAt: time.Now(), RecordHash: claimA1,
	}}); err != nil {
		t.Fatal(err)
	}
	claimB1 := "hash-gen-superseded-b1"
	if err := storeB.RecordClaims(ctx, []Claim{{
		ObservationID: obsB(threatID, claimB1), SyncID: syncB, InstanceID: instanceB, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvB, ObservedAt: time.Now(), RecordHash: claimB1,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := storeA.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	// A retracts; B alone still supports the technique, so it stays active.
	claimA2 := "hash-gen-superseded-a2"
	if err := storeA.RecordClaims(ctx, []Claim{{
		ObservationID: obsA(threatID, claimA2), SyncID: syncA, InstanceID: instanceA, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvA, ObservedAt: time.Now().Add(time.Hour), RecordHash: claimA2,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := storeA.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	genNum, err := storeA.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.RecordGeneration(ctx, threatID, "intel-gen-superseded", "cv-superseded", genNum, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	var snapJSON string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT evidence_snapshot::text FROM content_generations
		WHERE threat_id = $1 AND generation_number = $2`, threatID, genNum).Scan(&snapJSON); err != nil {
		t.Fatal(err)
	}
	var snap evidenceSnapshot
	if err := json.Unmarshal([]byte(snapJSON), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Techniques) != 1 {
		t.Fatalf("snapshot.Techniques = %+v, want exactly one entry for T1059", snap.Techniques)
	}
	// Resolve the two candidate claim IDs by hash to assert against the
	// snapshot's claim ID list directly, rather than re-deriving them.
	var claimAID, claimBID string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT id FROM technique_claims WHERE record_hash = $1`, claimA1).Scan(&claimAID); err != nil {
		t.Fatal(err)
	}
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT id FROM technique_claims WHERE record_hash = $1`, claimB1).Scan(&claimBID); err != nil {
		t.Fatal(err)
	}
	foundB := false
	for _, claimID := range snap.Techniques[0].ClaimIDs {
		if claimID == claimAID {
			t.Fatalf("snapshot includes A's superseded claim %s (A later retracted this technique)", claimAID)
		}
		if claimID == claimBID {
			foundB = true
		}
	}
	if !foundB {
		t.Fatalf("snapshot.Techniques[0].ClaimIDs = %v, want B's current claim %s", snap.Techniques[0].ClaimIDs, claimBID)
	}
}
