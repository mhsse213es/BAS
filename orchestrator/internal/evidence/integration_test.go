package evidence

import (
	"context"
	"testing"
	"time"
)

// TestIntegration_TwoSourceDropSequence pins spec §13 acceptance test 18:
// source A claims T1059, then drops it (A alone retracted); source B also
// claims T1059 and keeps claiming it -- the technique must stay active on
// B's support alone, with first_seen_at anchored to A's original claim.
// Once B also drops it, the technique goes retracted.
func TestIntegration_TwoSourceDropSequence(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	threatID := seedThreat(t, sharedDB.Pool, "APT-two-source-drop")
	jan1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	setup := func(instanceID string) (syncID string, trustVersionID int64, obs func(hash string) string) {
		if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
			t.Fatal(err)
		}
		sID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
		if err != nil {
			t.Fatal(err)
		}
		_, tvID, err := store.CurrentTrust(ctx, instanceID)
		if err != nil {
			t.Fatal(err)
		}
		return sID, tvID, func(hash string) string {
			id, err := store.RecordObservation(ctx, sID, instanceID, "evt-"+hash, "APT", hash, time.Now(), map[string]any{}, tvID)
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
	}

	// A claims T1059 on Jan 1.
	syncA1, tvA, obsA1 := setup("misp-two-source-A")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsA1("a-claim"), SyncID: syncA1, InstanceID: "misp-two-source-A", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvA, ObservedAt: jan1, RecordHash: "a-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	// B also claims T1059, independently.
	syncB1, tvB, obsB1 := setup("misp-two-source-B")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsB1("b-claim"), SyncID: syncB1, InstanceID: "misp-two-source-B", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvB, ObservedAt: jan1.Add(time.Hour), RecordHash: "b-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	// A drops T1059 (a later complete snapshot sync no longer sees it).
	syncA2, _, obsA2 := setup("misp-two-source-A")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsA2("a-retract"), SyncID: syncA2, InstanceID: "misp-two-source-A", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvA, ObservedAt: jan1.AddDate(0, 0, 10), RecordHash: "a-retract",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status string
	var firstSeenAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT status, first_seen_at FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &firstSeenAt); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("status after A alone drops = %q, want active (B still supports it)", status)
	}
	if !firstSeenAt.Equal(jan1) {
		t.Fatalf("first_seen_at = %v, want unchanged at %v (A's original claim; a later retraction never moves it)", firstSeenAt, jan1)
	}

	// B also drops it.
	syncB2, _, obsB2 := setup("misp-two-source-B")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsB2("b-retract"), SyncID: syncB2, InstanceID: "misp-two-source-B", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvB, ObservedAt: jan1.AddDate(0, 0, 11), RecordHash: "b-retract",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT status FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "retracted" {
		t.Fatalf("status after both sources drop = %q, want retracted", status)
	}
}

// TestIntegration_GenerationSnapshotsExplainTechniqueSetDifference pins spec
// §13 acceptance test 24: two generations' evidence_snapshot_hash values
// differ exactly when their active technique sets differ, and the earlier
// snapshot's own content explains which technique was missing.
func TestIntegration_GenerationSnapshotsExplainTechniqueSetDifference(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-gen-diff-test", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-generation-diff")

	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "gen-diff-1"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "gen-diff-1",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	gen1, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordGeneration(ctx, threatID, "intel-gen-diff", "cv-1", gen1, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	// A second technique arrives before generation 2.
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "gen-diff-2"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1055", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "gen-diff-2",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	gen2, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordGeneration(ctx, threatID, "intel-gen-diff", "cv-2", gen2, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	var hash1, hash2, snapshot1, snapshot2 string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT evidence_snapshot_hash, evidence_snapshot::text FROM content_generations
		WHERE threat_id = $1 AND generation_number = $2`, threatID, gen1).Scan(&hash1, &snapshot1); err != nil {
		t.Fatal(err)
	}
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT evidence_snapshot_hash, evidence_snapshot::text FROM content_generations
		WHERE threat_id = $1 AND generation_number = $2`, threatID, gen2).Scan(&hash2, &snapshot2); err != nil {
		t.Fatal(err)
	}
	if hash1 == hash2 {
		t.Fatal("generation 1 and 2 have different active sets but the same evidence_snapshot_hash")
	}
	if containsSubstring(snapshot1, "T1055") {
		t.Fatalf("generation 1's snapshot = %s, must not mention T1055 (claimed after generation 1)", snapshot1)
	}
	if !containsSubstring(snapshot2, "T1055") || !containsSubstring(snapshot2, "T1059") {
		t.Fatalf("generation 2's snapshot = %s, must mention both T1059 and T1055", snapshot2)
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
