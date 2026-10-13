package evidence

import (
	"context"
	"testing"
	"time"
)

// claimsFixture sets up one source instance + sync + observation, ready to
// record claims against. Returns the store and everything a claim needs.
func claimsFixture(t *testing.T, instanceID string, trust TrustState, completeness Completeness) (store *Store, syncID, trustVersionIDSource string, trustVersionID int64, obsID func(threatID, hash string) string) {
	t.Helper()
	ctx := context.Background()
	store = NewStore(sharedDB.Pool)
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, trust); err != nil {
		t.Fatal(err)
	}
	sID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", completeness, "")
	if err != nil {
		t.Fatal(err)
	}
	_, tvID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	return store, sID, instanceID, tvID, func(threatID, hash string) string {
		id, err := store.RecordObservation(ctx, sID, instanceID, "evt-"+hash, "APT", hash, time.Now(), map[string]any{}, tvID)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
}

func TestRecomputeThreatTechniques_ActiveFromTrustedClaim(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-proj-test-1", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-active")
	obsID := mkObs(threatID, "hash-active")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", RawConfidence: "high",
		TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "hash-active",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status string
	var confidence *int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT status, best_confidence FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &confidence); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("status = %q, want active", status)
	}
	if confidence == nil || *confidence != 85 {
		t.Fatalf("best_confidence = %v, want 85 (MISP \"high\")", confidence)
	}
}

func TestRecomputeThreatTechniques_SourceRetractionMarksRetracted(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-proj-test-2", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-retracted")
	claimObs := mkObs(threatID, "hash-r-claim")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: claimObs, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
		TrustVersionID: tvID, ObservedAt: time.Now().Add(-time.Hour), RecordHash: "hash-r-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	// A later, complete snapshot sync no longer contains this technique --
	// an explicit retraction observation (spec §6.1).
	retractObs := mkObs(threatID, "hash-r-retract")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: retractObs, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp",
		TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "hash-r-retract",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status, reason string
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT status, status_reason FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "retracted" || reason != "source_retraction" {
		t.Fatalf("status/reason = %q/%q, want retracted/source_retraction", status, reason)
	}
}

func TestRecomputeThreatTechniques_TrustRevocationDistinctFromSourceRetraction(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-proj-test-3", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-trust-revoked")
	obsID := mkObs(threatID, "hash-tr-claim")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
		TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "hash-tr-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	// Revoking trust removes this source's claims from current support
	// (spec §7.4) -- distinguishable from a source retraction.
	if err := store.SetTrust(ctx, instanceID, TrustUntrusted, "admin-1", "source compromised"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status, reason string
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT status, status_reason FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "retracted" || reason != "trust_revocation" {
		t.Fatalf("status/reason = %q/%q, want retracted/trust_revocation", status, reason)
	}
}

func TestRecomputeThreatTechniques_FirstSeenNeverBackdatedByLaterTrust(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "otx-proj-test-1", TrustUntrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-untrusted-then-trusted")
	untrustedObs := mkObs(threatID, "hash-ut-claim")
	untrustedTime := time.Now().Add(-48 * time.Hour)
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: untrustedObs, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "otx",
		TrustVersionID: tvID, ObservedAt: untrustedTime, RecordHash: "hash-ut-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTrust(ctx, instanceID, TrustTrusted, "admin-1", "elevated after review"); err != nil {
		t.Fatal(err)
	}
	_, trustedTvID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	trustedTime := time.Now()
	trustedSyncID, _, err := store.RecordSync(ctx, instanceID, ModeActivityWindow, trustedTime, "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	trustedObsID, err := store.RecordObservation(ctx, trustedSyncID, instanceID, "evt-trusted", "APT", "hash-t-claim", trustedTime, map[string]any{}, trustedTvID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: trustedObsID, SyncID: trustedSyncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "otx",
		TrustVersionID: trustedTvID, ObservedAt: trustedTime, RecordHash: "hash-t-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var firstSeenAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT first_seen_at FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&firstSeenAt); err != nil {
		t.Fatal(err)
	}
	if firstSeenAt.Before(trustedTime.Add(-time.Minute)) {
		t.Fatalf("first_seen_at = %v, must not be backdated to the untrusted claim at %v", firstSeenAt, untrustedTime)
	}
}
