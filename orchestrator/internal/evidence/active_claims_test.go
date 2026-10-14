package evidence

import (
	"context"
	"testing"
	"time"
)

// TestActiveClaimedTechniques_ExcludesRetractedAndOtherInstances pins the
// 2B final review's second Critical finding: nothing computed the set of
// techniques an instance currently claims so a later sync could diff
// against it and emit retractions. ActiveClaimedTechniques must return
// only the latest-claim (non-retracted) pairs for the given instance, and
// never another instance's claims.
func TestActiveClaimedTechniques_ExcludesRetractedAndOtherInstances(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-active-claims-test", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-active-claims")

	if err := store.RecordClaims(ctx, []Claim{
		{ObservationID: mkObs(threatID, "ac-1"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
			TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "ac-1"},
		{ObservationID: mkObs(threatID, "ac-2"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
			TechniqueID: "T1055", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "ac-2"},
	}); err != nil {
		t.Fatal(err)
	}
	// T1055 is later retracted by the same instance.
	if err := store.RecordClaims(ctx, []Claim{
		{ObservationID: mkObs(threatID, "ac-3"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
			TechniqueID: "T1055", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvID, ObservedAt: time.Now().Add(time.Hour), RecordHash: "ac-3"},
	}); err != nil {
		t.Fatal(err)
	}

	// A second instance claims the same threat+technique -- must not leak in.
	otherStore, otherSyncID, otherInstanceID, otherTVID, otherObs := claimsFixture(t, "misp-active-claims-other", TrustTrusted, Complete)
	if err := otherStore.RecordClaims(ctx, []Claim{
		{ObservationID: otherObs(threatID, "ac-other"), SyncID: otherSyncID, InstanceID: otherInstanceID, ThreatID: threatID,
			TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: otherTVID, ObservedAt: time.Now(), RecordHash: "ac-other"},
	}); err != nil {
		t.Fatal(err)
	}

	pairs, err := store.ActiveClaimedTechniques(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 || pairs[0].ThreatID != threatID || pairs[0].TechniqueID != "T1059" {
		t.Fatalf("ActiveClaimedTechniques(%q) = %+v, want exactly [{%s T1059}] (T1055 retracted, other instance's claim excluded)", instanceID, pairs, threatID)
	}
}
