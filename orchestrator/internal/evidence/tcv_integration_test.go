package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/tcv"
)

// TestIntegration_ClockStartNotRestartedByRetractionThenReappearance pins
// acceptance test 31: a technique that is claimed, retracted, and then
// re-claimed must not restart its already-written clock.
func TestIntegration_ClockStartNotRestartedByRetractionThenReappearance(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-tcv-reappear", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-acceptance-31")
	firstSeen := time.Now().Add(-72 * time.Hour)

	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "reappear-1"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: firstSeen, RecordHash: "reappear-1",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := tcv.RecordThreatClockStart(ctx, sharedDB.Pool, threatID, firstSeen, syncID); err != nil {
		t.Fatal(err)
	}

	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "reappear-2"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvID, ObservedAt: firstSeen.Add(24 * time.Hour), RecordHash: "reappear-2",
	}}); err != nil {
		t.Fatal(err)
	}
	reappeared := time.Now()
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "reappear-3"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: reappeared, RecordHash: "reappear-3",
	}}); err != nil {
		t.Fatal(err)
	}
	// The scheduler's real wiring (Task 11) would call this again on
	// reappearance; simulate that here directly against the package.
	if err := tcv.RecordThreatClockStart(ctx, sharedDB.Pool, threatID, reappeared, syncID); err != nil {
		t.Fatal(err)
	}

	var startedAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT started_at FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'threat'`,
		threatID).Scan(&startedAt); err != nil {
		t.Fatal(err)
	}
	if diff := startedAt.Sub(firstSeen); diff < -time.Second || diff > time.Second {
		t.Fatalf("started_at = %v, want the ORIGINAL first observation %v (reappearance must not restart the clock)", startedAt, firstSeen)
	}
}
