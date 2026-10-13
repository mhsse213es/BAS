package evidence

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecordClaims_RetractionRefusedOnNonAuthoritativeSync(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-claims-test-1"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, authoritative, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Partial, "one event detail fetch failed")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("test setup: this sync must not be authoritative")
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-retraction-refused")
	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT", "hash-1", time.Now(), map[string]any{}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}

	err = store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp",
		TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-1",
	}})
	if !errors.Is(err, ErrRetractionRefused) {
		t.Fatalf("err = %v, want ErrRetractionRefused", err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM technique_claims WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("technique_claims rows = %d, want 0 (refused call must write nothing)", count)
	}
}

func TestRecordClaims_RetractionAcceptedOnAuthoritativeSync(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-claims-test-2"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, authoritative, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	if !authoritative {
		t.Fatal("test setup: this sync must be authoritative")
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-retraction-accepted")
	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT", "hash-2", time.Now(), map[string]any{}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp",
		TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-2",
	}}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND kind = 'retraction'`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("retraction rows = %d, want 1", count)
	}
}

func TestRecordClaims_TwoSourcesSameClaimBothSurvive(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-two-sources")

	mispID, otherID := "misp-claims-test-3a", "misp-claims-test-3b"
	for _, id := range []string{mispID, otherID} {
		if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{mispID, otherID} {
		syncID, _, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "succeeded", Complete, "")
		if err != nil {
			t.Fatal(err)
		}
		_, trustVersionID, err := store.CurrentTrust(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		obsID, err := store.RecordObservation(ctx, syncID, id, "evt-x", "APT", "hash-"+id, time.Now(), map[string]any{}, trustVersionID)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RecordClaims(ctx, []Claim{{
			ObservationID: obsID, SyncID: syncID, InstanceID: id, ThreatID: threatID,
			TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
			TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-" + id,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND technique_id = 'T1059'`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("claim rows = %d, want 2 -- identical text from two providers must not be deduplicated away", count)
	}
}

func TestRecordClaims_IdempotentOnRecordHash(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-claims-test-4"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-idempotent")
	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT", "hash-rerun", time.Now(), map[string]any{}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}
	claim := Claim{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
		TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-rerun",
	}
	if err := store.RecordClaims(ctx, []Claim{claim}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClaims(ctx, []Claim{claim}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND technique_id = 'T1059'`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("claim rows after re-recording identical claim = %d, want 1", count)
	}
}
