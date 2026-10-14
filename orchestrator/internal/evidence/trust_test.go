package evidence

import (
	"context"
	"testing"
)

func TestSourceTrust_DefaultOnCreateThenAdminOverride(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-test-1"

	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test MISP", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	state, _, err := store.CurrentTrust(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != TrustTrusted {
		t.Fatalf("state = %q, want trusted (MISP default)", state)
	}

	// Re-ensuring an existing instance never resets trust (spec §5.1: trust
	// changes only through SetTrust).
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test MISP", ModeSnapshot, TrustUntrusted); err != nil {
		t.Fatal(err)
	}
	state, _, err = store.CurrentTrust(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != TrustTrusted {
		t.Fatalf("state = %q after re-ensure, want unchanged trusted", state)
	}

	if err := store.SetTrust(ctx, id, TrustUntrusted, "admin-1", "demoted for review"); err != nil {
		t.Fatal(err)
	}
	state, versionID, err := store.CurrentTrust(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != TrustUntrusted {
		t.Fatalf("state after SetTrust = %q, want untrusted", state)
	}
	if versionID == 0 {
		t.Fatal("trust version id must be set")
	}
}

func TestSourceTrust_SetTrustRequiresReason(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "otx-test-1"
	if err := store.EnsureSourceInstance(ctx, id, "otx", "Test OTX", ModeActivityWindow, TrustUntrusted); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTrust(ctx, id, TrustTrusted, "admin-1", ""); err == nil {
		t.Fatal("expected an error for an empty reason")
	}
}
