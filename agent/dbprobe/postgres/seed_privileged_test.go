package postgres

import (
	"context"
	"testing"

	"audspect/agent/dbprobe"
)

// The probe runs as the restricted account; seed and cleanup must run on the
// privileged (lab) session, because CREATE SCHEMA is refused on the restricted
// connection.
func TestSeedAndCleanupUseThePrivilegedSessionOnly(t *testing.T) {
	ro := &fakeSession{}
	priv := &fakeSession{}
	a := &Adapter{s: ro, adm: priv, mode: dbprobe.ModeLab}
	f := dbprobe.Fixture{ID: "ab12", Kind: "pg_basic"}

	if err := a.Seed(context.Background(), f); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(ro.calls) != 0 {
		t.Fatalf("seed ran %d statements on the restricted session", len(ro.calls))
	}
	if len(priv.calls) == 0 {
		t.Fatal("seed did not use the privileged session")
	}

	before := len(priv.calls)
	if _, err := a.Cleanup(context.Background(), f); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(ro.calls) != 0 {
		t.Fatalf("cleanup ran %d statements on the restricted session", len(ro.calls))
	}
	if len(priv.calls) == before {
		t.Fatal("cleanup did not use the privileged session")
	}
}

// Without a privileged session (every existing caller) seed keeps using the
// one connection it always used.
func TestSeedWithoutPrivilegedSessionUsesMainSession(t *testing.T) {
	ro := &fakeSession{}
	a := &Adapter{s: ro, mode: dbprobe.ModeLab}
	if err := a.Seed(context.Background(), dbprobe.Fixture{ID: "ab12", Kind: "pg_basic"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(ro.calls) == 0 {
		t.Fatal("seed did not run on the main session")
	}
}
