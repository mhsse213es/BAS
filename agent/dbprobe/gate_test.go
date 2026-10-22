package dbprobe

import (
	"context"
	"strings"
	"testing"
	"time"
)

func clientSpec(probeID string) DBProbeSpec {
	s := validSpec()
	s.ProbeID = probeID
	s.Mode = ModeClient
	return s
}

func mutationDef(id string) ProbeDef {
	return ProbeDef{ID: id, Class: ClassMutation, Engines: []string{"postgresql"}, ParamSchema: map[string]ParamKind{}}
}

func TestCheckSpecRejectsIdentityMismatch(t *testing.T) {
	def, _ := LookupProbe("read_roles")
	s := validSpec()
	if err := CheckSpec(s, def, "7001", "7002", true); err == nil {
		t.Fatal("identity mismatch must be rejected")
	}
	if err := CheckSpec(s, def, "7001 ", "7001", true); err == nil {
		t.Fatal("identity compare must be exact")
	}
	if err := CheckSpec(s, def, "7001", "7001", true); err != nil {
		t.Fatalf("matching identity in lab mode must pass: %v", err)
	}
}

func TestCheckSpecClientModeRejectsMutationProbe(t *testing.T) {
	def := mutationDef("drop_fixture")
	s := clientSpec("drop_fixture")
	if err := CheckSpec(s, def, "7001", "7001", true); err == nil {
		t.Fatal("client mode must reject mutation probe")
	}
}

func TestCheckSpecClientModeRejectsMislabelledScenarioByProbeID(t *testing.T) {
	// The spec claims client/read-only, but the probe's real class is mutation.
	def := mutationDef("drop_fixture")
	s := clientSpec("drop_fixture")
	s.Params = nil
	err := CheckSpec(s, def, "7001", "7001", true)
	if err == nil || !strings.Contains(err.Error(), "mutation") {
		t.Fatalf("want rejection citing real class, got %v", err)
	}
	// A forged def that disagrees with the catalog class must not help.
	forged := ProbeDef{ID: "read_roles", Class: ClassMutation}
	if err := CheckSpec(clientSpec("read_roles"), forged, "7001", "7001", true); err == nil {
		t.Fatal("def disagreeing with catalog class must be rejected")
	}
	// def for a different probe than the spec names is rejected.
	other, _ := LookupProbe("auth_check")
	if err := CheckSpec(clientSpec("read_roles"), other, "7001", "7001", true); err == nil {
		t.Fatal("def/spec probe id mismatch must be rejected")
	}
}

func TestCheckSpecClientModeRequiresEnabledAndRegisteredIdentity(t *testing.T) {
	def, _ := LookupProbe("read_roles")
	s := clientSpec("read_roles")
	if err := CheckSpec(s, def, "7001", "7001", false); err == nil {
		t.Fatal("client mode must be refused when not enabled")
	}
	if err := CheckSpec(s, def, "7001", "", true); err == nil {
		t.Fatal("client mode must not trust-on-first-use (empty expected identity)")
	}
	if err := CheckSpec(s, def, "7001", "7001", true); err != nil {
		t.Fatalf("enabled client read-only with matching identity must pass: %v", err)
	}
}

func TestBudgetChargeExceedsMaxRows(t *testing.T) {
	b := NewBudget(Limits{MaxRows: 10, TimeoutSec: 5, MaxConns: 1})
	if err := b.Charge(6); err != nil {
		t.Fatal(err)
	}
	if err := b.Charge(4); err != nil {
		t.Fatalf("exactly at limit must pass: %v", err)
	}
	if err := b.Charge(1); err == nil {
		t.Fatal("exceeding max rows must fail")
	}
	if err := NewBudget(Limits{MaxRows: 10}).Charge(-1); err == nil {
		t.Fatal("negative charge must fail")
	}
}

func TestWithDeadlineUsesTimeoutSec(t *testing.T) {
	ctx, cancel := WithDeadline(context.Background(), Limits{MaxRows: 1, TimeoutSec: 30, MaxConns: 1})
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) > 31*time.Second || time.Until(dl) < 25*time.Second {
		t.Fatalf("deadline not ~30s: %v %v", dl, ok)
	}
}
