package dbsim

import "testing"

func TestFixtureReadProbesAreRegistered(t *testing.T) {
	sr, ok := LookupProbeEntry("suspicious_read")
	if !ok || sr.Class != ClassBoundedSynthetic || sr.FixtureParam != "table" || sr.ParamSchema["table"] != "string" {
		t.Fatalf("suspicious_read: %+v ok=%v", sr, ok)
	}
	bb, ok := LookupProbeEntry("bounded_synthetic_read")
	if !ok || bb.Class != ClassBoundedSynthetic || bb.FixtureParam != "table" || bb.ParamSchema["table"] != "string" {
		t.Fatalf("bounded_synthetic_read: %+v ok=%v", bb, ok)
	}
	for _, id := range []string{"read_roles", "read_grants", "auth_check", "read_audit_config", "read_restricted_table"} {
		if e, _ := LookupProbeEntry(id); e.FixtureParam != "" {
			t.Errorf("%s must not be fixture-aware", id)
		}
	}
}

// DB-09 (bounded_synthetic) is refused for client targets and needs the lab
// confirmation plus the scenario's mutation approval; DB-05 (read_only) is also
// refused for client targets because it reads a per-run fixture.
func TestBoundedSyntheticReadRefusedInClientMode(t *testing.T) {
	bb, _ := LookupProbeEntry("bounded_synthetic_read")
	sr, _ := LookupProbeEntry("suspicious_read")
	for _, e := range []ProbeRegistryEntry{bb, sr} {
		if err := Authorize(goodTarget(ModeClient), e, in(true, true)); err == nil {
			t.Errorf("client target must be refused for %s", e.ID)
		}
	}
	if err := Authorize(goodTarget(ModeLab), bb, in(false, false)); err == nil {
		t.Error("bounded_synthetic_read without scenario mutation approval must be refused")
	}
	unconfirmed := goodTarget(ModeLab)
	unconfirmed.LabConfirmed = false
	if err := Authorize(unconfirmed, bb, in(false, true)); err == nil {
		t.Error("bounded_synthetic_read against an unconfirmed lab target must be refused")
	}
	if err := Authorize(goodTarget(ModeLab), bb, in(false, true)); err != nil {
		t.Errorf("confirmed lab target with approval must pass: %v", err)
	}
	// R-AI: suspicious_read seeds a fixture too and is gated identically.
	if err := Authorize(goodTarget(ModeLab), sr, in(false, false)); err == nil {
		t.Error("suspicious_read without scenario mutation approval must be refused")
	}
	if err := Authorize(unconfirmed, sr, in(false, true)); err == nil {
		t.Error("suspicious_read against an unconfirmed lab target must be refused")
	}
	if err := Authorize(goodTarget(ModeLab), sr, in(false, true)); err != nil {
		t.Errorf("confirmed lab target with approval must pass: %v", err)
	}
}

// R-AI: a step that names a fixture is a mutation for gating, whatever the
// probe's class, so a read_only probe with a fixture needs the same controls.
func TestAuthorizeAnyFixtureStepNeedsLabConfirmedAndApproval(t *testing.T) {
	ro := roEntry()
	withFx := func(approved bool) AuthInput { i := in(false, approved); i.Fixture = true; return i }
	if err := Authorize(goodTarget(ModeLab), ro, withFx(false)); err == nil {
		t.Error("read_only probe + fixture without approval accepted")
	}
	unconfirmed := goodTarget(ModeLab)
	unconfirmed.LabConfirmed = false
	if err := Authorize(unconfirmed, ro, withFx(true)); err == nil {
		t.Error("read_only probe + fixture on an unconfirmed lab target accepted")
	}
	if err := Authorize(goodTarget(ModeLab), ro, withFx(true)); err != nil {
		t.Errorf("confirmed + approved must pass: %v", err)
	}
	ci := withFx(true)
	ci.ClientEnabled = true
	if err := Authorize(goodTarget(ModeClient), ro, ci); err == nil {
		t.Error("client mode with a fixture must stay refused")
	}
	// No fixture: read-only probes are unchanged.
	if err := Authorize(goodTarget(ModeLab), ro, in(false, false)); err != nil {
		t.Errorf("read_only without fixture must be unchanged: %v", err)
	}
}

// A fixture-aware entry is lab-only even if a future registry edit relabels its class.
func TestAuthorizeFixtureAwareProbeIsLabOnlyWhateverTheClass(t *testing.T) {
	real := registerTestEntry(t, "t_fixture_ro", ClassReadOnly)
	real.FixtureParam = "table"
	probeRegistry[real.ID] = real
	if err := Authorize(goodTarget(ModeClient), real, in(true, true)); err == nil {
		t.Fatal("fixture-aware read_only probe must be refused in client mode")
	}
	if err := Authorize(goodTarget(ModeLab), real, in(false, false)); err == nil {
		t.Fatal("a fixture-aware entry needs approval even when labelled read_only")
	}
	if err := Authorize(goodTarget(ModeLab), real, in(false, true)); err != nil {
		t.Fatalf("lab mode with approval must pass: %v", err)
	}
}
