package admatrix

import "testing"

func capStatesByID(t *testing.T) map[string]CapabilityState {
	t.Helper()
	m := map[string]CapabilityState{}
	for _, cs := range CapabilityStates() {
		m[cs.PrimitiveID] = cs
	}
	return m
}

func TestCapabilityStates_CoverAll21WithIndependentAxes(t *testing.T) {
	states := CapabilityStates()
	if len(states) != 21 {
		t.Fatalf("expected one authoritative state per primitive (21), got %d", len(states))
	}
	for _, cs := range states {
		if cs.PrimitiveID == "" || cs.Name == "" {
			t.Fatalf("incomplete record: %+v", cs)
		}
		if !cs.Modeled {
			t.Fatalf("%s: every catalog primitive is modeled", cs.PrimitiveID)
		}
		// Honest defaults: nothing in this (synthetic/local) build may claim it
		// executed or that detection was validated -- that needs real evidence.
		if cs.ExecutionValidation != ExecNotExecuted {
			t.Fatalf("%s claims execution validation %q with no real run", cs.PrimitiveID, cs.ExecutionValidation)
		}
		if cs.DetectionValidation != DetNotValidated {
			t.Fatalf("%s claims detection %q with no attributable telemetry", cs.PrimitiveID, cs.DetectionValidation)
		}
		// Axis independence: a scenario-composed capability is NOT thereby executed.
		if cs.ScenarioComposed && cs.ExecutionValidation != ExecNotExecuted {
			t.Fatalf("%s conflates composition with execution", cs.PrimitiveID)
		}
	}
}

func TestCapabilityStates_AxesAreIndependentPerCapability(t *testing.T) {
	byID := capStatesByID(t)

	// Kerberoast baseline: scenario-composed (committed scenario) but still not executed.
	k := byID["kerberoast-tgs-request"]
	if !k.ScenarioComposed || k.ContentAvailability != ContentScenarioComposable {
		t.Errorf("kerberoast-tgs-request should be scenario-composed: %+v", k)
	}

	// DCSync: reusable content exists, yet it is NOT scenario-composed and NOT executed
	// -- the three axes must disagree here, proving they are tracked independently.
	d := byID["dcsync"]
	if d.ContentAvailability != ContentReusableUnmapped {
		t.Errorf("dcsync content should be reusable-unmapped, got %q", d.ContentAvailability)
	}
	if d.ScenarioComposed {
		t.Errorf("dcsync has no committed scenario; must not be scenario-composed")
	}
	if len(d.Outstanding) == 0 {
		t.Errorf("dcsync must list outstanding work (integrate upstream content, execute, detect)")
	}

	// A gap primitive: model-only, not composed, not executed.
	e := byID["adcs-esc6"]
	if e.ContentAvailability != ContentModelOnly || e.ScenarioComposed {
		t.Errorf("adcs-esc6 should be model-only and not composed: %+v", e)
	}
}

func TestSummarizeCapabilityStates_HonestRollup(t *testing.T) {
	s := SummarizeCapabilityStates()
	if s.Total != 21 || s.Modeled != 21 {
		t.Fatalf("expected 21 total/modeled, got total=%d modeled=%d", s.Total, s.Modeled)
	}
	if s.ScenarioComposed != 3 {
		t.Errorf("expected 3 scenario-composed (Kerberoast baseline), got %d", s.ScenarioComposed)
	}
	if s.Executed != 0 {
		t.Errorf("expected 0 executed (no real runs in this build), got %d", s.Executed)
	}
	if s.DetectionValidated != 0 {
		t.Errorf("expected 0 detection-validated, got %d", s.DetectionValidated)
	}
}

func TestReport_ExposesCapabilityStatesAsTheAuthoritativeModel(t *testing.T) {
	r := Report()
	// The authoritative Phase-1 model spans all 21 primitives -- broader than
	// Capabilities (18 gap entries) and distinct from ContentStates (which
	// does not carry ExecutionValidation/DetectionValidation/Outstanding).
	if len(r.CapabilityStates) != 21 {
		t.Fatalf("report must expose a CapabilityState for all 21 primitives, got %d", len(r.CapabilityStates))
	}
	if r.CapabilityStateSummary != SummarizeCapabilityStates() {
		t.Fatalf("report CapabilityStateSummary must equal SummarizeCapabilityStates(): %+v vs %+v",
			r.CapabilityStateSummary, SummarizeCapabilityStates())
	}
	// Existing axes must stay intact -- this is additive, not a replacement.
	if len(r.Capabilities) != len(AllEntries()) {
		t.Fatalf("Capabilities must still cover every matrix entry: %d vs %d", len(r.Capabilities), len(AllEntries()))
	}
	if len(r.ContentStates) != 21 {
		t.Fatalf("ContentStates must still cover all 21 primitives, got %d", len(r.ContentStates))
	}
}
