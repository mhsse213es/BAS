package admatrix

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

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
	if len(states) != 27 {
		t.Fatalf("expected one authoritative state per primitive (27), got %d", len(states))
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
	if s.Total != 27 || s.Modeled != 27 {
		t.Fatalf("expected 27 total/modeled, got total=%d modeled=%d", s.Total, s.Modeled)
	}
	if s.ScenarioComposed != 9 {
		t.Errorf("expected 9 scenario-composed (Kerberoast baseline + DCSync/ACL/ADCS/Delegation/Trust/GPO exposure checks), got %d", s.ScenarioComposed)
	}
	if s.Executed != 0 {
		t.Errorf("expected 0 executed (no real runs in this build), got %d", s.Executed)
	}
	if s.DetectionValidated != 0 {
		t.Errorf("expected 0 detection-validated, got %d", s.DetectionValidated)
	}
}

// TestCapabilityStates_IncludeCleanupSafetyAndEvidence enforces the rest of
// Phase 1's field list (AD Mastery E2E Directive): "preconditions, expected
// postconditions, cleanup and safety requirements" + "evidence sources, known
// limitations and outstanding work" -- independently represented for all 21,
// never left blank as if overlooked.
func TestCapabilityStates_IncludeCleanupSafetyAndEvidence(t *testing.T) {
	for _, cs := range CapabilityStates() {
		if cs.RiskClass == "" {
			t.Errorf("%s: missing safety requirement (RiskClass)", cs.PrimitiveID)
		}
		if len(cs.Cleanup) == 0 {
			t.Errorf("%s: missing cleanup", cs.PrimitiveID)
		}
		if len(cs.EvidenceRequirements) == 0 {
			t.Errorf("%s: missing evidence requirements", cs.PrimitiveID)
		}
		if len(cs.TelemetrySources) == 0 {
			t.Errorf("%s: missing telemetry sources", cs.PrimitiveID)
		}
		if len(cs.Limitations) == 0 {
			t.Errorf("%s: missing known limitations", cs.PrimitiveID)
		}
	}
}

// TestCapabilityStates_KerberoastingCitesRealScenarioContent is the Phase-2
// cross-reference for the one family that already has a committed scenario:
// it parses the real scenarios/kerberoasting-ad-drill.yaml and proves the
// curated Cleanup/EvidenceRequirements/TelemetrySources strings for
// spn-enumerate, kerberoast-tgs-request and asrep-roast-discover are actually
// present in that file's stages -- never hand-maintained drift.
func TestCapabilityStates_KerberoastingCitesRealScenarioContent(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "kerberoasting-ad-drill.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := scenario.ParseYAML(b)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	stageByOrdinal := map[int]scenario.Step{}
	for _, step := range sc.Steps {
		switch {
		case strings.Contains(step.Name, "Stage 1"):
			stageByOrdinal[1] = step
		case strings.Contains(step.Name, "Stage 2"):
			stageByOrdinal[2] = step
		case strings.Contains(step.Name, "Stage 3"):
			stageByOrdinal[3] = step
		}
	}

	cases := []struct {
		primitiveID string
		ordinal     int
	}{
		{"spn-enumerate", 1},
		{"kerberoast-tgs-request", 2},
		{"asrep-roast-discover", 3},
	}
	byID := capStatesByID(t)
	for _, c := range cases {
		step, ok := stageByOrdinal[c.ordinal]
		if !ok {
			t.Fatalf("scenario file has no Stage %d step", c.ordinal)
		}
		cs := byID[c.primitiveID]

		for _, telemetry := range cs.TelemetrySources {
			if !containsAny(step.Telemetry, telemetry) {
				t.Errorf("%s: cited telemetry %q not found in %s's real Telemetry list %v", c.primitiveID, telemetry, step.Name, step.Telemetry)
			}
		}
		for _, evidence := range cs.EvidenceRequirements {
			if !containsAny(step.Detection, evidence) {
				t.Errorf("%s: cited evidence %q not found in %s's real Detection list %v", c.primitiveID, evidence, step.Name, step.Detection)
			}
		}
		if step.Cleanup != "" {
			t.Fatalf("%s: test assumes Stage %d's real cleanup is empty (read-only); file now has %q -- update the curated Cleanup citation", c.primitiveID, c.ordinal, step.Cleanup)
		}
		if len(cs.Cleanup) == 0 {
			t.Errorf("%s: must explicitly state no cleanup is required, citing the real stage", c.primitiveID)
		}
	}
}

func containsAny(list []string, want string) bool {
	return slices.Contains(list, want)
}

// TestCapabilityStates_DCSyncExposureCheckCitesRealScenarioContent mirrors
// TestCapabilityStates_KerberoastingCitesRealScenarioContent for the new
// dcsync-replication-right-exposure-check primitive: parses the real,
// committed scenario and proves every cited Telemetry/Evidence/Cleanup
// string genuinely appears in it -- never hand-invented drift.
func TestCapabilityStates_DCSyncExposureCheckCitesRealScenarioContent(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "dcsync-replication-rights-audit.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := scenario.ParseYAML(b)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(sc.Steps) != 1 {
		t.Fatalf("expected exactly 1 step in %s, got %d", path, len(sc.Steps))
	}
	step := sc.Steps[0]

	byID := capStatesByID(t)
	cs := byID["dcsync-replication-right-exposure-check"]

	for _, telemetry := range cs.TelemetrySources {
		if !containsAny(step.Telemetry, telemetry) {
			t.Errorf("cited telemetry %q not found in %s's real Telemetry list %v", telemetry, step.Name, step.Telemetry)
		}
	}
	for _, evidence := range cs.EvidenceRequirements {
		if !containsAny(step.Detection, evidence) {
			t.Errorf("cited evidence %q not found in %s's real Detection list %v", evidence, step.Name, step.Detection)
		}
	}
	if step.Cleanup != "" {
		t.Fatalf("test assumes the real cleanup is empty (read-only); file now has %q -- update the curated Cleanup citation", step.Cleanup)
	}
	if len(cs.Cleanup) == 0 {
		t.Error("must explicitly state no cleanup is required, citing the real stage")
	}
	// The whole point of this primitive: it must never claim the full
	// DCSync postcondition (real credential material), only the discovery
	// of the prerequisite right.
	if len(cs.ExpectedPostconditions) != 1 || cs.ExpectedPostconditions[0].Kind != adprimitive.CapDCSyncRightHolderKnown {
		t.Fatalf("expected postcondition CapDCSyncRightHolderKnown, got %+v", cs.ExpectedPostconditions)
	}
}

// TestCapabilityStates_ACLExposureCheckCitesRealScenarioContent mirrors the
// DCSync grounding test for the ACL exposure-check: parses the real,
// committed scenario and proves every cited Telemetry/Evidence/Cleanup
// string genuinely appears in it, and that the primitive only ever claims
// the discovery postcondition -- never a real takeover.
func TestCapabilityStates_ACLExposureCheckCitesRealScenarioContent(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "acl-privilege-exposure-audit.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := scenario.ParseYAML(b)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(sc.Steps) != 1 {
		t.Fatalf("expected exactly 1 step in %s, got %d", path, len(sc.Steps))
	}
	step := sc.Steps[0]

	byID := capStatesByID(t)
	cs := byID["acl-privilege-exposure-check"]

	for _, telemetry := range cs.TelemetrySources {
		if !containsAny(step.Telemetry, telemetry) {
			t.Errorf("cited telemetry %q not found in %s's real Telemetry list %v", telemetry, step.Name, step.Telemetry)
		}
	}
	for _, evidence := range cs.EvidenceRequirements {
		if !containsAny(step.Detection, evidence) {
			t.Errorf("cited evidence %q not found in %s's real Detection list %v", evidence, step.Name, step.Detection)
		}
	}
	if step.Cleanup != "" {
		t.Fatalf("test assumes the real cleanup is empty (read-only); file now has %q -- update the curated Cleanup citation", step.Cleanup)
	}
	if len(cs.Cleanup) == 0 {
		t.Error("must explicitly state no cleanup is required, citing the real stage")
	}
	if len(cs.ExpectedPostconditions) != 1 || cs.ExpectedPostconditions[0].Kind != adprimitive.CapACLPrivilegeExposureKnown {
		t.Fatalf("expected postcondition CapACLPrivilegeExposureKnown (discovery, not takeover), got %+v", cs.ExpectedPostconditions)
	}
}

// TestCapabilityStates_ADCSExposureCheckCitesRealScenarioContent mirrors the
// DCSync/ACL grounding tests for the ADCS ESC template exposure-check: parses
// the real, committed scenario and proves every cited Telemetry/Evidence/
// Cleanup string genuinely appears in it, and that the primitive only ever
// claims the discovery postcondition -- never a real certificate request.
func TestCapabilityStates_ADCSExposureCheckCitesRealScenarioContent(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "adcs-esc-template-exposure-audit.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := scenario.ParseYAML(b)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(sc.Steps) != 1 {
		t.Fatalf("expected exactly 1 step in %s, got %d", path, len(sc.Steps))
	}
	step := sc.Steps[0]

	byID := capStatesByID(t)
	cs := byID["adcs-esc-exposure-check"]

	for _, telemetry := range cs.TelemetrySources {
		if !containsAny(step.Telemetry, telemetry) {
			t.Errorf("cited telemetry %q not found in %s's real Telemetry list %v", telemetry, step.Name, step.Telemetry)
		}
	}
	for _, evidence := range cs.EvidenceRequirements {
		if !containsAny(step.Detection, evidence) {
			t.Errorf("cited evidence %q not found in %s's real Detection list %v", evidence, step.Name, step.Detection)
		}
	}
	if step.Cleanup != "" {
		t.Fatalf("test assumes the real cleanup is empty (read-only); file now has %q -- update the curated Cleanup citation", step.Cleanup)
	}
	if len(cs.Cleanup) == 0 {
		t.Error("must explicitly state no cleanup is required, citing the real stage")
	}
	if len(cs.ExpectedPostconditions) != 1 || cs.ExpectedPostconditions[0].Kind != adprimitive.CapADCSTemplateExposureKnown {
		t.Fatalf("expected postcondition CapADCSTemplateExposureKnown (discovery, not certificate request), got %+v", cs.ExpectedPostconditions)
	}
}

// TestCapabilityStates_DelegationTrustGPOExposureChecksCiteRealScenarioContent
// is the table-driven grounding test for the delegation, trust, and GPO
// exposure-checks: for each, it parses the real committed scenario and proves
// every cited Telemetry/Evidence/Cleanup string genuinely appears in it, and
// that the primitive only ever claims the discovery postcondition.
func TestCapabilityStates_DelegationTrustGPOExposureChecksCiteRealScenarioContent(t *testing.T) {
	cases := []struct {
		primitiveID string
		file        string
		wantPost    adprimitive.CapabilityKind
	}{
		{"kerberos-delegation-exposure-check", "kerberos-delegation-exposure-audit.yaml", adprimitive.CapDelegationExposureKnown},
		{"trust-sid-history-exposure-check", "trust-sid-history-exposure-audit.yaml", adprimitive.CapTrustExposureKnown},
		{"gpo-abuse-exposure-check", "gpo-writable-linked-exposure-audit.yaml", adprimitive.CapGPOExposureKnown},
	}
	byID := capStatesByID(t)
	for _, tc := range cases {
		t.Run(tc.primitiveID, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "scenarios", tc.file)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			sc, err := scenario.ParseYAML(b)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if len(sc.Steps) != 1 {
				t.Fatalf("expected exactly 1 step in %s, got %d", path, len(sc.Steps))
			}
			step := sc.Steps[0]
			cs := byID[tc.primitiveID]

			for _, telemetry := range cs.TelemetrySources {
				if !containsAny(step.Telemetry, telemetry) {
					t.Errorf("cited telemetry %q not found in %s's real Telemetry list %v", telemetry, step.Name, step.Telemetry)
				}
			}
			for _, evidence := range cs.EvidenceRequirements {
				if !containsAny(step.Detection, evidence) {
					t.Errorf("cited evidence %q not found in %s's real Detection list %v", evidence, step.Name, step.Detection)
				}
			}
			if step.Cleanup != "" {
				t.Fatalf("test assumes the real cleanup is empty (read-only); file now has %q", step.Cleanup)
			}
			if len(cs.Cleanup) == 0 {
				t.Error("must explicitly state no cleanup is required, citing the real stage")
			}
			if len(cs.ExpectedPostconditions) != 1 || cs.ExpectedPostconditions[0].Kind != tc.wantPost {
				t.Fatalf("expected discovery postcondition %q, got %+v", tc.wantPost, cs.ExpectedPostconditions)
			}
		})
	}
}

func TestReport_ExposesCapabilityStatesAsTheAuthoritativeModel(t *testing.T) {
	r := Report()
	// The authoritative Phase-1 model spans all 27 primitives -- broader than
	// Capabilities (18 gap entries) and distinct from ContentStates (which
	// does not carry ExecutionValidation/DetectionValidation/Outstanding).
	if len(r.CapabilityStates) != 27 {
		t.Fatalf("report must expose a CapabilityState for all 27 primitives, got %d", len(r.CapabilityStates))
	}
	if r.CapabilityStateSummary != SummarizeCapabilityStates() {
		t.Fatalf("report CapabilityStateSummary must equal SummarizeCapabilityStates(): %+v vs %+v",
			r.CapabilityStateSummary, SummarizeCapabilityStates())
	}
	// Existing axes must stay intact -- this is additive, not a replacement.
	if len(r.Capabilities) != len(AllEntries()) {
		t.Fatalf("Capabilities must still cover every matrix entry: %d vs %d", len(r.Capabilities), len(AllEntries()))
	}
	if len(r.ContentStates) != 27 {
		t.Fatalf("ContentStates must still cover all 27 primitives, got %d", len(r.ContentStates))
	}
}
