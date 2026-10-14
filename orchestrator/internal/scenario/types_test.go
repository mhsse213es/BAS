package scenario

import (
	"encoding/json"
	"testing"
)

func TestPrivilegeExceeds(t *testing.T) {
	cases := []struct {
		name     string
		stepTier string
		maxTier  string
		want     bool
	}{
		{"empty maxTier means unconstrained", "admin", "", false},
		{"empty stepTier (legacy/unannotated) never exceeds", "", "user", false},
		{"user step under user ceiling", "user", "user", false},
		{"admin step under admin ceiling", "admin", "admin", false},
		{"admin step exceeds user ceiling", "admin", "user", true},
		{"system step exceeds admin ceiling", "system", "admin", true},
		{"system step under system ceiling", "system", "system", false},
		{"user step never exceeds admin ceiling", "user", "admin", false},
		{"unrecognized stepTier treated as user (lowest)", "bogus", "user", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PrivilegeExceeds(c.stepTier, c.maxTier); got != c.want {
				t.Errorf("PrivilegeExceeds(%q, %q) = %v, want %v", c.stepTier, c.maxTier, got, c.want)
			}
		})
	}
}

func TestExecutionPolicyJSONRoundTrip(t *testing.T) {
	in := ExecutionPolicy{MaxPrivilege: "user"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"maxPrivilege":"user"}` {
		t.Errorf("marshal = %s, want {\"maxPrivilege\":\"user\"}", raw)
	}
	var out ExecutionPolicy
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip = %+v, want %+v", out, in)
	}

	empty, _ := json.Marshal(ExecutionPolicy{})
	if string(empty) != `{}` {
		t.Errorf("empty policy marshal = %s, want {} (omitempty)", empty)
	}
}

func TestStep_ThreatIntelProvenanceFields_YAMLRoundTrip(t *testing.T) {
	sc, err := ParseYAML([]byte(`id: test-x
name: X
steps:
  - name: s
    technique_id: T1486
    framework: custom
    command: whoami
    threat_intel_sources:
      - reference: "CISA AA23-158A"
        url: "https://www.cisa.gov/example"
      - reference: "Vendor Report X"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sc.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(sc.Steps))
	}
	step := sc.Steps[0]
	if len(step.ThreatIntelSources) != 2 {
		t.Fatalf("got %d threat_intel_sources, want 2", len(step.ThreatIntelSources))
	}
	if step.ThreatIntelSources[0].Reference != "CISA AA23-158A" || step.ThreatIntelSources[0].URL != "https://www.cisa.gov/example" {
		t.Errorf("source[0] = %+v", step.ThreatIntelSources[0])
	}
	if step.ThreatIntelSources[1].Reference != "Vendor Report X" || step.ThreatIntelSources[1].URL != "" {
		t.Errorf("source[1] = %+v", step.ThreatIntelSources[1])
	}
	if step.LastReviewed != "2026-10-12" {
		t.Errorf("last_reviewed = %q, want 2026-10-12", step.LastReviewed)
	}
	if step.FamilyAttributionConfidence != FamilyAttributionReported {
		t.Errorf("family_attribution_confidence = %q, want %q", step.FamilyAttributionConfidence, FamilyAttributionReported)
	}
}

// TestStep_ThreatIntelProvenanceFields_ZeroValueWhenAbsent is the
// backward-compatibility guarantee at the parse layer: every step in every
// scenario that predates this change sets none of these three fields, and
// must continue to parse to their zero values exactly as before.
func TestStep_ThreatIntelProvenanceFields_ZeroValueWhenAbsent(t *testing.T) {
	sc, err := ParseYAML([]byte(`id: test-y
name: Y
steps:
  - name: s2
    technique_id: T1486
    framework: custom
    command: whoami
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	legacy := sc.Steps[0]
	if len(legacy.ThreatIntelSources) != 0 || legacy.LastReviewed != "" || legacy.FamilyAttributionConfidence != "" {
		t.Errorf("legacy step got non-zero provenance fields: %+v", legacy)
	}
}
