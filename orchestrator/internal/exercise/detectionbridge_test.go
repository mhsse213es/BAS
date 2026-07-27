package exercise

import (
	"testing"

	"github.com/audspect/bas/internal/verification"
)

func TestResolveDetectionEvidence_DomainMapping(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		want   string
	}{
		{"endpoint maps to edr_detected", "endpoint", "edr_detected"},
		{"siem maps to siem_alerted", "siem", "siem_alerted"},
		{"identity maps to security_control_detected", "identity", "security_control_detected"},
		{"network maps to security_control_detected", "network", "security_control_detected"},
		{"cloud maps to security_control_detected", "cloud", "security_control_detected"},
		{"email maps to security_control_detected", "email", "security_control_detected"},
		{"dlp maps to security_control_detected", "dlp", "security_control_detected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := []verification.Record{{ExpectationID: "e1", Domain: tc.domain, Result: verification.ResultDetected}}
			got := ResolveDetectionEvidence(records, nil)
			if len(got) != 1 {
				t.Fatalf("len(got) = %d, want 1", len(got))
			}
			if got[0].EvidenceType != tc.want {
				t.Errorf("EvidenceType = %q, want %q", got[0].EvidenceType, tc.want)
			}
		})
	}
}

func TestResolveDetectionEvidence_NotDetectedProducesNoEvidence(t *testing.T) {
	records := []verification.Record{
		{ExpectationID: "e1", Domain: "endpoint", Result: verification.ResultNotDetected},
		{ExpectationID: "e2", Domain: "endpoint", Result: verification.ResultNotApplicable},
	}
	got := ResolveDetectionEvidence(records, nil)
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}

func TestResolveDetectionEvidence_SkipsAlreadyRecorded(t *testing.T) {
	records := []verification.Record{
		{ExpectationID: "e1", Domain: "endpoint", Result: verification.ResultDetected},
		{ExpectationID: "e2", Domain: "endpoint", Result: verification.ResultDetected},
	}
	got := ResolveDetectionEvidence(records, map[string]bool{"e1": true})
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if id, _ := got[0].Payload["expectation_id"].(string); id != "e2" {
		t.Errorf("expectation_id = %q, want e2", id)
	}
}

func TestResolveDetectionEvidence_PayloadCarriesMetadata(t *testing.T) {
	records := []verification.Record{{
		ExpectationID: "e1", RunID: "run-1", TechniqueID: "T1055", Domain: "dlp",
		Provider: "trellix_dlp", Result: verification.ResultDetected,
		RuleIDs: []string{"AUDRULE-000042"},
	}}
	got := ResolveDetectionEvidence(records, nil)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	p := got[0].Payload
	if p["expectation_id"] != "e1" || p["run_id"] != "run-1" || p["technique_id"] != "T1055" ||
		p["control_domain"] != "dlp" || p["provider"] != "trellix_dlp" {
		t.Errorf("Payload = %+v, missing expected metadata", p)
	}
	ruleIDs, _ := p["rule_ids"].([]string)
	if len(ruleIDs) != 1 || ruleIDs[0] != "AUDRULE-000042" {
		t.Errorf("Payload[rule_ids] = %v, want [AUDRULE-000042]", p["rule_ids"])
	}
}

func TestResolveDetectionEvidence_EmptyRuleIDsDoesNotPanic(t *testing.T) {
	records := []verification.Record{{ExpectationID: "e1", Domain: "endpoint", Result: verification.ResultDetected}}
	got := ResolveDetectionEvidence(records, nil)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	_ = got[0].Payload["rule_ids"] // must not panic reading a nil []string
}
