package wafefficacy

import "testing"

func TestAudspectWAFCoverageReport_ReturnsTenDomains(t *testing.T) {
	r, err := AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	if r.Denominator() != 10 {
		t.Fatalf("Denominator() = %d, want 10", r.Denominator())
	}
	if r.CoveredCount() != 10 {
		t.Fatalf("CoveredCount() = %d, want 10 (all domains covered)", r.CoveredCount())
	}
}

// Review Focus: verify against waf.txt's own phase names verbatim, not
// just a count -- a transposition of two names must fail this test.
func TestAudspectWAFCoverageReport_MatchesWafTxtPhasesVerbatim(t *testing.T) {
	wantNames := map[string]string{
		"01": "WAF capability and vendor-neutral model",
		"02": "Core attack-prevention mastery",
		"03": "Configuration and policy-gap testing",
		"04": "Protocol, parser and evasion testing",
		"05": "API and business-flow protection",
		"06": "Bot, abuse and rate-limit efficacy",
		"07": "Origin, deployment and resilience",
		"08": "Detection and telemetry validation",
		"09": "Industry and regional profiles",
		"10": "Independent verification and continuous mastery",
	}

	r, err := AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	if got := len(wantNames); r.Denominator() != got {
		t.Fatalf("Denominator() = %d, want %d", r.Denominator(), got)
	}
	for id, name := range wantNames {
		found := false
		for _, d := range r.domains {
			if d.DomainID == id {
				found = true
				if d.DomainName != name {
					t.Errorf("domain %q DomainName = %q, want %q (verbatim from waf.txt)", id, d.DomainName, name)
				}
			}
		}
		if !found {
			t.Errorf("domain ID %q not found in AudspectWAFCoverageReport", id)
		}
	}
}
