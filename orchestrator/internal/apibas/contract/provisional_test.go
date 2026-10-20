package contract_test

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
)

func abuse002(t *testing.T) contract.Scenario {
	t.Helper()
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	for _, s := range all {
		if s.ID == "API-BAS-ABUSE-002" {
			return s
		}
	}
	t.Fatal("ABUSE-002 not in catalog")
	return contract.Scenario{}
}

// Expectation: timing_claim is accepted only on a timing scenario with a reason. Each other form is refused.
func TestTimingClaimRules(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*contract.Scenario)
		wantErr string
	}{
		{"provisional timing scenario with reason", func(s *contract.Scenario) {}, ""},
		{"unknown claim status", func(s *contract.Scenario) { s.TimingClaim = "approved" }, "not a claim status"},
		{"claim on a non-timing scenario", func(s *contract.Scenario) { s.Latency = nil }, "timing scenario"},
		{"provisional without a reason", func(s *contract.Scenario) { s.TimingClaimReason = " " }, "needs a reason"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := abuse002(t)
			c.mutate(&s)
			err := s.Validate()
			if c.wantErr == "" && err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("Validate = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}
