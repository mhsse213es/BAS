package runner_test

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

// The same ABUSE-001 run, graded through the Sentinel fixture instead of the Elastic
// one. Both sources read the same lab events, so the verdicts must agree.
func TestPhase17_SentinelGradesTheSameRunAsElastic(t *testing.T) {
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newEnv(t, mode, fixture.OrdersTwoTenant())
		base := scenarioByID(t, "API-BAS-ABUSE-001")
		sentinel := base
		sentinel.Detection = &contract.DetectionPolicy{
			Source:      detect.SourceSentinel,
			ExpectRule:  base.Detection.ExpectRule,
			MinSeverity: base.Detection.MinSeverity,
		}
		rep := e.run(t, sentinel, e.state)
		if rep.Outcome.Detection != "detected" {
			t.Errorf("%s sentinel detection = %q, want detected", mode, rep.Outcome.Detection)
		}
		if !strings.HasPrefix(rep.DetectionProvenance, "fixture-validated: microsoft-sentinel") {
			t.Errorf("%s provenance = %q, want the Sentinel fixture label", mode, rep.DetectionProvenance)
		}
	}
}

// The Sentinel source is accepted by the contract, and any other source is refused.
func TestPhase17_ContractAcceptsSentinelOnly(t *testing.T) {
	base := scenarioByID(t, "API-BAS-ABUSE-001")
	ok := base
	ok.Detection = &contract.DetectionPolicy{Source: detect.SourceSentinel, ExpectRule: "APIBAS-REL-001", MinSeverity: "high"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("sentinel source refused: %v", err)
	}
	bad := base
	bad.Detection = &contract.DetectionPolicy{Source: "splunk", ExpectRule: "APIBAS-REL-001", MinSeverity: "high"}
	if err := bad.Validate(); err == nil {
		t.Fatal("unsupported source accepted")
	}
}
