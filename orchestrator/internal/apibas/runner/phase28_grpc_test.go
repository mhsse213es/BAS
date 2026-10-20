package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/protocol"
)

// Phase 28 gRPC acceptance (JSON transcoding form). DISC-009 has a grader oracle: another customer's
// protected values appear in the response. The vulnerable build must FAIL exploited; the fixed build
// returns PERMISSION_DENIED (403) to the non-owner and must PASS enforced.
func TestPhase28_GRPCDISC009VulnerableFailsFixedPasses(t *testing.T) {
	s := scenarioByID(t, "API-BAS-DISC-009")

	vuln := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rv := vuln.run(t, s, vuln.state)
	if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable DISC-009 = %s/%s, want FAIL/exploited (detail: %s)", rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
	}

	fixed := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rf := fixed.run(t, s, fixed.state)
	if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed DISC-009 = %s/%s, want PASS/enforced (detail: %s)", rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
	}
}

// Every gRPC step in the catalog must have a fully qualified method path and a JSON object body.
func TestPhase28_GRPCCatalogStepsValidate(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	g := protocol.GRPC{}
	n := 0
	for _, s := range all {
		if s.Protocol != "grpc" {
			continue
		}
		for _, st := range s.Steps {
			n++
			if err := protocol.ValidateMethodPath(st.Path); err != nil {
				t.Fatalf("%s step %s: %v", s.ID, st.ID, err)
			}
			if err := g.Validate(st.Body); err != nil {
				t.Fatalf("%s step %s body: %v", s.ID, st.ID, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("no grpc steps found in the catalog")
	}
}
