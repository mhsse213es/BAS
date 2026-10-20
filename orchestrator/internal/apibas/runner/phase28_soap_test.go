package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/protocol"
)

// Phase 28 SOAP acceptance. INJ-005 has a grader oracle: the internal record's protected values
// appear in the response when the external entity is resolved. The vulnerable build must FAIL
// exploited; the fixed build refuses the DOCTYPE and must PASS enforced.
func TestPhase28_SOAPINJ005VulnerableFailsFixedPasses(t *testing.T) {
	s := scenarioByID(t, "API-BAS-INJ-005")

	vuln := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rv := vuln.run(t, s, vuln.state)
	if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable INJ-005 = %s/%s, want FAIL/exploited (detail: %s)", rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
	}

	fixed := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rf := fixed.run(t, s, fixed.state)
	if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed INJ-005 = %s/%s, want PASS/enforced (detail: %s)", rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
	}
}

// Every SOAP step body in the catalog must pass the adapter, so a catalog entry cannot ship a body
// the adapter refuses.
func TestPhase28_SOAPCatalogBodiesValidate(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	a := protocol.SOAP{}
	n := 0
	for _, s := range all {
		if s.Protocol != "soap" {
			continue
		}
		for _, st := range s.Steps {
			n++
			if err := a.Validate(st.Body); err != nil {
				t.Fatalf("%s step %s body fails the adapter: %v", s.ID, st.ID, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("no soap steps found in the catalog")
	}
}
