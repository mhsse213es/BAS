package runner_test

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/protocol"
)

// Phase 28 async acceptance.
//
// ABUSE-010 has a grader oracle: accepted publishes beyond the declared limit (max_accepted_attempts 5).
// The vulnerable build accepts all ten and must FAIL exploited; the fixed build accepts five and refuses
// the rest with 429, and must PASS enforced.
func TestPhase28_AsyncABUSE010VulnerableFailsFixedPasses(t *testing.T) {
	s := scenarioByID(t, "API-BAS-ABUSE-010")

	vuln := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rv := vuln.run(t, s, vuln.state)
	if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable ABUSE-010 = %s/%s, want FAIL/exploited (detail: %s)", rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
	}

	fixed := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rf := fixed.run(t, s, fixed.state)
	if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed ABUSE-010 = %s/%s, want PASS/enforced (detail: %s)", rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
	}
}

// INTEG-010 has a state oracle: the attack resends the created event's signature over a cancelled
// event for the same order. The vulnerable consumer processes it and the order's status changes:
// FAIL exploited. The fixed consumer verifies the signature, refuses with 403, and nothing changes:
// PASS enforced.
func TestPhase28_AsyncINTEG010VulnerableFailsFixedPasses(t *testing.T) {
	s := scenarioByID(t, "API-BAS-INTEG-010")

	vuln := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rv := vuln.run(t, s, vuln.state)
	if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable INTEG-010 = %s/%s, want FAIL/exploited (detail: %s)", rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
	}

	fixed := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rf := fixed.run(t, s, fixed.state)
	if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed INTEG-010 = %s/%s, want PASS/enforced (detail: %s)", rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
	}
}

// Every async step in the catalog must have a publish path, a JSON event body, and, where it signs
// the event, a well-formed signature header.
func TestPhase28_AsyncCatalogStepsValidate(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	a := protocol.Async{}
	n := 0
	for _, s := range all {
		if s.Protocol != "async" {
			continue
		}
		for _, st := range s.Steps {
			n++
			if err := protocol.ValidatePublishPath(st.Path); err != nil {
				t.Fatalf("%s step %s: %v", s.ID, st.ID, err)
			}
			// The runner substitutes {n} with the attempt number; validate the body as it is sent.
			body := strings.ReplaceAll(st.Body, "{n}", "1")
			if err := a.Validate(body); err != nil {
				t.Fatalf("%s step %s body: %v", s.ID, st.ID, err)
			}
			if sig, ok := st.Headers["X-Event-Signature"]; ok {
				if err := protocol.ValidateSignatureHeader(sig); err != nil {
					t.Fatalf("%s step %s: %v", s.ID, st.ID, err)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no async steps found in the catalog")
	}
}
