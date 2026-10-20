package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/protocol"
)

// Phase 28 GraphQL acceptance. INJ-007 has a grader oracle (protected values in the response), so
// it must FAIL exploited in the vulnerable build and PASS enforced in the fixed build.
func TestPhase28_GraphQLINJ007VulnerableFailsFixedPasses(t *testing.T) {
	s := scenarioByID(t, "API-BAS-INJ-007")
	vuln := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rv := vuln.run(t, s, vuln.state)
	if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable INJ-007 = %s/%s, want FAIL/exploited (detail: %s)", rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
	}

	fixed := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rf := fixed.run(t, s, fixed.state)
	if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed INJ-007 = %s/%s, want PASS/enforced (detail: %s)", rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
	}
}

// ABUSE-004 has a depth limit in the fixed build, which refuses a deeper query with 400. The vulnerable
// build executes the deep query, and its items relation nests the response by the query's depth. The
// max_response_depth oracle grades that nesting as exploitation: FAIL exploited vulnerable, PASS
// enforced fixed.
func TestPhase28_GraphQLABUSE004VulnerableFailsFixedPasses(t *testing.T) {
	s := scenarioByID(t, "API-BAS-ABUSE-004")

	vuln := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rv := vuln.run(t, s, vuln.state)
	if rv.Outcome.Result != grade.FAIL || rv.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable ABUSE-004 = %s/%s, want FAIL/exploited (detail: %s)", rv.Outcome.Result, rv.Outcome.Exploitability, rv.Detail)
	}

	fixed := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rf := fixed.run(t, s, fixed.state)
	if rf.Outcome.Result != grade.PASS || rf.Outcome.Control != grade.Enforced {
		t.Fatalf("fixed ABUSE-004 = %s/%s, want PASS/enforced (detail: %s)", rf.Outcome.Result, rf.Outcome.Control, rf.Detail)
	}
}

// Every GraphQL step body in the catalog must pass the adapter's validation, so a catalog entry
// cannot ship a body the adapter would refuse.
func TestPhase28_GraphQLCatalogBodiesValidate(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	g := protocol.GraphQL{}
	n := 0
	for _, s := range all {
		if s.Protocol != "graphql" {
			continue
		}
		for _, st := range s.Steps {
			n++
			if err := g.Validate(st.Body); err != nil {
				t.Fatalf("%s step %s body fails the adapter: %v", s.ID, st.ID, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("no graphql steps found in the catalog")
	}
}
