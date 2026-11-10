package contract

import (
	"strings"
	"testing"
)

// gqlScenario builds a read-only scenario whose steps are GraphQL POSTs with the given body, optionally marked graphql_query.
func gqlScenario(body string, mark bool, method string) Scenario {
	step := func(id, role string) Step {
		return Step{ID: id, Role: role, Identity: "alice", Auth: "valid", Method: method, Path: "/graphql", Body: body, GraphQLQuery: mark, Hypothesis: "h"}
	}
	return Scenario{
		ID: "API-BAS-AUTHZ-901", Name: "n", Category: "AUTHZ", Claim: "cross_identity", AttackObjective: "o",
		ThreatModel:     ThreatModel{Attacker: "a", Identity: "alice", AccessLevel: "l", Objective: "o"},
		Preconditions:   Preconditions{Fixture: "f", Identities: []string{"alice"}, Object: "bound-901"},
		Steps:           []Step{step("b", "baseline"), step("a", "attack")},
		CleanIsEnforced: true, ForbiddenValues: []string{"secret-value"},
		ExpectedControl: "e", GroundTruth: GroundTruth{Adapters: []string{"state", "response"}, Check: "c"},
		DetectionAssert: DetectionAssertion{Status: "not_evaluated", Reason: "r"},
		SideEffectClass: "READ_ONLY",
	}
}

func TestGraphQLQueryStepIsReadOnlyOnlyWhenTheBodyProvesIt(t *testing.T) {
	ok := `{"query":"query { order(id: \"A1\") { id } }"}`
	if err := gqlScenario(ok, true, "POST").Validate(); err != nil {
		t.Fatalf("a read-only GraphQL query was refused: %v", err)
	}
	// Without the mark a POST is a mutating step, as before.
	if err := gqlScenario(ok, false, "POST").Validate(); err == nil || !strings.Contains(err.Error(), "mutating") {
		t.Errorf("an unmarked POST: %v, want the mutating-step refusal", err)
	}
	bad := map[string]struct{ body, method, want string }{
		"mutation":                {`{"query":"mutation { setStatus(id: \"A1\") { id } }"}`, "POST", "start with the query keyword"},
		"mutation after query":    {`{"query":"query { a } mutation { b }"}`, "POST", "mutation or subscription"},
		"subscription":            {`{"query":"query { a } subscription { b }"}`, "POST", "mutation or subscription"},
		"anonymous mutation":      {`{"query":"{ a }"}`, "POST", "start with the query keyword"},
		"queryish word":           {`{"query":"queryMutationX { a }"}`, "POST", "start with the query keyword"},
		"extra key":               {`{"query":"query { a }","operationName":"x"}`, "POST", "only key is"},
		"variables key":           {`{"query":"query { a }","variables":{}}`, "POST", "only key is"},
		"not JSON":                {`query { a }`, "POST", "not a JSON object"},
		"query not a string":      {`{"query":5}`, "POST", "only key is"},
		"empty body":              {``, "POST", "needs a body"},
		"wrong method":            {ok, "PATCH", "is not a POST"},
		"case change is not fine": {`{"query":"Query { a }"}`, "POST", "start with the query keyword"},
	}
	for name, c := range bad {
		err := gqlScenario(c.body, true, c.method).Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error mentioning %q", name, err, c.want)
		}
	}
	// The query forms that are allowed.
	for _, q := range []string{`{"query":"query{a}"}`, `{"query":"query(){a}"}`, `{"query":"  query { a }  "}`} {
		if err := gqlScenario(q, true, "POST").Validate(); err != nil {
			t.Errorf("%s was refused: %v", q, err)
		}
	}
}

func TestRequireBaselineEvidenceNeedsValuesToLookFor(t *testing.T) {
	ok := `{"query":"query { a }"}`
	s := gqlScenario(ok, true, "POST")
	s.RequireBaselineEvidence = true
	if err := s.Validate(); err != nil {
		t.Fatalf("with values: %v", err)
	}
	s.ForbiddenValues = nil
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "require_baseline_evidence") {
		t.Errorf("without values: %v, want the requirement refused", err)
	}
}
