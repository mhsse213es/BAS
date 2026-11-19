package novelty

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
)

func st(identity, method, path string) contract.Step {
	return contract.Step{Identity: identity, Method: method, Path: path}
}

func scen(id, name, claim string, steps ...contract.Step) contract.Scenario {
	return contract.Scenario{ID: id, Name: name, Claim: claim, Steps: steps}
}

// plainBOLA has the shape of API-BAS-AUTHZ-001.
func plainBOLA() contract.Scenario {
	return scen("API-BAS-AUTHZ-001", "BOLA", "cross_identity",
		st("customer-b", "GET", "/api/orders/{object}"), st("customer-a", "GET", "/api/orders/{object}"))
}

// repeatedCredit has the shape of API-BAS-BIZ-003.
func repeatedCredit() contract.Scenario {
	atk := st("customer-b", "POST", "/api/biz/orders/{object}/credit")
	atk.Repeat = 2
	s := scen("API-BAS-BIZ-003", "credit", "function_level", st("customer-b", "GET", "/api/orders/{object}"), atk)
	s.MaxAcceptedAttempts = 1
	return s
}

// coActorFlow has the shape of API-BAS-DET-004.
func coActorFlow() contract.Scenario {
	co := st("customer-b", "GET", "/api/orders/ORD-1001")
	co.CoActor = true
	return scen("API-BAS-DET-004", "flow", "cross_identity",
		st("customer-b", "GET", "/api/orders/{object}"), co, st("customer-a", "GET", "/api/orders/{object}"))
}

func TestNoveltyMarksCatalogueOverlap(t *testing.T) {
	cat := []contract.Scenario{plainBOLA(), repeatedCredit()}
	gen := func(mut func(*contract.Scenario)) contract.Scenario {
		s := scen("ALEEF-GEN-P-OWN-1-00000000", "x", "cross_identity",
			st("alice", "get", "/API/orders/42?x=1"), st("bob", "GET", "/api/orders/{object}"))
		if mut != nil {
			mut(&s)
		}
		return s
	}
	last := func(s *contract.Scenario) *contract.Step { return &s.Steps[len(s.Steps)-1] }
	cases := []struct {
		name string
		s    contract.Scenario
		want bool
	}{
		{"plain cross-identity read", gen(nil), true},
		{"same shape, repeated", gen(func(s *contract.Scenario) { last(s).Repeat = 3; s.MaxAcceptedAttempts = 1 }), false},
		{"different method", gen(func(s *contract.Scenario) { last(s).Method = "DELETE" }), false},
		{"different path", gen(func(s *contract.Scenario) { last(s).Path = "/api/orders/{object}/lines" }), false},
		{"different claim", gen(func(s *contract.Scenario) { s.Claim = "property_level" }), false},
		{"same actor", gen(func(s *contract.Scenario) { last(s).Identity = "alice" }), false},
		{"no credential", gen(func(s *contract.Scenario) { last(s).Auth = "none" }), false},
		{"forged credential", gen(func(s *contract.Scenario) { last(s).Auth = "alg_none" }), false},
		{"parallel", gen(func(s *contract.Scenario) { last(s).Repeat = 3; last(s).Parallel = true }), false},
		{"unrelated app", scen("X", "n", "cross_identity", st("a", "GET", "/v9/widgets/{x}"), st("b", "GET", "/v9/widgets/{x}")), false},
		{"no steps", scen("X", "n", "cross_identity"), false},
	}
	for _, c := range cases {
		if got := Covered(c.s, cat); got != c.want {
			t.Errorf("%s: Covered = %v, want %v (%s)", c.name, got, c.want, Features(c.s))
		}
	}
	if Covered(gen(nil), nil) {
		t.Error("empty catalogue covers nothing")
	}
}

func TestNoveltyRepeatedPostCoveredOnlyWithSameFeatures(t *testing.T) {
	cat := []contract.Scenario{repeatedCredit()}
	same := repeatedCredit()
	same.ID = "ALEEF-GEN-P-RACE-1-00000000"
	if !Covered(same, cat) {
		t.Error("same repeated POST features must be covered")
	}
	once := repeatedCredit()
	once.Steps[1].Repeat = 0
	once.MaxAcceptedAttempts = 0
	if Covered(once, cat) {
		t.Error("a single POST on the same path is not what the catalogue repeats")
	}
	par := repeatedCredit()
	par.Steps[1].Repeat, par.Steps[1].Parallel = 4, true
	if Covered(par, cat) {
		t.Error("a parallel variant is not covered by a sequential repeat")
	}
}

func TestNoveltyCoActorFlowNotCoveredByPlainRead(t *testing.T) {
	if Covered(coActorFlow(), []contract.Scenario{plainBOLA()}) {
		t.Error("a co-actor flow must not be covered by a plain BOLA read")
	}
	if Covered(plainBOLA(), []contract.Scenario{coActorFlow()}) {
		t.Error("a plain read must not be covered by a co-actor flow")
	}
	if !Covered(coActorFlow(), []contract.Scenario{coActorFlow()}) {
		t.Error("an identical flow is covered")
	}
}

func TestNoveltyAgainstRealCatalogue(t *testing.T) {
	cat, err := catalog.All()
	if err != nil {
		t.Fatal(err)
	}
	if !Covered(plainBOLA(), cat) {
		t.Error("the plain orders BOLA read must be covered by the catalogue")
	}
	other := scen("X", "n", "cross_identity", st("a", "GET", "/v9/widgets/{x}"), st("b", "GET", "/v9/widgets/{x}"))
	if Covered(other, cat) {
		t.Error("an unrelated app is not covered")
	}
}

func TestNoveltyIgnoresIDAndName(t *testing.T) {
	cat := []contract.Scenario{plainBOLA()}
	a := plainBOLA()
	a.ID, a.Name = "ALEEF-GEN-P-OWN-1-00000000", "Totally different"
	b := plainBOLA()
	b.Steps[1].Path = "/other/7"
	if !Covered(a, cat) {
		t.Error("different id and name must still be covered")
	}
	if Covered(b, cat) {
		t.Error("same id and name but different shape must not be covered")
	}
}

func TestShape(t *testing.T) {
	for in, want := range map[string]string{
		"/a/{id}/b":    "/a/{id}/b",
		"/A/{object}":  "/a/{id}",
		"/a/123/b?q=1": "/a/{id}/b",
		"/a/3F2B8C1E-1111-4222-8333-444455556666": "/a/{id}",
		"/a/item-1": "/a/item-1",
		"a/b/":      "/a/b",
	} {
		if got := Shape(in); got != want {
			t.Errorf("Shape(%q) = %q, want %q", in, got, want)
		}
	}
}
