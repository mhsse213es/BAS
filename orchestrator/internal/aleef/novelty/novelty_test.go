package novelty

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/contract"
)

func scen(id, name, claim string, steps ...contract.Step) contract.Scenario {
	return contract.Scenario{ID: id, Name: name, Claim: claim, Steps: steps}
}

func st(method, path string) contract.Step { return contract.Step{Method: method, Path: path} }

func TestNoveltyMarksCatalogueOverlap(t *testing.T) {
	cat := []contract.Scenario{
		scen("API-BAS-AUTHZ-001", "c1", "cross_identity", st("GET", "/orders/{id}"), st("GET", "/orders/2")),
		scen("API-BAS-BIZ-001", "c2", "function_level", st("POST", "/admin/reports")),
	}
	cases := []struct {
		name string
		s    contract.Scenario
		want bool
	}{
		{"same claim, id shape matches", scen("X", "n", "cross_identity", st("GET", "/items/1"), st("GET", "/orders/{object}")), true},
		{"uuid segment", scen("X", "n", "cross_identity", st("GET", "/orders/3f2b8c1e-1111-4222-8333-444455556666")), true},
		{"query string ignored", scen("X", "n", "cross_identity", st("GET", "/orders/42?x=1")), true},
		{"case ignored", scen("X", "n", "cross_identity", st("get", "/ORDERS/9")), true},
		{"different method", scen("X", "n", "cross_identity", st("DELETE", "/orders/9")), false},
		{"different path shape", scen("X", "n", "cross_identity", st("GET", "/orders/9/lines")), false},
		{"different property class", scen("X", "n", "function_level", st("GET", "/orders/9")), false},
		{"empty catalogue entry shape", scen("X", "n", "function_level", st("POST", "/admin/reports")), true},
		{"no steps", scen("X", "n", "cross_identity"), false},
	}
	for _, c := range cases {
		if got := Covered(c.s, cat); got != c.want {
			t.Errorf("%s: Covered = %v, want %v", c.name, got, c.want)
		}
	}
	if Covered(scen("X", "n", "cross_identity", st("GET", "/orders/9")), nil) {
		t.Error("empty catalogue covers nothing")
	}
}

func TestNoveltyIgnoresIDAndName(t *testing.T) {
	cat := []contract.Scenario{scen("API-BAS-AUTHZ-001", "Catalogue name", "cross_identity", st("GET", "/orders/{id}"))}
	a := scen("ALEEF-GEN-P-OWN-1-00000000", "Totally different", "cross_identity", st("GET", "/orders/7"))
	b := scen("API-BAS-AUTHZ-001", "Catalogue name", "cross_identity", st("GET", "/other/7"))
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
