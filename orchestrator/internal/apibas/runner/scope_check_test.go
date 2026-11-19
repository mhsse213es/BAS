package runner

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

func scenarioWithPaths(paths ...string) contract.Scenario {
	s := contract.Scenario{ID: "API-BAS-TEST-001"}
	for i, p := range paths {
		s.Steps = append(s.Steps, contract.Step{ID: string(rune('a' + i)), Method: "GET", Path: p})
	}
	return s
}

func TestCheckScope(t *testing.T) {
	allowed := []string{"/api/orders"}
	cases := []struct {
		name  string
		paths []string
		ok    bool
	}{
		{"object under prefix", []string{"/api/orders/{object}"}, true},
		{"several steps inside", []string{"/api/orders/{object}", "/api/orders"}, true},
		{"one step outside", []string{"/api/orders/{object}", "/api/customers/{object}"}, false},
		{"sibling sharing a string prefix", []string{"/api/orders-admin/{object}"}, false},
		{"path starts with a placeholder", []string{"{object}"}, false},
		{"placeholder at the root", []string{"/{object}"}, false},
		{"traversal", []string{"/api/orders/../admin"}, false},
		{"absolute URL", []string{"http://evil.example/x"}, false},
		{"authority smuggling", []string{"@evil.example/x"}, false},
	}
	for _, c := range cases {
		err := CheckScope(allowed, scenarioWithPaths(c.paths...))
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	if err := CheckScope(nil, scenarioWithPaths("/anything")); err != nil {
		t.Errorf("no scope configured but scenario refused: %v", err)
	}
}

// The send-time backstop refuses a path outside scope without touching the network.
func TestDoRefusesOutOfScopePath(t *testing.T) {
	r := &Runner{cfg: Config{BaseURL: "http://127.0.0.1:1", AllowedPaths: []string{"/api/orders"}}}
	ex, transport := r.do(t.Context(), contract.Step{ID: "s", Method: "GET", Path: "/api/customers/1"}, "", fixture.Object{ID: "ORD-1"}, nil)
	if !transport || ex.Status != 0 {
		t.Fatalf("out-of-scope request: transport=%v status=%d, want refused before sending", transport, ex.Status)
	}
}
