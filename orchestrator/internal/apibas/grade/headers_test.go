package grade

import "testing"

// A response header that exposes a scenario's forbidden value is exploitation,
// even with no leaked protected value and no state change.
func TestForbiddenHeaderIsExploitation(t *testing.T) {
	out := Assess(Evidence{
		Baseline:           Exchange{Status: 200},
		Attack:             Exchange{Status: 200, ForbiddenHeaders: 1},
		CleanIsEnforcement: true,
	})
	if out.Result != FAIL || out.Exploitability != Exploited {
		t.Fatalf("got %s / %s, want FAIL / exploited", out.Result, out.Exploitability)
	}
}

// With no forbidden header, a clean 2xx on a clean-is-enforcement scenario passes.
func TestCleanHeadersPassWhenEnforced(t *testing.T) {
	out := Assess(Evidence{
		Baseline:           Exchange{Status: 200},
		Attack:             Exchange{Status: 200},
		CleanIsEnforcement: true,
	})
	if out.Result != PASS {
		t.Fatalf("got %s, want PASS", out.Result)
	}
}
