package grade

import "testing"

// Accepted attempts above the tolerated maximum are exploitation.
func TestAcceptedAttemptsOverLimitAreExploitation(t *testing.T) {
	out := Assess(Evidence{
		Baseline:    Exchange{Status: 200},
		Attack:      Exchange{Status: 401, Accepted: 5},
		MaxAccepted: 3,
		Denied:      []int{429},
	})
	if out.Result != FAIL || out.Exploitability != Exploited {
		t.Fatalf("got %s / %s, want FAIL / exploited", out.Result, out.Exploitability)
	}
}

// Within the limit, a final denial passes.
func TestAcceptedAttemptsWithinLimitPass(t *testing.T) {
	out := Assess(Evidence{
		Baseline:    Exchange{Status: 200},
		Attack:      Exchange{Status: 429, Accepted: 3},
		MaxAccepted: 3,
		Denied:      []int{429},
	})
	if out.Result != PASS {
		t.Fatalf("got %s, want PASS", out.Result)
	}
}
