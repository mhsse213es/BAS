package grade

import "testing"

// A forbidden value found in an attack response is an exposure: FAIL, exploited, whatever the status.
func TestForbiddenHit_FailsExploited(t *testing.T) {
	o := Assess(Evidence{
		Baseline: Exchange{Status: 200},
		Attack:   Exchange{Status: 200, ForbiddenValues: 1},
		Denied:   []int{403},
	})
	if o.Result != FAIL || o.Exploitability != Exploited {
		t.Fatalf("forbidden hit: %s/%s, want FAIL/exploited", o.Result, o.Exploitability)
	}
}

// An attack response that cannot be fully searched never passes, even with a denied status.
func TestUninspectableResponse_NeverPasses(t *testing.T) {
	o := Assess(Evidence{
		Baseline: Exchange{Status: 200},
		Attack:   Exchange{Status: 403, Uninspectable: 1},
		Denied:   []int{403},
	})
	if o.Result == PASS {
		t.Fatalf("uninspectable response passed: %s/%s", o.Result, o.Control)
	}
	if o.Result != SKIPPED || o.Reason != ReasonEvidenceInconclusive {
		t.Fatalf("uninspectable response: %s (%s), want SKIPPED %s", o.Result, o.Reason, ReasonEvidenceInconclusive)
	}
}

// A confirmed exposure outranks an uninspectable response from another attempt.
func TestForbiddenHit_OutranksUninspectable(t *testing.T) {
	o := Assess(Evidence{
		Baseline: Exchange{Status: 200},
		Attack:   Exchange{Status: 200, ForbiddenValues: 1, Uninspectable: 1},
		Denied:   []int{403},
	})
	if o.Result != FAIL {
		t.Fatalf("hit with an uninspectable attempt: %s, want FAIL", o.Result)
	}
}

// With no forbidden values and an inspectable response, the verdict is unchanged: a denied status passes.
func TestNoForbiddenHit_DeniedStillPasses(t *testing.T) {
	o := Assess(Evidence{
		Baseline: Exchange{Status: 200},
		Attack:   Exchange{Status: 403},
		Denied:   []int{403},
	})
	if o.Result != PASS || o.Control != Enforced {
		t.Fatalf("denied, inspectable: %s/%s, want PASS/enforced", o.Result, o.Control)
	}
}
