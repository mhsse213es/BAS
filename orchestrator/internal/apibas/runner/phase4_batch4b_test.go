package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 4 batch 4b: BIZ-012 (fraud control down, and the high-risk flow alerts). Expectations, written before the run:
//
//   BIZ-012  vulnerable FAIL/exploited (authorizes while the fraud check is down) with REL-009 detected.
//            fixed PASS/enforced (424, fails closed) with REL-009 not detected: no completion occurred to alert on.
//   control  no fault: the authorization completes in either build, and REL-009 stays silent. This is the negative
//            control for DET-006 (false positives): the rule must not alert on a healthy payment.

// TestPhase4_Batch4bFraudControlAlert runs BIZ-012 in both builds and the healthy-control negative case.
func TestPhase4_Batch4bFraudControlAlert(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 4 batch 4b run skipped in -short mode")
	}
	fx := fixtureFor(t, "orders-two-tenant")
	s := scenarioByID(t, "API-BAS-BIZ-012")

	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
		o := e.run(t, s, e.state).Outcome
		if mode == lab.ModeVulnerable {
			if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
				t.Errorf("BIZ-012 vulnerable: %s/%s (%s), want FAIL/exploited", o.Result, o.Exploitability, o.Reason)
			}
			if o.Detection != detect.Detected {
				t.Errorf("BIZ-012 vulnerable: REL-009 %q, want detected", o.Detection)
			}
		} else {
			if o.Result != grade.PASS || o.Control != grade.Enforced {
				t.Errorf("BIZ-012 fixed: %s/%s (%s), want PASS/enforced", o.Result, o.Control, o.Reason)
			}
			if o.Detection != detect.NotDetected {
				t.Errorf("BIZ-012 fixed: REL-009 %q, want not_detected (nothing completed)", o.Detection)
			}
		}
	}

	// Healthy control: the same authorization with no fault. It completes in both builds and must not alert.
	healthy := s
	healthy.Preconditions.LabFaults = nil
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newEnvFaults(t, mode, fx, nil)
		o := e.run(t, healthy, e.state).Outcome
		if o.Detection != detect.NotDetected {
			t.Errorf("healthy %s: REL-009 %q on a completed authorization with the fraud check up, want not_detected", modeName(mode), o.Detection)
		}
	}
}
