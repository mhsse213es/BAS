package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 4 batch 4a: DET-002 (repeated failures are logged and alerted), DET-005 (alert routed to the declared source),
// DET-007 (events attribute activity to the verified identity). Expectations, written before the run:
//
//   DET-002  vulnerable FAIL/exploited (accepts the revoked credential) with REL-001 not_detected: no failures are logged.
//            fixed PASS/enforced with REL-001 detected.
//   DET-005  vulnerable FAIL/exploited, fixed PASS. The detection provenance is the Elastic fixture label. REL-004 detected.
//   DET-007  vulnerable FAIL/exploited, fixed PASS. REL-004 detected in the fixed build and not detected in the vulnerable
//            build, where the forged header makes the request look like the owner's (the documented blind spot).

// TestPhase4_Batch4aDetectionAndVerdicts runs the batch 4a scenarios in both builds.
func TestPhase4_Batch4aDetectionAndVerdicts(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 4 batch 4a run skipped in -short mode")
	}
	fx := fixtureFor(t, "orders-two-tenant")

	// DET-002: the vulnerable build accepts a revoked credential, so it logs no failure and REL-001 does not fire.
	// The fixed build refuses it three times and REL-001 fires.
	s := scenarioByID(t, "API-BAS-DET-002")
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
		rep := e.run(t, s, e.state)
		o := rep.Outcome
		if mode == lab.ModeVulnerable {
			if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
				t.Errorf("DET-002 vulnerable: %s/%s (%s), want FAIL/exploited", o.Result, o.Exploitability, o.Reason)
			}
			if o.Detection != detect.NotDetected {
				t.Errorf("DET-002 vulnerable: REL-001 %q, want not_detected (no failures were logged)", o.Detection)
			}
		} else {
			if o.Result != grade.PASS || o.Control != grade.Enforced {
				t.Errorf("DET-002 fixed: %s/%s (%s), want PASS/enforced", o.Result, o.Control, o.Reason)
			}
			if o.Detection != detect.Detected {
				t.Errorf("DET-002 fixed: REL-001 %q, want detected", o.Detection)
			}
		}
	}

	// DET-005 and DET-007: the object-ownership attack, with detection graded in each build.
	for _, id := range []string{"API-BAS-DET-005", "API-BAS-DET-007"} {
		s := scenarioByID(t, id)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
			rep := e.run(t, s, e.state)
			o := rep.Outcome
			if mode == lab.ModeVulnerable {
				if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
					t.Errorf("%s vulnerable: %s/%s (%s), want FAIL/exploited", id, o.Result, o.Exploitability, o.Reason)
				}
			} else if o.Result != grade.PASS || o.Control != grade.Enforced {
				t.Errorf("%s fixed: %s/%s (%s), want PASS/enforced", id, o.Result, o.Control, o.Reason)
			}
			if id == "API-BAS-DET-005" && rep.DetectionProvenance != detect.Provenance {
				t.Errorf("DET-005 %s: provenance %q, want the Elastic fixture label", modeName(mode), rep.DetectionProvenance)
			}
			want := detect.Detected
			if id == "API-BAS-DET-007" && mode == lab.ModeVulnerable {
				want = detect.NotDetected // the forged header attributes the request to the owner; the documented blind spot
			}
			if o.Detection != want {
				t.Errorf("%s %s: REL-004 detection %q, want %q", id, modeName(mode), o.Detection, want)
			}
		}
	}
}
