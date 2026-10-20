package runner_test

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

// API-BAS-DET-009: detection holds when telemetry is delayed or partly missing (blueprint DET-009).
// Each configuration's expected detection is written before the run, from the lab's hold and the runner's
// window:
//
//   - declared (telemetry-delayed, default window): the events arrive 3s late and the window is 2s, so the
//     rule cannot see the attack in time. Expected: inconclusive. Not not_detected, and not a pass.
//   - telemetry-delayed, window 6s: the window covers the hold. Expected: detected.
//   - telemetry-missing (with the required delay fault also active), default window: no events arrive.
//     Expected: inconclusive (absence is not evidence). The scenario needs telemetry-delayed to run, so the
//     missing fault is added to it rather than replacing it.
//   - no telemetry-delayed fault: the scenario cannot run, because its precondition is absent. Expected: the run
//     is SKIPPED and detection is not_evaluated. It must never grade not_detected.
//
// The exploitability verdict is the same in every configuration. Telemetry changes only the detection axis.
// The declared configuration is the scenario as catalogued. The fixture does not meet the blueprint's
// requirement at the default window; that is recorded as a gap, not hidden.
func TestDET009DetectionUnderTelemetryStates(t *testing.T) {
	if testing.Short() {
		t.Skip("DET-009 run skipped in -short mode")
	}
	s := scenarioByID(t, "API-BAS-DET-009")
	fx := fixture.OrdersTwoTenant()

	cases := []struct {
		name   string
		faults []string
		window time.Duration
		want   string
		reason string
	}{
		{name: "declared-delayed-default-window", faults: s.Preconditions.LabFaults, window: 0, want: detect.Inconclusive, reason: "telemetry incomplete"},
		{name: "delayed-window-covers-hold", faults: s.Preconditions.LabFaults, window: 6 * time.Second, want: detect.Detected},
		{name: "missing-default-window", faults: []string{"telemetry-delayed", "telemetry-missing"}, window: 0, want: detect.Inconclusive, reason: "telemetry incomplete"},
		{name: "no-delay-fault-skipped", faults: nil, window: 0, want: detect.NotEvaluated, reason: "run did not execute"},
	}

	// The window the test uses for the declared case must be the runner's default, or the expectation above is
	// not the one the runner applies.
	if runner.DefaultDetectionWindow != 2*time.Second {
		t.Fatalf("runner default window is %s; the DET-009 expectations assume 2s", runner.DefaultDetectionWindow)
	}

	var exploit *grade.Outcome
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		for _, c := range cases {
			e := newEnvFaults(t, mode, fx, c.faults)
			e.window = c.window
			rep := e.run(t, s, e.state)
			if rep.Outcome.Detection != c.want {
				t.Errorf("%s %s: detection = %q, want %q (reason %q)", modeName(mode), c.name, rep.Outcome.Detection, c.want, rep.DetectionReason)
			}
			if c.reason != "" && !strings.Contains(rep.DetectionReason, c.reason) {
				t.Errorf("%s %s: reason %q does not contain %q", modeName(mode), c.name, rep.DetectionReason, c.reason)
			}
			if c.want == detect.NotDetected {
				t.Errorf("%s %s: a telemetry gap must never grade not_detected", modeName(mode), c.name)
			}
			if c.name == "no-delay-fault-skipped" && rep.Outcome.Result != grade.SKIPPED {
				t.Errorf("%s %s: result = %s, want SKIPPED (precondition)", modeName(mode), c.name, rep.Outcome.Result)
			}
			if mode == lab.ModeVulnerable && c.name == "declared-delayed-default-window" {
				if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
					t.Errorf("declared DET-009 vulnerable = %s/%s, want FAIL/exploited", rep.Outcome.Result, rep.Outcome.Exploitability)
				}
			}
			if mode == lab.ModeFixed && c.name == "declared-delayed-default-window" {
				if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
					t.Errorf("declared DET-009 fixed = %s/%s, want PASS/enforced", rep.Outcome.Result, rep.Outcome.Control)
				}
			}
			if mode == lab.ModeVulnerable && exploit == nil {
				o := rep.Outcome
				exploit = &o
			}
		}
	}
	if exploit == nil {
		t.Fatal("no vulnerable exploit verdict recorded")
	}
}
