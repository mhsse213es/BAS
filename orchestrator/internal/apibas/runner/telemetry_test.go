package runner_test

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Telemetry acceptance. AUTHZ-001 is detected by REL-004 when its events arrive. Each case below states its
// expected detection before the run, from what the SIEM is allowed to see:
//
//   - normal: every event is delivered, so the rule fires: detected.
//   - missing: the SIEM receives no events. Absence is not evidence, so the result is inconclusive, not
//     not_detected.
//   - delayed beyond the window: the events arrive after the SIEM stops listening, so the rule cannot see
//     them: inconclusive, never detected.
//   - delayed inside the window: the events arrive in time, so the rule fires: detected. The correlation holds
//     after the delay.
//
// The exploitability result must be the same in every case. Telemetry changes only the detection axis.
func TestPhase34_TelemetryStates(t *testing.T) {
	if testing.Short() {
		t.Skip("telemetry run skipped in -short mode")
	}
	s := scenarioByID(t, "API-BAS-AUTHZ-001")
	fx := fixture.OrdersTwoTenant()
	cases := []struct {
		name      string
		faults    []string
		window    time.Duration
		want      string
		reasonHas string
	}{
		{name: "normal", window: 0, want: detect.Detected},
		{name: "missing", faults: []string{"telemetry-missing"}, window: 0, want: detect.Inconclusive, reasonHas: "telemetry incomplete"},
		{name: "delayed-beyond-window", faults: []string{"telemetry-delayed"}, window: time.Second, want: detect.Inconclusive},
		{name: "delayed-inside-window", faults: []string{"telemetry-delayed"}, window: 6 * time.Second, want: detect.Detected},
	}
	var baseline *grade.Outcome
	for _, c := range cases {
		e := newEnvFaults(t, lab.ModeVulnerable, fx, c.faults)
		e.window = c.window
		rep := e.run(t, s, e.state)
		if rep.Outcome.Detection != c.want {
			t.Errorf("%s: detection = %q, want %q (reason %q)", c.name, rep.Outcome.Detection, c.want, rep.DetectionReason)
		}
		if c.reasonHas != "" && !strings.Contains(rep.DetectionReason, c.reasonHas) {
			t.Errorf("%s: reason %q does not contain %q", c.name, rep.DetectionReason, c.reasonHas)
		}
		if c.want == detect.NotDetected {
			t.Errorf("%s: a telemetry gap must never grade not_detected", c.name)
		}
		if baseline == nil {
			o := rep.Outcome
			baseline = &o
		} else if rep.Outcome.Result != baseline.Result || rep.Outcome.Exploitability != baseline.Exploitability {
			t.Errorf("%s: exploitability %s/%s changed from %s/%s; telemetry must not change it",
				c.name, rep.Outcome.Result, rep.Outcome.Exploitability, baseline.Result, baseline.Exploitability)
		}
	}
}
