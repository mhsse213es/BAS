package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// AUTHZ-007 regression. The bulk body names ORD-1001 (owned by the attacker, cust-a) before ORD-2001 (owned
// by cust-b). Expectations are written from REL-004's definition before the run:
//
//   - extraction off: the body is not read, so no object is named in the path or query. REL-004 is not_detected.
//   - extraction on: the body names a foreign object (ORD-2001), so REL-004 is detected. The access event must
//     carry every named owner, not only the first. Before the multiple-owner contract this was the recorded
//     gap: the event kept cust-a alone and the foreign object was dropped.
//
// Exploitability is checked alongside, so detection never changes the exploit verdict.
func TestPhase35_AUTHZ007DetectionBothConfigurations(t *testing.T) {
	if testing.Short() {
		t.Skip("detection run skipped in -short mode")
	}
	s := scenarioByID(t, "API-BAS-AUTHZ-007")
	fx := fixture.OrdersTwoTenant()
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		var exploit *grade.Outcome
		for _, c := range []struct {
			extract bool
			want    string
		}{{false, detect.NotDetected}, {true, detect.Detected}} {
			e := newEnvWith(t, mode, fx, s.Preconditions.LabFaults, c.extract)
			rep := e.run(t, s, e.state)
			if rep.Outcome.Detection != c.want {
				t.Errorf("%s extract=%t: detection = %q, want %q (reason %q)",
					modeName(mode), c.extract, rep.Outcome.Detection, c.want, rep.DetectionReason)
			}
			if exploit == nil {
				o := rep.Outcome
				exploit = &o
			} else if rep.Outcome.Result != exploit.Result || rep.Outcome.Exploitability != exploit.Exploitability {
				t.Errorf("%s extract=%t: exploitability %s/%s changed from %s/%s",
					modeName(mode), c.extract, rep.Outcome.Result, rep.Outcome.Exploitability, exploit.Result, exploit.Exploitability)
			}
		}
	}
}
