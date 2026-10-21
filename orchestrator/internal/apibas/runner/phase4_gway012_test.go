package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/lab"
)

// GWAY-012 is graded on the TLS environment, because the attack fetches an upstream whose certificate the runner does not
// trust. The vulnerable build relays that content; REL-017 fires on the relay. The fixed build refuses the fetch, and a
// refused fetch relays nothing, so REL-017 does not fire. The detection table has no TLS harness, so it skips this id.
func TestPhase4_GWAY012UpstreamDetection(t *testing.T) {
	s := tlsScenario(t, "API-BAS-GWAY-012")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		want := detect.NotDetected
		if mode == lab.ModeVulnerable {
			want = detect.Detected
		}
		for pass := 0; pass < 2; pass++ { // repeatability, as the detection table requires
			rep := newTLSEnv(t, mode, fx, true, true).run(t, s)
			if got := rep.Outcome.Detection; got != want {
				t.Errorf("%s pass %d: GWAY-012 detection = %q, want %q (result %s, %s)",
					modeName(mode), pass, got, want, rep.Outcome.Result, rep.DetectionReason)
			}
		}
	}
}
