package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/lab"
)

// AUTHN-007 is graded on the TLS environment. The attacker presents a self-signed certificate that names the owner. The
// vulnerable build trusts the name, so the access is recorded under an identity no certificate chain proves, and REL-013
// fires. The fixed build refuses a certificate that does not chain to the lab CA, so nothing is accepted and REL-013 does
// not fire.
func TestPhase4_AUTHN007ForgedCertificateDetection(t *testing.T) {
	s := tlsScenario(t, "API-BAS-AUTHN-007")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		want := detect.NotDetected
		if mode == lab.ModeVulnerable {
			want = detect.Detected
		}
		for pass := 0; pass < 2; pass++ {
			rep := newTLSEnv(t, mode, fx, true, true).run(t, s)
			if got := rep.Outcome.Detection; got != want {
				t.Errorf("%s pass %d: AUTHN-007 detection = %q, want %q (result %s, %s)",
					modeName(mode), pass, got, want, rep.Outcome.Result, rep.DetectionReason)
			}
		}
	}
}
