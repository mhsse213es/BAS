package runner_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

// forgedIdentityHeaders are the request headers the vulnerable build trusts as the caller's identity
// (LAB-AUTHN-IDHDR-001 and LAB-GWAY-IDTRUST-001). The access log records the identity the product
// accepted, so a forged header makes the event look like the claimed identity's own access.
var forgedIdentityHeaders = []string{"X-Customer-Id", "X-Gateway-Identity"}

// Phase 34: detection is graded separately from exploitability. A scenario whose rule is
// APIBAS-REL-004 (access to an object owned by another identity) must get the result the fixture's
// ownership predicts, in each build. The expectation is computed before the run:
//
//   - the attacker is the identity the product accepted. In the vulnerable build a forged identity
//     header is accepted, so the attacker looks like the claimed identity;
//   - detected when the request names an object (in its path or decoded query) owned by someone other
//     than that attacker. The lab attributes owner from both places;
//   - not_detected otherwise. A request that names no object, or carries it only in its body, is outside
//     the rule's view.
//
// A mismatch is a finding. The expectation is never edited to match a result.
func TestPhase34_DetectionMatchesFixtureOwnership(t *testing.T) {
	if testing.Short() {
		t.Skip("detection run skipped in -short mode")
	}
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	var failures []string
	n := 0
	for _, s := range all {
		if s.Detection == nil || s.Detection.ExpectRule != "APIBAS-REL-004" {
			continue
		}
		n++
		fx := fixtureFor(t, s.Preconditions.Fixture)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			want := expectedDetection(t, fx, s, mode)
			e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
			rep := e.run(t, s, e.state)
			if got := rep.Outcome.Detection; got != want {
				failures = append(failures, fmt.Sprintf("%s %s: detection %q, expected %q", s.ID, modeName(mode), got, want))
			}
		}
	}
	if n == 0 {
		t.Fatal("no scenario declares the REL-004 detection")
	}
	if len(failures) > 0 {
		t.Fatalf("%d detection results differ from the fixture-derived expectation:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

// expectedDetection derives the result from the fixture for one build.
func expectedDetection(t *testing.T, fx fixture.Fixture, s contract.Scenario, mode lab.Mode) string {
	t.Helper()
	attack := s.Steps[len(s.Steps)-1]
	attacker := ""
	if attack.Auth != "none" {
		id, ok := fx.Identity(attack.Identity)
		if !ok {
			t.Fatalf("%s: attack identity %s is not in the fixture", s.ID, attack.Identity)
		}
		attacker = id.CustomerID
		if mode == lab.ModeVulnerable {
			for _, h := range forgedIdentityHeaders {
				if claimed, ok := attack.Headers[h]; ok {
					attacker = claimed
				}
			}
		}
	}
	target := strings.ReplaceAll(attack.Path, "{object}", s.Preconditions.Object)
	named := namedInRequest(target)
	for _, o := range fx.Objects {
		if named(o.ID) && o.OwnerID != attacker {
			return "detected"
		}
	}
	return "not_detected"
}

// namedInRequest reports whether an object ID appears in the request target's path or in a decoded
// query value. It mirrors the lab's owner attribution.
func namedInRequest(target string) func(id string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return func(string) bool { return false }
	}
	parts := []string{u.Path}
	for _, vals := range u.Query() {
		parts = append(parts, vals...)
	}
	return func(id string) bool {
		for _, p := range parts {
			if strings.Contains(p, id) {
				return true
			}
		}
		return false
	}
}

func modeName(m lab.Mode) string {
	if m == lab.ModeVulnerable {
		return "vulnerable"
	}
	return "fixed"
}
