package runner_test

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Detection is a separate axis. ABUSE-001 sends five failed guesses against the
// vulnerable build and three against the fixed build, so the repeated-failure rule
// fires in both: the SIEM sees the attempts whether or not the control holds.
// AUTHZ-001 is a single denied or successful request, which the threshold rule cannot
// see. That miss is recorded as a real coverage gap, not hidden.
func TestPhase15_DetectionIsSeparateFromExploitation(t *testing.T) {
	cases := []struct {
		id        string
		vulnExpl  grade.Exploitability
		detection string
	}{
		{"API-BAS-ABUSE-001", grade.Exploited, "detected"},
		{"API-BAS-AUTHZ-001", grade.Exploited, "detected"},
	}
	for _, c := range cases {
		e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
		rep := e.run(t, scenarioByID(t, c.id), e.state)
		if rep.Outcome.Exploitability != c.vulnExpl {
			t.Errorf("%s vulnerable exploitability = %s, want %s", c.id, rep.Outcome.Exploitability, c.vulnExpl)
		}
		if rep.Outcome.Detection != c.detection {
			t.Errorf("%s vulnerable detection = %q, want %q", c.id, rep.Outcome.Detection, c.detection)
		}
		if !strings.HasPrefix(rep.DetectionProvenance, "fixture-validated") {
			t.Errorf("%s provenance = %q, want fixture-validated label", c.id, rep.DetectionProvenance)
		}
	}
}

// The fixed build's ABUSE-001 sequence still crosses the repeated-failure threshold
// (three 401s before the 429s), so detection is "detected" there too.
func TestPhase15_FixedAbuseStillDetected(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-ABUSE-001"), e.state)
	if rep.Outcome.Detection != "detected" {
		t.Fatalf("fixed ABUSE-001 detection = %q, want detected", rep.Outcome.Detection)
	}
	if rep.Outcome.Result != grade.PASS {
		t.Fatalf("fixed ABUSE-001 result = %s, want PASS; detection must not change exploitability", rep.Outcome.Result)
	}
}

// A protocol with no adapter is reported UNSUPPORTED, never counted as covered.
func TestPhase15_UnsupportedProtocolIsSkipped(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	s := contract.Scenario{ID: "API-BAS-AUTHN-011", Protocol: "websocket"}
	rep := e.run(t, s, e.state)
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonUnsupportedProtocol {
		t.Fatalf("websocket scenario = %s / %s, want SKIPPED / UNSUPPORTED_PROTOCOL", rep.Outcome.Result, rep.Outcome.Reason)
	}
}

// The detection fixture names its provenance so a report cannot read it as live.
func TestPhase15_ProvenanceNamesFixtureNotLive(t *testing.T) {
	if !strings.Contains(detect.Provenance, "not validated against a live SIEM") {
		t.Fatalf("provenance %q does not disclaim live SIEM validation", detect.Provenance)
	}
}
