package dbsim

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

// F1: a fixture-gated probe is never a PASS without a POSITIVE cleanup status.
func TestFixtureProbePassNeedsPositiveCleanup(t *testing.T) {
	for _, c := range []struct {
		status   string
		incident bool
		want     RunResult
	}{
		{CleanupOK, false, ResultPass},
		{"", false, ResultError},
		{CleanupNotApplicable, false, ResultError},
		{CleanupResidual, true, ResultError},
		{CleanupFailed, true, ResultError},
	} {
		o := revokeOutcome(true, "auth_failed", stepsDenied)
		o.Probe.CleanupStatus, o.Probe.SafetyIncident = c.status, c.incident
		if got := ToRunResult(revokeMeta(), o); got != c.want {
			t.Errorf("DB-06 cleanup %q: %s want %s", c.status, got, c.want)
		}
	}
	// DB-05 / DB-09 style probes (fixture param) and DB-07 (required fixture).
	for _, probe := range []string{"suspicious_read", "bounded_synthetic_read", ProbeReadClassifiedFixture} {
		for status, want := range map[string]RunResult{CleanupOK: ResultPass, "": ResultError, CleanupNotApplicable: ResultError} {
			o := Outcome{ProbeID: probe, ProbeRan: true, Probe: DBProbeResult{RowsRead: 3, CleanupStatus: status}, CollectedAt: time.Unix(1700000000, 0).UTC(),
				Corr: Correlation{Evaluated: true, Telemetry: dlpreport.TelemetryPresent, Response: dlpreport.ResponseAlerted, Match: MatchExactMarker, Alerts: 1}}
			m := ScenarioMeta{ID: "x", ExpectedPrevention: "allow", ExpectDetection: true, ExpectResponse: true}
			if probe == ProbeReadClassifiedFixture {
				o.Classification, m.ExpectClassification = dlpreport.ClassificationCorrect, true
			}
			if got := ToRunResult(m, o); got != want {
				t.Errorf("%s cleanup %q: %s want %s", probe, status, got, want)
			}
		}
	}
	// Non-fixture probes are unchanged: empty cleanup status still passes.
	o := Outcome{ProbeID: "read_roles", ProbeRan: true, Probe: DBProbeResult{RowsRead: 3}}
	if got := ToRunResult(ScenarioMeta{ID: "x", ExpectedPrevention: "allow"}, o); got != ResultPass {
		t.Errorf("read_roles: %s", got)
	}
}

func TestFixtureProbeUnverifiedCleanupIsInTheRecord(t *testing.T) {
	o := revokeOutcome(true, "auth_failed", stepsDenied)
	o.Probe.CleanupStatus = ""
	rec, err := ToRecord(revokeMeta(), o)
	if err != nil || !strings.Contains(rec.Limitations, "cleanup was not verified") {
		t.Fatalf("%v %q", err, rec.Limitations)
	}
}

// F6: an expected-but-unevaluated classification always says why, even when
// ToRecord is called outside dbrun.Evaluate.
func TestToRecordExplainsUnevaluatedClassification(t *testing.T) {
	m := ScenarioMeta{ID: "x", ExpectedPrevention: "allow", ExpectClassification: true}
	rec, err := ToRecord(m, Outcome{ProbeID: ProbeReadClassifiedFixture, ProbeRan: true, Probe: DBProbeResult{RowsRead: 1, CleanupStatus: CleanupOK}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Limitations, "classification rule configured/applicable") || strings.Contains(rec.Limitations, "does not classify data") {
		t.Fatalf("%q", rec.Limitations)
	}
}

// F2
func corrOK(tel dlpreport.TelemetryOutcome, m MatchGrade) Outcome {
	return Outcome{ProbeRan: true, Probe: DBProbeResult{RowsRead: 6},
		Corr: Correlation{Evaluated: true, Telemetry: tel, Match: m, Alerts: 1}}
}

func TestClassifyByRuleFalseIncorrectPathsAreUnknown(t *testing.T) {
	const rule = "BAS dbsim classified-fixture read"
	present := corrOK(dlpreport.TelemetryPresent, MatchExactMarker)
	// Clean case-exact miss: Incorrect.
	if c, _ := ClassifyByRule(rule, present, []string{GenericMarkerRuleName}, 0); c != dlpreport.ClassificationIncorrect {
		t.Fatalf("clean miss: %s", c)
	}
	for name, tc := range map[string]struct {
		rules  []string
		hidden int
	}{
		"empty rule name":      {[]string{GenericMarkerRuleName, ""}, 0},
		"case-only difference": {[]string{GenericMarkerRuleName, "bas dbsim Classified-Fixture read"}, 0},
		"whitespace-only diff": {[]string{GenericMarkerRuleName, " " + rule + " "}, 0},
		"strong alerts hidden": {[]string{GenericMarkerRuleName}, 1},
	} {
		if c, _ := ClassifyByRule(rule, present, tc.rules, tc.hidden); c != dlpreport.ClassificationUnknown {
			t.Errorf("%s: %s, want Unknown", name, c)
		}
	}
	// Correct is a rule-identity verdict: also granted when telemetry is Delayed.
	delayed := corrOK(dlpreport.TelemetryDelayed, MatchExactMarker)
	if c, _ := ClassifyByRule(rule, delayed, []string{rule}, 0); c != dlpreport.ClassificationCorrect {
		t.Errorf("delayed classification alert: %s", c)
	}
}
