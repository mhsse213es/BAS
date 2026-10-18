package reporting

import (
	"strings"
	"testing"
)

// The appcontrol family compares a test contract's declared intent against
// the outcome the oracle observed. Inconclusive and unsupported results are
// never Match, and a blocked-as-expected result is only a Match when the
// contract said the path should be blocked.
func TestAppControlComparator_ExpectedBlocked(t *testing.T) {
	c := appcontrolComparator{}
	cases := map[string]ComparisonResult{
		"blocked_as_expected":  Match,
		"allowed_unexpectedly": Mismatch,
		"not_enforced":         Mismatch,
		"inconclusive":         MissingEvidence,
		"not_applicable":       NotApplicable,
		"allowed_by_policy":    Mismatch,
	}
	for observed, want := range cases {
		if got := c.Compare("blocked", observed); got != want {
			t.Errorf("Compare(blocked, %s) = %s, want %s", observed, got, want)
		}
	}
}

func TestAppControlComparator_ExpectedAllowed(t *testing.T) {
	c := appcontrolComparator{}
	cases := map[string]ComparisonResult{
		"allowed_by_policy":    Match,
		"blocked_as_expected":  Mismatch,
		"allowed_unexpectedly": Mismatch,
		"inconclusive":         MissingEvidence,
		"not_applicable":       NotApplicable,
	}
	for observed, want := range cases {
		if got := c.Compare("allowed", observed); got != want {
			t.Errorf("Compare(allowed, %s) = %s, want %s", observed, got, want)
		}
	}
}

func TestAppControlComparator_UnknownValuesAreUnknown(t *testing.T) {
	c := appcontrolComparator{}
	if got := c.Compare("blocked", "something_else"); got != Unknown {
		t.Errorf("unrecognized observed value = %s, want Unknown", got)
	}
	if got := c.Compare("maybe", "blocked_as_expected"); got != Unknown {
		t.Errorf("unrecognized expected value = %s, want Unknown", got)
	}
}

func TestParseAppControlOutcome(t *testing.T) {
	out := "APPCTL_COVERAGE: Exe=Enabled\nPASS: blocked\nAPPCTL_OUTCOME: blocked_as_expected\n"
	got, ok := ParseAppControlOutcome(out)
	if !ok || got != "blocked_as_expected" {
		t.Fatalf("ParseAppControlOutcome = %q,%v; want blocked_as_expected,true", got, ok)
	}
	if _, ok := ParseAppControlOutcome("APPCTL_OUTCOME: made_up\n"); ok {
		t.Error("an unrecognized outcome value must not parse")
	}
	if _, ok := ParseAppControlOutcome("PASS: no marker here"); ok {
		t.Error("output without the marker must not parse")
	}
}

func TestAppControlEvidence_LimitationsAlwaysPopulated(t *testing.T) {
	e := NewAppControlEvidence("local-oracle", "corr-1", "fx-1", "Exe=Enabled", "2026-10-18T10:00:00Z", true)
	if e.Limitations == "" {
		t.Fatal("Limitations must never be empty")
	}
}

func TestParseAppControlFamily(t *testing.T) {
	out := "APPCTL_FAMILY: script_host_proxy\nAPPCTL_OUTCOME: blocked_as_expected\n"
	got, ok := ParseAppControlFamily(out)
	if !ok || got != "script_host_proxy" {
		t.Fatalf("ParseAppControlFamily = %q,%v; want script_host_proxy,true", got, ok)
	}
	if _, ok := ParseAppControlFamily("APPCTL_FAMILY: made_up_family\n"); ok {
		t.Error("an unknown family must not parse")
	}
	if _, ok := ParseAppControlFamily("no family line"); ok {
		t.Error("output without APPCTL_FAMILY must not parse")
	}
}

func TestParseAppControlVisibility(t *testing.T) {
	cases := map[string]string{
		"APPCTL_DETECTION: source=sysmon_process_create result=visible\n":     "visible",
		"APPCTL_DETECTION: source=sysmon_process_create result=not_visible\n": "not_visible",
		"APPCTL_DETECTION: source=sysmon_process_create result=unknown\n":     "unknown",
	}
	for out, want := range cases {
		got, ok := ParseAppControlVisibility(out)
		if !ok || got != want {
			t.Errorf("ParseAppControlVisibility(%q) = %q,%v; want %q,true", out, got, ok, want)
		}
	}
	if _, ok := ParseAppControlVisibility("APPCTL_DETECTION: result=maybe\n"); ok {
		t.Error("an unrecognized visibility value must not parse")
	}
}

// Prevention and telemetry visibility are separate columns. A path that was
// blocked but not visible in telemetry must show both facts, never one
// folded into the other.
func TestRenderAppControlMatrix_SeparatesPreventionFromVisibility(t *testing.T) {
	rows := []AppControlPathResult{
		{Family: "indirect_execution", Technique: "T1202", Outcome: AppCtlBlockedAsExpected, Visibility: "visible"},
		{Family: "script_host_proxy", Technique: "T1059.005", Outcome: AppCtlAllowedUnexpected, Visibility: "not_visible"},
		{Family: "alternate_ps_host", Technique: "T1059.001", Outcome: AppCtlNotApplicable, Visibility: "unknown"},
	}
	md := RenderAppControlMatrix(rows)
	for _, want := range []string{
		"| Family | Technique | Prevention outcome | Telemetry visibility |",
		"| indirect_execution | T1202 | blocked_as_expected | visible |",
		"| script_host_proxy | T1059.005 | allowed_unexpectedly | not_visible |",
		"| alternate_ps_host | T1059.001 | not_applicable | unknown |",
		"Telemetry visibility is not a prevention verdict",
		"Results hold only for the tested Windows build",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("matrix missing %q\n%s", want, md)
		}
	}
}

func TestRenderAppControlMatrix_EmptyStillStatesLimitations(t *testing.T) {
	md := RenderAppControlMatrix(nil)
	if !strings.Contains(md, "No application-control paths were evaluated") {
		t.Errorf("empty matrix must say nothing was evaluated, got:\n%s", md)
	}
	if !strings.Contains(md, "Results hold only for the tested Windows build") {
		t.Error("empty matrix must still carry the limitations statement")
	}
}
