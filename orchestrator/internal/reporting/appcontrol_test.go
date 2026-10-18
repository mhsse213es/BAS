package reporting

import (
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
