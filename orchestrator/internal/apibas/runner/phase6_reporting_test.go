package runner_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/reporting"
	"github.com/audspect/bas/internal/apibas/runner"
)

// REPORT scenarios run against the fixture-backed reporting receiver. Each case sets the receiver's faults, runs the scenario
// through the runner, and checks the grade and its reason. The receiver is identical in both builds, so every case is
// checked against both. A simulated PASS is only a workflow check: it never reports a genuine receipt.

// runReporting builds a lab in the given mode, sets the reporting faults, and runs the scenario through the runner.
func runReporting(t *testing.T, mode lab.Mode, id string, faults map[string]any) runner.Report {
	t.Helper()
	s := scenarioByID(t, id)
	fx := fixtureFor(t, s.Preconditions.Fixture)
	e := newEnvWith(t, mode, fx, nil, false)
	if faults != nil {
		if err := e.admin.SetReportingFaults(context.Background(), faults); err != nil {
			t.Fatalf("%s: set reporting faults: %v", modeName(mode), err)
		}
	}
	return e.run(t, s, e.state)
}

func expectReporting(t *testing.T, label string, rep runner.Report, want grade.Result, reason string) {
	t.Helper()
	if rep.Outcome.Result != want {
		t.Errorf("%s: result %s (%s), want %s", label, rep.Outcome.Result, rep.Outcome.Reason, want)
	}
	if rep.Reporting == nil {
		t.Fatalf("%s: no reporting grade recorded", label)
	}
	if rep.Reporting.Reason != reason {
		t.Errorf("%s: reason %q, want %q", label, rep.Reporting.Reason, reason)
	}
}

// REPORT-001: the CERT-In six-hour obligation. The clock starts at the fixture's awareness time.
func TestPhase6_REPORT001_CertInCases(t *testing.T) {
	cases := []struct {
		name   string
		faults map[string]any
		want   grade.Result
		reason string
	}{
		{"on time", nil, grade.PASS, ""},
		{"exactly at the deadline", map[string]any{"delay_seconds": 21600}, grade.PASS, ""},
		{"late by one second", map[string]any{"delay_seconds": 21601}, grade.FAIL, reporting.ReasonDeadlineMissed},
		{"dispatch failed", map[string]any{"fail_recipient": "cert-in-receiver"}, grade.FAIL, reporting.ReasonDispatchFailed},
		{"receipt missing", map[string]any{"omit_receipt": true}, grade.FAIL, reporting.ReasonEvidenceMissing},
		{"misrouted", map[string]any{"misroute_to": "unexpected-receiver"}, grade.FAIL, reporting.ReasonWrongRecipient},
	}
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		for _, c := range cases {
			rep := runReporting(t, mode, "API-BAS-REPORT-001", c.faults)
			expectReporting(t, modeName(mode)+" "+c.name, rep, c.want, c.reason)
		}
	}
}

// A simulated run is labelled simulated and never reports a genuine receipt, even when it passes.
func TestPhase6_REPORT001_SimulatedNeverGenuine(t *testing.T) {
	rep := runReporting(t, lab.ModeFixed, "API-BAS-REPORT-001", nil)
	if rep.Reporting == nil {
		t.Fatal("no reporting grade")
	}
	if rep.Reporting.Mode != reporting.ModeSimulated {
		t.Errorf("mode %s, want simulated", rep.Reporting.Mode)
	}
	if rep.Reporting.ReceiptGenuine {
		t.Error("a simulated run reported a genuine receipt")
	}
}

// REPORT-002: the CBUAE obligations declare no numeric deadline, because the provision states none. A dispatch can
// therefore never PASS on timeliness; it is SKIPPED, and the failure cases still FAIL.
func TestPhase6_REPORT002_CBUAECases(t *testing.T) {
	cases := []struct {
		name   string
		faults map[string]any
		want   grade.Result
		reason string
	}{
		{"dispatched, deadline undefined by the provision", nil, grade.SKIPPED, reporting.ReasonDeadlineUndefined},
		{"dispatch failed", map[string]any{"fail_recipient": "cbuae-central-bank"}, grade.FAIL, reporting.ReasonDispatchFailed},
		{"misrouted", map[string]any{"misroute_to": "unexpected-receiver"}, grade.FAIL, reporting.ReasonWrongRecipient},
		{"receipt missing", map[string]any{"omit_receipt": true}, grade.FAIL, reporting.ReasonEvidenceMissing},
	}
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		for _, c := range cases {
			rep := runReporting(t, mode, "API-BAS-REPORT-002", c.faults)
			expectReporting(t, modeName(mode)+" "+c.name, rep, c.want, c.reason)
		}
	}
}

// An unreachable target is an ERROR, never a PASS or a FAIL.
func TestPhase6_ReportingUnreachableIsError(t *testing.T) {
	s := scenarioByID(t, "API-BAS-REPORT-001")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	e := newEnvWith(t, lab.ModeFixed, fx, nil, false)
	r, err := runner.New(runner.Config{
		BaseURL: "http://127.0.0.1:1", Fixture: fx, Secrets: e.secrets, State: e.state, Reset: e.admin,
		Events: e.admin, Reporting: e.admin,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	rep, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome.Result != grade.ERROR {
		t.Errorf("unreachable target: result %s, want ERROR", rep.Outcome.Result)
	}
}

// A reporting scenario run with no reporting adapter is an ERROR. It is never graded from the HTTP response alone.
func TestPhase6_ReportingWithoutAdapterIsError(t *testing.T) {
	s := scenarioByID(t, "API-BAS-REPORT-001")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	e := newEnvWith(t, lab.ModeFixed, fx, nil, false)
	r, err := runner.New(runner.Config{
		BaseURL: e.url, Fixture: fx, Secrets: e.secrets, State: e.state, Reset: e.admin, Events: e.admin,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	rep, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcome.Result != grade.ERROR {
		t.Errorf("no reporting adapter: result %s, want ERROR", rep.Outcome.Result)
	}
}
