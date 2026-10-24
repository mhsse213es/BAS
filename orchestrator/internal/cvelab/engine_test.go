package cvelab

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cvecatalog"
	"github.com/audspect/bas/internal/cveval"
)

// fakeAudit records every event. failOn, when non-empty, makes Record
// return an error for that one Action, so tests can prove the engine
// aborts immediately rather than continuing past a failed audit write.
type fakeAudit struct {
	events []AuditEvent
	failOn string
}

func (f *fakeAudit) Record(_ context.Context, ev AuditEvent) error {
	if ev.Action == f.failOn {
		return errors.New("audit backend unavailable")
	}
	f.events = append(f.events, ev)
	return nil
}

// fakeProber is a controllable test double. It never performs real I/O.
type fakeProber struct {
	result     ProbeResult
	err        error
	blockUntil func(ctx context.Context) // if set, called instead of returning immediately
	lastReq    ProbeRequest
	calls      int
}

func (f *fakeProber) Probe(ctx context.Context, req ProbeRequest) (ProbeResult, error) {
	f.calls++
	f.lastReq = req
	if f.blockUntil != nil {
		f.blockUntil(ctx)
		return ProbeResult{}, ctx.Err()
	}
	return f.result, f.err
}

func testEntry(t *testing.T, profile cveval.ExecutionProfile) cvecatalog.CVEEntry {
	t.Helper()
	e, err := cvecatalog.NewCVEEntry(
		"CVE-2021-44228",
		[]string{"CWE-502"},
		cvecatalog.SeverityCritical,
		cvecatalog.AffectedProduct{Name: "x:y", Ranges: []cvecatalog.VersionRange{{Introduced: "1.0", Fixed: "2.0"}}},
		"description", "preconditions", profile,
		[]cvecatalog.Reference{{Source: "NVD", URL: "https://nvd.nist.gov/x"}},
		"2026-10-24",
		cvecatalog.ConfigFixture{Description: "vuln", Indicator: "v1", Implies: cveval.VerdictVulnerable},
		cvecatalog.ConfigFixture{Description: "patched", Indicator: "v2", Implies: cveval.VerdictNotVulnerable},
		"test fixture",
	)
	if err != nil {
		t.Fatalf("testEntry: %v", err)
	}
	return e
}

func newEngine(t *testing.T, allowed AllowedLabTargets, prober Prober, audit Audit) *Engine {
	t.Helper()
	eng, err := NewEngine(Config{Allowed: allowed, Prober: prober, Audit: audit})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func TestNewEngine_RequiresAudit(t *testing.T) {
	if _, err := NewEngine(Config{}); err == nil {
		t.Fatal("NewEngine with a nil Audit must be refused")
	}
}

func TestAssess_UnknownCVERefusesWithoutLiveExecution(t *testing.T) {
	audit := &fakeAudit{}
	eng := newEngine(t, AllowedLabTargets{}, nil, audit)
	res, err := eng.Assess(context.Background(), RunRequest{CVEID: "CVE-9999-00000"})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR", res.Verdict)
	}
	if len(audit.events) != 1 || audit.events[0].Action != "requested" {
		t.Fatalf("audit events = %+v, want exactly one 'requested' event", audit.events)
	}
}

func TestAssessEntry_DefaultsToFixtureOnly(t *testing.T) {
	audit := &fakeAudit{}
	prober := &fakeProber{}
	eng := newEngine(t, AllowedLabTargets{}, prober, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, err := eng.AssessEntry(context.Background(), entry, RunRequest{CVEID: entry.ID, ObservedConfig: "v1"})
	if err != nil {
		t.Fatalf("AssessEntry: %v", err)
	}
	if res.Verdict != cveval.VerdictVulnerable {
		t.Fatalf("Verdict = %q, want VULNERABLE", res.Verdict)
	}
	if res.Evidence.Source != cveval.SourceFixture {
		t.Fatalf("Evidence.Source = %q, want fixture -- the zero-value RunRequest must never touch the network", res.Evidence.Source)
	}
	if prober.calls != 0 {
		t.Fatalf("Prober.Probe was called %d times for a non-Live request, want 0", prober.calls)
	}
}

func TestAssessEntry_FailClosedAuditAbortsImmediately(t *testing.T) {
	audit := &fakeAudit{failOn: "requested"}
	eng := newEngine(t, AllowedLabTargets{}, nil, audit)
	entry := testEntry(t, cveval.ProfileFixtureOnly)

	_, err := eng.AssessEntry(context.Background(), entry, RunRequest{CVEID: entry.ID, ObservedConfig: "v1"})
	if err == nil {
		t.Fatal("a failed 'requested' audit write must abort the assessment with an error")
	}
	if len(audit.events) != 0 {
		t.Fatalf("no events should have been recorded after the failed write, got %+v", audit.events)
	}
}

func TestAssessEntry_LiveRefusedWhenNotLabCapable(t *testing.T) {
	audit := &fakeAudit{}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, &fakeProber{}, audit)
	entry := testEntry(t, cveval.ProfileFixtureOnly)

	res, err := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080",
		Timeout: time.Second, MaxRequests: 1,
	})
	if err != nil {
		t.Fatalf("AssessEntry: %v", err)
	}
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (fixture_only must refuse live execution)", res.Verdict)
	}
}

func TestAssessEntry_LiveRefusedWhenNotAuthorized(t *testing.T) {
	audit := &fakeAudit{}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, &fakeProber{}, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, _ := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: false, LabTarget: "10.50.0.12:8080",
		Timeout: time.Second, MaxRequests: 1,
	})
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (unauthorized live request must be refused)", res.Verdict)
	}
}

func TestAssessEntry_LiveRefusedWhenTargetNotAllowListed(t *testing.T) {
	audit := &fakeAudit{}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, &fakeProber{}, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, _ := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.99:8080",
		Timeout: time.Second, MaxRequests: 1,
	})
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (a target off the allow-list must be refused)", res.Verdict)
	}
}

func TestAssessEntry_LiveRefusedWhenTargetIsPublic(t *testing.T) {
	audit := &fakeAudit{}
	// Deliberately allow-list a public address too, to prove the public-
	// address check is independent of (and cannot be bypassed by) the
	// allow-list -- a misconfigured allow-list entry is still refused.
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"8.8.8.8:443"}}, &fakeProber{}, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, _ := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "8.8.8.8:443",
		Timeout: time.Second, MaxRequests: 1,
	})
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (a public target must be refused even if allow-listed by mistake)", res.Verdict)
	}
}

func TestAssessEntry_LiveRefusedWhenNoTimeout(t *testing.T) {
	audit := &fakeAudit{}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, &fakeProber{}, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, _ := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080", MaxRequests: 1,
	})
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (Timeout <= 0 must be refused)", res.Verdict)
	}
}

func TestAssessEntry_LiveRefusedWhenNoMaxRequests(t *testing.T) {
	audit := &fakeAudit{}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, &fakeProber{}, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, _ := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080", Timeout: time.Second,
	})
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (MaxRequests <= 0 must be refused)", res.Verdict)
	}
}

func TestAssessEntry_LiveRefusedWhenNoProberConfigured(t *testing.T) {
	audit := &fakeAudit{}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, nil, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, _ := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080",
		Timeout: time.Second, MaxRequests: 1,
	})
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (a nil Prober must make live execution impossible)", res.Verdict)
	}
}

func TestAssessEntry_LiveSuccessReturnsLabRuntimeEvidence(t *testing.T) {
	audit := &fakeAudit{}
	prober := &fakeProber{result: ProbeResult{Verdict: cveval.VerdictVulnerable, Detail: "received a callback from the target process"}}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, prober, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, err := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080",
		Timeout: time.Second, MaxRequests: 3,
	})
	if err != nil {
		t.Fatalf("AssessEntry: %v", err)
	}
	if res.Verdict != cveval.VerdictVulnerable {
		t.Fatalf("Verdict = %q, want VULNERABLE", res.Verdict)
	}
	if res.Evidence.Source != cveval.SourceLabRuntime || res.Evidence.Target != "10.50.0.12:8080" {
		t.Fatalf("Evidence = %+v, want lab_runtime source with the target set", res.Evidence)
	}
	if prober.lastReq.MaxRequests != 3 || prober.lastReq.Target != "10.50.0.12:8080" {
		t.Fatalf("Prober received %+v, want MaxRequests=3 and the configured target", prober.lastReq)
	}
	var sawExecuted, sawOutcome bool
	for _, ev := range audit.events {
		if ev.Action == "live_executed" {
			sawExecuted = true
		}
		if ev.Action == "outcome" {
			sawOutcome = true
		}
	}
	if !sawExecuted || !sawOutcome {
		t.Fatalf("audit events = %+v, want live_executed and outcome", audit.events)
	}
}

func TestAssessEntry_ProbeTimeoutIsInconclusiveNotError(t *testing.T) {
	audit := &fakeAudit{}
	prober := &fakeProber{blockUntil: func(ctx context.Context) { <-ctx.Done() }}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, prober, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, err := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080",
		Timeout: 10 * time.Millisecond, MaxRequests: 1,
	})
	if err != nil {
		t.Fatalf("AssessEntry: %v", err)
	}
	if res.Verdict != cveval.VerdictInconclusive {
		t.Fatalf("Verdict = %q, want INCONCLUSIVE (a probe that never returns before the deadline must not be ERROR or a false VULNERABLE/NOT_VULNERABLE)", res.Verdict)
	}
}

func TestAssessEntry_ProbeErrorIsError(t *testing.T) {
	audit := &fakeAudit{}
	prober := &fakeProber{err: errors.New("connection refused")}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, prober, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, err := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080",
		Timeout: time.Second, MaxRequests: 1,
	})
	if err != nil {
		t.Fatalf("AssessEntry: %v", err)
	}
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR", res.Verdict)
	}
}

func TestAssessEntry_InvalidProbeResultIsDowngradedToError(t *testing.T) {
	audit := &fakeAudit{}
	// An empty Verdict is not one of cveval's known constants -- a buggy
	// Prober implementation producing this must never reach the caller
	// as-is.
	prober := &fakeProber{result: ProbeResult{Verdict: cveval.Verdict(""), Detail: "malformed"}}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, prober, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	res, err := eng.AssessEntry(context.Background(), entry, RunRequest{
		CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080",
		Timeout: time.Second, MaxRequests: 1,
	})
	if err != nil {
		t.Fatalf("AssessEntry: %v", err)
	}
	if res.Verdict != cveval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR (an invalid probe result must be downgraded, never passed through)", res.Verdict)
	}
	if err := cveval.ValidateResult(res); err != nil {
		t.Fatalf("the engine's own returned Result fails ValidateResult: %v", err)
	}
}

func TestAssessEntry_EveryResultPassesValidateResult(t *testing.T) {
	audit := &fakeAudit{}
	prober := &fakeProber{result: ProbeResult{Verdict: cveval.VerdictNotVulnerable, Detail: "no callback observed"}}
	eng := newEngine(t, AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}, prober, audit)
	entry := testEntry(t, cveval.ProfileLabCapable)

	cases := []RunRequest{
		{CVEID: entry.ID},
		{CVEID: entry.ID, ObservedConfig: "v1"},
		{CVEID: entry.ID, ObservedConfig: "unknown-indicator"},
		{CVEID: entry.ID, Live: true, Authorized: true, LabTarget: "10.50.0.12:8080", Timeout: time.Second, MaxRequests: 1},
		{CVEID: entry.ID, Live: true},
	}
	for i, req := range cases {
		res, err := eng.AssessEntry(context.Background(), entry, req)
		if err != nil {
			t.Fatalf("case %d: AssessEntry: %v", i, err)
		}
		if err := cveval.ValidateResult(res); err != nil {
			t.Fatalf("case %d: Result %+v fails ValidateResult: %v", i, res, err)
		}
	}
}
