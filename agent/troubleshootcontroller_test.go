//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"audspect/agent/statusclient"
)

func fakeDiagnosticsDeps() diagnosticsDeps {
	return diagnosticsDeps{
		queryServiceRunning: func() (bool, error) { return true, nil },
		getStatus: func() (statusclient.StatusResponse, error) {
			return statusclient.StatusResponse{ServerURL: "https://orchestrator.local:9443"}, nil
		},
		testConnection: func(host string) (TestOutcome, string, time.Time, error) {
			return TestOutcomeConnected, "Connected", time.Now(), nil
		},
		getLastConnError: func() *LastConnError { return nil },
	}
}

func TestRunDiagnostics_ServiceStopped_Check1Fails(t *testing.T) {
	deps := fakeDiagnosticsDeps()
	deps.queryServiceRunning = func() (bool, error) { return false, nil }

	checks := RunDiagnostics(deps)
	if checks[0].Status != CheckFail {
		t.Fatalf("checks[0].Status = %q, want %q", checks[0].Status, CheckFail)
	}
	if checks[0].ActionButton == nil {
		t.Fatal("expected an ActionButton offering to start the service")
	}
}

func TestRunDiagnostics_ClockSkewOnlyFlaggedWithEvidence(t *testing.T) {
	t.Run("close to local time is CheckPass", func(t *testing.T) {
		deps := fakeDiagnosticsDeps()
		deps.testConnection = func(host string) (TestOutcome, string, time.Time, error) {
			return TestOutcomeConnected, "Connected", time.Now(), nil
		}
		checks := RunDiagnostics(deps)
		if checks[3].Status != CheckPass {
			t.Fatalf("checks[3].Status = %q, want %q", checks[3].Status, CheckPass)
		}
	})

	t.Run("more than 5 minutes skew is CheckWarn with evidence", func(t *testing.T) {
		deps := fakeDiagnosticsDeps()
		deps.testConnection = func(host string) (TestOutcome, string, time.Time, error) {
			return TestOutcomeConnected, "Connected", time.Now().Add(-10 * time.Minute), nil
		}
		checks := RunDiagnostics(deps)
		if checks[3].Status != CheckWarn {
			t.Fatalf("checks[3].Status = %q, want %q", checks[3].Status, CheckWarn)
		}
		if checks[3].Evidence == "" {
			t.Fatal("expected skew evidence to be non-empty")
		}
	})
}

func TestRunDiagnostics_ProxyAuthOnlyLabeledWithEvidence(t *testing.T) {
	deps := fakeDiagnosticsDeps()
	deps.getLastConnError = func() *LastConnError {
		return &LastConnError{Category: ConnErrorTCP, Detail: "connection refused", At: time.Now()}
	}

	checks := RunDiagnostics(deps)
	if checks[5].Cause == "" {
		t.Fatal("expected check 6 to explain the TCP failure")
	}
	if strings.Contains(strings.ToLower(checks[5].Cause), "proxy") {
		t.Fatalf("check 6 must not claim a proxy issue for ConnErrorTCP evidence, got cause=%q", checks[5].Cause)
	}
}

func TestRunDiagnostics_Check3_AlwaysCallsLiveTest_NeverCached(t *testing.T) {
	deps := fakeDiagnosticsDeps()
	calls := 0
	deps.testConnection = func(host string) (TestOutcome, string, time.Time, error) {
		calls++
		if calls == 1 {
			return TestOutcomeHostUnreachable, "unreachable", time.Time{}, nil
		}
		return TestOutcomeConnected, "Connected", time.Now(), nil
	}

	first := RunDiagnosticCheck(3, deps)
	if first.Status != CheckFail {
		t.Fatalf("first call: Status = %q, want %q", first.Status, CheckFail)
	}
	second := RunDiagnosticCheck(3, deps)
	if second.Status != CheckPass {
		t.Fatalf("second call: Status = %q, want %q -- check 3 must reflect the live result, not a cached first-call value", second.Status, CheckPass)
	}
	if calls != 2 {
		t.Fatalf("testConnection called %d times, want exactly 2 (one per RunDiagnosticCheck call)", calls)
	}
}

func TestRunDiagnostics_GetStatusFails_PropagatesAsFailure(t *testing.T) {
	deps := fakeDiagnosticsDeps()
	deps.getStatus = func() (statusclient.StatusResponse, error) {
		return statusclient.StatusResponse{}, errors.New("local API unreachable")
	}

	checks := RunDiagnostics(deps)
	if checks[1].Status != CheckFail {
		t.Fatalf("checks[1].Status = %q, want %q when getStatus fails", checks[1].Status, CheckFail)
	}
}
