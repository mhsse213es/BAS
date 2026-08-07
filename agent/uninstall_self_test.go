package main

import (
	"errors"
	"reflect"
	"testing"
)

var errSelfUninstallFailedForTest = errors.New("self-uninstall failed for test")

func TestUninstallSelf_SuccessReportsThenDisablesThenExits(t *testing.T) {
	var calls []string

	origSelfUninstall := platformSelfUninstallFn
	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	origReport := reportUninstallResultFn
	defer func() {
		platformSelfUninstallFn = origSelfUninstall
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
		reportUninstallResultFn = origReport
	}()
	platformSelfUninstallFn = func() error { calls = append(calls, "selfUninstall"); return nil }
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return nil }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }
	reportUninstallResultFn = func(a *Agent, err error) {
		calls = append(calls, "report:"+boolToOutcome(err == nil))
	}

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle" // shutdownFinalize is a no-op when idle -- isolates this test to uninstallSelf's own sequencing

	a.uninstallSelf("decommissioning host")

	want := []string{"selfUninstall", "report:success", "disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestUninstallSelf_CleanupFailureStillReportsThenDisablesThenExits(t *testing.T) {
	var calls []string

	origSelfUninstall := platformSelfUninstallFn
	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	origReport := reportUninstallResultFn
	defer func() {
		platformSelfUninstallFn = origSelfUninstall
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
		reportUninstallResultFn = origReport
	}()
	platformSelfUninstallFn = func() error { calls = append(calls, "selfUninstall"); return errSelfUninstallFailedForTest }
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return nil }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }
	reportUninstallResultFn = func(a *Agent, err error) {
		calls = append(calls, "report:"+boolToOutcome(err == nil))
	}

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle"

	a.uninstallSelf("decommissioning host")

	want := []string{"selfUninstall", "report:failure", "disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v (a cleanup failure must still be reported, then still disable+exit)", calls, want)
	}
}

func boolToOutcome(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}
