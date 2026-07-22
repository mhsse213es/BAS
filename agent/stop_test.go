package main

import (
	"reflect"
	"testing"
)

func TestStopSelf_FinalizesHeartbeatsDisablesThenExits(t *testing.T) {
	var calls []string

	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	defer func() {
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
	}()
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return nil }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle" // shutdownFinalize is a no-op when idle — isolates this test to stopSelf's own sequencing

	a.stopSelf("decommissioning host")

	want := []string{"disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestStopSelf_DisableFailureStillExits(t *testing.T) {
	var calls []string

	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	defer func() {
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
	}()
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return errDisableFailedForTest }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle"

	a.stopSelf("decommissioning host")

	want := []string{"disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v (a disable failure must not prevent exit)", calls, want)
	}
}
