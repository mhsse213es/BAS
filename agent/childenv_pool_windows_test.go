//go:build windows

package main

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/sched"
)

// The warm PowerShell pool spawns its hosts with the agent's environment; the
// dbsim secrets must not be in it.
func TestChildEnvWarmPoolHostNeverSeesDBSecrets(t *testing.T) {
	t.Setenv("BAS_DBCRED_X", "TOPSECRET-cred-value")
	t.Setenv("BAS_VISIBLE_MARKER", "visible-ok")
	pool := NewHostPool(1)
	if pool == nil || len(pool.free) == 0 {
		t.Skip("warm pool host could not start on this machine")
	}
	step := ScenarioStep{TaskID: "p", Executor: "powershell", TimeoutSec: 30,
		Command:  "Get-ChildItem Env: | ForEach-Object { $_.Name + '=' + $_.Value }",
		Resource: &sched.ResourceProfile{Risk: sched.RiskObservation}}
	if !pooledCandidate(step) {
		t.Fatal("test step is not pool-eligible")
	}
	r, ok := pool.Run(context.Background(), step)
	if !ok {
		t.Skip("pool miss; fell back to per-process path")
	}
	if !strings.Contains(r.Stdout, "visible-ok") {
		t.Fatalf("control: pooled host did not print env: %q / %q", r.Stdout, r.Stderr)
	}
	if strings.Contains(r.Stdout, "TOPSECRET-cred-value") || strings.Contains(r.Stdout, "BAS_DBCRED_X") {
		t.Fatalf("pooled host leaked secret:\n%s", r.Stdout)
	}
}
