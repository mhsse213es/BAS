//go:build windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas-agent/sched"
)

func obsStep(taskID, command string) ScenarioStep {
	return ScenarioStep{
		TaskID:   taskID,
		Executor: "powershell",
		Command:  command,
		Resource: &sched.ResourceProfile{
			Domains: []sched.ResourceLock{{Domain: "process"}},
			Scope:   "local",
			Risk:    sched.RiskObservation,
		},
	}
}

func TestHostPoolRunsCommand(t *testing.T) {
	p := NewHostPool(2)
	defer p.Close()

	r, ok := p.Run(context.Background(), obsStep("t1", `Write-Output "hello-pool"`))
	if !ok {
		t.Fatal("pool reported no result (ok=false) for a simple command")
	}
	if r.ExitCode != 0 {
		t.Errorf("exit=%d stderr=%q", r.ExitCode, r.Stderr)
	}
	if !strings.Contains(r.Stdout, "hello-pool") {
		t.Errorf("stdout missing output: %q", r.Stdout)
	}
}

// TestHostPoolReusesWarmHost runs several commands and asserts they all succeed —
// exercising host reuse across requests (no per-command process spawn).
func TestHostPoolReusesWarmHost(t *testing.T) {
	p := NewHostPool(1) // single host → every command reuses it
	defer p.Close()

	for i := range 5 {
		r, ok := p.Run(context.Background(), obsStep("t", `Write-Output 42`))
		if !ok || r.ExitCode != 0 || !strings.Contains(r.Stdout, "42") {
			t.Fatalf("run %d failed: ok=%v exit=%d out=%q", i, ok, r.ExitCode, r.Stdout)
		}
	}
}

// TestHostPoolIsolatesState is the accuracy guard: a variable set by one step must
// NOT be visible to the next, because each runs in a fresh runspace. If isolation
// broke, the second command would print the leaked value instead of an empty line.
func TestHostPoolIsolatesState(t *testing.T) {
	p := NewHostPool(1) // force both commands onto the same host
	defer p.Close()

	if _, ok := p.Run(context.Background(), obsStep("a", `$global:leak = "CONTAMINATED"`)); !ok {
		t.Fatal("first command did not run")
	}
	r, ok := p.Run(context.Background(), obsStep("b", `Write-Output "[$($global:leak)]"`))
	if !ok {
		t.Fatal("second command did not run")
	}
	if strings.Contains(r.Stdout, "CONTAMINATED") {
		t.Errorf("state leaked across steps — runspace isolation broken: %q", r.Stdout)
	}
}

// TestHostPoolInjectsEnv verifies BAS_PAYLOAD_DIR is visible to the command and
// cleared afterward (the harness sets process env per command, then unsets it).
func TestHostPoolInjectsEnv(t *testing.T) {
	p := NewHostPool(1)
	defer p.Close()

	step := obsStep("e", `Write-Output $env:BAS_PAYLOAD_DIR`)
	step.PayloadDir = `C:\bas-test-dir`
	r, ok := p.Run(context.Background(), step)
	if !ok || !strings.Contains(r.Stdout, `C:\bas-test-dir`) {
		t.Fatalf("env not injected: ok=%v out=%q", ok, r.Stdout)
	}

	// Next command (no PayloadDir) must not see the previous value.
	r2, _ := p.Run(context.Background(), obsStep("e2", `Write-Output "[$env:BAS_PAYLOAD_DIR]"`))
	if strings.Contains(r2.Stdout, "bas-test-dir") {
		t.Errorf("env not cleared between steps: %q", r2.Stdout)
	}
}

func TestPooledCandidate(t *testing.T) {
	obs := &sched.ResourceProfile{Domains: []sched.ResourceLock{{Domain: "process"}}, Scope: "local", Risk: sched.RiskObservation}
	mod := &sched.ResourceProfile{Domains: []sched.ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: sched.RiskModification}

	cases := []struct {
		name string
		step ScenarioStep
		want bool
	}{
		{"observation powershell", ScenarioStep{Executor: "powershell", Resource: obs}, true},
		{"observation psh", ScenarioStep{Executor: "psh", Resource: obs}, true},
		{"observation default executor", ScenarioStep{Executor: "", Resource: obs}, true},
		{"modification not pooled", ScenarioStep{Executor: "powershell", Resource: mod}, false},
		{"unlabeled not pooled", ScenarioStep{Executor: "powershell"}, false},
		{"cmd executor not pooled", ScenarioStep{Executor: "cmd", Resource: obs}, false},
		{"with payload not pooled", ScenarioStep{Executor: "powershell", Resource: obs, Payloads: []Payload{{Name: "x"}}}, false},
	}
	for _, c := range cases {
		if got := pooledCandidate(c.step); got != c.want {
			t.Errorf("%s: pooledCandidate=%v want %v", c.name, got, c.want)
		}
	}
}

// TestHostPoolTimeout verifies a hung command is bounded by the context deadline
// and the host is discarded (the pool stays usable afterward via replacement).
func TestHostPoolTimeout(t *testing.T) {
	p := NewHostPool(1)
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	r, ok := p.Run(ctx, obsStep("slow", `Start-Sleep -Seconds 30`))
	if !ok {
		t.Fatal("expected a (timeout) result, got ok=false")
	}
	if r.ExitCode != -1 {
		t.Errorf("expected exit -1 on timeout, got %d", r.ExitCode)
	}

	// Pool must still serve commands after recycling the timed-out host.
	r2, ok2 := p.Run(context.Background(), obsStep("after", `Write-Output ok`))
	if !ok2 || !strings.Contains(r2.Stdout, "ok") {
		t.Errorf("pool unusable after timeout recycle: ok=%v out=%q", ok2, r2.Stdout)
	}
}
