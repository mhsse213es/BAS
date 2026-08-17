package main

import (
	"context"
	"testing"
	"time"

	"audspect/agent/sched"
)

func TestCheckDefersExecution(t *testing.T) {
	ran := false
	c := check("T1000", "demo", "execution", "High", "threat", "fix",
		func() (string, string) { ran = true; return "pass", "ok" })
	if ran {
		t.Fatal("check() executed fn eagerly; expected deferred execution")
	}
	if c.ID == "" || c.Technique.ID != "T1000" {
		t.Fatalf("metadata not populated pre-run: %+v", c)
	}
	c.run()
	if !ran || c.Result != "pass" || c.Details != "ok" {
		t.Fatalf("run() did not execute fn / fill result: ran=%v %+v", ran, c)
	}
}

func TestRunChecksFiltersBySelection(t *testing.T) {
	cats := []SimCategory{{Phase: "p", Checks: []SimCheck{
		check("T1", "a", "t", "High", "x", "y", func() (string, string) { return "pass", "" }),
		check("T2", "b", "t", "High", "x", "y", func() (string, string) { return "fail", "" }),
	}}}
	idB := checkID("T2", "b")
	out, _ := runChecks(context.Background(), cats, map[string]bool{idB: true}, nil, nil)
	got := 0
	for _, cat := range out {
		got += len(cat.Checks)
	}
	if got != 1 || out[0].Checks[0].ID != idB {
		t.Fatalf("expected only selected check b, got %d: %+v", got, out)
	}
	if out[0].Checks[0].Result != "fail" {
		t.Fatalf("selected check not executed: %+v", out[0].Checks[0])
	}
}

// TestRunChecksInvokesCallbackPerExecutedCheck proves the optional onCheck
// callback fires once per check that actually runs, with its result already
// filled in -- this is what runLocalScan hooks to emit live progress events,
// without it the orchestrator's Live Run view has no way to know a local
// check scan is progressing at all.
func TestRunChecksInvokesCallbackPerExecutedCheck(t *testing.T) {
	cats := []SimCategory{{Phase: "p", Checks: []SimCheck{
		check("T1", "a", "t", "High", "x", "y", func() (string, string) { return "pass", "" }),
		check("T2", "b", "t", "High", "x", "y", func() (string, string) { return "fail", "" }),
	}}}
	var seen []SimCheck
	runChecks(context.Background(), cats, nil, nil, func(c SimCheck) { seen = append(seen, c) })
	if len(seen) != 2 {
		t.Fatalf("expected callback for both checks, got %d: %+v", len(seen), seen)
	}
	if seen[0].Result == "" || seen[1].Result == "" {
		t.Fatalf("callback fired before check.run() filled in Result: %+v", seen)
	}
}

// TestRunChecksBlocksOnPausedGate proves a paused gate holds the next check
// (not the currently-running one, since there isn't one yet) and Resume lets
// it proceed -- this is what makes Pause/Resume actually work for
// posture-mode scans, not just show a button that does nothing.
func TestRunChecksBlocksOnPausedGate(t *testing.T) {
	gate := sched.NewGate()
	gate.Pause()
	cats := []SimCategory{{Phase: "p", Checks: []SimCheck{
		check("T1", "a", "t", "High", "x", "y", func() (string, string) { return "pass", "" }),
	}}}
	done := make(chan []SimCategory, 1)
	go func() { out, _ := runChecks(context.Background(), cats, nil, gate, nil); done <- out }()

	select {
	case <-done:
		t.Fatal("runChecks completed while the gate was paused -- pause did not block execution")
	case <-time.After(50 * time.Millisecond):
		// expected: still blocked
	}

	gate.Resume()
	select {
	case out := <-done:
		if len(out) != 1 || len(out[0].Checks) != 1 {
			t.Fatalf("expected the one check to run after resume, got %+v", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runChecks did not complete after Resume")
	}
}

// TestRunChecksCancelWhilePausedStopsAndReturnsPartial proves cancelling ctx
// while the gate is paused actually unblocks and stops runChecks (rather
// than waiting forever for a Resume that may never come), and that it
// reports partial=true with none of the still-queued checks run.
func TestRunChecksCancelWhilePausedStopsAndReturnsPartial(t *testing.T) {
	gate := sched.NewGate()
	gate.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	cats := []SimCategory{{Phase: "p", Checks: []SimCheck{
		check("T1", "a", "t", "High", "x", "y", func() (string, string) { return "pass", "" }),
		check("T2", "b", "t", "High", "x", "y", func() (string, string) { return "pass", "" }),
	}}}
	type result struct {
		out     []SimCategory
		partial bool
	}
	done := make(chan result, 1)
	go func() {
		out, partial := runChecks(ctx, cats, nil, gate, nil)
		done <- result{out, partial}
	}()

	// Give the goroutine a moment to actually be blocked inside gate.Wait
	// before cancelling, so this exercises the "cancel arrives while
	// already waiting" path, not just "cancel arrives before Wait is called".
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case res := <-done:
		if !res.partial {
			t.Fatal("expected partial=true after cancelling a paused run")
		}
		total := 0
		for _, cat := range res.out {
			total += len(cat.Checks)
		}
		if total != 0 {
			t.Fatalf("expected zero checks to have run before the cancel, got %d: %+v", total, res.out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runChecks did not return after cancelling while paused")
	}
}

func TestBuildPostureCatalogHarvestsWithoutRunning(t *testing.T) {
	cat := BuildPostureCatalog()
	if len(cat) == 0 {
		t.Fatal("expected at least one posture scenario in catalog")
	}
	for sid, checks := range cat {
		if len(checks) == 0 {
			t.Errorf("scenario %s has no checks", sid)
		}
		for _, c := range checks {
			if c.ID == "" || c.Name == "" {
				t.Errorf("scenario %s has a check with empty id/name: %+v", sid, c)
			}
		}
	}
}

// TestBuildPostureCatalogIncludesDefaultFallback proves the catalog carries a
// postureCatalogDefaultKey entry matching RunAllChecks() -- the set a custom
// (unrecognized) scenario ID actually runs at execution time. Without this,
// the orchestrator's Customize picker and any check-count summary have
// nothing to show for a custom Local Check scenario.
func TestBuildPostureCatalogIncludesDefaultFallback(t *testing.T) {
	cat := BuildPostureCatalog()
	def, ok := cat[postureCatalogDefaultKey]
	if !ok || len(def) == 0 {
		t.Fatalf("expected a %q fallback entry in the catalog, got keys: %v", postureCatalogDefaultKey, cat)
	}
	wantCount := len(checksToMeta(RunAllChecks()))
	if len(def) != wantCount {
		t.Errorf("default catalog entry has %d checks, want %d (RunAllChecks())", len(def), wantCount)
	}
}
