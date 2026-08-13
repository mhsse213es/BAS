package main

import "testing"

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
	out := runChecks(cats, map[string]bool{idB: true}, nil)
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
	runChecks(cats, nil, func(c SimCheck) { seen = append(seen, c) })
	if len(seen) != 2 {
		t.Fatalf("expected callback for both checks, got %d: %+v", len(seen), seen)
	}
	if seen[0].Result == "" || seen[1].Result == "" {
		t.Fatalf("callback fired before check.run() filled in Result: %+v", seen)
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
