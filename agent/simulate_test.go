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
	out := runChecks(cats, map[string]bool{idB: true})
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
