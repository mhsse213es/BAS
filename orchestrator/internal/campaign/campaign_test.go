package campaign

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

func mk(status string) ChildRun { return ChildRun{Status: status} }

// res builds a SimulationResult with the given verdict and technique ID.
func res(verdict models.CheckResult, techID string) models.SimulationResult {
	return models.SimulationResult{
		Technique: models.AttackTechnique{ID: techID},
		Result:    verdict,
	}
}

func TestDeriveStatus(t *testing.T) {
	cases := []struct {
		name    string
		runs    []ChildRun
		skips   int
		stopped bool
		want    string
	}{
		{"stopped wins", []ChildRun{mk("running")}, 0, true, "stopped"},
		{"stopped with no children", nil, 3, true, "stopped"},
		{"no children all skipped", nil, 3, false, "empty"},
		{"any running", []ChildRun{mk("completed"), mk("running")}, 1, false, "running"},
		{"all completed", []ChildRun{mk("completed"), mk("completed")}, 0, false, "completed"},
		{"all failed", []ChildRun{mk("failed"), mk("failed")}, 0, false, "failed"},
		{"mixed terminal", []ChildRun{mk("completed"), mk("partial")}, 0, false, "partial"},
		{"completed+failed is partial", []ChildRun{mk("completed"), mk("failed")}, 0, false, "partial"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DeriveStatus(c.runs, c.skips, c.stopped); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestAggregate(t *testing.T) {
	// Two dispatched children + two skipped targets.
	//  child A (completed): T1 pass → Prevented; T2 fail, detected → Detected
	//  child B (completed): T3 blocked → Prevented; T4 fail, detected → Detected
	runs := []ChildRun{
		{
			Status:        "completed",
			Results:       []models.SimulationResult{res(models.ResultPass, "T1"), res(models.ResultFail, "T2")},
			DetectedTechs: map[string]bool{"T2": true},
		},
		{
			Status:        "completed",
			Results:       []models.SimulationResult{res(models.ResultBlocked, "T3"), res(models.ResultFail, "T4")},
			DetectedTechs: map[string]bool{"T4": true},
		},
	}
	skips := []Skip{{AgentID: "a3", Reason: "offline"}, {AgentID: "a4", Reason: "busy"}}

	got := Aggregate(runs, skips)
	want := Summary{
		Status:     "completed",
		Progress:   100,
		Targets:    4,
		Dispatched: 2,
		Skipped:    2,
		Prevented:  2,
		Detected:   2,
		Missed:     0,
		Errored:    0,
	}
	if got != want {
		t.Errorf("Aggregate()\n got  %+v\n want %+v", got, want)
	}
}

func TestAggregateMissAndProgress(t *testing.T) {
	// One running, one completed → 50% progress, status running.
	// completed child: T1 fail, NOT detected → Missed; T2 error → Errored.
	runs := []ChildRun{
		{Status: "running"},
		{
			Status:  "completed",
			Results: []models.SimulationResult{res(models.ResultFail, "T1"), res(models.ResultError, "T2")},
		},
	}
	got := Aggregate(runs, nil)
	if got.Progress != 50 {
		t.Errorf("Progress = %d, want 50", got.Progress)
	}
	if got.Status != "running" {
		t.Errorf("Status = %q, want running", got.Status)
	}
	if got.Missed != 1 {
		t.Errorf("Missed = %d, want 1", got.Missed)
	}
	if got.Errored != 1 {
		t.Errorf("Errored = %d, want 1", got.Errored)
	}
	if got.Detected != 0 {
		t.Errorf("Detected = %d, want 0", got.Detected)
	}
}

func TestAggregate_PausedIsAnyRunningChildPaused(t *testing.T) {
	cases := []struct {
		name string
		runs []ChildRun
		want bool
	}{
		{"no children", nil, false},
		{"all running, none paused", []ChildRun{{Status: "running"}, {Status: "running"}}, false},
		{"one running child paused", []ChildRun{{Status: "running"}, {Status: "running", Paused: true}}, true},
		{"paused flag on a terminal child is ignored", []ChildRun{{Status: "completed", Paused: true}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Aggregate(c.runs, nil).Paused; got != c.want {
				t.Errorf("Paused = %v, want %v", got, c.want)
			}
		})
	}
}
