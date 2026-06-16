package campaign

import "testing"

func mk(status string) ChildRun { return ChildRun{Status: status} }

func TestDeriveStatus(t *testing.T) {
	cases := []struct {
		name    string
		runs    []ChildRun
		skips   int
		stopped bool
		want    string
	}{
		{"stopped wins", []ChildRun{mk("running")}, 0, true, "stopped"},
		{"no children all skipped", nil, 3, false, "empty"},
		{"any running", []ChildRun{mk("completed"), mk("running")}, 1, false, "running"},
		{"all completed", []ChildRun{mk("completed"), mk("completed")}, 0, false, "completed"},
		{"all failed", []ChildRun{mk("failed"), mk("failed")}, 0, false, "failed"},
		{"mixed terminal", []ChildRun{mk("completed"), mk("partial")}, 0, false, "partial"},
		{"completed+failed is partial", []ChildRun{mk("completed"), mk("failed")}, 0, false, "partial"},
	}
	for _, c := range cases {
		if got := DeriveStatus(c.runs, c.skips, c.stopped); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
