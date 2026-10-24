package reporting

import "testing"

func TestBuildInsights_LeastProtectedOnlyWhenItDiffersFromMost(t *testing.T) {
	cases := []struct {
		name        string
		heatmap     []TacticEntry
		wantLeast   bool
	}{
		{"single tactic tested", []TacticEntry{{Tactic: "initial-access", Total: 2, PassPct: 0}}, false},
		{"all tactics tied", []TacticEntry{{Tactic: "execution", Total: 2, PassPct: 0}, {Tactic: "persistence", Total: 2, PassPct: 0}}, false},
		{"tactics differ", []TacticEntry{{Tactic: "execution", Total: 2, PassPct: 50}, {Tactic: "persistence", Total: 2, PassPct: 0}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ins := buildInsights(c.heatmap, DetectionSummary{TelemetryObserved: true})
			if got := ins.Least != nil; got != c.wantLeast {
				t.Fatalf("Least set = %v, want %v", got, c.wantLeast)
			}
			if ins.Least != nil && ins.Most != nil && ins.Least.Tactic == ins.Most.Tactic {
				t.Errorf("Least and Most name the same tactic %q", ins.Least.Tactic)
			}
		})
	}
}
