package slapolicy

import (
	"testing"
	"time"
)

func TestDeadlineFor(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := DeadlineFor(Policy{Severity: "High", DurationHours: 72}, start)
	want := start.Add(72 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("DeadlineFor = %v, want %v", got, want)
	}
}

func TestEvaluateSLABreach(t *testing.T) {
	deadline := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before deadline", deadline.Add(-time.Minute), false},
		{"exactly at deadline", deadline, true},
		{"after deadline", deadline.Add(time.Minute), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EvaluateSLABreach(deadline, c.now); got != c.want {
				t.Errorf("EvaluateSLABreach(%v, %v) = %v, want %v", deadline, c.now, got, c.want)
			}
		})
	}
}
