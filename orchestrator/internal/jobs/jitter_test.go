package jobs

import (
	"testing"
	"time"
)

func TestJitterOffset_Deterministic(t *testing.T) {
	first := jitterOffset("sched-a", scheduleJitterWindow)
	second := jitterOffset("sched-a", scheduleJitterWindow)
	if first != second {
		t.Errorf("jitterOffset() = %v then %v, want identical results for the same ID", first, second)
	}
}

func TestJitterOffset_WithinBounds(t *testing.T) {
	ids := []string{"sched-a", "sched-b", "sched-c", "sched-d", "sched-e", "sched-f", "sched-g", "sched-h", "sched-i", "sched-j"}
	for _, id := range ids {
		off := jitterOffset(id, scheduleJitterWindow)
		if off < -scheduleJitterWindow || off > scheduleJitterWindow {
			t.Errorf("jitterOffset(%q) = %v, want within [%v, %v]", id, off, -scheduleJitterWindow, scheduleJitterWindow)
		}
	}
}

func TestJitterOffset_PinnedValues(t *testing.T) {
	cases := []struct {
		id   string
		want time.Duration
	}{
		{"sched-a", 13504439675 * time.Nanosecond},
		{"sched-c", -25518816738 * time.Nanosecond},
	}
	for _, c := range cases {
		got := jitterOffset(c.id, scheduleJitterWindow)
		if got != c.want {
			t.Errorf("jitterOffset(%q) = %v, want %v -- if this legitimately changed, the derivation algorithm changed and every schedule's fire time silently shifted", c.id, got, c.want)
		}
	}
}
