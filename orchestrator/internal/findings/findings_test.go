package findings

import (
	"testing"
	"time"
)

func TestControlClass(t *testing.T) {
	cases := []struct {
		ds   []string
		want string
	}{
		{[]string{"Logon Session", "Process: Process Creation"}, "Identity"},
		{[]string{"Network Traffic: Network Connection Creation"}, "Network"},
		{[]string{"Domain Name: Active DNS"}, "DNS"},
		{[]string{"Cloud Service: Cloud Service Enumeration"}, "Cloud"},
		{[]string{"Command: Command Execution"}, "Endpoint"},
		{nil, "Endpoint"},
	}
	for _, c := range cases {
		if got := ControlClass(c.ds); got != c.want {
			t.Errorf("ControlClass(%v) = %q, want %q", c.ds, got, c.want)
		}
	}
}

func obs(out, run string, ts time.Time) Observation {
	return Observation{Outcome: out, RunID: run, ObservedAt: ts}
}

func TestApply(t *testing.T) {
	t0 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	// create on a miss
	s, tr := Apply(State{}, obs("missed", "r1", t0))
	if tr != Created || !s.Exists || s.Status != "open" || s.ExposureState != "missed" || s.OccurrenceCount != 1 {
		t.Fatalf("create: %v %+v", tr, s)
	}
	// recur newer run → count++
	s, tr = Apply(s, obs("missed", "r2", t1))
	if tr != Recurred || s.OccurrenceCount != 2 {
		t.Fatalf("recur: %v %+v", tr, s)
	}
	// same-run refine: detection arrives for r2 → detected_only, no count change
	s, tr = Apply(s, obs("detected_only", "r2", t1))
	if tr != Refined || s.ExposureState != "detected_only" || s.OccurrenceCount != 2 {
		t.Fatalf("refine: %v %+v", tr, s)
	}
	// worst across runs: a newer miss makes it missed again
	s, tr = Apply(s, obs("missed", "r3", t2))
	if s.ExposureState != "missed" || s.OccurrenceCount != 3 {
		t.Fatalf("worst: %v %+v", tr, s)
	}
	// heal on prevented (newer)
	healed, tr := Apply(s, obs("prevented", "r4", t2.Add(time.Hour)))
	if tr != Healed || healed.Status != "remediated" || !healed.Resolved {
		t.Fatalf("heal: %v %+v", tr, healed)
	}
	// reopen on a new miss after remediation
	re, tr := Apply(healed, obs("missed", "r5", t2.Add(2*time.Hour)))
	if tr != Reopened || re.Status != "open" || re.ReopenedCount != 1 || re.Resolved {
		t.Fatalf("reopen: %v %+v", tr, re)
	}
	// stale: an older run never changes state or heals
	st, tr := Apply(re, obs("prevented", "rOld", t0))
	if tr != Stale || st.Status != "open" {
		t.Fatalf("stale: %v %+v", tr, st)
	}
	// risk_accepted sticky vs heal
	ra := State{Exists: true, Status: "risk_accepted", ExposureState: "missed", OccurrenceCount: 1, LastObservedAt: t0}
	ra2, tr := Apply(ra, obs("prevented", "rN", t1))
	if tr != Noop || ra2.Status != "risk_accepted" {
		t.Fatalf("ra-heal: %v %+v", tr, ra2)
	}
	// prevented on a non-existent finding → nothing
	none, tr := Apply(State{}, obs("prevented", "rX", t1))
	if tr != Noop || none.Exists {
		t.Fatalf("prevented-noop: %v %+v", tr, none)
	}
}
