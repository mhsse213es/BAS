package auditpurge

import (
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func TestEffectiveCutoff_ConfiguredMaximum(t *testing.T) {
	cutoff := EffectiveCutoff(fixedNow, 365)
	if !cutoff.Equal(fixedNow.AddDate(0, 0, -365)) {
		t.Fatalf("cutoff %s, want 365 days before now", cutoff)
	}
}

// A maximum below the 180-day minimum is raised to it. Rows inside the window are never eligible.
func TestEffectiveCutoff_NeverInsideTheMinimumWindow(t *testing.T) {
	for _, days := range []int{0, 1, 90, 179, 180} {
		cutoff := EffectiveCutoff(fixedNow, days)
		if !cutoff.Equal(fixedNow.AddDate(0, 0, -180)) {
			t.Errorf("maximum %d: cutoff %s, want 180 days before now", days, cutoff)
		}
	}
}

func TestEffectiveCutoff_UsesUTC(t *testing.T) {
	local := time.FixedZone("IST", 5*3600+1800)
	cutoff := EffectiveCutoff(fixedNow.In(local), 365)
	if cutoff.Location() != time.UTC {
		t.Fatalf("cutoff location %s, want UTC", cutoff.Location())
	}
}

func TestBatchID_IsDeterministic(t *testing.T) {
	c := EffectiveCutoff(fixedNow, 365)
	if BatchID(c, 10, 20) != BatchID(c, 10, 20) {
		t.Fatal("the same batch must always get the same id, so a resumed purge rewrites the same archive")
	}
	if BatchID(c, 10, 20) == BatchID(c, 10, 21) {
		t.Fatal("different id ranges must get different batch ids")
	}
}
