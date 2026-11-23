package segprobe

import (
	"testing"

	"github.com/audspect/bas/internal/segprobe/runstore"
)

func TestLatestCompletedPerPack_NewestCompletedRunWinsPerPack(t *testing.T) {
	// The store lists newest first.
	runs := []runstore.Run{
		{ID: "r5", PackID: "swift-isolation", Status: "failed"},    // newest, but not completed: skipped
		{ID: "r4", PackID: "swift-isolation", Status: "completed"}, // newest completed for swift: chosen
		{ID: "r3", PackID: "swift-isolation", Status: "completed"}, // older: not chosen
		{ID: "r2", PackID: "cde-atm-isolation", Status: "running"},
		{ID: "r1", PackID: "cde-atm-isolation", Status: "completed"}, // only completed run for cde: chosen
	}
	got := LatestCompletedPerPack(runs)
	ids := map[string]bool{}
	for _, r := range got {
		ids[r.ID] = true
	}
	if len(got) != 2 || !ids["r4"] || !ids["r1"] {
		t.Fatalf("got %+v, want runs r4 and r1", got)
	}
}
