package contentregistry

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestCompareDrift_VariantPresentInCurrentStaysUnknown(t *testing.T) {
	hist := map[string]scenario.StepMeta{
		"v1": {Component: "art", ResolvedSHA256: "aaa", BaseTaskID: "base"},
	}
	got := CompareDrift(hist, map[string]string{"v1": "aaa"}, scenario.ComponentVersions{})
	if len(got) != 1 || got[0].Status != "DRIFT_UNKNOWN" {
		t.Fatalf("%+v", got)
	}
}

func TestCompareDrift(t *testing.T) { // A10
	hist := map[string]scenario.StepMeta{
		"same":    {Component: "art", ComponentVersion: "v1", ResolvedSHA256: "aaa"},
		"changed": {Component: "art", ComponentVersion: "v1", ResolvedSHA256: "bbb"},
		"removed": {Component: "caldera", ResolvedSHA256: "ccc"},
		"legacy":  {Component: "art"},
		"variant": {Component: "custom", BaseTaskID: "same"},
	}
	cur := map[string]string{"same": "aaa", "changed": "zzz"}
	got := map[string]DriftItem{}
	for _, it := range CompareDrift(hist, cur, scenario.ComponentVersions{ART: "v2"}) {
		got[it.TaskID] = it
	}
	want := map[string]string{"same": "NO_DRIFT", "changed": "COMPONENT_DRIFT", "removed": "COMPONENT_DRIFT",
		"legacy": "DRIFT_UNKNOWN", "variant": "DRIFT_UNKNOWN"}
	for id, st := range want {
		if got[id].Status != st {
			t.Errorf("%s: %s want %s", id, got[id].Status, st)
		}
	}
	if c := got["changed"]; c.HistoricalVersion != "v1" || c.CurrentVersion != "v2" {
		t.Fatalf("versions: %+v", c)
	}
}
