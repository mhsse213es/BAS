package contentregistry

import (
	"sort"

	"github.com/audspect/bas/internal/scenario"
)

type DriftItem struct {
	TaskID            string `json:"taskId"`
	Status            string `json:"status"` // NO_DRIFT | COMPONENT_DRIFT | DRIFT_UNKNOWN
	HistoricalVersion string `json:"historicalComponentVersion,omitempty"`
	CurrentVersion    string `json:"currentComponentVersion,omitempty"`
}

// CompareDrift compares a run's recorded resolved hashes with a fresh
// rebuild of the same immutable version (spec §7). Steps without a recorded
// resolved hash (pre-registry runs, variant expansions) are DRIFT_UNKNOWN,
// never assumed unchanged.
func CompareDrift(historical map[string]scenario.StepMeta, current map[string]string, cv scenario.ComponentVersions) []DriftItem {
	out := make([]DriftItem, 0, len(historical))
	for taskID, m := range historical {
		it := DriftItem{TaskID: taskID, HistoricalVersion: m.ComponentVersion}
		switch m.Component {
		case "art":
			it.CurrentVersion = cv.ART
		case "caldera":
			it.CurrentVersion = cv.Caldera
		}
		cur, present := current[taskID]
		switch {
		case m.ResolvedSHA256 == "" || m.BaseTaskID != "":
			it.Status = "DRIFT_UNKNOWN"
		case !present || cur != m.ResolvedSHA256:
			it.Status = "COMPONENT_DRIFT"
		default:
			it.Status = "NO_DRIFT"
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TaskID < out[j].TaskID })
	return out
}
