package rwresponse

import (
	"sort"
	"time"

	"github.com/audspect/bas/internal/db"
)

// BuildEffectivenessReport groups rows by TechniqueID, selects each
// technique's earliest row per capability in {detection, containment,
// recovery} (deterministic -- ties and input-slice reordering never
// change the result, mirroring dxcorrelate.selectLegEvidence's own
// earliest-wins rule), and attaches latency evidence by (TechniqueID,
// Action) when latencies supplies a match. Output rows are sorted by
// TechniqueID for deterministic ordering. A technique whose only rows are
// Prevention/DataProtection still appears in the output, with Detection/
// Containment/Recovery all nil -- this package groups by TechniqueID
// first and filters by capability second, so no technique silently
// disappears because its rows happen to be outside this package's three
// read capabilities.
func BuildEffectivenessReport(rows []db.RWAttemptRow, latencies []DetectionLatencyEvidence) EffectivenessReport {
	byTechnique := map[string][]db.RWAttemptRow{}
	for _, r := range rows {
		byTechnique[r.TechniqueID] = append(byTechnique[r.TechniqueID], r)
	}

	latencyByKey := map[string]time.Duration{}
	for _, l := range latencies {
		latencyByKey[l.TechniqueID+"/"+l.Action] = l.Latency
	}

	techniqueIDs := make([]string, 0, len(byTechnique))
	for id := range byTechnique {
		techniqueIDs = append(techniqueIDs, id)
	}
	sort.Strings(techniqueIDs)

	out := make([]EffectivenessRow, 0, len(techniqueIDs))
	for _, id := range techniqueIDs {
		techRows := byTechnique[id]
		detection := selectDimension(techRows, "detection")
		containment := selectDimension(techRows, "containment")
		recovery := selectDimension(techRows, "recovery")

		rowOut := EffectivenessRow{
			TechniqueID:           id,
			Detection:             detection,
			Containment:           containment,
			Recovery:              recovery,
			ResponseLatency:       ResponseLatencyNotEstablishable,
			ResponseLatencyReason: responseLatencyNotEstablishableReason,
		}
		if detection != nil {
			if lat, ok := latencyByKey[id+"/"+detection.Action]; ok {
				rowOut.DetectionLatency = &lat
			}
		}
		out = append(out, rowOut)
	}
	return EffectivenessReport{Rows: out}
}

func selectDimension(rows []db.RWAttemptRow, capability string) *DimensionEvidence {
	var matching []db.RWAttemptRow
	for _, r := range rows {
		if r.Capability == capability {
			matching = append(matching, r)
		}
	}
	if len(matching) == 0 {
		return nil
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].CreatedAt.Before(matching[j].CreatedAt) })
	first := matching[0]
	return &DimensionEvidence{Verdict: first.Verdict, SkipReason: first.SkipReason, Reason: first.Reason, Action: first.Action, CreatedAt: first.CreatedAt}
}
