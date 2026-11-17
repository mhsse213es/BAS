package rwresponse

import (
	"sort"
	"time"

	"github.com/audspect/bas/internal/controlval"
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

// dimensionSeverity ranks a row so the worst outcome for a technique is the
// one reported: FAIL, then ERROR, then an unproven skip, then PASS, then
// not_applicable. Earliest row wins a tie, keeping output deterministic.
func dimensionSeverity(r db.RWAttemptRow) int {
	switch {
	case r.Verdict == controlval.VerdictFail:
		return 4
	case r.Verdict == controlval.VerdictError:
		return 3
	case r.Verdict == controlval.VerdictSkipped && r.SkipReason != controlval.SkipNotApplicable:
		return 2
	case r.Verdict == controlval.VerdictPass:
		return 1
	}
	return 0
}

// selectDimension reports the WORST row for the capability across every
// action sharing the technique, so a later FAIL is never hidden behind an
// earlier PASS (several steps can share one technique, e.g. three T1490).
func selectDimension(rows []db.RWAttemptRow, capability string) *DimensionEvidence {
	var best *db.RWAttemptRow
	for i := range rows {
		r := &rows[i]
		if r.Capability != capability {
			continue
		}
		if best == nil || dimensionSeverity(*r) > dimensionSeverity(*best) ||
			(dimensionSeverity(*r) == dimensionSeverity(*best) && r.CreatedAt.Before(best.CreatedAt)) {
			best = r
		}
	}
	if best == nil {
		return nil
	}
	return &DimensionEvidence{Verdict: best.Verdict, SkipReason: best.SkipReason, Reason: best.Reason, Action: best.Action, CreatedAt: best.CreatedAt}
}
