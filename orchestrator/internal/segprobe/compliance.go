package segprobe

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/segprobe/runstore"
)

// segmentationTechnique is the ATT&CK technique a prohibited cross-zone probe is scored under. The probe is a
// reachability attempt across a zone boundary, which is network service discovery from the attacker's side.
var segmentationTechnique = models.AttackTechnique{ID: "T1046", Name: "Network Service Discovery", Tactic: "discovery"}

// ComplianceResults turns one segmentation run's probe rows into simulation results the compliance mapper can
// score. Only deny probes count: an allowed flow shows connectivity, not that a control works. A deny probe
// that the firewall blocked with evidence is a control pass; one that reached the target is a failure; a probe
// without attributable evidence is skipped, and a probe that could not run is an error, never a pass.
func ComplianceResults(runID string, rows []runstore.ProbeRow) []models.SimulationResult {
	var out []models.SimulationResult
	for _, row := range rows {
		if row.Expect != string(ExpectDeny) {
			continue
		}
		var result models.CheckResult
		switch row.Verdict {
		case string(PASS):
			result = models.ResultBlocked
		case string(FAIL):
			result = models.ResultFail
		case string(UNKNOWN):
			result = models.ResultSkipped
		default:
			result = models.ResultError
		}
		out = append(out, models.SimulationResult{
			ID:        fmt.Sprintf("segprobe-%s-%d-%d", runID, row.RunIndex, row.Seq),
			StepName:  row.ProbeID,
			Technique: segmentationTechnique,
			Result:    result,
			Details:   row.Reason,
			Framework: "segprobe",
			StartedAt: derefTime(row.StartedAt),
		})
	}
	return out
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
