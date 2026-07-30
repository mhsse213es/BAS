package reporting

import (
	"encoding/json"

	"github.com/audspect/bas/internal/models"
)

// DetectedTechniques returns the set of technique ids whose FAIL was
// detected, from a run's persisted detection_summary.techniques (the
// agent's post-run alert sweep), falling back to ClassifyDetectionStatus
// per FAILed result when no sweep data marks a technique detected. This
// mirrors how buildKillChain decides detected vs missed -- the same
// persisted detection_summary column feeds both.
//
// The second loop is NOT gated on detRaw being empty -- it always runs,
// checking every FAILed result's Events for any technique the sweep data
// didn't already mark detected.
func DetectedTechniques(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) > 0 {
		var ds struct {
			Techniques []struct {
				TechniqueID string `json:"techniqueId"`
				Verdict     string `json:"verdict"`
			} `json:"techniques"`
		}
		if json.Unmarshal(detRaw, &ds) == nil {
			for _, t := range ds.Techniques {
				if t.Verdict == "detected" {
					out[t.TechniqueID] = true
				}
			}
		}
	}
	for _, res := range results {
		if res.Result == models.ResultFail && !out[res.Technique.ID] {
			if ClassifyDetectionStatus(res.Events) == "Detected" {
				out[res.Technique.ID] = true
			}
		}
	}
	return out
}
