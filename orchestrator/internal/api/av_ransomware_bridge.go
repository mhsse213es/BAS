package api

import (
	"net/http"
	"sort"

	"github.com/audspect/bas/internal/rwevidence"
)

// This file is the AV/NGAV mastery initiative's bridge into ransomware
// mastery for av.txt §2 group F (ransomware and destructive-impact
// precursors) / §3's "Ransomware behavior" scenario family. av.txt §8
// step 5 explicitly requires integrating with the existing ransomware
// mastery rather than duplicating it, so group F has no Vector of its
// own in internal/avcatalog and no evaluation of its own in
// internal/avefficacy -- a parallel evaluator over the same techniques
// would be exactly the duplication the spec forbids.
//
// The real evaluation pipeline already exists and is already wired:
// rwevidence.EvaluateStep (dispatched for every step of every
// ransomwareScenarioIDs run via recordRWEvidence in
// rwevidence_dispatch.go) persists real, independently-verified
// CapabilityResults, and GetRunRWScore (rwscore_handlers.go) serves them
// per run at GET /api/scenarios/runs/{runId}/rw-score. This handler adds
// no new evaluation: it only answers "which of rwevidence's modeled
// ransomware techniques does a real, already-integrated scenario
// actually exercise", computed live from the engine's real loaded
// scenarios, so an AV/NGAV-facing console can point a customer at real
// evidence instead of fabricating a second copy of it.

// avRansomwareTechnique is one rwevidence-modeled technique's bridge
// entry: its real coverage across the real, already-integrated
// ransomware scenario corpus.
type avRansomwareTechnique struct {
	TechniqueID     string   `json:"techniqueId"`
	TechniqueName   string   `json:"techniqueName"`
	RealScenarioIDs []string `json:"realScenarioIds"`
}

// avRansomwarePrecursorCoverageResponse is GetAVRansomwarePrecursorCoverage's
// JSON shape.
type avRansomwarePrecursorCoverageResponse struct {
	Techniques          []avRansomwareTechnique `json:"techniques"`
	ScoreEndpointFormat string                  `json:"scoreEndpointFormat"`
	Note                string                  `json:"note"`
}

// avRansomwareModeledTechniques are the exact techniques
// rwevidence.EvaluateStep classifies and evaluates today (rwevidence's
// own techniqueFor switch) -- reused here as the real Technique
// constructors, never re-stated as hardcoded strings.
func avRansomwareModeledTechniques() []rwevidence.Technique {
	return []rwevidence.Technique{
		rwevidence.VSSInhibition(),
		rwevidence.DataEncryptedForImpact(),
		rwevidence.DataExfiltrationToCloud(),
		rwevidence.ArchiveStagingViaUtility(),
	}
}

// GetAVRansomwarePrecursorCoverage reports, for each rwevidence-modeled
// ransomware technique, which real scenarios already in
// ransomwareScenarioIDs (the same gate recordRWEvidence itself uses)
// declare a step for that technique in the engine's real, currently
// loaded scenario set -- never a hardcoded or cached list, so this can
// never drift from what the engine actually dispatches today. A
// technique with zero RealScenarioIDs is a genuine, visible gap, not a
// silently omitted row.
func (h *Handler) GetAVRansomwarePrecursorCoverage(w http.ResponseWriter, r *http.Request) {
	coverage := map[string]map[string]bool{} // techniqueID -> set of scenario IDs
	for _, techniqueMeta := range avRansomwareModeledTechniques() {
		coverage[techniqueMeta.MitreID] = map[string]bool{}
	}

	if h.engine != nil {
		for _, sc := range h.engine.List() {
			if sc == nil || !ransomwareScenarioIDs[sc.ID] {
				continue
			}
			for _, step := range sc.Steps {
				if set, ok := coverage[step.TechniqueID]; ok {
					set[sc.ID] = true
				}
			}
		}
	}

	out := make([]avRansomwareTechnique, 0, len(avRansomwareModeledTechniques()))
	for _, techniqueMeta := range avRansomwareModeledTechniques() {
		ids := make([]string, 0, len(coverage[techniqueMeta.MitreID]))
		for id := range coverage[techniqueMeta.MitreID] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out = append(out, avRansomwareTechnique{
			TechniqueID:     techniqueMeta.MitreID,
			TechniqueName:   techniqueMeta.Name,
			RealScenarioIDs: ids,
		})
	}

	respond(w, avRansomwarePrecursorCoverageResponse{
		Techniques:          out,
		ScoreEndpointFormat: "/api/scenarios/runs/{runId}/rw-score",
		Note: "Ransomware-precursor findings for AV/NGAV assessments are evaluated and " +
			"scored by the existing ransomware mastery evidence pipeline (internal/rwevidence, " +
			"internal/rwscore), not by this endpoint. Dispatch one of realScenarioIds and read " +
			"its findings from scoreEndpointFormat once the run completes.",
	})
}
