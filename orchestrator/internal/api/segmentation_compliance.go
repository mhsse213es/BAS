package api

import (
	"context"
	"log"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/segprobe"
)

// segmentationEvidenceApplies reports whether a framework's report includes segmentation lab evidence.
func segmentationEvidenceApplies(frameworkID string) bool {
	return frameworkID == "PCI_DSS_V4"
}

// segmentationEvidenceFor returns the segmentation probe results to add to a framework's report: the newest
// completed run of each pack, converted for the compliance mapper. The evidence is lab-wide, not per agent.
// A store error logs and returns nothing, so the report still builds from endpoint results alone.
func (h *Handler) segmentationEvidenceFor(ctx context.Context, frameworkID string) []models.SimulationResult {
	if !segmentationEvidenceApplies(frameworkID) || h.segRuns == nil {
		return nil
	}
	runs, err := h.segRuns.List(ctx, 200)
	if err != nil {
		log.Printf("[report] segmentation runs for %s: %v", frameworkID, err)
		return nil
	}
	var out []models.SimulationResult
	for _, run := range segprobe.LatestCompletedPerPack(runs) {
		_, rows, err := h.segRuns.Get(ctx, run.ID)
		if err != nil {
			log.Printf("[report] segmentation run %s rows: %v", run.ID, err)
			continue
		}
		out = append(out, segprobe.ComplianceResults(run.ID, rows)...)
	}
	return out
}
