package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwresponse"
)

type rwDimensionJSON struct {
	Verdict    string `json:"verdict"`
	SkipReason string `json:"skipReason,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Action     string `json:"action,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
}

type rwEffectivenessRowJSON struct {
	TechniqueID           string           `json:"techniqueId"`
	Detection             *rwDimensionJSON `json:"detection"`
	Containment           *rwDimensionJSON `json:"containment"`
	Recovery              *rwDimensionJSON `json:"recovery"`
	DetectionLatencyMs    *int64           `json:"detectionLatencyMs"`
	ResponseLatency       string           `json:"responseLatency"`
	ResponseLatencyReason string           `json:"responseLatencyReason"`
}

type rwEffectivenessReportJSON struct {
	Rows []rwEffectivenessRowJSON `json:"rows"`
}

func toDimensionJSON(d *rwresponse.DimensionEvidence) *rwDimensionJSON {
	if d == nil {
		return nil
	}
	return &rwDimensionJSON{
		Verdict:    string(d.Verdict),
		SkipReason: string(d.SkipReason),
		Reason:     d.Reason,
		Action:     d.Action,
		CreatedAt:  d.CreatedAt.Format(time.RFC3339),
	}
}

func toEffectivenessReportJSON(report rwresponse.EffectivenessReport) rwEffectivenessReportJSON {
	out := rwEffectivenessReportJSON{Rows: make([]rwEffectivenessRowJSON, len(report.Rows))}
	for i, r := range report.Rows {
		rowOut := rwEffectivenessRowJSON{
			TechniqueID:           r.TechniqueID,
			Detection:             toDimensionJSON(r.Detection),
			Containment:           toDimensionJSON(r.Containment),
			Recovery:              toDimensionJSON(r.Recovery),
			ResponseLatency:       string(r.ResponseLatency),
			ResponseLatencyReason: r.ResponseLatencyReason,
		}
		if r.DetectionLatency != nil {
			ms := r.DetectionLatency.Milliseconds()
			rowOut.DetectionLatencyMs = &ms
		}
		out.Rows[i] = rowOut
	}
	return out
}

func (h *Handler) GetDetectionResponseEffectiveness(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID := chi.URLParam(r, "runId")

	rows, err := db.RWCapabilityAttempts(ctx, h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	report := rwresponse.BuildEffectivenessReport(rows, nil)
	jsonOK(w, toEffectivenessReportJSON(report))
}
