package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dxcorrelate"
)

// toAttemptRows adapts raw per-attempt rows into dxcorrelate's own Leg
// vocabulary -- the one place in this sub-project allowed to know both
// MITRE technique IDs and dxcorrelate's types. No case produces
// Leg=encryption, or Behavior=Occurred for any leg: there is no accepted
// direct-behavior signal in this codebase today (design spec section A).
// T1486's Prevention/Detection/Containment rows are deliberately NOT
// translated into any AttemptRow at all.
func toAttemptRows(rows []db.RWAttemptRow) []dxcorrelate.AttemptRow {
	out := make([]dxcorrelate.AttemptRow, 0, len(rows))
	for _, r := range rows {
		var leg dxcorrelate.Leg
		switch {
		case r.TechniqueID == "T1560.001" && r.Capability == "data_protection":
			leg = dxcorrelate.LegStaging
		case r.TechniqueID == "T1567.002" && r.Capability == "data_protection":
			leg = dxcorrelate.LegTransfer
		default:
			continue
		}
		out = append(out, dxcorrelate.AttemptRow{
			Leg:             leg,
			Action:          r.Action,
			ControlEfficacy: controlEfficacyFor(r),
			Behavior:        dxcorrelate.BehaviorNotEstablished,
			Reason:          r.Reason,
			CreatedAt:       r.CreatedAt,
		})
	}
	return out
}

func controlEfficacyFor(r db.RWAttemptRow) dxcorrelate.ControlEfficacyStatus {
	switch {
	case r.Verdict == "PASS":
		return dxcorrelate.EfficacyDetected
	case r.Verdict == "FAIL":
		return dxcorrelate.EfficacyNotDetected
	case r.Verdict == "SKIPPED" && r.SkipReason == "not_applicable":
		return dxcorrelate.EfficacyNotApplicable
	default:
		return dxcorrelate.EfficacyNoEvidence
	}
}

type dxLegJSON struct {
	Leg             string `json:"leg"`
	ControlEfficacy string `json:"controlEfficacy"`
	Behavior        string `json:"behavior"`
	Reason          string `json:"reason,omitempty"`
}

type dxCorrelationJSON struct {
	Legs           []dxLegJSON `json:"legs"`
	Classification string      `json:"classification"`
	Anomaly        string      `json:"anomaly,omitempty"`
}

func toCorrelationJSON(result dxcorrelate.CorrelationResult) dxCorrelationJSON {
	out := dxCorrelationJSON{Legs: make([]dxLegJSON, len(result.Legs)), Classification: string(result.Classification), Anomaly: result.Anomaly}
	for i, l := range result.Legs {
		out.Legs[i] = dxLegJSON{Leg: string(l.Leg), ControlEfficacy: string(l.ControlEfficacy), Behavior: string(l.Behavior), Reason: l.Reason}
	}
	return out
}

func (h *Handler) GetDoubleExtortionCorrelation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID := chi.URLParam(r, "runId")

	rows, err := db.RWCapabilityAttempts(ctx, h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	result := dxcorrelate.Correlate(toAttemptRows(rows))
	jsonOK(w, toCorrelationJSON(result))
}
