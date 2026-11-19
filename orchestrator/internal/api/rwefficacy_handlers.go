package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rwefficacy"
)

// efficacyResponse is the run-level statement plus the steps that have no
// capability evidence. EndpointOnly is not part of the overall statement.
type efficacyResponse struct {
	rwefficacy.Report
	EndpointOnly []rwefficacy.EndpointStep `json:"endpointOnly"`
}

// GetRansomwareEfficacy returns the run-level ransomware efficacy statement:
// per-dimension status (proven / partial / unproven / gap / not_applicable),
// per-attempt worst-case verdicts, and an overall that is never "evidenced"
// unless detection, containment and recovery are each fully proven. Steps
// with no capability evidence are listed separately as endpoint-only.
func (h *Handler) GetRansomwareEfficacy(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	rows, err := db.RWCapabilityAttempts(r.Context(), h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	var raw []byte
	steps := []rwefficacy.EndpointStep{}
	err = h.db.QueryRow(r.Context(), `SELECT results FROM scenario_runs WHERE id = $1`, runID).Scan(&raw)
	if err != nil && err != pgx.ErrNoRows {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if err == nil && len(raw) > 0 {
		var results []models.SimulationResult
		if json.Unmarshal(raw, &results) != nil {
			jsonError(w, "stored results unreadable", http.StatusInternalServerError)
			return
		}
		for _, s := range results {
			steps = append(steps, rwefficacy.EndpointStep{
				TechniqueID: s.Technique.ID,
				StepName:    s.StepName,
				Result:      string(s.Result),
				Details:     s.Details,
			})
		}
	}

	jsonOK(w, efficacyResponse{
		Report:       rwefficacy.Build(rows),
		EndpointOnly: rwefficacy.EndpointOnly(rows, steps),
	})
}
