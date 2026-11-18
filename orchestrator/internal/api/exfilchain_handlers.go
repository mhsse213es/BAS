package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/exfilchain"
	"github.com/audspect/bas/internal/models"
)

// GetExfilChain returns the collection-to-exfiltration chain report for one run,
// built from the run's stored step results. It reads only what the run recorded.
func (h *Handler) GetExfilChain(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	var raw []byte
	err := h.db.QueryRow(r.Context(), `SELECT results FROM scenario_runs WHERE id = $1`, runID).Scan(&raw)
	if err == pgx.ErrNoRows {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	var results []models.SimulationResult
	if len(raw) > 0 && json.Unmarshal(raw, &results) != nil {
		jsonError(w, "stored results unreadable", http.StatusInternalServerError)
		return
	}
	inputs := make([]exfilchain.Input, 0, len(results))
	for _, s := range results {
		inputs = append(inputs, exfilchain.Input{
			TechniqueID: s.Technique.ID,
			StepName:    s.StepName,
			Result:      string(s.Result),
			Details:     s.Details + " " + s.RawOutput,
		})
	}
	rep := exfilchain.Build(inputs)
	jsonOK(w, struct {
		exfilchain.Report
		Summary string `json:"summary"`
	}{Report: rep, Summary: rep.Summary()})
}
