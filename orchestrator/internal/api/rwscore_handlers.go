package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwscore"
)

// ── GET /api/scenarios/runs/{runId}/rw-score ──────────────────────────────

func (h *Handler) GetRunRWScore(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	ctx := r.Context()

	var exists string
	if err := h.db.QueryRow(ctx, `SELECT id FROM scenario_runs WHERE id = $1`, runID).Scan(&exists); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	rows, err := db.RWCapabilityCoverage(ctx, h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	scoreRows := make([]rwscore.CoverageRow, len(rows))
	for i, row := range rows {
		scoreRows[i] = rwscore.CoverageRow{
			TechniqueID:    row.TechniqueID,
			Capability:     row.Capability,
			Verdict:        row.Verdict,
			SkipReason:     row.SkipReason,
			SpecificReason: row.SpecificReason,
			Count:          row.Count,
		}
	}
	jsonOK(w, rwscore.ScoreRun(scoreRows))
}
