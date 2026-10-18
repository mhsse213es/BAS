package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/reporting"
)

// GET /api/phishing-runs/{id}/report -- renders the client-facing
// report for one persisted run. Sources exclusively from the run's
// own persisted Result (see BuildPhishingScenarioReport's own doc
// comment); never re-evaluates. The run's own Status (e.g. still
// pending) is rendered as-is, never papered over.
func (h *Handler) GetPhishingRunReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetPhishingRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "phishing run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	catalog, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var catalogEntry phishcatalog.Scenario
	for _, s := range catalog {
		if s.ID == run.ScenarioID {
			catalogEntry = s
			break
		}
	}

	rep, err := reporting.BuildPhishingScenarioReport(run, catalogEntry)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reporting.PhishingScenarioReportHTML(w, rep); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
