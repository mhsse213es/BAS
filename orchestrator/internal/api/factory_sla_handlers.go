package api

import (
	"net/http"
	"time"

	"github.com/audspect/bas/internal/tcv"
)

// GetFactorySLA -- GET /api/intel/factory/sla?stage=&since=. Read-only internal
// factory-velocity reporting (spec §9); same access level as the sibling
// intel/analytics read endpoints. stage defaults to queue; since (RFC3339,
// optional) bounds the reporting window and defaults to all history.
func (h *Handler) GetFactorySLA(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	stage := parseStage(r.URL.Query().Get("stage"))
	var since time.Time
	if raw := r.URL.Query().Get("since"); raw != "" {
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			jsonError(w, "since must be an RFC3339 timestamp", http.StatusBadRequest)
			return
		}
		since = ts
	}
	report, err := tcv.NewStore(h.db).SLA(r.Context(), stage, since)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, report)
}

// parseStage maps the stage query parameter to a tcv.Stage, defaulting to the
// queue stage for an empty or unrecognised value.
func parseStage(s string) tcv.Stage {
	switch tcv.Stage(s) {
	case tcv.StageGeneration:
		return tcv.StageGeneration
	case tcv.StageValidation:
		return tcv.StageValidation
	case tcv.StageEndToEnd:
		return tcv.StageEndToEnd
	default:
		return tcv.StageQueue
	}
}
